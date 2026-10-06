import asyncio
import datetime
import re

import pyotp
import pytest
from quart import Quart
from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, select
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy_models import Base

from quart_security import (
    Security,
    SecurityState,
    SQLAlchemyUserDatastore,
    UserMixin,
    auth_required,
    hash_password,
    roles_required,
)
from quart_security.totp import decrypt_totp_secret


class AuthUser(Base, UserMixin):
    __tablename__ = "auth_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    fs_uniquifier: Mapped[str] = mapped_column(String, unique=True)
    email: Mapped[str] = mapped_column(String, unique=True)
    password: Mapped[str] = mapped_column(String)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime.datetime | None] = mapped_column(DateTime)
    tf_primary_method: Mapped[str | None] = mapped_column(String)
    tf_totp_secret: Mapped[str | None] = mapped_column(String)
    mf_recovery_codes: Mapped[list] = mapped_column(JSON, default=list)
    roles: Mapped[list["AuthRole"]] = relationship()
    last_login_at: Mapped[datetime.datetime | None] = mapped_column(DateTime)
    current_login_at: Mapped[datetime.datetime | None] = mapped_column(DateTime)
    last_login_ip: Mapped[str | None] = mapped_column(String)
    current_login_ip: Mapped[str | None] = mapped_column(String)
    login_count: Mapped[int] = mapped_column(Integer, default=0)


class AuthRole(Base):
    __tablename__ = "auth_roles"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_users.id"))
    name: Mapped[str] = mapped_column(String)


@pytest.fixture
async def sql_app(database):
    async with database.kw["bind"].begin() as connection:
        await connection.run_sync(SecurityState.metadata.create_all)
    app = Quart(__name__)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret",
        SECURITY_WEBAUTHN=False,
        SECURITY_PASSWORD_BREACH_CHECK=False,
        SECURITY_ARGON2_MEMORY_COST=64,
        SECURITY_ARGON2_TIME_COST=1,
        SECURITY_POST_LOGIN_VIEW="/protected",
    )
    datastore = SQLAlchemyUserDatastore(database, AuthUser, AuthRole)
    Security(app, datastore)
    async with database() as seed:
        seed.add(
            AuthUser(
                fs_uniquifier="user-1",
                email="user@example.com",
                password=hash_password("correct-password", app=app),
                roles=[AuthRole(name="admin")],
            )
        )
        await seed.commit()

    @app.get("/protected")
    @auth_required("session")
    @roles_required("admin")
    async def protected():
        return "ok"

    yield app
    await datastore.close()


async def csrf(client, route):
    response = await client.get(route)
    assert response.status_code == 200
    return re.search(
        r'name="csrf_token"[^>]*value="([^"]+)"', await response.get_data(as_text=True)
    )[1]


async def test_sql_login_password_change_and_roles(sql_app, database):
    client = sql_app.test_client()
    token = await csrf(client, "/login")
    result = await client.post(
        "/login",
        form={
            "csrf_token": token,
            "email": "user@example.com",
            "password": "correct-password",
        },
    )
    assert result.status_code == 302
    assert (await client.get("/protected")).status_code == 200
    async with database() as check:
        user = await check.scalar(select(AuthUser))
        assert user.login_count == 1
    stolen = sql_app.test_client()
    async with client.session_transaction() as state:
        old = dict(state)
    async with stolen.session_transaction() as state:
        state.update(old)
    token = await csrf(client, "/change")
    result = await client.post(
        "/change",
        form={
            "csrf_token": token,
            "password": "correct-password",
            "new_password": "updated-password",
            "new_password_confirm": "updated-password",
        },
    )
    assert result.status_code == 302
    assert (await stolen.get("/protected")).status_code == 302
    assert (await client.get("/protected")).status_code == 200
    assert database.kw["bind"].pool.checkedout() == 0


async def test_sql_mfa_setup_and_recovery(sql_app, database):
    client = sql_app.test_client()
    token = await csrf(client, "/login")
    await client.post(
        "/login",
        form={
            "csrf_token": token,
            "email": "user@example.com",
            "password": "correct-password",
        },
    )
    token = await csrf(client, "/tf-setup?setup=authenticator")
    async with client.session_transaction() as state:
        pending_token = state["tf_setup_state"]
    async with database() as check:
        pending = await check.scalar(
            select(SecurityState.payload).where(SecurityState.token == pending_token)
        )
    assert pending["secret"].startswith("fernet$")
    result = await client.post(
        "/tf-setup",
        form={
            "csrf_token": token,
            "action": "verify",
            "token": pyotp.TOTP(
                decrypt_totp_secret(pending["secret"], app=sql_app)
            ).now(),
        },
    )
    assert result.status_code == 200
    body = await result.get_data(as_text=True)
    code = re.search(r"[0-9a-f]{5}-[0-9a-f]{5}", body)[0]
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', body)[1]
    await client.post("/logout", form={"csrf_token": token})
    token = await csrf(client, "/login")
    await client.post(
        "/login",
        form={
            "csrf_token": token,
            "email": "user@example.com",
            "password": "correct-password",
        },
    )
    token = await csrf(client, "/mf-recovery")
    result = await client.post("/mf-recovery", form={"csrf_token": token, "code": code})
    assert result.status_code == 302
    assert (await client.get("/protected")).status_code == 200
    async with database() as check:
        user = await check.scalar(select(AuthUser))
        assert len(user.mf_recovery_codes) == 2
    assert database.kw["bind"].pool.checkedout() == 0


async def test_concurrent_enrollment_has_one_winner(sql_app, database, monkeypatch):
    from quart_security import views

    clients = [sql_app.test_client(), sql_app.test_client()]
    forms = []
    for client in clients:
        token = await csrf(client, "/login")
        await client.post(
            "/login",
            form={
                "csrf_token": token,
                "email": "user@example.com",
                "password": "correct-password",
            },
        )
        token = await csrf(client, "/tf-setup?setup=authenticator")
        async with client.session_transaction() as state:
            reference = state["tf_setup_state"]
        async with database() as check:
            payload = await check.scalar(
                select(SecurityState.payload).where(SecurityState.token == reference)
            )
        forms.append(
            {
                "csrf_token": token,
                "action": "verify",
                "token": pyotp.TOTP(
                    decrypt_totp_secret(payload["secret"], app=sql_app)
                ).now(),
            }
        )
    barrier = asyncio.Barrier(2)
    verify = views._verify_totp_once

    async def synchronized_verify(secret, token):
        result = await verify(secret, token)
        await barrier.wait()
        return result

    monkeypatch.setattr(views, "_verify_totp_once", synchronized_verify)
    results = await asyncio.gather(
        *(
            client.post("/tf-setup", form=form)
            for client, form in zip(clients, forms, strict=True)
        )
    )
    assert sorted(result.status_code for result in results) == [200, 409]
