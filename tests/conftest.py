import datetime
import secrets
import time
from dataclasses import dataclass, field
from itertools import count

import pytest
from quart import Quart

from quart_security import Security, auth_required, hash_password, roles_required
from quart_security.models import RoleMixin, UserMixin


@dataclass
class Role(RoleMixin):
    name: str
    description: str | None = None


@dataclass
class WebAuthnCredential:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    name: str
    usage: str = "secondary"
    backup_state: bool = False
    device_type: str = "single_device"
    lastuse_datetime: datetime.datetime | None = None
    user_id: str | None = None


@dataclass
class User(UserMixin):
    fs_uniquifier: str
    email: str
    password: str
    active: bool = True
    name: str | None = None
    roles: list[Role] = field(default_factory=list)
    password_set: bool = True
    login_count: int | None = None
    last_login_at: object = None
    current_login_at: object = None
    last_login_ip: str | None = None
    current_login_ip: str | None = None
    tf_primary_method: str | None = None
    tf_totp_secret: str | None = None
    mf_recovery_codes: list[str] | None = None
    fs_webauthn_user_handle: str | None = None
    webauthn: list[WebAuthnCredential] = field(default_factory=list)
    failed_login_count: int | None = None
    locked_until: datetime.datetime | None = None

    @property
    def has_usable_password(self):
        return self.password_set


class InMemoryDatastore:
    def __init__(self):
        self.users: list[User] = []
        self.roles: list[Role] = []
        self._user_ids = count(1)
        self._role_ids = count(1)

    def find_user(self, **kwargs):
        for user in self.users:
            if all(getattr(user, key, None) == value for key, value in kwargs.items()):
                return user
        return None

    def find_role(self, name):
        for role in self.roles:
            if role.name == name:
                return role
        return None

    def create_user(self, **kwargs):
        kwargs.setdefault("fs_uniquifier", f"user-{next(self._user_ids)}")
        user = User(**kwargs)
        self.users.append(user)
        return user

    def create_role(self, **kwargs):
        kwargs.setdefault("name", f"role-{next(self._role_ids)}")
        role = Role(**kwargs)
        self.roles.append(role)
        return role

    def add_role_to_user(self, user, role_name):
        role = self.find_role(role_name)
        if role is None:
            role = self.create_role(name=role_name)
        if role in user.roles:
            return False
        user.roles.append(role)
        return True

    def remove_role_from_user(self, user, role_name):
        for role in list(user.roles):
            if role.name == role_name:
                user.roles.remove(role)
                return True
        return False

    def toggle_active(self, user):
        user.active = not user.active
        return user.active

    def set_uniquifier(self, user, uniquifier=None):
        user.fs_uniquifier = uniquifier or user.fs_uniquifier
        return user.fs_uniquifier

    def rotate_uniquifier(self, user, expected, replacement):
        if user.fs_uniquifier != expected:
            return False
        user.fs_uniquifier = replacement
        return True

    def commit(self):
        return None

    def record_auth_failure(self, user, *, max_attempts, lockout_minutes):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= max_attempts:
            from quart_security.utils import naive_utcnow

            user.locked_until = naive_utcnow() + datetime.timedelta(
                minutes=lockout_minutes
            )

    def replace_recovery_codes(self, user, expected, remaining):
        if user.mf_recovery_codes != expected:
            return False
        user.mf_recovery_codes = remaining
        return True

    def get_webauthn_credentials(self, user, usage=None):
        credentials = list(user.webauthn or [])
        if usage:
            credentials = [
                credential
                for credential in credentials
                if getattr(credential, "usage", None) == usage
            ]
        return credentials

    def find_webauthn_credential(self, credential_id, user=None):
        if user is not None:
            candidates = self.get_webauthn_credentials(user)
        else:
            # Global lookup across all users (discoverable credential flow)
            candidates = [cred for u in self.users for cred in (u.webauthn or [])]
        for credential in candidates:
            if credential.credential_id == credential_id:
                return credential
        return None

    def create_webauthn_credential(self, user, **kwargs):
        credential = WebAuthnCredential(**kwargs)
        credential.user_id = user.fs_webauthn_user_handle
        user.webauthn.append(credential)
        return credential

    def delete_webauthn_credential(self, user, credential):
        if credential in user.webauthn:
            user.webauthn.remove(credential)
            return True
        return False


class MemoryStateStore:
    def __init__(self):
        self.records = {}

    async def put(self, payload, *, ttl, token=None):
        token = token or secrets.token_urlsafe(32)
        self.records[token] = (payload, time.time() + ttl)
        return token

    async def get(self, token):
        record = self.records.get(token)
        return record[0] if record and record[1] > time.time() else None

    async def pop(self, token):
        record = self.records.pop(token, None)
        return record[0] if record and record[1] > time.time() else None

    async def claim(self, token, *, ttl):
        if await self.get(token) is not None:
            return False
        await self.put({}, ttl=ttl, token=token)
        return True


@pytest.fixture
def datastore():
    return InMemoryDatastore()


def _build_app(
    datastore: InMemoryDatastore, *, two_factor: bool, webauthn: bool
) -> Quart:
    app = Quart(__name__)
    app.config.update(
        SECRET_KEY="test-secret",
        TESTING=True,
        SECURITY_PASSWORD_SALT="test-salt",
        SECURITY_PASSWORD_LENGTH_MIN=8,
        SECURITY_POST_REGISTER_VIEW="/login",
        SECURITY_POST_LOGIN_VIEW="/protected",
        SECURITY_CSRF_PROTECT=False,
        SECURITY_REGISTERABLE=True,
        SECURITY_CHANGEABLE=True,
        SECURITY_TWO_FACTOR=two_factor,
        SECURITY_WEBAUTHN=webauthn,
        # Low-cost argon2 params for fast tests (OWASP min used in production)
        SECURITY_ARGON2_MEMORY_COST=64,
        SECURITY_ARGON2_TIME_COST=1,
        SECURITY_ARGON2_PARALLELISM=1,
        # Disable breach check by default; individual tests opt in via respx mocks
        SECURITY_PASSWORD_BREACH_CHECK=False,
    )

    Security(app, datastore, state_store=MemoryStateStore())

    basic_user = datastore.create_user(
        fs_uniquifier="user-1",
        email="user@example.com",
        password=hash_password("correct-password", app=app),
        active=True,
    )

    admin_user = datastore.create_user(
        fs_uniquifier="admin-1",
        email="admin@example.com",
        password=hash_password("correct-password", app=app),
        active=True,
    )

    datastore.add_role_to_user(admin_user, "admin")

    @app.get("/protected")
    @auth_required("session")
    async def protected():
        return "ok"

    @app.get("/admin")
    @auth_required("session")
    @roles_required("admin")
    async def admin_only():
        return "admin"

    @app.get("/")
    async def index():
        return "index"

    app.extensions["test_basic_user"] = basic_user
    app.extensions["test_admin_user"] = admin_user
    app.extensions["test_datastore"] = datastore
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def app(datastore):
    return _build_app(datastore, two_factor=False, webauthn=False)


@pytest.fixture
def app_two_factor(datastore):
    return _build_app(datastore, two_factor=True, webauthn=False)


@pytest.fixture
def client_two_factor(app_two_factor):
    return app_two_factor.test_client()


@pytest.fixture
def app_webauthn(datastore):
    return _build_app(datastore, two_factor=False, webauthn=True)


@pytest.fixture
def client_webauthn(app_webauthn):
    return app_webauthn.test_client()


@pytest.fixture
async def database(tmp_path):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy_models import Base

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()
