import datetime

import pytest

from quart_security.utils import naive_utcnow


@pytest.mark.asyncio
async def test_protected_redirects_to_login(client):
    response = await client.get("/protected")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


@pytest.mark.asyncio
async def test_login_then_access_protected(client):
    response = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/protected")

    protected = await client.get("/protected")
    assert protected.status_code == 200
    assert (await protected.get_data(as_text=True)) == "ok"


@pytest.mark.asyncio
async def test_admin_route_forbidden_without_role(client):
    await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )

    response = await client.get("/admin")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_route_allowed_with_role(client):
    await client.post(
        "/login",
        form={"email": "admin@example.com", "password": "correct-password"},
    )

    response = await client.get("/admin")
    assert response.status_code == 200
    assert (await response.get_data(as_text=True)) == "admin"


@pytest.mark.asyncio
async def test_login_lockout_blocks_after_repeated_failures(client, app):
    user = app.extensions["test_basic_user"]
    app.config["SECURITY_LOGIN_MAX_ATTEMPTS"] = 2
    app.config["SECURITY_LOCKOUT_MINUTES"] = 15

    first = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "wrong-password"},
    )
    assert first.status_code == 200
    assert user.failed_login_count == 1
    assert user.locked_until is None

    second = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "wrong-password"},
    )
    assert second.status_code == 200
    assert user.failed_login_count == 2
    assert user.locked_until is not None

    locked = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    assert locked.status_code == 200
    assert user.failed_login_count == 2
    assert user.locked_until is not None

    protected = await client.get("/protected")
    assert protected.status_code == 302
    assert "/login" in protected.headers["Location"]


@pytest.mark.asyncio
async def test_login_lockout_resets_after_expiry(client, app):
    user = app.extensions["test_basic_user"]
    user.failed_login_count = 3
    user.locked_until = naive_utcnow() - datetime.timedelta(minutes=1)

    response = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/protected")
    assert user.failed_login_count == 0
    assert user.locked_until is None


@pytest.mark.asyncio
async def test_login_verifies_a_hash_even_without_an_active_account(
    client, app, monkeypatch
):
    """Skipping the hash for unknown or inactive emails would let response time
    reveal which addresses have an account."""
    from quart_security import views

    checked = []
    real = views.verify_password_async

    async def counting(password, password_hash, **kwargs):
        checked.append(password_hash)
        return await real(password, password_hash, **kwargs)

    monkeypatch.setattr(views, "verify_password_async", counting)
    app.extensions["test_admin_user"].active = False
    for email in ("nobody@example.com", "admin@example.com"):
        response = await client.post(
            "/login", form={"email": email, "password": "correct-password"}
        )
        assert response.status_code == 200
    assert len(checked) == 2
    assert checked[0] == checked[1]  # the same stand-in hash, not the user's
