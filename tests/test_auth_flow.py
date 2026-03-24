import datetime

import pytest


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
    user.locked_until = datetime.datetime.now() - datetime.timedelta(minutes=1)

    response = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/protected")
    assert user.failed_login_count == 0
    assert user.locked_until is None
