import pytest

from quart_security import verify_password


@pytest.mark.asyncio
async def test_register_creates_user(client, app):
    datastore = app.extensions["test_datastore"]

    response = await client.post(
        "/register",
        form={
            "name": "New User",
            "email": "new@example.com",
            "password": "new-password-123",
            "password_confirm": "new-password-123",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")

    user = datastore.find_user(email="new@example.com")
    assert user is not None
    assert user.password != "new-password-123"
    assert verify_password("new-password-123", user.password)


@pytest.mark.asyncio
async def test_register_duplicate_email_returns_form(client, app):
    datastore = app.extensions["test_datastore"]
    existing = len(datastore.users)

    response = await client.post(
        "/register",
        form={
            "name": "Duplicate",
            "email": "user@example.com",
            "password": "new-password-123",
            "password_confirm": "new-password-123",
        },
    )

    assert response.status_code == 200
    assert len(datastore.users) == existing


@pytest.mark.asyncio
async def test_logout_clears_session(client):
    await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )

    protected_before = await client.get("/protected")
    assert protected_before.status_code == 200

    logout_response = await client.get("/logout")
    assert logout_response.status_code == 302
    assert "/login" in logout_response.headers["Location"]

    protected_after = await client.get("/protected")
    assert protected_after.status_code == 302
    assert "/login" in protected_after.headers["Location"]


@pytest.mark.asyncio
async def test_change_password_requires_current_for_standard_user(client, app):
    user = app.extensions["test_basic_user"]
    old_hash = user.password

    await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )

    response = await client.post(
        "/change",
        form={
            "password": "correct-password",
            "new_password": "updated-password-123",
            "new_password_confirm": "updated-password-123",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/change")
    assert user.password != old_hash
    assert verify_password("updated-password-123", user.password)

    await client.get("/logout")

    invalid_login = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    assert invalid_login.status_code == 200

    valid_login = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "updated-password-123"},
    )
    assert valid_login.status_code == 302
    assert valid_login.headers["Location"].endswith("/protected")


@pytest.mark.asyncio
async def test_change_password_skips_current_for_oauth_style_user(client, app):
    user = app.extensions["test_basic_user"]
    user.password_set = False

    await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )

    response = await client.post(
        "/change",
        form={
            "password": "",
            "new_password": "oauth-updated-123",
            "new_password_confirm": "oauth-updated-123",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/change")
    assert user.password_set is True
    assert verify_password("oauth-updated-123", user.password)
