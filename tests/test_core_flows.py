import time

import pytest

from quart_security import user_register_conflict, verify_password, views
from quart_security.views import _safe_redirect_target


@pytest.mark.asyncio
async def test_register_creates_user(client, app):
    datastore = app.extensions["test_datastore"]

    response = await client.post(
        "/register",
        form={
            "name": "New User",
            "email": "  New@Example.COM  ",
            "password": "new-password-123",
            "password_confirm": "new-password-123",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")

    user = datastore.find_user(email="new@example.com")
    assert user is not None
    assert user.password != "new-password-123"
    assert verify_password("new-password-123", user.password, app=app)


@pytest.mark.asyncio
async def test_login_accepts_email_case_and_surrounding_spaces(client):
    response = await client.post(
        "/login",
        form={"email": "  UsEr@ExAmPlE.CoM  ", "password": "correct-password"},
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/protected")


@pytest.mark.asyncio
async def test_register_with_an_existing_email_looks_like_success(client, app):
    datastore = app.extensions["test_datastore"]
    existing = len(datastore.users)
    owner = datastore.find_user(email="user@example.com")
    conflicts = []

    async def record(sender, user):
        conflicts.append(user)

    form = {
        "email": "User@Example.com",
        "password": "new-password-123",
        "password_confirm": "new-password-123",
    }
    with user_register_conflict.connected_to(record):
        duplicate = await client.post("/register", form=form)
    fresh = await client.post("/register", form={**form, "email": "fresh@example.com"})

    assert duplicate.status_code == fresh.status_code == 302
    assert duplicate.headers["Location"] == fresh.headers["Location"]
    assert len(datastore.users) == existing + 1
    assert conflicts == [owner]
    assert verify_password("correct-password", owner.password, app=app)


@pytest.mark.asyncio
async def test_login_returns_to_the_page_that_asked(client):
    await client.get("/login?next=/%3Ftab%3D2")
    response = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    assert response.headers["Location"] == "/?tab=2"


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["//evil.example", "https://evil.example/", ""])
async def test_login_ignores_unsafe_or_stale_next(client, target):
    await client.get("/login?next=/%3Fold")
    # A later visit replaces the earlier target, even with no or an unsafe one.
    await client.get(f"/login?next={target}")
    response = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    assert response.headers["Location"].endswith("/protected")


@pytest.mark.asyncio
async def test_logout_clears_session(client):
    await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )

    protected_before = await client.get("/protected")
    assert protected_before.status_code == 200

    logout_response = await client.post("/logout")
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
    assert verify_password("updated-password-123", user.password, app=app)

    await client.post("/logout")

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
    assert verify_password("oauth-updated-123", user.password, app=app)


@pytest.mark.asyncio
async def test_session_fixation_pre_login_keys_cleared(client):
    """Pre-login session state must not survive into the authenticated session."""
    async with client.session_transaction() as sess:
        sess["attacker_key"] = "injected"
        sess["_csrf_token"] = "sometoken"

    await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )

    async with client.session_transaction() as sess:
        assert "attacker_key" not in sess
        assert "_user_id" in sess


@pytest.mark.asyncio
async def test_inactive_user_session_is_revoked(client, app):
    await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    app.extensions["test_basic_user"].active = False

    response = await client.get("/protected")

    assert response.status_code == 302
    async with client.session_transaction() as sess:
        assert "_user_id" not in sess


@pytest.mark.asyncio
async def test_logout_rejects_get(client):
    response = await client.get("/logout")
    assert response.status_code == 405


@pytest.mark.asyncio
async def test_logout_requires_valid_csrf(client, app):
    await client.post(
        "/login", form={"email": "user@example.com", "password": "correct-password"}
    )
    app.config["SECURITY_CSRF_PROTECT"] = True
    async with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-token"

    rejected = await client.post("/logout")
    accepted = await client.post("/logout", form={"csrf_token": "valid-token"})

    assert rejected.status_code == 400
    assert accepted.status_code == 302


@pytest.mark.asyncio
async def test_stale_session_cannot_change_mfa(client_two_factor):
    await client_two_factor.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    async with client_two_factor.session_transaction() as sess:
        sess["_auth_at"] = 0

    response = await client_two_factor.get("/tf-setup")

    assert response.status_code == 401


def test_safe_redirect_allows_good_paths():
    assert _safe_redirect_target("/good") == "/good"
    assert _safe_redirect_target("/good?next=x") == "/good?next=x"


def test_safe_redirect_blocks_external():
    assert _safe_redirect_target("//evil.com") == "/"
    assert _safe_redirect_target("http://evil.com/path") == "/"
    assert _safe_redirect_target("//evil.com/path") == "/"


def test_safe_redirect_blocks_backslash():
    assert _safe_redirect_target("/\\evil.com") == "/"
    assert _safe_redirect_target("\\/\\/evil.com") == "/"


def test_safe_redirect_blocks_control_chars():
    assert _safe_redirect_target("/path\x00evil") == "/"
    assert _safe_redirect_target("/path\nevil") == "/"


@pytest.mark.asyncio
async def test_login_ignores_a_next_older_than_the_login_attempt(client, monkeypatch):
    await client.get("/login?next=/%3Fold")
    later = time.time() + views.NEXT_TTL_SECONDS + 1
    monkeypatch.setattr(views.time, "time", lambda: later)
    response = await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    assert response.headers["Location"].endswith("/protected")
