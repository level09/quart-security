"""A page that needs a fresh login sends a stale session to /verify and back."""

import datetime
import time

from quart_security.utils import naive_utcnow


async def stale_login(client):
    await client.post(
        "/login", form={"email": "user@example.com", "password": "correct-password"}
    )
    async with client.session_transaction() as state:
        state["_auth_at"] = int(time.time()) - 7200


async def test_stale_page_visit_goes_to_verify_and_back(client):
    await stale_login(client)
    response = await client.get("/change?tab=1")
    assert response.headers["Location"] == "/verify?next=/change?tab%3D1"

    page = await client.get(response.headers["Location"])
    assert b'type="password"' in await page.get_data()
    verified = await client.post(
        response.headers["Location"], form={"password": "correct-password"}
    )
    assert verified.headers["Location"] == "/change?tab=1"
    assert (await client.get("/change")).status_code == 200


async def test_stale_api_call_gets_401(client):
    await stale_login(client)
    response = await client.post("/change", json={})
    assert response.status_code == 401


async def test_stale_form_post_goes_to_verify_without_next(client):
    await stale_login(client)
    response = await client.post("/change", form={}, headers={"Accept": "text/html"})
    assert response.headers["Location"] == "/verify"


async def test_wrong_password_counts_and_stays_stale(app, client):
    await stale_login(client)
    response = await client.post("/verify?next=/change", form={"password": "wrong"})
    assert response.status_code == 200
    assert app.extensions["test_basic_user"].failed_login_count == 1
    assert (await client.get("/change")).headers["Location"].startswith("/verify")


async def test_locked_account_cannot_verify(app, client):
    await stale_login(client)
    user = app.extensions["test_basic_user"]
    user.locked_until = naive_utcnow() + datetime.timedelta(minutes=5)
    response = await client.post("/verify", form={"password": "correct-password"})
    assert response.status_code == 200
    assert (await client.get("/change")).headers["Location"].startswith("/verify")


async def test_unsafe_next_falls_back(client):
    await stale_login(client)
    response = await client.post(
        "/verify?next=//evil.example", form={"password": "correct-password"}
    )
    assert response.headers["Location"] == "/protected"


async def test_user_without_password_is_offered_sign_out(app, client):
    await stale_login(client)
    app.extensions["test_basic_user"].password = None
    page = await client.get("/verify")
    assert b"Sign out and sign in again" in await page.get_data()
    response = await client.post("/verify", form={"password": "anything"})
    assert response.status_code == 200
    assert (await client.get("/change")).headers["Location"].startswith("/verify")


async def test_signed_out_verify_goes_to_login(client):
    response = await client.get("/verify")
    assert response.headers["Location"].startswith("/login")


async def test_passkey_verify_keeps_next(client_webauthn):
    await client_webauthn.post(
        "/login", form={"email": "user@example.com", "password": "correct-password"}
    )
    page = await client_webauthn.get("/wan-verify?next=/wan-register")
    assert b"/wan-verify?next=/wan-register" in await page.get_data()


async def test_fresh_session_skips_the_prompt(client):
    await client.post(
        "/login", form={"email": "user@example.com", "password": "correct-password"}
    )
    response = await client.get("/verify?next=/change")
    assert response.headers["Location"] == "/change"
