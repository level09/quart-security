"""Password reset and email confirmation: links, single use, no account oracle."""

import asyncio
import datetime
import re

import pytest
from quart import Quart

from quart_security import Security, verify_password, views
from quart_security.utils import naive_utcnow

FORM = {"password": "brand-new-password", "password_confirm": "brand-new-password"}


class Outbox(list):
    def __init__(self, app):
        super().__init__()
        self.app = app

    async def settle(self):
        """Wait for the jobs that run after each response."""
        while self.app.background_tasks:
            await asyncio.gather(*list(self.app.background_tasks))


@pytest.fixture
def mail(app):
    app.config.update(
        SECURITY_RECOVERABLE=True,
        SECURITY_CONFIRMABLE=True,
        SECURITY_PUBLIC_URL="https://app.example.com",
    )
    for user in app.extensions["test_datastore"].users:
        user.confirmed_at = naive_utcnow()
    outbox = Outbox(app)

    async def send_mail(subject, recipient, body):
        outbox.append({"subject": subject, "to": recipient, "body": body})

    app.extensions["security"].send_mail = send_mail
    return outbox


def link(message):
    return re.search(r"https://app\.example\.com(/\S+)", message["body"]).group(1)


async def post(client, mail, path, **form):
    response = await client.post(path, form=form)
    await mail.settle()
    return response


async def flashes(app, mail, email, password):
    client = app.test_client()
    await post(client, mail, "/login", email=email, password=password)
    async with client.session_transaction() as cookie:
        return cookie.get("_flashes")


async def signs_in(app, mail, email, password):
    client = app.test_client()
    response = await post(client, mail, "/login", email=email, password=password)
    return response.status_code == 302


@pytest.mark.asyncio
async def test_reset_sets_the_password_and_signs_out_every_session(client, app, mail):
    user = app.extensions["test_datastore"].find_user(email="user@example.com")
    old_id = user.fs_uniquifier
    await post(
        client, mail, "/login", email="user@example.com", password="correct-password"
    )
    assert (await client.get("/protected")).status_code == 200

    other = app.test_client()
    await post(other, mail, "/reset", email=" USER@example.com ")
    assert [m["to"] for m in mail] == ["user@example.com"]
    path = link(mail[0])
    # Opening the link (or a mail scanner opening it) does not spend it.
    assert (await other.get(path)).status_code == 200
    assert (await other.get(path)).status_code == 200
    response = await post(other, mail, path, **FORM)

    assert response.headers["Location"].endswith("/login")
    assert verify_password("brand-new-password", user.password, app=app)
    assert user.fs_uniquifier != old_id
    assert (await client.get("/protected")).status_code == 302
    assert mail[-1]["subject"] == views.RESET_NOTICE_SUBJECT
    # Single use.
    again = await post(other, mail, path, **FORM)
    assert again.headers["Location"].endswith("/reset")


@pytest.mark.asyncio
async def test_reset_answers_the_same_and_does_no_work_in_the_request(
    client, app, mail
):
    store = app.extensions["security"].state_store
    held = []
    app.add_background_task = held.append
    known = await client.post("/reset", form={"email": "user@example.com"})
    unknown = await client.post("/reset", form={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 302
    assert known.headers["Location"] == unknown.headers["Location"]
    # Lookups, token writes and mail all wait until after the response.
    assert store.records == {} and mail == []
    async with app.app_context():
        for job in held:
            await job()
    assert len(store.records) == 1 and len(mail) == 1


@pytest.mark.asyncio
async def test_a_reset_link_dies_when_the_password_or_email_changes(client, app, mail):
    user = app.extensions["test_datastore"].find_user(email="user@example.com")
    await post(client, mail, "/reset", email="user@example.com")
    await post(client, mail, "/reset", email="user@example.com")
    first, second = link(mail[0]), link(mail[1])
    user.password = "changed elsewhere"
    assert (await client.get(first)).headers["Location"].endswith("/reset")
    user.email = "moved@example.com"
    assert (await client.get(second)).headers["Location"].endswith("/reset")


@pytest.mark.asyncio
async def test_reset_link_rejects_a_guessed_token(client, mail):
    response = await client.get("/reset/not-a-real-token")
    assert response.headers["Location"].endswith("/reset")


@pytest.mark.asyncio
async def test_registration_needs_confirmation_and_hides_existing_accounts(
    client, app, mail
):
    fresh = await post(client, mail, "/register", email="new@example.com", **FORM)
    duplicate = await post(client, mail, "/register", email="user@example.com", **FORM)
    assert fresh.headers["Location"] == duplicate.headers["Location"]
    assert [(m["to"], m["subject"]) for m in mail] == [
        ("new@example.com", views.CONFIRM_SUBJECT),
        ("user@example.com", views.REGISTER_CONFLICT_SUBJECT),
    ]

    # The register-then-login probe: an unconfirmed account fails like a wrong
    # password, with the same message.
    assert await flashes(app, mail, "new@example.com", FORM["password"]) == (
        await flashes(app, mail, "user@example.com", FORM["password"])
    )

    path = link(mail[0])
    # Opening the link, as a mail scanner does, confirms nothing.
    assert (await client.get(path)).status_code == 200
    assert not await signs_in(app, mail, "new@example.com", FORM["password"])
    confirmed = await post(client, mail, path)
    assert confirmed.headers["Location"].endswith("/login")
    assert await signs_in(app, mail, "new@example.com", FORM["password"])
    # Single use.
    again = await post(client, mail, path)
    assert again.headers["Location"].endswith("/confirm")


@pytest.mark.asyncio
async def test_a_locked_account_fails_like_a_wrong_password(app, mail):
    user = app.extensions["test_datastore"].find_user(email="user@example.com")
    user.locked_until = naive_utcnow() + datetime.timedelta(minutes=5)
    locked = await flashes(app, mail, "user@example.com", "correct-password")
    unknown = await flashes(app, mail, "nobody@example.com", "correct-password")
    assert locked == unknown


@pytest.mark.asyncio
async def test_resend_confirmation_only_mails_unconfirmed_accounts(client, mail):
    await post(client, mail, "/register", email="new@example.com", **FORM)
    for email in ("new@example.com", "user@example.com", "nobody@example.com"):
        response = await post(client, mail, "/confirm", email=email)
        assert response.headers["Location"].endswith("/login")
    assert [m["to"] for m in mail] == ["new@example.com", "new@example.com"]


@pytest.mark.asyncio
async def test_reset_confirms_an_unconfirmed_account(client, app, mail):
    await post(client, mail, "/register", email="new@example.com", **FORM)
    await post(client, mail, "/reset", email="new@example.com")
    new_password = {
        "password": "another-password1",
        "password_confirm": "another-password1",
    }
    await post(client, mail, link(mail[-1]), **new_password)
    assert await signs_in(app, mail, "new@example.com", "another-password1")


def test_links_need_a_public_url():
    app = Quart(__name__)
    app.config.update(SECRET_KEY="k", SECURITY_RECOVERABLE=True)

    class Store:
        async def put(self, *a, **k): ...
        async def get(self, *a): ...
        async def pop(self, *a): ...
        async def claim(self, *a, **k): ...

    class Datastore:
        def rotate_uniquifier(self, *a): ...
        def record_auth_failure(self, *a, **k): ...
        def replace_recovery_codes(self, *a): ...

    with pytest.raises(RuntimeError, match="SECURITY_PUBLIC_URL"):
        Security(app, Datastore(), state_store=Store())


@pytest.mark.asyncio
async def test_disabled_flows_are_not_found(client):
    for path in ("/reset", "/reset/x", "/confirm", "/confirm/x"):
        assert (await client.get(path)).status_code == 404
