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
