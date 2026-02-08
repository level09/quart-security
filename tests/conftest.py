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

    def commit(self):
        return None


@pytest.fixture
def datastore():
    return InMemoryDatastore()


def _build_app(datastore: InMemoryDatastore, *, two_factor: bool) -> Quart:
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
        SECURITY_WEBAUTHN=False,
    )

    Security(app, datastore)

    basic_user = datastore.create_user(
        fs_uniquifier="user-1",
        email="user@example.com",
        password=hash_password("correct-password"),
        active=True,
    )

    admin_user = datastore.create_user(
        fs_uniquifier="admin-1",
        email="admin@example.com",
        password=hash_password("correct-password"),
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
    return _build_app(datastore, two_factor=False)


@pytest.fixture
def app_two_factor(datastore):
    return _build_app(datastore, two_factor=True)


@pytest.fixture
def client_two_factor(app_two_factor):
    return app_two_factor.test_client()
