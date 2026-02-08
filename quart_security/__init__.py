"""Public API for quart-security."""

from .core import Security
from .datastore import SQLAlchemyUserDatastore
from .decorators import auth_required, roles_required
from .models import RoleMixin, UserMixin
from .password import hash_password, verify_password
from .proxies import current_user
from .signals import (
    password_changed,
    tf_profile_changed,
    user_authenticated,
    user_logged_out,
    user_registered,
)
from .utils import url_for_security

__all__ = [
    "Security",
    "SQLAlchemyUserDatastore",
    "auth_required",
    "roles_required",
    "UserMixin",
    "RoleMixin",
    "hash_password",
    "verify_password",
    "current_user",
    "user_authenticated",
    "user_logged_out",
    "password_changed",
    "tf_profile_changed",
    "user_registered",
    "url_for_security",
]
