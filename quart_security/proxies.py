"""Proxy objects for current user and active security extension."""

from quart import current_app, g
from werkzeug.local import LocalProxy


class AnonymousUser:
    """Fallback user object when no authenticated user is present."""

    is_authenticated = False
    is_active = False
    is_anonymous = True

    def has_role(self, _role: str) -> bool:
        return False

    def get_id(self):
        return None


def _get_current_user():
    return getattr(g, "_current_user", AnonymousUser())


current_user = LocalProxy(_get_current_user)


def _get_security():
    return current_app.extensions["security"]


_security = LocalProxy(_get_security)
