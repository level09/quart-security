"""Model mixins compatible with the quart-security auth workflow."""


class UserMixin:
    """Basic user mixin similar to Flask-Login/Flask-Security semantics."""

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return bool(getattr(self, "active", True))

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return getattr(self, "fs_uniquifier", None)

    def has_role(self, role_name: str) -> bool:
        roles = getattr(self, "roles", []) or []
        for role in roles:
            if getattr(role, "name", None) == role_name:
                return True
        return False


class RoleMixin:
    """Role comparison behavior used by access-control checks."""

    def __eq__(self, other):
        if isinstance(other, RoleMixin):
            return getattr(self, "name", None) == getattr(other, "name", None)
        return getattr(self, "name", None) == other

    def __hash__(self):
        return hash(getattr(self, "name", None))
