"""Datastore abstraction for user/role CRUD."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select


class SQLAlchemyUserDatastore:
    """Datastore for SQLAlchemy/Flask-SQLAlchemy models."""

    def __init__(self, db, user_model, role_model, webauthn_model=None):
        self.db = db
        self.user_model = user_model
        self.role_model = role_model
        self.webauthn_model = webauthn_model

    @property
    def session(self):
        return getattr(self.db, "session", self.db)

    def _first(self, model, **kwargs):
        stmt = select(model).filter_by(**kwargs)
        return self.session.execute(stmt).scalars().first()

    def find_user(self, **kwargs):
        return self._first(self.user_model, **kwargs)

    def find_role(self, name):
        return self._first(self.role_model, name=name)

    def create_user(self, **kwargs):
        kwargs.setdefault("fs_uniquifier", uuid4().hex)
        user = self.user_model(**kwargs)
        self.session.add(user)
        return user

    def create_role(self, **kwargs):
        role = self.role_model(**kwargs)
        self.session.add(role)
        return role

    def add_role_to_user(self, user, role_name) -> bool:
        role = self.find_role(role_name)
        if role is None:
            role = self.create_role(name=role_name)

        user_roles = getattr(user, "roles", None)
        if user_roles is None:
            return False
        if role in user_roles:
            return False

        user_roles.append(role)
        self.session.add(user)
        return True

    def remove_role_from_user(self, user, role_name) -> bool:
        user_roles = getattr(user, "roles", None)
        if not user_roles:
            return False

        target = None
        for role in user_roles:
            if getattr(role, "name", None) == role_name:
                target = role
                break

        if target is None:
            return False

        user_roles.remove(target)
        self.session.add(user)
        return True

    def toggle_active(self, user) -> bool:
        current = bool(getattr(user, "active", True))
        user.active = not current
        self.session.add(user)
        return user.active

    def set_uniquifier(self, user, uniquifier=None):
        user.fs_uniquifier = uniquifier or uuid4().hex
        self.session.add(user)
        return user.fs_uniquifier

    def commit(self):
        return self.session.commit()
