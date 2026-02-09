"""Datastore abstraction for user/role CRUD — fully async."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select


class SQLAlchemyUserDatastore:
    """Async datastore backed by SQLAlchemy AsyncSession."""

    def __init__(self, session_factory, user_model, role_model, webauthn_model=None):
        self.session_factory = session_factory
        self.user_model = user_model
        self.role_model = role_model
        self.webauthn_model = webauthn_model

    @property
    def session(self):
        return self.session_factory()

    async def _first(self, model, **kwargs):
        stmt = select(model).filter_by(**kwargs)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def _all(self, model, **kwargs):
        stmt = select(model).filter_by(**kwargs)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def find_user(self, **kwargs):
        return await self._first(self.user_model, **kwargs)

    async def find_role(self, name):
        return await self._first(self.role_model, name=name)

    async def create_user(self, **kwargs):
        kwargs.setdefault("fs_uniquifier", uuid4().hex)
        user = self.user_model(**kwargs)
        self.session.add(user)
        return user

    async def create_role(self, **kwargs):
        role = self.role_model(**kwargs)
        self.session.add(role)
        return role

    async def add_role_to_user(self, user, role_name) -> bool:
        role = await self.find_role(role_name)
        if role is None:
            role = await self.create_role(name=role_name)

        user_roles = getattr(user, "roles", None)
        if user_roles is None:
            return False
        if role in user_roles:
            return False

        user_roles.append(role)
        self.session.add(user)
        return True

    async def remove_role_from_user(self, user, role_name) -> bool:
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

    async def toggle_active(self, user) -> bool:
        current = bool(getattr(user, "active", True))
        user.active = not current
        self.session.add(user)
        return user.active

    async def set_uniquifier(self, user, uniquifier=None):
        user.fs_uniquifier = uniquifier or uuid4().hex
        self.session.add(user)
        return user.fs_uniquifier

    async def get_webauthn_credentials(self, user, usage=None):
        credentials = list(getattr(user, "webauthn", None) or [])
        if not credentials and self.webauthn_model is not None:
            user_handle = getattr(user, "fs_webauthn_user_handle", None)
            if user_handle is not None and hasattr(self.webauthn_model, "user_id"):
                credentials = await self._all(self.webauthn_model, user_id=user_handle)

        if usage:
            credentials = [
                credential
                for credential in credentials
                if getattr(credential, "usage", None) == usage
            ]
        return credentials

    async def find_webauthn_credential(self, credential_id, user=None):
        candidates = [credential_id]
        if isinstance(credential_id, bytearray):
            candidates = [bytes(credential_id)]
        elif isinstance(credential_id, memoryview):
            candidates = [credential_id.tobytes()]

        if user is not None:
            user_credentials = await self.get_webauthn_credentials(user)
            for credential in user_credentials:
                current_id = getattr(credential, "credential_id", None)
                if any(current_id == candidate for candidate in candidates):
                    return credential
            return None

        if self.webauthn_model is None:
            return None

        for candidate in candidates:
            credential = await self._first(self.webauthn_model, credential_id=candidate)
            if credential is not None:
                return credential
        return None

    async def create_webauthn_credential(self, user, **kwargs):
        if self.webauthn_model is None:
            raise RuntimeError("webauthn_model is required for WebAuthn credentials")

        credential = self.webauthn_model(**kwargs)

        attached = False
        user_credentials = getattr(user, "webauthn", None)
        if user_credentials is not None and hasattr(user_credentials, "append"):
            user_credentials.append(credential)
            attached = True

        if hasattr(credential, "user_id"):
            user_handle = getattr(user, "fs_webauthn_user_handle", None)
            if user_handle is not None:
                credential.user_id = user_handle
                attached = True
            elif hasattr(user, "id"):
                credential.user_id = user.id
                attached = True

        if not attached and hasattr(credential, "user"):
            credential.user = user

        self.session.add(credential)
        self.session.add(user)
        return credential

    async def delete_webauthn_credential(self, user, credential):
        user_credentials = getattr(user, "webauthn", None)
        if user_credentials is not None and credential in user_credentials:
            user_credentials.remove(credential)

        if hasattr(self.session, "delete"):
            await self.session.delete(credential)
        return True

    async def commit(self):
        await self.session.commit()
