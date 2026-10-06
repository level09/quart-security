"""Datastore abstraction for user/role CRUD — fully async."""

from __future__ import annotations

from contextvars import ContextVar
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import String, case, cast, func, inspect, literal, select, update
from sqlalchemy.orm import selectinload

from .utils import naive_utcnow


class SQLAlchemyUserDatastore:
    """Async datastore backed by SQLAlchemy AsyncSession."""

    def __init__(self, session_factory, user_model, role_model, webauthn_model=None):
        self.session_factory = session_factory
        self.user_model = user_model
        self.role_model = role_model
        self.webauthn_model = webauthn_model
        self._active_session = ContextVar("quart_security_session", default=None)

    @property
    def session(self):
        source = self.session_factory
        configured = getattr(source, "session", None)
        if configured is not None:
            active = configured
        else:
            active = self._active_session.get()
            if active is None:
                active = source() if callable(source) else source
                self._active_session.set(active)
        sync_session = getattr(active, "sync_session", None)
        if sync_session is not None and sync_session.expire_on_commit:
            raise RuntimeError("Configure AsyncSession with expire_on_commit=False")
        return active

    async def _first(self, model, **kwargs):
        stmt = self._select(model).filter_by(**kwargs)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def _all(self, model, **kwargs):
        stmt = self._select(model).filter_by(**kwargs)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    def _select(model):
        stmt = select(model)
        relationships = inspect(model).relationships
        for name in ("roles", "webauthn", "user"):
            if name in relationships:
                stmt = stmt.options(selectinload(getattr(model, name)))
        return stmt

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

    async def rotate_uniquifier(self, user, expected, replacement):
        # Acquire the account update before autoflush can overwrite newer state.
        with self.session.no_autoflush:
            result = await self.session.execute(
                update(self.user_model)
                .where(self.user_model.fs_uniquifier == expected)
                .values(fs_uniquifier=replacement)
                .execution_options(synchronize_session=False)
            )
        if result.rowcount != 1:
            await self.session.rollback()
            return False
        user.fs_uniquifier = replacement
        await self.commit()
        return True

    async def record_auth_failure(self, user, *, max_attempts, lockout_minutes):
        model = self.user_model
        count = func.coalesce(model.failed_login_count, 0) + 1
        await self.session.execute(
            update(model)
            .where(model.fs_uniquifier == user.fs_uniquifier)
            .values(
                failed_login_count=count,
                locked_until=case(
                    (
                        count >= max_attempts,
                        naive_utcnow() + timedelta(minutes=lockout_minutes),
                    ),
                    else_=model.locked_until,
                ),
            )
            .execution_options(synchronize_session=False)
        )
        await self.commit()
        await self.session.refresh(user, ["failed_login_count", "locked_until"])

    async def replace_recovery_codes(self, user, expected, remaining):
        model = self.user_model
        codes = model.mf_recovery_codes
        # Casting both sides supports JSON, JSONB, and array column types.
        result = await self.session.execute(
            update(model)
            .where(
                model.fs_uniquifier == user.fs_uniquifier,
                cast(codes, String)
                == cast(literal(expected, type_=codes.type), String),
            )
            .values(mf_recovery_codes=remaining)
            .execution_options(synchronize_session=False)
        )
        await self.commit()
        await self.session.refresh(user, ["mf_recovery_codes"])
        return result.rowcount == 1

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

    async def find_user_for_webauthn_credential(self, credential):
        related_user = getattr(credential, "user", None)
        if related_user is not None:
            return related_user
        owner_id = getattr(credential, "user_id", None)
        if owner_id is None:
            return None
        user = await self.find_user(fs_webauthn_user_handle=owner_id)
        if user is None and hasattr(self.user_model, "id"):
            user = await self.find_user(id=owner_id)
        return user

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

    def begin_request(self):
        self._active_session.set(None)

    async def close(self):
        active = self._active_session.get()
        try:
            if active is not None and callable(self.session_factory):
                await active.close()
        finally:
            self._active_session.set(None)
