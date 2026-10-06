"""Shared, expiring state for authentication and single-use verification."""

import secrets
import time

from sqlalchemy import JSON, BigInteger, String, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class _StateBase(DeclarativeBase):
    pass


class SecurityState(_StateBase):
    __tablename__ = "quart_security_state"

    token: Mapped[str] = mapped_column(String(160), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[int] = mapped_column(BigInteger, index=True)


class SQLAlchemyStateStore:
    """Uses the datastore transaction; host migrations must create SecurityState."""

    def __init__(self, datastore):
        self.datastore = datastore

    async def validate(self):
        await self.datastore.session.execute(select(SecurityState).limit(0))

    async def put(self, payload, *, ttl, token=None):
        token = token or secrets.token_urlsafe(32)
        await self.datastore.session.execute(
            delete(SecurityState).where(SecurityState.expires_at <= int(time.time()))
        )
        self.datastore.session.add(
            SecurityState(
                token=token, payload=payload, expires_at=int(time.time()) + ttl
            )
        )
        await self.datastore.commit()
        return token

    async def get(self, token):
        return await self.datastore.session.scalar(
            select(SecurityState.payload).where(
                SecurityState.token == token,
                SecurityState.expires_at > int(time.time()),
            )
        )

    async def pop(self, token):
        payload = await self.get(token)
        if payload is None:
            return None
        result = await self.datastore.session.execute(
            delete(SecurityState).where(
                SecurityState.token == token,
                SecurityState.expires_at > int(time.time()),
            )
        )
        await self.datastore.commit()
        return payload if result.rowcount == 1 else None

    async def claim(self, token, *, ttl):
        active = self.datastore.session
        await active.execute(
            delete(SecurityState).where(
                SecurityState.token == token,
                SecurityState.expires_at <= int(time.time()),
            )
        )
        try:
            async with active.begin_nested():
                active.add(
                    SecurityState(
                        token=token, payload={}, expires_at=int(time.time()) + ttl
                    )
                )
                await active.flush()
        except IntegrityError:
            await self.datastore.commit()
            return False
        await self.datastore.commit()
        return True

    async def purge_expired(self):
        await self.datastore.session.execute(
            delete(SecurityState).where(SecurityState.expires_at <= int(time.time()))
        )
        await self.datastore.commit()
