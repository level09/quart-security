import asyncio

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy_models import User

from quart_security import SQLAlchemyUserDatastore


async def test_factory_persists_mutations_after_commit(database):
    datastore = SQLAlchemyUserDatastore(database, User, User)
    try:
        user = await datastore.create_user(email="before@example.com")
        await datastore.commit()
        user.email = "after@example.com"
        await datastore.commit()
        async with database() as check:
            assert await check.scalar(select(User.email)) == "after@example.com"
    finally:
        await datastore.session.close()


async def test_request_cleanup_releases_read_transaction(database):
    datastore = SQLAlchemyUserDatastore(database, User, User)
    await datastore.find_user(email="unknown@example.com")
    old_session = datastore.session
    assert old_session.in_transaction()
    await datastore.close()
    assert not old_session.in_transaction()
    assert datastore.session is not old_session
    await datastore.close()


async def test_concurrent_recovery_consumption(database):
    owner = SQLAlchemyUserDatastore(database, User, User)
    user = await owner.create_user(
        email="test@example.com", mf_recovery_codes=["a", "b"]
    )
    await owner.commit()
    user_id = user.fs_uniquifier
    await owner.close()
    ready = asyncio.Barrier(2)

    async def consume():
        worker = SQLAlchemyUserDatastore(database, User, User)
        try:
            target = await worker.find_user(fs_uniquifier=user_id)
            await ready.wait()
            return await worker.replace_recovery_codes(target, ["a", "b"], ["b"])
        finally:
            await worker.close()

    results = await asyncio.gather(consume(), consume())
    assert sorted(results) == [False, True]
    async with database() as check:
        assert await check.scalar(select(User.mf_recovery_codes)) == ["b"]


async def test_auth_failure_increment_is_atomic(database):
    owner = SQLAlchemyUserDatastore(database, User, User)
    user = await owner.create_user(email="test@example.com")
    await owner.commit()
    user_id = user.fs_uniquifier
    await owner.close()

    async def fail():
        worker = SQLAlchemyUserDatastore(database, User, User)
        try:
            target = await worker.find_user(fs_uniquifier=user_id)
            await worker.record_auth_failure(target, max_attempts=5, lockout_minutes=15)
        finally:
            await worker.close()

    await asyncio.gather(*(fail() for _ in range(6)))
    async with database() as check:
        user = await check.scalar(select(User))
        assert user.failed_login_count == 6
        assert user.locked_until is not None


async def test_expiring_factory_fails_fast(database):
    factory = async_sessionmaker(database.kw["bind"])
    datastore = SQLAlchemyUserDatastore(factory, User, User)
    with pytest.raises(RuntimeError, match="expire_on_commit=False"):
        await datastore.create_user(email="test@example.com")


async def test_expiring_supplied_session_fails_fast(database):
    session = async_sessionmaker(database.kw["bind"])()

    class Owner:
        pass

    owner = Owner()
    owner.session = session
    datastore = SQLAlchemyUserDatastore(owner, User, User)
    try:
        with pytest.raises(RuntimeError, match="expire_on_commit=False"):
            await datastore.find_user(email="unknown@example.com")
    finally:
        await session.close()
