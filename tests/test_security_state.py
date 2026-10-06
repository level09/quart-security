import asyncio

from sqlalchemy_models import User

from quart_security.datastore import SQLAlchemyUserDatastore


async def test_state_is_consumed_once_across_workers(database):
    from quart_security.state import SecurityState, SQLAlchemyStateStore

    async with database.kw["bind"].begin() as connection:
        await connection.run_sync(SecurityState.metadata.create_all)
    first = SQLAlchemyUserDatastore(database, User, User)
    second = SQLAlchemyUserDatastore(database, User, User)
    store = SQLAlchemyStateStore(first)
    token = await store.put({"secret": "test"}, ttl=300)
    await first.close()

    async def consume(worker):
        try:
            return await SQLAlchemyStateStore(worker).pop(token)
        finally:
            await worker.close()

    results = await asyncio.gather(consume(first), consume(second))
    assert results.count({"secret": "test"}) == 1
    assert results.count(None) == 1


async def test_claim_is_atomic_across_workers(database):
    from quart_security.state import SecurityState, SQLAlchemyStateStore

    async with database.kw["bind"].begin() as connection:
        await connection.run_sync(SecurityState.metadata.create_all)
    workers = [SQLAlchemyUserDatastore(database, User, User) for _ in range(2)]

    async def claim(worker):
        try:
            return await SQLAlchemyStateStore(worker).claim("otp:1", ttl=300)
        finally:
            await worker.close()

    results = await asyncio.gather(*(claim(worker) for worker in workers))
    assert sorted(results) == [False, True]
