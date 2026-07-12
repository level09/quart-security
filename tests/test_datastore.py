from quart_security.datastore import SQLAlchemyUserDatastore


class Session:
    def __init__(self):
        self.added = []
        self.commits = 0

    def add(self, value):
        self.added.append(value)

    async def commit(self):
        self.commits += 1


class User:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class Role:
    pass


async def test_factory_session_is_reused_until_commit():
    sessions = []

    def factory():
        session = Session()
        sessions.append(session)
        return session

    datastore = SQLAlchemyUserDatastore(factory, User, Role)
    user = await datastore.create_user(email="person@example.com")
    await datastore.commit()

    assert len(sessions) == 1
    assert sessions[0].added == [user]
    assert sessions[0].commits == 1
