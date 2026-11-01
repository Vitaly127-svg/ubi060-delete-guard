import asyncio
from sqlalchemy import select
from app.db import outbox
from app.messaging import publish_once
import pytest


def test_unconfirmed_event_stays_in_outbox(rig):
    core, now, seed, admin, owner = rig
    seed()
    class Exchange:
        async def publish(self, *args, **kwargs):
            raise ConnectionError("Broker unavailable")
    class Channel:
        default_exchange = Exchange()
    with pytest.raises(ConnectionError):
        asyncio.run(publish_once(core.db, Channel()))
    with core.db.engine.connect() as c:
        assert c.execute(select(outbox.c.published)).scalar_one() is False


def test_confirmed_event_is_marked_published(rig):
    core, now, seed, admin, owner = rig
    seed()
    sent = []
    class Exchange:
        async def publish(self, message, **kwargs):
            sent.append(message.message_id)
            assert kwargs["mandatory"] is True
            return True
    class Channel:
        default_exchange = Exchange()
    assert asyncio.run(publish_once(core.db, Channel())) == 1
    assert len(sent) == 1
    assert asyncio.run(publish_once(core.db, Channel())) == 0
