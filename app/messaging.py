import asyncio
import json
import logging

import aio_pika
from sqlalchemy import select, update

from app.db import datasets, outbox
from app.security import canonical

log = logging.getLogger("ubi060")


async def topology(connection):
    channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
    await channel.set_qos(prefetch_count=20)
    await channel.declare_queue("ubi060.dead", durable=True)
    queue = await channel.declare_queue("ubi060.audit", durable=True,
        arguments={"x-dead-letter-exchange": "", "x-dead-letter-routing-key": "ubi060.dead"})
    return channel, queue


async def publish_once(db, channel):
    with db.engine.connect() as c:
        batch = list(c.execute(select(outbox).where(outbox.c.published.is_(False))
                              .order_by(outbox.c.created_at).limit(100)).mappings())
    for row in batch:
        await channel.default_exchange.publish(aio_pika.Message(canonical(row["payload"]),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT, message_id=row["id"], content_type="application/json"),
            routing_key="ubi060.audit", mandatory=True, timeout=10)
        # A crash between confirmation and this update causes a duplicate, not a lost event.
        with db.transaction() as c:
            c.execute(update(outbox).where(outbox.c.id == row["id"]).values(published=True))
    return len(batch)


async def publisher(controller, url):
    while True:
        try:
            connection = await aio_pika.connect_robust(url)
            async with connection:
                channel, _ = await topology(connection)
                while True:
                    await publish_once(controller.db, channel)
                    await asyncio.sleep(1)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("Outbox publication postponed: %s", type(exc).__name__)
            await asyncio.sleep(3)


async def consumer(controller, url):
    while True:
        try:
            connection = await aio_pika.connect_robust(url)
            async with connection:
                _, queue = await topology(connection)
                async with queue.iterator() as messages:
                    async for message in messages:
                        try:
                            event = json.loads(message.body)
                            if not isinstance(event, dict) or not {"id", "time", "dataset_id", "owner", "actor", "kind", "rule"} <= event.keys():
                                raise ValueError("Invalid event")
                        except (ValueError, TypeError):
                            await message.reject(requeue=False)
                            continue
                        try:
                            added = await asyncio.to_thread(controller.consume, event)
                            if added:
                                print(canonical(event).decode("utf-8"), flush=True)
                            await message.ack()  # SQL commit has completed.
                        except Exception:
                            await message.reject(requeue=True)
                            await asyncio.sleep(1)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("Audit consumption postponed: %s", type(exc).__name__)
            await asyncio.sleep(3)


async def sweeper(controller, seconds):
    while True:
        try:
            with controller.db.engine.connect() as c:
                ids = list(c.execute(select(datasets.c.id).where(
                    (datasets.c.state == "PURGING") | ((datasets.c.state == "QUARANTINED") &
                    (datasets.c.deadline <= controller.clock())))).scalars())
            for id in ids:
                await asyncio.to_thread(controller.purge_one, id)
        except Exception as exc:
            log.warning("Purge postponed: %s", type(exc).__name__)
        await asyncio.sleep(seconds)
