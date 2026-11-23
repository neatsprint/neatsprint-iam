"""Consume assignment events and create in-app notifications.

The Team/Task outboxes publish at-least-once, so notifications record the source event id
and skip duplicates. Failures are retried three times before the stream entry is
acknowledged; notifications are informative, not billing-critical.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any
from uuid import UUID

from neatsprint_lib.ids import new_id
from redis.asyncio import Redis
from redis.exceptions import ResponseError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from neatsprint_iam.db.models import Notification, User

logger = logging.getLogger(__name__)

ASSIGNMENT_EVENT = "item.assigned"


def _uuid(value: object) -> UUID | None:
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


async def handle_event(session: AsyncSession, fields: dict[str, Any]) -> bool:
    if fields.get("event_type") != ASSIGNMENT_EVENT:
        return False
    tenant_id = _uuid(fields.get("tenant_id"))
    event_id = _uuid(fields.get("event_id"))
    try:
        payload = json.loads(fields.get("data") or "{}")
    except (TypeError, ValueError):
        logger.warning("notification_bad_payload")
        return False
    if not tenant_id or not isinstance(payload, dict):
        return False
    assignee_id = _uuid(payload.get("assignee_id"))
    actor_id = _uuid(fields.get("actor_id"))
    project_id = _uuid(payload.get("project_id"))
    item_key = str(payload.get("key") or "").strip()
    item_title = str(payload.get("title") or "").strip()
    if not assignee_id or not project_id or not item_key:
        return False
    if actor_id is not None and actor_id == assignee_id:
        return False

    if event_id is not None:
        existing = (
            await session.execute(
                select(Notification.id).where(Notification.source_event_id == event_id)
            )
        ).first()
        if existing is not None:
            return False

    user = await session.get(User, assignee_id)
    if user is None or user.tenant_id != tenant_id or user.deleted_at is not None:
        logger.warning(
            "notification_assignee_missing",
            extra={"assignee_id": str(assignee_id), "tenant_id": str(tenant_id)},
        )
        return False

    session.add(
        Notification(
            id=new_id(),
            tenant_id=tenant_id,
            user_id=assignee_id,
            type="ITEM_ASSIGNED",
            title=f"{item_key} assigned to you",
            body=item_title or None,
            link=f"/projects/{project_id}/backlog",
            source_event_id=event_id,
        )
    )
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        return False
    return True


async def _ensure_group(redis: Redis, stream: str, group: str) -> None:
    try:
        await redis.xgroup_create(stream, group, id="$", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def run_consumer(
    session_factory: async_sessionmaker[AsyncSession],
    redis_url: str,
    stream: str,
    group: str,
    stop: asyncio.Event,
    *,
    block_ms: int = 2000,
) -> None:
    redis = Redis.from_url(redis_url, decode_responses=True)
    name = f"iam-{uuid.uuid4().hex[:8]}"
    try:
        while not stop.is_set():
            try:
                await _ensure_group(redis, stream, group)
                break
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - Redis may not be ready yet
                logger.exception("notification_consumer_group_failed")
                await asyncio.sleep(2)
        while not stop.is_set():
            try:
                batches = await redis.xreadgroup(
                    group, name, {stream: ">"}, count=100, block=block_ms
                )
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the consumer must survive transient failures
                logger.exception("notification_consumer_read_failed")
                await asyncio.sleep(2)
                continue
            for _, messages in batches or []:
                for message_id, fields in messages:
                    for attempt in range(3):
                        try:
                            async with session_factory() as session:
                                await handle_event(session, fields)
                            break
                        except Exception:  # noqa: BLE001 - retry, then acknowledge
                            logger.exception(
                                "notification_event_failed",
                                extra={"attempt": attempt + 1},
                            )
                            await asyncio.sleep(0.5)
                    await redis.xack(stream, group, message_id)
    finally:
        await redis.aclose()
