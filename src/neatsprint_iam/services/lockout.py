"""Redis-backed login lockout shared across IAM replicas."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _key(email: str) -> str:
    return f"iam:login-fail:{email}"


async def is_locked(redis: Any | None, email: str, max_failures: int) -> bool:
    if redis is None:
        return False
    try:
        value = await redis.get(_key(email))
    except Exception:  # noqa: BLE001 - fail open; gateway rate limits remain
        logger.warning("lockout_read_failed")
        return False
    return value is not None and int(value) >= max_failures


async def record_failure(
    redis: Any | None, email: str, *, max_failures: int, window_seconds: int
) -> None:
    if redis is None:
        return
    try:
        key = _key(email)
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, window_seconds)
        elif count >= max_failures:
            await redis.expire(key, window_seconds)
    except Exception:  # noqa: BLE001 - fail open
        logger.warning("lockout_write_failed")


async def clear(redis: Any | None, email: str) -> None:
    if redis is None:
        return
    try:
        await redis.delete(_key(email))
    except Exception:  # noqa: BLE001 - fail open
        logger.warning("lockout_clear_failed")
