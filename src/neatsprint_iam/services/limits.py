"""Plan limit enforcement (seats for M1)."""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

import httpx
from fastapi import Request
from neatsprint_lib.errors import ApiError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from neatsprint_iam.db.models import User

logger = logging.getLogger(__name__)


async def _plan_limits(request: Request, tenant_id: UUID) -> dict[str, Any] | None:
    settings = request.app.state.settings
    token = settings.service_token or settings.bootstrap_token
    if not token:
        return None
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            response = await client.get(
                f"{settings.core_internal_url}/internal/tenants/{tenant_id}/limits",
                headers={"X-Bootstrap-Token": token},
            )
    except httpx.HTTPError:
        logger.warning("plan_limits_unavailable", extra={"tenant_id": str(tenant_id)})
        return None
    if response.status_code != 200:
        logger.warning(
            "plan_limits_failed",
            extra={"tenant_id": str(tenant_id), "status": response.status_code},
        )
        return None
    data = response.json().get("data")
    return data if isinstance(data, dict) else None


async def enforce_user_seat_limit(
    session: AsyncSession, request: Request, tenant_id: UUID
) -> None:
    limits = await _plan_limits(request, tenant_id)
    if not limits:
        return
    max_users = int(limits.get("max_users", 0))
    if max_users <= 0:
        return
    count = (
        await session.execute(
            select(func.count())
            .select_from(User)
            .where(User.tenant_id == tenant_id, User.deleted_at.is_(None))
        )
    ).scalar_one()
    if count >= max_users:
        raise ApiError(
            429,
            "quota_exceeded",
            f"This workspace has reached its plan limit of {max_users} users.",
        )
