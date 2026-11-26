"""In-app notifications for the signed-in user."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from neatsprint_lib.auth import Principal, get_principal
from neatsprint_lib.errors import ApiError
from sqlalchemy import func, select, update

from neatsprint_iam.api.deps import TenantSessionDep
from neatsprint_iam.api.responses import envelope
from neatsprint_iam.db.models import Notification

router = APIRouter(prefix="/iam/notifications", tags=["notifications"])

CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def _payload(notification: Notification) -> dict[str, object]:
    return {
        "id": str(notification.id),
        "type": notification.type,
        "title": notification.title,
        "body": notification.body,
        "link": notification.link,
        "read_at": notification.read_at.isoformat() if notification.read_at else None,
        "created_at": notification.created_at.isoformat(),
    }


@router.get("", summary="List my notifications")
async def list_notifications(
    principal: CurrentPrincipal,
    request: Request,
    session: TenantSessionDep,
    unread_only: bool = Query(default=False),
    limit: int = Query(default=20, ge=1, le=100),
) -> JSONResponse:
    query = select(Notification).where(
        Notification.tenant_id == principal.tenant_id,
        Notification.user_id == principal.user_id,
    )
    if unread_only:
        query = query.where(Notification.read_at.is_(None))
    rows = (
        await session.execute(query.order_by(Notification.created_at.desc()).limit(limit))
    ).scalars()
    unread = (
        await session.execute(
            select(func.count())
            .select_from(Notification)
            .where(
                Notification.tenant_id == principal.tenant_id,
                Notification.user_id == principal.user_id,
                Notification.read_at.is_(None),
            )
        )
    ).scalar_one()
    return JSONResponse(
        envelope(request, [_payload(row) for row in rows], unread=unread)
    )


@router.post("/read-all", summary="Mark every notification as read")
async def mark_all_read(
    principal: CurrentPrincipal, request: Request, session: TenantSessionDep
) -> JSONResponse:
    result = await session.execute(
        update(Notification)
        .where(
            Notification.tenant_id == principal.tenant_id,
            Notification.user_id == principal.user_id,
            Notification.read_at.is_(None),
        )
        .values(read_at=datetime.now(tz=UTC))
    )
    await session.commit()
    return JSONResponse(envelope(request, {"updated": result.rowcount}))  # type: ignore[attr-defined]


@router.post("/{notification_id}/read", summary="Mark one notification as read")
async def mark_read(
    notification_id: UUID,
    principal: CurrentPrincipal,
    request: Request,
    session: TenantSessionDep,
) -> JSONResponse:
    notification = await session.get(Notification, notification_id)
    if (
        notification is None
        or notification.tenant_id != principal.tenant_id
        or notification.user_id != principal.user_id
    ):
        raise ApiError(404, "not_found", "Notification not found.")
    if notification.read_at is None:
        notification.read_at = datetime.now(tz=UTC)
        await session.commit()
    return JSONResponse(envelope(request, _payload(notification)))
