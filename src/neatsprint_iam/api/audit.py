"""Tenant audit log query and CSV export."""

from __future__ import annotations

import csv
import io
from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from neatsprint_lib.auth import Principal, require_permission
from sqlalchemy import select

from neatsprint_iam.api.deps import SessionDep
from neatsprint_iam.api.responses import envelope
from neatsprint_iam.db.models import AuditLog

router = APIRouter(prefix="/iam/audit", tags=["audit"])
AuditView = Annotated[Principal, Depends(require_permission("report:audit:view"))]


def _payload(row: AuditLog) -> dict[str, object]:
    return {
        "id": str(row.id),
        "actor_id": str(row.actor_id) if row.actor_id else None,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "created_at": row.created_at.isoformat(),
        "request_id": row.request_id,
        "before": row.before,
        "after": row.after,
    }


@router.get("", summary="Query the tenant audit log", response_model=None)
async def list_audit(
    principal: AuditView,
    request: Request,
    session: SessionDep,
    action: str | None = Query(default=None, max_length=64),
    actor_id: UUID | None = Query(default=None),
    from_date: date | None = Query(default=None, alias="from"),
    to_date: date | None = Query(default=None, alias="to"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    export: str | None = Query(default=None, pattern="^csv$"),
) -> JSONResponse | Response:
    query = select(AuditLog).where(AuditLog.tenant_id == principal.tenant_id)
    if action:
        query = query.where(AuditLog.action == action)
    if actor_id:
        query = query.where(AuditLog.actor_id == actor_id)
    if from_date:
        query = query.where(
            AuditLog.created_at >= datetime.combine(from_date, time.min, tzinfo=UTC)
        )
    if to_date:
        query = query.where(
            AuditLog.created_at
            < datetime.combine(to_date + timedelta(days=1), time.min, tzinfo=UTC)
        )
    rows = list(
        (
            await session.execute(
                query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
            )
        ).scalars()
    )
    if export == "csv":
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        writer.writerow(
            ["created_at", "actor_id", "action", "target_type", "target_id", "request_id"]
        )
        for row in rows:
            writer.writerow(
                [
                    row.created_at.isoformat(),
                    row.actor_id or "",
                    row.action,
                    row.target_type or "",
                    row.target_id or "",
                    row.request_id or "",
                ]
            )
        return Response(
            content=buffer.getvalue().encode("utf-8"),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="audit-log.csv"'},
        )
    return JSONResponse(
        envelope(request, [_payload(row) for row in rows], count=len(rows))
    )
