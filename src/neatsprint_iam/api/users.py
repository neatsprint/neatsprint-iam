from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from neatsprint_lib.auth import Principal, require_permission
from neatsprint_lib.errors import ApiError
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from neatsprint_iam.api.deps import SessionDep
from neatsprint_iam.api.responses import envelope
from neatsprint_iam.api.schemas import AssignRolesRequest, ProfileOut, UserOut
from neatsprint_iam.db.models import Session, User
from neatsprint_iam.services.accounts import (
    effective_permissions,
    get_user,
    roles_for_user,
    set_user_roles,
)
from neatsprint_iam.services.audit import audit

router = APIRouter(prefix="/iam", tags=["users"])

ReadPrincipal = Annotated[Principal, Depends(require_permission("core:user:read"))]
ManagePrincipal = Annotated[Principal, Depends(require_permission("core:role:manage"))]
UpdatePrincipal = Annotated[Principal, Depends(require_permission("core:user:update"))]


async def _user_out(session: AsyncSession, user: User) -> UserOut:
    roles = [role.code for role in await roles_for_user(session, user.id)]
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        status=user.status,
        job_title=user.job_title,
        roles=roles,
        last_login_at=user.last_login_at,
    )


@router.get("/users", summary="List users in the tenant")
async def list_users(
    principal: ReadPrincipal,
    request: Request,
    session: SessionDep,
    search: str | None = Query(default=None, max_length=120),
    status_filter: str | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> JSONResponse:
    base = select(User).where(User.tenant_id == principal.tenant_id, User.deleted_at.is_(None))
    if search:
        like = f"%{search.lower()}%"
        base = base.where(
            or_(func.lower(User.email).like(like), func.lower(User.full_name).like(like))
        )
    if status_filter:
        base = base.where(User.status == status_filter.upper())

    total = (
        await session.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()
    rows = (
        await session.execute(
            base.order_by(User.full_name).offset((page - 1) * per_page).limit(per_page)
        )
    ).scalars()
    data = [await _user_out(session, user) for user in rows]
    return JSONResponse(
        envelope(
            request,
            [item.model_dump(mode="json") for item in data],
            page=page,
            per_page=per_page,
            total=total,
        )
    )


@router.get("/users/{user_id}", summary="Read a user")
async def read_user(
    user_id: UUID, principal: ReadPrincipal, request: Request, session: SessionDep
) -> JSONResponse:
    user = await get_user(session, tenant_id=principal.tenant_id, user_id=user_id)
    if user is None:
        raise ApiError(404, "not_found", "User not found.")
    return JSONResponse(envelope(request, (await _user_out(session, user)).model_dump(mode="json")))


@router.post("/users/{user_id}/roles", summary="Replace a user's roles")
async def assign_roles(
    user_id: UUID,
    payload: AssignRolesRequest,
    principal: ManagePrincipal,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    user = await get_user(session, tenant_id=principal.tenant_id, user_id=user_id)
    if user is None:
        raise ApiError(404, "not_found", "User not found.")

    roles = await set_user_roles(
        session,
        user_id=user.id,
        tenant_id=principal.tenant_id,
        role_ids=payload.role_ids,
        assigned_by=principal.user_id,
    )
    target_codes = {role.code for role in roles}
    if "OWNER" in target_codes and "OWNER" not in principal.roles:
        raise ApiError(403, "permission_denied", "Only an owner can grant the OWNER role.")

    await audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="user.roles_changed",
        target_type="user",
        target_id=str(user.id),
        after={"roles": sorted(target_codes)},
        request=request,
    )
    await session.commit()
    return JSONResponse(envelope(request, (await _user_out(session, user)).model_dump(mode="json")))


@router.patch("/users/{user_id}", summary="Update status or profile")
async def update_user(
    user_id: UUID,
    payload: dict[str, object],
    principal: UpdatePrincipal,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    user = await get_user(session, tenant_id=principal.tenant_id, user_id=user_id)
    if user is None:
        raise ApiError(404, "not_found", "User not found.")
    if user.id == principal.user_id and payload.get("status") == "DISABLED":
        raise ApiError(422, "invalid_operation", "You cannot deactivate your own account.")

    before = {"status": user.status, "job_title": user.job_title}
    if payload.get("status"):
        status_value = str(payload["status"]).upper()
        if status_value not in {"ACTIVE", "DISABLED"}:
            raise ApiError(422, "validation_failed", "Status must be ACTIVE or DISABLED.")
        user.status = status_value
        if status_value == "DISABLED":
            sessions = (
                await session.execute(
                    select(Session).where(
                        Session.user_id == user.id, Session.revoked_at.is_(None)
                    )
                )
            ).scalars()
            for session_row in sessions:
                session_row.revoked_at = datetime.now(tz=UTC)
                session_row.revoke_reason = "user_disabled"
    if "job_title" in payload:
        job_title = payload["job_title"]
        if job_title is None or isinstance(job_title, str):
            user.job_title = job_title

    await audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="user.updated",
        target_type="user",
        target_id=str(user.id),
        before=before,
        after={"status": user.status, "job_title": user.job_title},
        request=request,
    )
    await session.commit()
    return JSONResponse(envelope(request, (await _user_out(session, user)).model_dump(mode="json")))


@router.get("/me/profile", summary="Full profile for the current user")
async def profile(
    principal: ReadPrincipal, request: Request, session: SessionDep
) -> JSONResponse:
    user = await get_user(session, tenant_id=principal.tenant_id, user_id=principal.user_id)
    if user is None:
        raise ApiError(404, "not_found", "User not found.")
    roles, permissions = await effective_permissions(session, user.id)
    data = ProfileOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        tenant_id=user.tenant_id,
        status=user.status,
        job_title=user.job_title,
        timezone=user.timezone,
        locale=user.locale,
        roles=roles,
        permissions=permissions,
        last_login_at=user.last_login_at,
    )
    return JSONResponse(envelope(request, data.model_dump(mode="json")))
