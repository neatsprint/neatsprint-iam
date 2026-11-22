from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from neatsprint_lib.auth import Principal, require_permission
from neatsprint_lib.errors import ApiError
from neatsprint_lib.events import enqueue
from neatsprint_lib.ids import new_id
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from neatsprint_iam.api.deps import SessionDep
from neatsprint_iam.api.responses import envelope
from neatsprint_iam.api.schemas import RoleCreate, RoleUpdate
from neatsprint_iam.db.models import Permission, Role, RolePermission, UserRole
from neatsprint_iam.services.audit import audit

router = APIRouter(prefix="/iam", tags=["roles"])

ReadPrincipal = Annotated[Principal, Depends(require_permission("core:role:read"))]
ManagePrincipal = Annotated[Principal, Depends(require_permission("core:role:manage"))]


async def _validate_permissions(session: AsyncSession, codes: list[str]) -> None:
    known = set(
        (
            await session.execute(select(Permission.code).where(Permission.code.in_(codes)))
        ).scalars().all()
    )
    unknown = set(codes) - known
    if unknown:
        raise ApiError(
            422, "invalid_permission", f"Unknown permission: {', '.join(sorted(unknown))}."
        )


async def _set_permissions(session: AsyncSession, role_id: UUID, codes: list[str]) -> None:
    await session.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
    for code in sorted(set(codes)):
        session.add(RolePermission(role_id=role_id, permission_code=code))


@router.get("/roles", summary="List roles with their permissions")
async def list_roles(
    principal: ReadPrincipal, request: Request, session: SessionDep
) -> JSONResponse:
    roles = (
        await session.execute(
            select(Role).where(Role.tenant_id == principal.tenant_id).order_by(Role.code)
        )
    ).scalars()
    permission_rows = (
        await session.execute(
            select(RolePermission).join(Role, Role.id == RolePermission.role_id).where(
                Role.tenant_id == principal.tenant_id
            )
        )
    ).scalars()

    by_role: dict[str, list[str]] = {}
    for row in permission_rows:
        by_role.setdefault(str(row.role_id), []).append(row.permission_code)

    data = [
        {
            "id": str(role.id),
            "code": role.code,
            "name": role.name,
            "description": role.description,
            "is_system": role.is_system,
            "permissions": sorted(by_role.get(str(role.id), [])),
        }
        for role in roles
    ]
    return JSONResponse(envelope(request, data))


@router.get("/permissions", summary="Permission catalogue")
async def list_permissions(
    principal: ReadPrincipal, request: Request, session: SessionDep
) -> JSONResponse:
    rows = (await session.execute(select(Permission).order_by(Permission.code))).scalars()
    return JSONResponse(
        envelope(
            request,
            [
                {"code": row.code, "description": row.description}
                for row in rows
            ],
        )
    )


@router.get("/roles/{role_id}", summary="Read a role")
async def read_role(
    role_id: str, principal: ReadPrincipal, request: Request, session: SessionDep
) -> JSONResponse:
    role = await session.get(Role, role_id)
    if role is None or role.tenant_id != principal.tenant_id:
        raise ApiError(404, "not_found", "Role not found.")
    permissions = (
        await session.execute(
            select(RolePermission.permission_code).where(RolePermission.role_id == role.id)
        )
    ).scalars()
    return JSONResponse(
        envelope(
            request,
            {
                "id": str(role.id),
                "code": role.code,
                "name": role.name,
                "description": role.description,
                "is_system": role.is_system,
                "permissions": sorted(permissions),
            },
        )
    )


@router.post("/roles", status_code=status.HTTP_201_CREATED, summary="Create a custom role")
async def create_role(
    payload: RoleCreate,
    principal: ManagePrincipal,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    await _validate_permissions(session, payload.permissions)
    existing = (
        await session.execute(
            select(Role).where(
                Role.tenant_id == principal.tenant_id, Role.code == payload.code
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ApiError(409, "duplicate_key", "A role with that code already exists.")

    role = Role(
        id=new_id(),
        tenant_id=principal.tenant_id,
        code=payload.code,
        name=payload.name,
        description=payload.description,
        is_system=False,
    )
    session.add(role)
    await session.flush()
    await _set_permissions(session, role.id, payload.permissions)
    await audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="role.created",
        target_type="role",
        target_id=str(role.id),
        after={"code": role.code, "permissions": sorted(payload.permissions)},
        request=request,
    )
    enqueue(
        session,
        event_type="role.changed",
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        payload={"role_id": str(role.id), "change": "created"},
    )
    await session.commit()
    return JSONResponse(
        envelope(
            request,
            {
                "id": str(role.id),
                "code": role.code,
                "name": role.name,
                "description": role.description,
                "is_system": False,
                "permissions": sorted(set(payload.permissions)),
            },
        ),
        status_code=status.HTTP_201_CREATED,
    )


@router.patch("/roles/{role_id}", summary="Update a custom role")
async def update_role(
    role_id: UUID,
    payload: RoleUpdate,
    principal: ManagePrincipal,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    role = await session.get(Role, role_id)
    if role is None or role.tenant_id != principal.tenant_id:
        raise ApiError(404, "not_found", "Role not found.")
    if role.is_system:
        raise ApiError(403, "system_role", "System roles are immutable.")

    if payload.name is not None:
        role.name = payload.name
    if payload.description is not None:
        role.description = payload.description
    if payload.permissions is not None:
        await _validate_permissions(session, payload.permissions)
        await _set_permissions(session, role.id, payload.permissions)

    await audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="role.updated",
        target_type="role",
        target_id=str(role.id),
        request=request,
    )
    enqueue(
        session,
        event_type="role.changed",
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        payload={"role_id": str(role.id), "change": "updated"},
    )
    await session.commit()
    permissions = (
        await session.execute(
            select(RolePermission.permission_code).where(RolePermission.role_id == role.id)
        )
    ).scalars()
    return JSONResponse(
        envelope(
            request,
            {
                "id": str(role.id),
                "code": role.code,
                "name": role.name,
                "description": role.description,
                "is_system": role.is_system,
                "permissions": sorted(permissions),
            },
        )
    )


@router.delete(
    "/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a custom role",
)
async def delete_role(
    role_id: UUID,
    principal: ManagePrincipal,
    request: Request,
    session: SessionDep,
) -> Response:
    role = await session.get(Role, role_id)
    if role is None or role.tenant_id != principal.tenant_id:
        raise ApiError(404, "not_found", "Role not found.")
    if role.is_system:
        raise ApiError(403, "system_role", "System roles are immutable.")
    assigned = (
        await session.execute(
            select(func.count()).select_from(UserRole).where(UserRole.role_id == role.id)
        )
    ).scalar_one()
    if assigned:
        raise ApiError(409, "role_in_use", "Remove this role from users before deleting it.")

    await session.delete(role)
    await audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="role.deleted",
        target_type="role",
        target_id=str(role.id),
        request=request,
    )
    enqueue(
        session,
        event_type="role.changed",
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        payload={"role_id": str(role.id), "change": "deleted"},
    )
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
