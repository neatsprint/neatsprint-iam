from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from neatsprint_lib.auth import Principal, require_permission
from neatsprint_lib.errors import ApiError
from sqlalchemy import select

from neatsprint_iam.api.deps import SessionDep
from neatsprint_iam.api.responses import envelope
from neatsprint_iam.db.models import Permission, Role, RolePermission

router = APIRouter(prefix="/iam", tags=["roles"])

ReadPrincipal = Annotated[Principal, Depends(require_permission("core:role:read"))]


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
