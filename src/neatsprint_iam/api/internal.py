from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from neatsprint_lib.errors import ApiError
from neatsprint_lib.events import enqueue
from sqlalchemy import select

from neatsprint_iam.api.deps import AdminSessionDep, require_bootstrap
from neatsprint_iam.api.responses import envelope
from neatsprint_iam.api.schemas import BootstrapUserRequest, UserLookupRequest
from neatsprint_iam.db.models import Role, User, UserCredential
from neatsprint_iam.security.passwords import hash_password
from neatsprint_iam.services.accounts import (
    ensure_system_roles,
    get_user_by_email,
    normalise_email,
    set_user_roles,
)
from neatsprint_iam.services.limits import enforce_user_seat_limit

router = APIRouter(prefix="/internal", tags=["internal"])

BootstrapDep = Annotated[None, Depends(require_bootstrap)]


def _bearer(request: Request) -> str:
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise ApiError(401, "unauthenticated", "A bearer access token is required.")
    return token.strip()


@router.get("/auth/verify", summary="ForwardAuth verification endpoint")
async def verify(request: Request) -> Response:
    verifier = request.app.state.token_verifier
    principal = await verifier.verify(_bearer(request))
    return Response(
        status_code=200,
        headers={
            "X-User-ID": str(principal.user_id),
            "X-Tenant-ID": str(principal.tenant_id),
            "X-Roles": ",".join(principal.roles),
            "X-Permissions": " ".join(sorted(principal.permissions)),
        },
    )


@router.post("/tenants/{tenant_id}/bootstrap", summary="Create system roles for a tenant")
async def bootstrap_tenant(
    tenant_id: str, _: BootstrapDep, request: Request, session: AdminSessionDep
) -> JSONResponse:
    from uuid import UUID

    try:
        parsed = UUID(tenant_id)
    except ValueError as exc:
        raise ApiError(422, "validation_failed", "Invalid tenant id.") from exc
    roles = await ensure_system_roles(session, parsed)
    return JSONResponse(
        envelope(request, [{"id": str(role.id), "code": role.code} for role in roles])
    )


@router.post("/users/bootstrap", summary="Create or update a seed user")
async def bootstrap_user(
    payload: BootstrapUserRequest,
    _: BootstrapDep,
    request: Request,
    session: AdminSessionDep,
) -> JSONResponse:
    email = normalise_email(str(payload.email))
    existing = await get_user_by_email(session, email)

    role_rows = (
        await session.execute(
            select(Role).where(
                Role.tenant_id == payload.tenant_id, Role.code.in_(payload.role_codes)
            )
        )
    ).scalars()
    roles = list(role_rows)
    if len(roles) != len(set(payload.role_codes)):
        raise ApiError(422, "invalid_role", "Unknown role code for this tenant.")

    if existing is not None:
        if existing.tenant_id != payload.tenant_id:
            raise ApiError(409, "email_unavailable", "That email address cannot be used.")
        user = existing
        user.full_name = payload.full_name
        user.status = "ACTIVE"
        credential = await session.get(UserCredential, user.id)
        if credential is None:
            session.add(
                UserCredential(user_id=user.id, password_hash=hash_password(payload.password))
            )
        else:
            credential.password_hash = hash_password(payload.password)
    else:
        from neatsprint_lib.ids import new_id

        await enforce_user_seat_limit(session, request, payload.tenant_id)
        user = User(
            id=new_id(),
            tenant_id=payload.tenant_id,
            email=email,
            full_name=payload.full_name,
            status="ACTIVE",
        )
        session.add(user)
        await session.flush()
        session.add(
            UserCredential(user_id=user.id, password_hash=hash_password(payload.password))
        )

    await set_user_roles(
        session,
        user_id=user.id,
        tenant_id=payload.tenant_id,
        role_ids=[role.id for role in roles],
        assigned_by=None,
    )
    enqueue(
        session,
        event_type="user.created",
        tenant_id=payload.tenant_id,
        actor_id=user.id,
        payload={"user_id": str(user.id), "email": user.email, "source": "bootstrap"},
    )
    await session.commit()

    return JSONResponse(
        envelope(
            request,
            {
                "user_id": str(user.id),
                "tenant_id": str(user.tenant_id),
                "email": user.email,
                "roles": sorted(role.code for role in roles),
            },
        )
    )


@router.post("/users/lookup", summary="Batch user summaries for internal callers")
async def lookup_users(
    payload: UserLookupRequest,
    _: BootstrapDep,
    request: Request,
    session: AdminSessionDep,
) -> JSONResponse:
    rows = (
        await session.execute(
            select(User).where(
                User.tenant_id == payload.tenant_id,
                User.id.in_(payload.user_ids),
                User.deleted_at.is_(None),
            )
        )
    ).scalars()
    return JSONResponse(
        envelope(
            request,
            [
                {
                    "id": str(user.id),
                    "email": user.email,
                    "full_name": user.full_name,
                    "status": user.status,
                }
                for user in rows
            ],
        )
    )
