from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from neatsprint_lib.auth import Principal, get_principal
from neatsprint_lib.errors import ApiError
from neatsprint_lib.ids import new_id
from sqlalchemy import select, update

from neatsprint_iam.api.deps import SessionDep
from neatsprint_iam.api.responses import envelope
from neatsprint_iam.api.schemas import (
    LoginRequest,
    ProfileOut,
    RefreshRequest,
    SessionUser,
    TokenPair,
)
from neatsprint_iam.db.models import RefreshToken, Session, User, UserCredential
from neatsprint_iam.security.passwords import needs_rehash, verify_password
from neatsprint_iam.security.tokens import (
    create_access_token,
    hash_token,
    new_refresh_token,
)
from neatsprint_iam.services.accounts import (
    effective_permissions,
    get_user_by_email,
    normalise_email,
    roles_for_user,
)
from neatsprint_iam.services.audit import audit

router = APIRouter(prefix="/auth", tags=["auth"])

PrincipalDep = Annotated[Principal, Depends(get_principal)]


def _session_user(user: User, roles: list[str], permissions: list[str]) -> SessionUser:
    return SessionUser(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        tenant_id=user.tenant_id,
        roles=roles,
        permissions=permissions,
    )


def _issue(
    request: Request,
    *,
    user: User,
    session_id: UUID,
    roles: list[str],
    permissions: list[str],
    refresh_token: str,
) -> TokenPair:
    settings = request.app.state.settings
    access, expires_in = create_access_token(
        private_key=request.app.state.private_key,
        kid=request.app.state.jwt_kid,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        user_id=user.id,
        tenant_id=user.tenant_id,
        session_id=session_id,
        roles=roles,
        permissions=permissions,
        minutes=settings.access_token_minutes,
    )
    return TokenPair(
        access_token=access,
        expires_in=expires_in,
        refresh_token=refresh_token,
        user=_session_user(user, roles, permissions),
    )


@router.post("/login", response_model=None, summary="Exchange credentials for tokens")
async def login(
    payload: LoginRequest, request: Request, session: SessionDep
) -> JSONResponse:
    settings = request.app.state.settings
    user = await get_user_by_email(session, str(payload.email))
    credential = await session.get(UserCredential, user.id) if user else None

    if (
        user is None
        or credential is None
        or user.status != "ACTIVE"
        or not verify_password(credential.password_hash, payload.password)
    ):
        await audit(
            session,
            tenant_id=user.tenant_id if user else None,
            actor_id=None,
            action="auth.login_failed",
            target_type="user",
            target_id=normalise_email(str(payload.email)),
            request=request,
        )
        await session.commit()
        raise ApiError(401, "invalid_credentials", "Invalid email or password.")

    if needs_rehash(credential.password_hash):
        from neatsprint_iam.security.passwords import hash_password

        credential.password_hash = hash_password(payload.password)

    now = datetime.now(tz=UTC)
    session_row = Session(
        id=new_id(),
        tenant_id=user.tenant_id,
        user_id=user.id,
        device_id=payload.device.name if payload.device else None,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        expires_at=now + timedelta(days=settings.refresh_token_days),
    )
    session.add(session_row)
    await session.flush()

    raw_refresh, refresh_hash = new_refresh_token()
    session.add(
        RefreshToken(
            id=new_id(),
            session_id=session_row.id,
            token_hash=refresh_hash,
            expires_at=now + timedelta(days=settings.refresh_token_days),
        )
    )

    user.last_login_at = now
    roles = [role.code for role in await roles_for_user(session, user.id)]
    _, permissions = await effective_permissions(session, user.id)

    await audit(
        session,
        tenant_id=user.tenant_id,
        actor_id=user.id,
        action="auth.login",
        target_type="session",
        target_id=str(session_row.id),
        request=request,
    )
    await session.commit()

    tokens = _issue(
        request,
        user=user,
        session_id=session_row.id,
        roles=roles,
        permissions=permissions,
        refresh_token=raw_refresh,
    )
    return JSONResponse(envelope(request, tokens.model_dump(mode="json")))


@router.post("/refresh", summary="Rotate a refresh token")
async def refresh(payload: RefreshRequest, request: Request, session: SessionDep) -> JSONResponse:
    settings = request.app.state.settings
    token_hash = hash_token(payload.refresh_token)
    result = await session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    stored = result.scalar_one_or_none()
    now = datetime.now(tz=UTC)

    if stored is None:
        raise ApiError(401, "invalid_refresh_token", "The refresh token is invalid.")

    session_row = await session.get(Session, stored.session_id)
    if session_row is None or session_row.revoked_at is not None:
        raise ApiError(401, "session_revoked", "This session has ended. Sign in again.")

    if stored.used_at is not None:
        # Reuse detection: revoke the whole session family.
        session_row.revoked_at = now
        session_row.revoke_reason = "refresh_reuse"
        await session.execute(
            update(RefreshToken)
            .where(RefreshToken.session_id == stored.session_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await audit(
            session,
            tenant_id=session_row.tenant_id,
            actor_id=session_row.user_id,
            action="auth.refresh_reuse",
            target_type="session",
            target_id=str(session_row.id),
            request=request,
        )
        await session.commit()
        raise ApiError(401, "refresh_reuse", "This session was revoked for security reasons.")

    if stored.revoked_at is not None or stored.expires_at <= now:
        raise ApiError(401, "invalid_refresh_token", "The refresh token has expired.")

    user = await session.get(User, session_row.user_id)
    if user is None or user.status != "ACTIVE":
        raise ApiError(401, "invalid_credentials", "This account is not active.")

    stored.used_at = now
    raw_refresh, refresh_hash = new_refresh_token()
    new_row = RefreshToken(
        id=new_id(),
        session_id=session_row.id,
        token_hash=refresh_hash,
        expires_at=now + timedelta(days=settings.refresh_token_days),
    )
    session.add(new_row)
    stored.replaced_by = new_row.id
    session_row.last_used_at = now

    roles = [role.code for role in await roles_for_user(session, user.id)]
    _, permissions = await effective_permissions(session, user.id)
    await session.commit()

    tokens = _issue(
        request,
        user=user,
        session_id=session_row.id,
        roles=roles,
        permissions=permissions,
        refresh_token=raw_refresh,
    )
    return JSONResponse(envelope(request, tokens.model_dump(mode="json")))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke the session")
async def logout(principal: PrincipalDep, request: Request, session: SessionDep) -> Response:
    if principal.session_id:
        session_row = await session.get(Session, principal.session_id)
        if session_row is not None and session_row.revoked_at is None:
            now = datetime.now(tz=UTC)
            session_row.revoked_at = now
            session_row.revoke_reason = "logout"
            await session.execute(
                update(RefreshToken)
                .where(RefreshToken.session_id == session_row.id, RefreshToken.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            await audit(
                session,
                tenant_id=session_row.tenant_id,
                actor_id=session_row.user_id,
                action="auth.logout",
                target_type="session",
                target_id=str(session_row.id),
                request=request,
            )
            await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", summary="Current user profile and permissions")
async def me(principal: PrincipalDep, request: Request, session: SessionDep) -> JSONResponse:
    user = await session.get(User, principal.user_id)
    if user is None or user.status != "ACTIVE":
        raise ApiError(401, "invalid_credentials", "This account is not active.")
    roles = [role.code for role in await roles_for_user(session, user.id)]
    _, permissions = await effective_permissions(session, user.id)
    profile = ProfileOut(
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
    return JSONResponse(envelope(request, profile.model_dump(mode="json")))


@router.get("/.well-known/jwks.json", summary="JSON Web Key Set")
async def jwks_endpoint(request: Request) -> dict[str, Any]:
    return request.app.state.jwks  # type: ignore[no-any-return]
