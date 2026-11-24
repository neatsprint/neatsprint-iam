from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from neatsprint_lib.auth import Principal, get_principal
from neatsprint_lib.errors import ApiError
from neatsprint_lib.events import enqueue
from neatsprint_lib.ids import new_id
from sqlalchemy import select, update

from neatsprint_iam.api.deps import SessionDep
from neatsprint_iam.api.responses import envelope
from neatsprint_iam.api.schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    ProfileOut,
    RefreshRequest,
    ResetPasswordRequest,
    SessionOut,
)
from neatsprint_iam.db.models import (
    PasswordResetToken,
    RefreshToken,
    Session,
    User,
    UserCredential,
)
from neatsprint_iam.security.passwords import (
    hash_password,
    needs_rehash,
    password_problems,
    verify_password,
)
from neatsprint_iam.security.tokens import (
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
from neatsprint_iam.services.captcha import verify_captcha
from neatsprint_iam.services.lockout import clear as clear_lockout
from neatsprint_iam.services.lockout import is_locked, record_failure
from neatsprint_iam.services.mailer import send_password_reset
from neatsprint_iam.services.session_tokens import issue_tokens, start_session

router = APIRouter(prefix="/auth", tags=["auth"])

PrincipalDep = Annotated[Principal, Depends(get_principal)]


@router.post("/login", response_model=None, summary="Exchange credentials for tokens")
async def login(
    payload: LoginRequest, request: Request, session: SessionDep
) -> JSONResponse:
    await verify_captcha(request, payload.captcha_token)
    settings = request.app.state.settings
    redis = getattr(request.app.state, "redis", None)
    email = normalise_email(str(payload.email))
    if await is_locked(redis, email, settings.login_max_failures):
        raise ApiError(
            429,
            "account_locked",
            "Too many failed sign-in attempts. Try again later.",
        )
    user = await get_user_by_email(session, str(payload.email))
    credential = await session.get(UserCredential, user.id) if user else None

    if (
        user is None
        or credential is None
        or user.status != "ACTIVE"
        or not verify_password(credential.password_hash, payload.password)
    ):
        await record_failure(
            redis,
            email,
            max_failures=settings.login_max_failures,
            window_seconds=settings.login_failure_window_minutes * 60,
        )
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

    await clear_lockout(redis, email)
    tokens = await start_session(
        request,
        session,
        user,
        device_name=payload.device.name if payload.device else None,
        action="auth.login",
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

    tokens = issue_tokens(
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


@router.post(
    "/forgot-password",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a password reset",
)
async def forgot_password(
    payload: ForgotPasswordRequest, request: Request, session: SessionDep
) -> JSONResponse:
    await verify_captcha(request, payload.captcha_token)
    user = await get_user_by_email(session, str(payload.email))
    if user is not None and user.status == "ACTIVE":
        raw_token = secrets.token_urlsafe(32)
        session.add(
            PasswordResetToken(
                id=new_id(),
                user_id=user.id,
                token_hash=hash_token(raw_token),
                expires_at=datetime.now(tz=UTC) + timedelta(minutes=30),
            )
        )
        enqueue(
            session,
            event_type="auth.password_reset_requested",
            tenant_id=user.tenant_id,
            actor_id=user.id,
            payload={"user_id": str(user.id)},
        )
        await audit(
            session,
            tenant_id=user.tenant_id,
            actor_id=user.id,
            action="auth.password_reset_requested",
            target_type="user",
            target_id=str(user.id),
            request=request,
        )
        await session.commit()
        await send_password_reset(request, to=user.email, token=raw_token)

    # Always the same response: no account enumeration.
    return JSONResponse(
        envelope(request, {"status": "accepted"}),
        status_code=status.HTTP_202_ACCEPTED,
    )


@router.post(
    "/reset-password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Complete a password reset",
)
async def reset_password(
    payload: ResetPasswordRequest, request: Request, session: SessionDep
) -> Response:
    await verify_captcha(request, payload.captcha_token)
    token_hash = hash_token(payload.token)
    token = (
        await session.execute(
            select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
        )
    ).scalar_one_or_none()
    now = datetime.now(tz=UTC)

    if token is None or token.used_at is not None or token.expires_at <= now:
        raise ApiError(410, "reset_token_invalid", "This reset link is invalid or expired.")

    problems = password_problems(
        payload.password, min_length=request.app.state.settings.password_min_length
    )
    if problems:
        raise ApiError(
            422,
            "validation_failed",
            "The password does not meet the policy.",
            errors=[
                {"field": "password", "code": "weak_password", "message": item}
                for item in problems
            ],
        )

    credential = await session.get(UserCredential, token.user_id)
    if credential is None:
        raise ApiError(410, "reset_token_invalid", "This reset link is invalid or expired.")

    credential.password_hash = hash_password(payload.password)
    token.used_at = now

    sessions = (
        await session.execute(
            select(Session).where(Session.user_id == token.user_id, Session.revoked_at.is_(None))
        )
    ).scalars()
    for session_row in sessions:
        session_row.revoked_at = now
        session_row.revoke_reason = "password_reset"
    await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.session_id.in_(
                select(Session.id).where(Session.user_id == token.user_id)
            ),
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    await audit(
        session,
        tenant_id=None,
        actor_id=token.user_id,
        action="auth.password_reset",
        target_type="user",
        target_id=str(token.user_id),
        request=request,
    )
    enqueue(
        session,
        event_type="auth.password_reset",
        tenant_id=None,
        actor_id=token.user_id,
        payload={"user_id": str(token.user_id)},
    )
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/sessions", summary="List my active sessions")
async def list_sessions(
    principal: PrincipalDep, request: Request, session: SessionDep
) -> JSONResponse:
    rows = (
        await session.execute(
            select(Session)
            .where(Session.user_id == principal.user_id, Session.revoked_at.is_(None))
            .order_by(Session.created_at.desc())
        )
    ).scalars()
    data = [
        SessionOut(
            id=row.id,
            device_id=row.device_id,
            ip=row.ip,
            user_agent=row.user_agent,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
            expires_at=row.expires_at,
            current=str(row.id) == principal.session_id,
        ).model_dump(mode="json")
        for row in rows
    ]
    return JSONResponse(envelope(request, data))


@router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke one of my sessions",
)
async def revoke_session(
    session_id: UUID, principal: PrincipalDep, request: Request, session: SessionDep
) -> Response:
    row = await session.get(Session, session_id)
    if row is None or row.user_id != principal.user_id:
        raise ApiError(404, "not_found", "Session not found.")
    if row.revoked_at is None:
        now = datetime.now(tz=UTC)
        row.revoked_at = now
        row.revoke_reason = "user_revoked"
        await session.execute(
            update(RefreshToken)
            .where(RefreshToken.session_id == row.id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await audit(
            session,
            tenant_id=row.tenant_id,
            actor_id=principal.user_id,
            action="auth.session_revoked",
            target_type="session",
            target_id=str(row.id),
            request=request,
        )
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/logout-all",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke every session for my account",
)
async def logout_all(
    principal: PrincipalDep, request: Request, session: SessionDep
) -> Response:
    now = datetime.now(tz=UTC)
    sessions = (
        await session.execute(
            select(Session).where(
                Session.user_id == principal.user_id, Session.revoked_at.is_(None)
            )
        )
    ).scalars()
    for row in sessions:
        row.revoked_at = now
        row.revoke_reason = "logout_all"
    await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.session_id.in_(
                select(Session.id).where(Session.user_id == principal.user_id)
            ),
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    await audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="auth.logout_all",
        target_type="user",
        target_id=str(principal.user_id),
        request=request,
    )
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/.well-known/jwks.json", summary="JSON Web Key Set")
async def jwks_endpoint(request: Request) -> dict[str, Any]:
    return request.app.state.jwks  # type: ignore[no-any-return]
