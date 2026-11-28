"""Session creation and token issuance shared by password and social login."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import Request
from neatsprint_lib.ids import new_id
from sqlalchemy.ext.asyncio import AsyncSession

from neatsprint_iam.api.schemas import SessionUser, TokenPair
from neatsprint_iam.db.models import RefreshToken, Session, User
from neatsprint_iam.security.tokens import create_access_token, new_refresh_token
from neatsprint_iam.services.accounts import effective_permissions, roles_for_user
from neatsprint_iam.services.audit import audit


def issue_tokens(
    request: Request,
    *,
    user: User,
    session_id: UUID,
    roles: list[str],
    permissions: list[str],
    refresh_token: str,
    device_id: UUID | None = None,
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
        device_id=device_id,
    )
    return TokenPair(
        access_token=access,
        expires_in=expires_in,
        refresh_token=refresh_token,
        user=SessionUser(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            tenant_id=user.tenant_id,
            roles=roles,
            permissions=permissions,
        ),
    )


async def start_session(
    request: Request,
    session: AsyncSession,
    user: User,
    *,
    device_name: str | None = None,
    device_id: UUID | None = None,
    action: str = "auth.login",
) -> TokenPair:
    settings = request.app.state.settings
    now = datetime.now(tz=UTC)

    session_row = Session(
        id=new_id(),
        tenant_id=user.tenant_id,
        user_id=user.id,
        device_id=device_name,
        bound_device_id=device_id,
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
        action=action,
        target_type="session",
        target_id=str(session_row.id),
        request=request,
    )
    await session.commit()

    return issue_tokens(
        request,
        user=user,
        session_id=session_row.id,
        roles=roles,
        permissions=permissions,
        refresh_token=raw_refresh,
        device_id=device_id,
    )
