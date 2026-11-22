"""Social sign-in (Google Identity Services ID token)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from neatsprint_lib.errors import ApiError
from neatsprint_lib.events import enqueue
from sqlalchemy import select

from neatsprint_iam.api.deps import SessionDep
from neatsprint_iam.api.responses import envelope
from neatsprint_iam.api.schemas import GoogleLoginRequest
from neatsprint_iam.db.models import Invitation, SocialAccount
from neatsprint_iam.services.accounts import create_user, get_user_by_email
from neatsprint_iam.services.audit import audit
from neatsprint_iam.services.captcha import verify_captcha
from neatsprint_iam.services.google import verify_google_id_token
from neatsprint_iam.services.session_tokens import start_session

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/social/google", summary="Sign in with a Google ID token")
async def google_login(
    payload: GoogleLoginRequest, request: Request, session: SessionDep
) -> JSONResponse:
    await verify_captcha(request, payload.captcha_token)
    client_id = request.app.state.settings.google_client_id
    if not client_id:
        raise ApiError(503, "google_disabled", "Google sign-in is not configured.")

    identity = await verify_google_id_token(payload.id_token, client_id)
    user = await get_user_by_email(session, identity.email)

    if user is None:
        invitation = (
            await session.execute(
                select(Invitation).where(
                    Invitation.email == identity.email,
                    Invitation.accepted_at.is_(None),
                    Invitation.revoked_at.is_(None),
                    Invitation.expires_at > datetime.now(tz=UTC),
                )
            )
        ).scalars().first()
        if invitation is None:
            raise ApiError(
                403,
                "invitation_required",
                "Ask your admin for an invitation before signing in with Google.",
            )
        user = await create_user(
            session,
            tenant_id=invitation.tenant_id,
            email=identity.email,
            full_name=identity.name,
            password=None,
            role_ids=list(invitation.role_ids or []),
            assigned_by=invitation.invited_by,
        )
        invitation.accepted_at = datetime.now(tz=UTC)
        enqueue(
            session,
            event_type="user.created",
            tenant_id=user.tenant_id,
            actor_id=user.id,
            payload={"user_id": str(user.id), "email": user.email, "source": "google"},
        )

    if user.status != "ACTIVE":
        raise ApiError(401, "invalid_credentials", "This account is not active.")

    linked = (
        await session.execute(
            select(SocialAccount).where(
                SocialAccount.provider == "google",
                SocialAccount.provider_subject == identity.subject,
            )
        )
    ).scalar_one_or_none()
    if linked is None:
        session.add(
            SocialAccount(
                user_id=user.id,
                provider="google",
                provider_subject=identity.subject,
                email_at_provider=identity.email,
            )
        )
    elif linked.user_id != user.id:
        raise ApiError(409, "social_account_conflict", "This Google account is already linked.")

    await audit(
        session,
        tenant_id=user.tenant_id,
        actor_id=user.id,
        action="auth.social_login",
        target_type="user",
        target_id=str(user.id),
        request=request,
    )
    await session.flush()
    tokens = await start_session(
        request,
        session,
        user,
        device_name=payload.device.name if payload.device else None,
        action="auth.social_login",
    )
    return JSONResponse(envelope(request, tokens.model_dump(mode="json")))
