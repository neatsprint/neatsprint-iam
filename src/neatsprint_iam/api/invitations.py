from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Annotated

import aiosmtplib
from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from neatsprint_lib.auth import Principal, require_permission
from neatsprint_lib.errors import ApiError
from neatsprint_lib.ids import new_id
from sqlalchemy import select

from neatsprint_iam.api.deps import SessionDep
from neatsprint_iam.api.responses import envelope
from neatsprint_iam.api.schemas import InvitationAccept, InvitationCreate, InvitationOut
from neatsprint_iam.db.models import Invitation, Role
from neatsprint_iam.security.passwords import password_problems
from neatsprint_iam.security.tokens import hash_token
from neatsprint_iam.services.accounts import (
    create_user,
    get_user_by_email,
    normalise_email,
    roles_for_user,
)
from neatsprint_iam.services.audit import audit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/iam", tags=["invitations"])

InvitePrincipal = Annotated[Principal, Depends(require_permission("core:user:invite"))]


def _out(invitation: Invitation, dev_token: str | None = None) -> InvitationOut:
    return InvitationOut(
        id=invitation.id,
        email=invitation.email,
        role_ids=list(invitation.role_ids or []),
        team_ids=list(invitation.team_ids or []),
        expires_at=invitation.expires_at,
        accepted_at=invitation.accepted_at,
        revoked_at=invitation.revoked_at,
        dev_token=dev_token,
    )


async def _send_email(request: Request, email: str, token: str) -> None:
    settings = request.app.state.settings
    if not settings.email_enabled:
        return
    link = f"{settings.web_base_url}/accept-invitation?token={token}"
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = email
    message["Subject"] = "You have been invited to NeatSprint"
    message.set_content(
        "You have been invited to join a NeatSprint workspace.\n\n"
        f"Accept the invitation: {link}\n\n"
        "If you were not expecting this, you can ignore this email."
    )
    try:
        await aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            timeout=5,
        )
    except Exception:  # noqa: BLE001 - email delivery must not fail the invite
        logger.exception("invitation_email_failed", extra={"email": email})


@router.post("/invitations", status_code=status.HTTP_201_CREATED, summary="Invite a user")
async def create_invitation(
    payload: InvitationCreate,
    principal: InvitePrincipal,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    email = normalise_email(str(payload.email))
    if await get_user_by_email(session, email) is not None:
        raise ApiError(409, "email_unavailable", "That email address cannot be used.")

    admin_roles = await roles_for_user(session, principal.user_id)
    if "OWNER" not in {role.code for role in admin_roles}:
        target = (
            await session.execute(
                select(Role).where(
                    Role.tenant_id == principal.tenant_id, Role.id.in_(payload.role_ids)
                )
            )
        ).scalars()
        if any(role.code == "OWNER" for role in target):
            raise ApiError(403, "permission_denied", "Only an owner can invite an owner.")

    role_count = (
        await session.execute(
            select(Role.id).where(
                Role.tenant_id == principal.tenant_id, Role.id.in_(payload.role_ids)
            )
        )
    ).scalars().all()
    if len(role_count) != len(set(payload.role_ids)):
        raise ApiError(422, "invalid_role", "One or more roles do not belong to this tenant.")

    raw_token = secrets.token_urlsafe(32)
    invitation = Invitation(
        id=new_id(),
        tenant_id=principal.tenant_id,
        email=email,
        token_hash=hash_token(raw_token),
        invited_by=principal.user_id,
        role_ids=list(payload.role_ids),
        team_ids=list(payload.team_ids),
        expires_at=datetime.now(tz=UTC) + timedelta(days=7),
    )
    session.add(invitation)
    await audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="invitation.created",
        target_type="invitation",
        target_id=str(invitation.id),
        after={"email": email, "role_ids": [str(item) for item in payload.role_ids]},
        request=request,
    )
    await session.commit()

    await _send_email(request, email, raw_token)
    dev_token = raw_token if request.app.state.settings.environment == "local" else None
    return JSONResponse(
        envelope(request, _out(invitation, dev_token).model_dump(mode="json")),
        status_code=status.HTTP_201_CREATED,
    )


@router.get("/invitations", summary="List pending invitations")
async def list_invitations(
    principal: InvitePrincipal, request: Request, session: SessionDep
) -> JSONResponse:
    rows = (
        await session.execute(
            select(Invitation)
            .where(
                Invitation.tenant_id == principal.tenant_id,
                Invitation.accepted_at.is_(None),
                Invitation.revoked_at.is_(None),
            )
            .order_by(Invitation.created_at.desc())
        )
    ).scalars()
    return JSONResponse(
        envelope(request, [_out(row).model_dump(mode="json") for row in rows])
    )


@router.delete(
    "/invitations/{invitation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke an invitation",
)
async def revoke_invitation(
    invitation_id: str,
    principal: InvitePrincipal,
    request: Request,
    session: SessionDep,
) -> Response:
    invitation = await session.get(Invitation, invitation_id)
    if invitation is None or invitation.tenant_id != principal.tenant_id:
        raise ApiError(404, "not_found", "Invitation not found.")
    if invitation.accepted_at is None and invitation.revoked_at is None:
        invitation.revoked_at = datetime.now(tz=UTC)
        await audit(
            session,
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action="invitation.revoked",
            target_type="invitation",
            target_id=str(invitation.id),
            request=request,
        )
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/invitations/accept",
    status_code=status.HTTP_201_CREATED,
    summary="Accept an invitation and create the account",
)
async def accept_invitation(
    payload: InvitationAccept, request: Request, session: SessionDep
) -> JSONResponse:
    token_hash = hash_token(payload.token)
    invitation = (
        await session.execute(select(Invitation).where(Invitation.token_hash == token_hash))
    ).scalar_one_or_none()
    now = datetime.now(tz=UTC)

    if invitation is None:
        raise ApiError(404, "invitation_not_found", "This invitation is not valid.")
    if invitation.revoked_at is not None or invitation.accepted_at is not None:
        raise ApiError(410, "invitation_used", "This invitation has already been used.")
    if invitation.expires_at <= now:
        raise ApiError(410, "invitation_expired", "This invitation has expired.")

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

    if await get_user_by_email(session, invitation.email) is not None:
        raise ApiError(409, "email_unavailable", "That email address cannot be used.")

    user = await create_user(
        session,
        tenant_id=invitation.tenant_id,
        email=invitation.email,
        full_name=payload.full_name,
        password=payload.password,
        role_ids=list(invitation.role_ids or []),
        assigned_by=invitation.invited_by,
    )
    invitation.accepted_at = now

    await audit(
        session,
        tenant_id=invitation.tenant_id,
        actor_id=user.id,
        action="invitation.accepted",
        target_type="user",
        target_id=str(user.id),
        request=request,
    )
    await session.commit()

    roles = [role.code for role in await roles_for_user(session, user.id)]
    return JSONResponse(
        envelope(
            request,
            {
                "user_id": str(user.id),
                "tenant_id": str(user.tenant_id),
                "email": user.email,
                "full_name": user.full_name,
                "roles": roles,
            },
        ),
        status_code=status.HTTP_201_CREATED,
    )
