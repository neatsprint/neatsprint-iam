"""Transactional email helpers (Mailpit locally, SES/SMTP elsewhere)."""

from __future__ import annotations

import logging
from email.message import EmailMessage

import aiosmtplib
from fastapi import Request

logger = logging.getLogger(__name__)


async def send_email(request: Request, *, to: str, subject: str, body: str) -> None:
    settings = request.app.state.settings
    if not settings.email_enabled:
        return
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    try:
        await aiosmtplib.send(
            message, hostname=settings.smtp_host, port=settings.smtp_port, timeout=5
        )
    except Exception:  # noqa: BLE001 - email failure must not break the API
        logger.exception("email_delivery_failed", extra={"to": to, "subject": subject})


async def send_invitation(request: Request, *, to: str, token: str) -> None:
    settings = request.app.state.settings
    link = f"{settings.web_base_url}/accept-invitation?token={token}"
    await send_email(
        request,
        to=to,
        subject="You have been invited to NeatSprint",
        body=(
            "You have been invited to join a NeatSprint workspace.\n\n"
            f"Accept the invitation: {link}\n\n"
            "If you were not expecting this, you can ignore this email."
        ),
    )


async def send_password_reset(request: Request, *, to: str, token: str) -> None:
    settings = request.app.state.settings
    link = f"{settings.web_base_url}/reset-password?token={token}"
    await send_email(
        request,
        to=to,
        subject="Reset your NeatSprint password",
        body=(
            "A password reset was requested for your account.\n\n"
            f"Reset your password: {link}\n\n"
            "The link expires in 30 minutes. If you did not request it, ignore this email."
        ),
    )
