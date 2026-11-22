"""Optional CAPTCHA verification (Cloudflare Turnstile compatible).

When ``CAPTCHA_SECRET`` is unset, verification is skipped so local development and
self-hosting remain simple. When set, auth endpoints require a valid token.
"""

from __future__ import annotations

import httpx
from fastapi import Request
from neatsprint_lib.errors import ApiError


async def verify_captcha(request: Request, token: str | None) -> None:
    settings = request.app.state.settings
    if not settings.captcha_secret:
        return
    if not token:
        raise ApiError(422, "captcha_required", "A CAPTCHA token is required.")
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(
                settings.captcha_verify_url,
                data={"secret": settings.captcha_secret, "response": token},
            )
    except httpx.HTTPError as exc:
        raise ApiError(503, "captcha_unavailable", "CAPTCHA verification failed.") from exc
    content_type = response.headers.get("content-type", "")
    payload = response.json() if content_type.startswith("application/json") else {}
    if response.status_code != 200 or not payload.get("success"):
        raise ApiError(403, "captcha_failed", "CAPTCHA verification failed.")
