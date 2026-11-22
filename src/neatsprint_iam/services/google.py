"""Google Identity Services ID-token verification."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import jwt
from jwt import PyJWKClient
from neatsprint_lib.errors import ApiError

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")


@dataclass(frozen=True, slots=True)
class GoogleIdentity:
    subject: str
    email: str
    name: str


async def verify_google_id_token(id_token: str, client_id: str) -> GoogleIdentity:
    client = PyJWKClient(GOOGLE_JWKS_URL, cache_keys=True)
    try:
        signing_key = await asyncio.to_thread(client.get_signing_key_from_jwt, id_token)
        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=list(GOOGLE_ISSUERS),
        )
    except jwt.InvalidTokenError as exc:
        raise ApiError(
            401, "invalid_social_token", "Google sign-in could not be verified."
        ) from exc

    if not payload.get("email_verified"):
        raise ApiError(403, "email_not_verified", "This Google email is not verified.")
    email = str(payload.get("email", "")).lower()
    if not email:
        raise ApiError(401, "invalid_social_token", "Google did not return an email address.")
    return GoogleIdentity(
        subject=str(payload["sub"]),
        email=email,
        name=str(payload.get("name") or email.split("@")[0]),
    )
