"""Access-token issuance, refresh-token material and JWKS publishing."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm

REFRESH_BYTES = 48


def create_access_token(
    *,
    private_key: str,
    kid: str,
    issuer: str,
    audience: str,
    user_id: UUID,
    tenant_id: UUID,
    session_id: UUID,
    roles: list[str],
    permissions: list[str] | tuple[str, ...] | frozenset[str],
    minutes: int = 15,
) -> tuple[str, int]:
    now = datetime.now(tz=UTC)
    expires = now + timedelta(minutes=minutes)
    payload: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": str(user_id),
        "tid": str(tenant_id),
        "sid": str(session_id),
        "jti": str(uuid4()),
        "roles": list(roles),
        "scope": sorted(permissions),
        "iat": now,
        "exp": expires,
    }
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
    return token, minutes * 60


def new_refresh_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(REFRESH_BYTES)
    return raw, hash_token(raw)


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def jwks(public_key_pem: str, kid: str) -> dict[str, Any]:
    key = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(key, RSAPublicKey):
        raise ValueError("JWT signing keys must be RSA")
    jwk = json.loads(RSAAlgorithm.to_jwk(key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}
