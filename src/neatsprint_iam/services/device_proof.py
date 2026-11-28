"""Device-proof verification shared by ForwardAuth and device-bound login (M3-T23).

A bound access token carries ``did`` (device id). Requests using it must present:

- ``X-Device-ID`` - the same device id;
- ``X-Device-Proof`` - ``v1:<timestamp>:<nonce>:<body_sha256>:<signature_b64>``.

The signature is Ed25519 over::

    v1\\n<METHOD>\\n<PATH>\\n<timestamp>\\n<nonce>\\n<body_sha256>

so a stolen token is useless without the private key held in the device keychain.
Nonces are single-use for the clock-skew window.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Request
from neatsprint_lib.auth import Principal
from neatsprint_lib.errors import ApiError

PROOF_VERSION = "v1"
CLOCK_SKEW_SECONDS = 60
NONCE_TTL_SECONDS = 120
DEVICE_CACHE_SECONDS = 30


@dataclass(frozen=True)
class DeviceProof:
    timestamp: int
    nonce: str
    body_sha256: str
    signature: bytes


def parse_proof(header: str) -> DeviceProof:
    parts = header.split(":")
    if len(parts) != 5 or parts[0] != PROOF_VERSION:
        raise ApiError(401, "device_proof_invalid", "The device proof is malformed.")
    _, timestamp, nonce, body_sha256, signature_b64 = parts
    try:
        parsed_timestamp = int(timestamp)
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ApiError(401, "device_proof_invalid", "The device proof is malformed.") from exc
    if len(signature) != 64 or not nonce or len(nonce) > 128:
        raise ApiError(401, "device_proof_invalid", "The device proof is malformed.")
    return DeviceProof(parsed_timestamp, nonce, body_sha256, signature)


def canonical_message(
    method: str, path: str, timestamp: int, nonce: str, body_sha256: str
) -> bytes:
    canonical = (
        f"{PROOF_VERSION}\n{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_sha256}"
    )
    return canonical.encode()


def verify_signature(public_key_b64: str, message: bytes, signature: bytes) -> None:
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
        key = Ed25519PublicKey.from_public_bytes(raw)
        key.verify(signature, message)
    except (binascii.Error, ValueError) as exc:
        raise ApiError(401, "device_proof_invalid", "The device key is invalid.") from exc
    except InvalidSignature as exc:
        raise ApiError(401, "device_proof_invalid", "The device signature is invalid.") from exc


async def _cached_device(request: Request, device_id: UUID) -> dict[str, Any]:
    redis = getattr(request.app.state, "redis", None)
    cache_key = f"device:key:{device_id}"
    if redis is not None:
        cached = await redis.get(cache_key)
        if cached:
            cached_device: dict[str, Any] = json.loads(cached)
            return cached_device

    settings = request.app.state.settings
    headers = {"X-Service-Token": settings.service_token or ""}
    async with httpx.AsyncClient(timeout=3) as client:
        response = await client.get(
            f"{settings.monitoring_internal_url}/internal/devices/{device_id}",
            headers=headers,
        )
    if response.status_code == 404:
        raise ApiError(401, "device_unknown", "This device is not registered.")
    if response.status_code >= 400:
        raise ApiError(503, "device_lookup_failed", "The device registry is unavailable.")

    device: dict[str, Any] = response.json().get("data", {})
    if redis is not None:
        await redis.setex(cache_key, DEVICE_CACHE_SECONDS, json.dumps(device))
    return device


async def _consume_nonce(request: Request, device_id: UUID, nonce: str) -> None:
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise ApiError(503, "replay_cache_unavailable", "Device proof cannot be checked.")
    stored = await redis.set(
        f"device:nonce:{device_id}:{nonce}", "1", nx=True, ex=NONCE_TTL_SECONDS
    )
    if not stored:
        raise ApiError(401, "device_replay", "This device proof was already used.")


def _forwarded_request(request: Request) -> tuple[str, str]:
    method = request.headers.get("x-forwarded-method", request.method)
    uri = request.headers.get("x-forwarded-uri", request.url.path)
    return method.upper(), urlsplit(uri).path


async def enforce_device_proof(
    request: Request,
    principal: Principal,
    *,
    device_id: UUID | None = None,
    method: str | None = None,
    path: str | None = None,
    body_sha256: str | None = None,
) -> dict[str, Any] | None:
    """Validate the proof for a device-bound principal, or raise ``ApiError``.

    ``device_id`` lets the binding endpoint check a device explicitly; otherwise the
    device comes from the token's ``did`` claim.
    """
    effective_device = device_id if device_id is not None else principal.device_id
    if effective_device is None:
        return None

    header_device = request.headers.get("x-device-id", "")
    if header_device.lower() != str(effective_device).lower():
        raise ApiError(401, "device_mismatch", "The request device does not match the token.")

    proof_header = request.headers.get("x-device-proof")
    if not proof_header:
        raise ApiError(401, "device_proof_required", "A device proof is required.")
    proof = parse_proof(proof_header)

    now = int(time.time())
    if abs(now - proof.timestamp) > CLOCK_SKEW_SECONDS:
        raise ApiError(401, "device_proof_expired", "The device proof has expired.")

    forwarded_method, forwarded_path = _forwarded_request(request)
    signed_method = (method or forwarded_method).upper()
    signed_path = path or forwarded_path
    signed_body = body_sha256 if body_sha256 is not None else proof.body_sha256

    device = await _cached_device(request, effective_device)
    if device.get("status") != "ACTIVE":
        raise ApiError(401, "device_inactive", "This device has been suspended or revoked.")
    if (
        UUID(str(device.get("user_id"))) != principal.user_id
        or UUID(str(device.get("tenant_id"))) != principal.tenant_id
    ):
        raise ApiError(401, "device_mismatch", "This device belongs to another account.")

    message = canonical_message(
        signed_method, signed_path, proof.timestamp, proof.nonce, signed_body
    )
    verify_signature(str(device.get("public_key", "")), message, proof.signature)
    await _consume_nonce(request, effective_device, proof.nonce)
    return device


def body_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
