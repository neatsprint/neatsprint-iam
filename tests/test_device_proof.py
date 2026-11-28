"""Unit tests for the device proof format (M3-T23)."""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from neatsprint_lib.errors import ApiError

from neatsprint_iam.services.device_proof import (
    body_hash,
    canonical_message,
    parse_proof,
    verify_signature,
)


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, base64.b64encode(raw).decode()


def _proof_header(private: Ed25519PrivateKey, message: bytes) -> str:
    signature = base64.b64encode(private.sign(message)).decode()
    return f"v1:1700000000:nonce-123456:{body_hash(b'{}')}:{signature}"


def test_canonical_message_is_stable() -> None:
    message = canonical_message("post", "/api/v1/x", 1700000000, "nonce-123", "abc")
    assert message == b"v1\nPOST\n/api/v1/x\n1700000000\nnonce-123\nabc"


def test_body_hash_is_sha256() -> None:
    assert body_hash(b"{}") == hashlib.sha256(b"{}").hexdigest()


def test_signature_round_trip() -> None:
    private, public_b64 = _keypair()
    message = canonical_message("GET", "/api/v1/monitor/devices", 1700000000, "n1", body_hash(b""))
    verify_signature(public_b64, message, private.sign(message))


def test_signature_rejects_tampering() -> None:
    private, public_b64 = _keypair()
    message = canonical_message("GET", "/api/v1/monitor/devices", 1700000000, "n1", body_hash(b""))
    signature = private.sign(message)
    with pytest.raises(ApiError) as error:
        verify_signature(public_b64, message + b"x", signature)
    assert error.value.code == "device_proof_invalid"


def test_signature_rejects_another_key() -> None:
    private, _ = _keypair()
    _, other_public = _keypair()
    message = canonical_message("GET", "/x", 1, "n1", "")
    with pytest.raises(ApiError):
        verify_signature(other_public, message, private.sign(message))


def test_parse_proof_accepts_the_wire_format() -> None:
    private, _ = _keypair()
    message = canonical_message("GET", "/x", 1700000000, "nonce-123456", body_hash(b""))
    proof = parse_proof(_proof_header(private, message))
    assert proof.timestamp == 1700000000
    assert proof.nonce == "nonce-123456"
    assert len(proof.signature) == 64


@pytest.mark.parametrize(
    "header",
    [
        "",
        "v2:1:nonce-123456:hash:sig",
        "v1:not-a-time:nonce-123456:hash:c2ln",
        "v1:1:nonce-123456:hash:c2ln",
        "v1:1::hash:c2ln",
    ],
)
def test_parse_proof_rejects_malformed_headers(header: str) -> None:
    with pytest.raises(ApiError) as error:
        parse_proof(header)
    assert error.value.code == "device_proof_invalid"
