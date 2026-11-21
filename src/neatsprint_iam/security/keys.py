"""JWT signing keys.

Local development generates a persistent RSA key pair under the mounted keys volume.
Every other environment must provide the keys explicitly; missing keys are fatal.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyConfigurationError(RuntimeError):
    pass


def _kid(public_pem: str) -> str:
    der = serialization.load_pem_public_key(public_pem.encode()).public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


def load_or_create_keys(
    private_path: str, public_path: str, *, environment: str
) -> tuple[str, str, str]:
    private = Path(private_path)
    public = Path(public_path)

    if private.exists() and public.exists():
        private_pem = private.read_text(encoding="utf-8")
        public_pem = public.read_text(encoding="utf-8")
        return private_pem, public_pem, _kid(public_pem)

    if environment not in {"local", "ci"}:
        raise KeyConfigurationError(
            f"JWT keys not found at {private_path} / {public_path}. "
            "Provide them through the secret manager."
        )

    private.parent.mkdir(parents=True, exist_ok=True)
    public.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    private.write_text(private_pem, encoding="utf-8")
    public.write_text(public_pem, encoding="utf-8")
    if os.name != "nt":
        private.chmod(0o600)
        public.chmod(0o644)

    return private_pem, public_pem, _kid(public_pem)
