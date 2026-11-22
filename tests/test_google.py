from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from neatsprint_lib.errors import ApiError

from neatsprint_iam.services import google as google_service

CLIENT_ID = "test-client.apps.googleusercontent.com"


def _keys() -> tuple[str, str]:
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
    return private_pem, public_pem


def _token(private_pem: str, **overrides: object) -> str:
    now = datetime.now(tz=UTC)
    claims: dict[str, object] = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "sub": "google-subject-1",
        "email": "Person@Example.com",
        "email_verified": True,
        "name": "Person Example",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    claims.update(overrides)
    return jwt.encode(claims, private_pem, algorithm="RS256")


class _FakeJwks:
    public_key: str = ""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def get_signing_key_from_jwt(self, token: str) -> SimpleNamespace:
        return SimpleNamespace(key=_FakeJwks.public_key)


async def test_google_identity_is_extracted(monkeypatch: pytest.MonkeyPatch) -> None:
    private_pem, public_pem = _keys()
    _FakeJwks.public_key = public_pem
    monkeypatch.setattr(google_service, "PyJWKClient", _FakeJwks)

    identity = await google_service.verify_google_id_token(_token(private_pem), CLIENT_ID)
    assert identity.email == "person@example.com"
    assert identity.name == "Person Example"
    assert identity.subject == "google-subject-1"


async def test_google_rejects_wrong_audience(monkeypatch: pytest.MonkeyPatch) -> None:
    private_pem, public_pem = _keys()
    _FakeJwks.public_key = public_pem
    monkeypatch.setattr(google_service, "PyJWKClient", _FakeJwks)

    with pytest.raises(ApiError):
        await google_service.verify_google_id_token(_token(private_pem, aud="other"), CLIENT_ID)


async def test_google_rejects_unverified_email(monkeypatch: pytest.MonkeyPatch) -> None:
    private_pem, public_pem = _keys()
    _FakeJwks.public_key = public_pem
    monkeypatch.setattr(google_service, "PyJWKClient", _FakeJwks)

    with pytest.raises(ApiError):
        await google_service.verify_google_id_token(
            _token(private_pem, email_verified=False), CLIENT_ID
        )
