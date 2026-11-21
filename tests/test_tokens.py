from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from neatsprint_iam.security.tokens import (
    create_access_token,
    hash_token,
    jwks,
    new_refresh_token,
)


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


def test_access_token_claims() -> None:
    private_pem, public_pem = _keys()
    user_id, tenant_id, session_id = uuid4(), uuid4(), uuid4()
    token, expires_in = create_access_token(
        private_key=private_pem,
        kid="kid-1",
        issuer="neatsprint-iam",
        audience="neatsprint",
        user_id=user_id,
        tenant_id=tenant_id,
        session_id=session_id,
        roles=["MANAGER"],
        permissions=["task:item:create", "task:project:view"],
        minutes=15,
    )
    assert expires_in == 900
    payload = jwt.decode(
        token, public_pem, algorithms=["RS256"], issuer="neatsprint-iam", audience="neatsprint"
    )
    assert payload["sub"] == str(user_id)
    assert payload["tid"] == str(tenant_id)
    assert payload["sid"] == str(session_id)
    assert payload["roles"] == ["MANAGER"]
    assert payload["scope"] == ["task:item:create", "task:project:view"]
    assert jwt.get_unverified_header(token)["kid"] == "kid-1"


def test_refresh_material_is_hashed() -> None:
    raw, digest = new_refresh_token()
    assert raw != digest
    assert len(raw) > 40
    assert hash_token(raw) == digest


def test_jwks_shape() -> None:
    _, public_pem = _keys()
    document = jwks(public_pem, "kid-1")
    key = document["keys"][0]
    assert key["kid"] == "kid-1"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["kty"] == "RSA"
    assert "n" in key and "e" in key
