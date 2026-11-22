"""S3/MinIO helpers for avatar storage."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore.client import Config  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from fastapi import Request
from neatsprint_lib.errors import ApiError

ALLOWED_IMAGE_TYPES = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
}


def _client(request: Request, *, public: bool = False) -> Any:
    settings = request.app.state.settings
    if not settings.s3_endpoint or not settings.s3_access_key:
        raise ApiError(503, "storage_unavailable", "Object storage is not configured.")
    endpoint = (
        settings.s3_public_endpoint
        if public and settings.s3_public_endpoint
        else settings.s3_endpoint
    )
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        region_name=settings.s3_region,
        config=Config(signature_version="s3v4"),
    )


def avatar_key(tenant_id: str, user_id: str, content_type: str) -> str:
    extension = ALLOWED_IMAGE_TYPES.get(content_type, "bin")
    return f"tenant/{tenant_id}/avatars/{user_id}/{uuid.uuid4().hex}.{extension}"


def presign_upload(request: Request, key: str, content_type: str) -> str:
    settings = request.app.state.settings
    try:
        return str(
            _client(request, public=True).generate_presigned_url(
                "put_object",
                Params={
                    "Bucket": settings.s3_bucket,
                    "Key": key,
                    "ContentType": content_type,
                },
                ExpiresIn=300,
            )
        )
    except (BotoCoreError, ClientError) as exc:
        raise ApiError(503, "storage_unavailable", "Could not prepare the upload.") from exc


async def read_object(request: Request, key: str) -> tuple[bytes, str]:
    def _read() -> tuple[bytes, str]:
        response = _client(request).get_object(
            Bucket=request.app.state.settings.s3_bucket, Key=key
        )
        return response["Body"].read(), response.get("ContentType", "application/octet-stream")

    try:
        return await asyncio.to_thread(_read)
    except (BotoCoreError, ClientError) as exc:
        raise ApiError(404, "not_found", "Avatar not found.") from exc
