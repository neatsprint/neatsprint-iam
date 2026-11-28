from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class DeviceInfo(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    platform: str | None = Field(default=None, max_length=32)
    app_version: str | None = Field(default=None, max_length=32)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    device: DeviceInfo | None = None
    captcha_token: str | None = None


class DeviceSessionRequest(BaseModel):
    device_id: UUID


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=16, max_length=512)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    captcha_token: str | None = None


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)
    password: str = Field(min_length=10, max_length=256)
    captcha_token: str | None = None


class GoogleLoginRequest(BaseModel):
    id_token: str = Field(min_length=20, max_length=8192)
    device: DeviceInfo | None = None
    captcha_token: str | None = None


class SessionOut(BaseModel):
    id: UUID
    device_id: str | None
    ip: str | None
    user_agent: str | None
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime
    current: bool


class SessionUser(BaseModel):
    id: UUID
    email: str
    full_name: str
    tenant_id: UUID
    roles: list[str]
    permissions: list[str]


class TokenPair(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - token type, not a secret
    expires_in: int
    refresh_token: str
    user: SessionUser


class ProfileOut(BaseModel):
    id: UUID
    email: str
    full_name: str
    tenant_id: UUID
    status: str
    job_title: str | None
    timezone: str
    locale: str
    roles: list[str]
    permissions: list[str]
    last_login_at: datetime | None


class UserOut(BaseModel):
    id: UUID
    email: str
    full_name: str
    status: str
    job_title: str | None
    roles: list[str]
    last_login_at: datetime | None


class AssignRolesRequest(BaseModel):
    role_ids: list[UUID] = Field(min_length=1)


class AvatarPresignRequest(BaseModel):
    content_type: str = Field(min_length=3, max_length=64)


class AvatarConfirmRequest(BaseModel):
    object_key: str = Field(min_length=10, max_length=512)


class AvatarOut(BaseModel):
    avatar_url: str


class InvitationCreate(BaseModel):
    email: EmailStr
    role_ids: list[UUID] = Field(min_length=1)
    team_ids: list[UUID] = Field(default_factory=list)


class InvitationAccept(BaseModel):
    token: str = Field(min_length=16, max_length=512)
    full_name: str = Field(min_length=1, max_length=160)
    password: str = Field(min_length=10, max_length=256)
    device: DeviceInfo | None = None
    captcha_token: str | None = None


class InvitationOut(BaseModel):
    id: UUID
    email: str
    role_ids: list[UUID]
    team_ids: list[UUID]
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None
    dev_token: str | None = None


class RoleOut(BaseModel):
    id: UUID
    code: str
    name: str
    description: str | None
    is_system: bool
    permissions: list[str]


class RoleCreate(BaseModel):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,31}$")
    name: str = Field(min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[str] = Field(min_length=1)


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[str] | None = None


class PermissionOut(BaseModel):
    code: str
    description: str | None


class BootstrapUserRequest(BaseModel):
    tenant_id: UUID
    email: EmailStr
    full_name: str
    password: str = Field(min_length=10, max_length=256)
    role_codes: list[str] = Field(default_factory=lambda: ["MEMBER"])


class UserLookupRequest(BaseModel):
    tenant_id: UUID
    user_ids: list[UUID] = Field(min_length=1, max_length=200)
