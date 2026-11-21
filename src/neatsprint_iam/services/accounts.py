"""Identity, role and permission operations."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from neatsprint_lib.errors import ApiError
from neatsprint_lib.ids import new_id
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from neatsprint_iam.db.models import (
    Permission,
    Role,
    RolePermission,
    User,
    UserCredential,
    UserRole,
)
from neatsprint_iam.domain.permissions import (
    PERMISSIONS,
    ROLE_PERMISSIONS,
    SYSTEM_ROLE_CODES,
    SYSTEM_ROLE_NAMES,
    permissions_for_roles,
)
from neatsprint_iam.security.passwords import hash_password


def normalise_email(email: str) -> str:
    return email.strip().lower()


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(
        select(User).where(User.email == normalise_email(email), User.deleted_at.is_(None))
    )
    return result.scalar_one_or_none()


async def get_user(session: AsyncSession, *, tenant_id: UUID, user_id: UUID) -> User | None:
    result = await session.execute(
        select(User).where(
            User.id == user_id, User.tenant_id == tenant_id, User.deleted_at.is_(None)
        )
    )
    return result.scalar_one_or_none()


async def get_credential(session: AsyncSession, user_id: UUID) -> UserCredential | None:
    return await session.get(UserCredential, user_id)


async def roles_for_user(session: AsyncSession, user_id: UUID) -> list[Role]:
    result = await session.execute(
        select(Role).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )
    return list(result.scalars().all())


async def role_codes_for_user(session: AsyncSession, user_id: UUID) -> list[str]:
    return sorted(role.code for role in await roles_for_user(session, user_id))


async def permission_codes_for_user(session: AsyncSession, user_id: UUID) -> frozenset[str]:
    result = await session.execute(
        select(RolePermission.permission_code)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user_id)
    )
    return frozenset(result.scalars().all())


async def ensure_permission_catalogue(session: AsyncSession) -> None:
    rows = []
    for code, description in PERMISSIONS.items():
        parts = code.split(":")
        domain = parts[0]
        action = parts[-1]
        resource = ":".join(parts[1:-1]) or action
        rows.append(
            {
                "code": code,
                "domain": domain,
                "resource": resource,
                "action": action,
                "description": description,
            }
        )
    statement = pg_insert(Permission).values(rows)
    statement = statement.on_conflict_do_update(
        index_elements=[Permission.code],
        set_={
            "domain": statement.excluded.domain,
            "resource": statement.excluded.resource,
            "action": statement.excluded.action,
            "description": statement.excluded.description,
        },
    )
    await session.execute(statement)
    await session.commit()


async def ensure_system_roles(session: AsyncSession, tenant_id: UUID) -> list[Role]:
    """Create the six system roles and their permissions for a tenant (idempotent)."""
    existing_result = await session.execute(select(Role).where(Role.tenant_id == tenant_id))
    existing = {role.code: role for role in existing_result.scalars().all()}

    created: list[Role] = []
    for code in SYSTEM_ROLE_CODES:
        role = existing.get(code)
        if role is None:
            name, description = SYSTEM_ROLE_NAMES[code]
            role = Role(
                id=new_id(),
                tenant_id=tenant_id,
                code=code,
                name=name,
                description=description,
                is_system=True,
            )
            session.add(role)
            await session.flush()
            created.append(role)

        current = set(
            (
                await session.execute(
                    select(RolePermission.permission_code).where(
                        RolePermission.role_id == role.id
                    )
                )
            )
            .scalars()
            .all()
        )
        wanted = ROLE_PERMISSIONS[code]
        missing = wanted - current
        if missing:
            await session.execute(
                pg_insert(RolePermission)
                .values(
                    [
                        {"role_id": role.id, "permission_code": permission}
                        for permission in sorted(missing)
                    ]
                )
                .on_conflict_do_nothing()
            )
        stale = current - wanted
        if stale:
            await session.execute(
                delete(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_code.in_(sorted(stale)),
                )
            )

    await session.commit()
    result = await session.execute(select(Role).where(Role.tenant_id == tenant_id))
    return list(result.scalars().all())


async def create_user(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    email: str,
    full_name: str,
    password: str | None,
    status: str = "ACTIVE",
    role_ids: list[UUID] | None = None,
    assigned_by: UUID | None = None,
    job_title: str | None = None,
) -> User:
    email = normalise_email(email)
    if await get_user_by_email(session, email) is not None:
        raise ApiError(409, "email_unavailable", "That email address cannot be used.")

    user = User(
        id=new_id(),
        tenant_id=tenant_id,
        email=email,
        full_name=full_name.strip(),
        status=status,
        job_title=job_title,
    )
    session.add(user)
    await session.flush()

    if password:
        session.add(
            UserCredential(user_id=user.id, password_hash=hash_password(password))
        )

    if role_ids:
        await set_user_roles(
            session,
            user_id=user.id,
            tenant_id=tenant_id,
            role_ids=role_ids,
            assigned_by=assigned_by,
        )

    return user


async def set_user_roles(
    session: AsyncSession,
    *,
    user_id: UUID,
    tenant_id: UUID,
    role_ids: list[UUID],
    assigned_by: UUID | None,
) -> list[Role]:
    result = await session.execute(
        select(Role).where(Role.tenant_id == tenant_id, Role.id.in_(role_ids))
    )
    roles = list(result.scalars().all())
    if len(roles) != len(set(role_ids)):
        raise ApiError(422, "invalid_role", "One or more roles do not belong to this tenant.")

    await session.execute(delete(UserRole).where(UserRole.user_id == user_id))
    for role in roles:
        session.add(UserRole(user_id=user_id, role_id=role.id, assigned_by=assigned_by))
    return roles


async def effective_permissions(
    session: AsyncSession, user_id: UUID
) -> tuple[list[str], list[str]]:
    roles = await role_codes_for_user(session, user_id)
    permissions = await permission_codes_for_user(session, user_id)
    if not permissions and roles:
        permissions = permissions_for_roles(roles)
    return roles, sorted(permissions)


def mark_login(user: User, when: datetime) -> None:
    user.last_login_at = when
