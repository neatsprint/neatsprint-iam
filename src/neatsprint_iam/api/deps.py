from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Header, Request
from neatsprint_lib.auth import get_principal
from neatsprint_lib.db import get_session
from neatsprint_lib.errors import ApiError
from sqlalchemy.ext.asyncio import AsyncSession

SessionDep = Annotated[AsyncSession, Depends(get_session)]
AdminSessionDep = Annotated[AsyncSession, Depends(get_session)]
PrincipalDep = Annotated[object, Depends(get_principal)]


async def get_tenant_optional_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Bind the tenant when a user token is present; leave unbound for auth/internal calls."""
    factory = request.app.state.session_factory
    async with factory() as session:
        try:
            principal = await get_principal(request)
        except ApiError:
            pass
        else:
            session.info["tenant_id"] = str(principal.tenant_id)
        yield session


TenantSessionDep = Annotated[AsyncSession, Depends(get_tenant_optional_session)]


async def require_bootstrap(
    request: Request,
    x_bootstrap_token: Annotated[str | None, Header()] = None,
) -> None:
    expected = request.app.state.settings.bootstrap_token
    if not expected:
        raise ApiError(404, "not_found", "Not found.")
    if not x_bootstrap_token or not secrets.compare_digest(x_bootstrap_token, expected):
        raise ApiError(403, "permission_denied", "Invalid bootstrap token.")
