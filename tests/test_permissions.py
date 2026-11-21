from neatsprint_iam.domain.permissions import (
    ALL,
    PERMISSIONS,
    ROLE_PERMISSIONS,
    SYSTEM_ROLE_CODES,
    permissions_for_roles,
)


def test_catalogue_and_role_matrix_are_consistent() -> None:
    assert len(SYSTEM_ROLE_CODES) == 6
    for role, permissions in ROLE_PERMISSIONS.items():
        assert permissions <= set(PERMISSIONS), role
    assert ROLE_PERMISSIONS["OWNER"] == ALL


def test_admin_cannot_change_tenant_or_view_everything() -> None:
    admin = ROLE_PERMISSIONS["ADMIN"]
    assert "core:tenant:update" not in admin
    assert "monitor:data:view_all" not in admin
    assert "core:user:invite" in admin
    assert "report:audit:view" in admin


def test_member_scope_is_personal() -> None:
    member = ROLE_PERMISSIONS["MEMBER"]
    assert "work:log:view_own" in member
    assert "work:log:view_team" not in member
    assert "monitor:data:view_own" in member
    assert "monitor:data:view_team" not in member
    assert "core:user:invite" not in member


def test_viewer_is_read_only() -> None:
    viewer = ROLE_PERMISSIONS["VIEWER"]
    assert "task:item:create" not in viewer
    assert "task:item:view" in viewer
    assert "work:timer:start" not in viewer


def test_multiple_roles_union_permissions() -> None:
    combined = permissions_for_roles(["MEMBER", "LEAD"])
    assert "work:log:view_team" in combined
    assert "task:item:create" in combined
