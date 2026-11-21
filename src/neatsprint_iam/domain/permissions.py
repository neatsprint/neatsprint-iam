"""Permission catalogue and system role matrix (docs/SECURITY.md §4.3)."""

from __future__ import annotations

from types import MappingProxyType

# code -> human description
PERMISSIONS: MappingProxyType[str, str] = MappingProxyType(
    {
        "core:tenant:read": "Read tenant details and settings",
        "core:tenant:update": "Update tenant settings and billing",
        "core:role:read": "Read roles and permissions",
        "core:role:manage": "Create roles and assign permissions",
        "core:user:read": "Read users in the tenant",
        "core:user:invite": "Invite users to the tenant",
        "core:user:update": "Update or deactivate users",
        "task:project:view": "View projects",
        "task:project:create": "Create projects",
        "task:project:edit": "Edit project settings",
        "task:project:archive": "Archive projects",
        "task:item:view": "View backlog items",
        "task:item:create": "Create backlog items",
        "task:item:edit": "Edit backlog items",
        "task:item:transition": "Change item status",
        "task:item:assign": "Assign items",
        "task:item:delete": "Delete items",
        "task:item:comment": "Comment on items",
        "task:item:moderate": "Moderate comments",
        "task:sprint:view": "View sprints",
        "task:sprint:manage": "Plan and run sprints",
        "team:team:view": "View teams",
        "team:team:manage": "Create and edit teams",
        "team:member:manage": "Add and remove team members",
        "work:timer:start": "Start and stop the timer",
        "work:log:write": "Record and edit own time",
        "work:log:view_own": "View own time",
        "work:log:view_team": "View team time",
        "work:log:view_all": "View all tenant time",
        "work:log:edit_any": "Edit any time entry",
        "monitor:data:view_own": "View own screenshots",
        "monitor:data:view_team": "View team screenshots",
        "monitor:data:view_all": "View all tenant screenshots",
        "monitor:config:manage": "Configure monitoring policy",
        "monitor:device:manage": "Manage devices and remote controls",
        "report:productivity:view": "View productivity reports",
        "report:agile:view": "View agile reports",
        "report:monitoring:view": "View monitoring reports",
        "report:audit:view": "View audit logs",
        "report:export": "Export reports",
        "report:transparency:view": "View own transparency log",
        "ai:use": "Use the AI assistant",
        "ai:audit:view": "View AI audit logs",
    }
)

ALL = frozenset(PERMISSIONS)

_SYSTEM_ROLE_NAMES = {
    "OWNER": ("Owner", "Full control of the tenant"),
    "ADMIN": ("Administrator", "Manages users, roles, settings and all projects"),
    "MANAGER": ("Project Manager", "Plans work, manages teams and reviews delivery"),
    "LEAD": ("Team Lead", "Runs the team board and membership"),
    "MEMBER": ("Team Member", "Executes work and tracks own time"),
    "VIEWER": ("Viewer", "Read-only stakeholder access"),
}

ROLE_PERMISSIONS: MappingProxyType[str, frozenset[str]] = MappingProxyType(
    {
        "OWNER": ALL,
        "ADMIN": ALL - {"core:tenant:update", "monitor:data:view_all"},
        "MANAGER": frozenset(
            {
                "core:tenant:read",
                "core:role:read",
                "core:user:read",
                "task:project:view",
                "task:project:create",
                "task:project:edit",
                "task:item:view",
                "task:item:create",
                "task:item:edit",
                "task:item:transition",
                "task:item:assign",
                "task:item:delete",
                "task:item:comment",
                "task:item:moderate",
                "task:sprint:view",
                "task:sprint:manage",
                "team:team:view",
                "team:team:manage",
                "team:member:manage",
                "work:timer:start",
                "work:log:write",
                "work:log:view_own",
                "work:log:view_team",
                "monitor:data:view_own",
                "monitor:data:view_team",
                "monitor:device:manage",
                "report:productivity:view",
                "report:agile:view",
                "report:monitoring:view",
                "report:export",
                "report:transparency:view",
                "ai:use",
            }
        ),
        "LEAD": frozenset(
            {
                "core:tenant:read",
                "core:user:read",
                "task:project:view",
                "task:item:view",
                "task:item:create",
                "task:item:edit",
                "task:item:transition",
                "task:item:comment",
                "task:sprint:view",
                "task:sprint:manage",
                "team:team:view",
                "team:member:manage",
                "work:timer:start",
                "work:log:write",
                "work:log:view_own",
                "work:log:view_team",
                "monitor:data:view_own",
                "monitor:data:view_team",
                "report:productivity:view",
                "report:agile:view",
                "report:monitoring:view",
                "report:export",
                "report:transparency:view",
                "ai:use",
            }
        ),
        "MEMBER": frozenset(
            {
                "core:tenant:read",
                "core:user:read",
                "task:project:view",
                "task:item:view",
                "task:item:create",
                "task:item:transition",
                "task:item:comment",
                "task:sprint:view",
                "team:team:view",
                "work:timer:start",
                "work:log:write",
                "work:log:view_own",
                "monitor:data:view_own",
                "report:agile:view",
                "report:transparency:view",
                "ai:use",
            }
        ),
        "VIEWER": frozenset(
            {
                "core:tenant:read",
                "core:user:read",
                "task:project:view",
                "task:item:view",
                "task:sprint:view",
                "team:team:view",
                "work:log:view_own",
                "report:productivity:view",
                "report:agile:view",
                "report:transparency:view",
            }
        ),
    }
)

SYSTEM_ROLE_CODES = tuple(_SYSTEM_ROLE_NAMES)
SYSTEM_ROLE_NAMES = MappingProxyType(_SYSTEM_ROLE_NAMES)


def permissions_for_roles(role_codes: list[str] | tuple[str, ...]) -> frozenset[str]:
    result: set[str] = set()
    for code in role_codes:
        result.update(ROLE_PERMISSIONS.get(code, frozenset()))
    return frozenset(result)
