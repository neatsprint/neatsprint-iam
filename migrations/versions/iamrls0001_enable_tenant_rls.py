"""Add RLS policies to IAM tenant-owned tables.

Revision ID: iamrls0001
Revises: 8b38fb0ebea6
"""

from __future__ import annotations

from alembic import op

revision = "iamrls0001"
down_revision = "8b38fb0ebea6"
branch_labels = None
depends_on = None

# ``users`` is intentionally excluded: email is globally unique (ADR-012) and is
# looked up before a tenant is known during login, invitation and password reset.
TABLES = (
    "sessions",
    "roles",
    "invitations",
    "audit_log",
    "notifications",
)

POLICY = (
    "(nullif(current_setting('app.tenant_id', true), '') IS NULL OR "
    "tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)"
)


def upgrade() -> None:
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({POLICY}) WITH CHECK ({POLICY})"
        )


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
