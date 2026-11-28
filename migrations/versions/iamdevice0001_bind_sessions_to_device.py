"""Bind sessions to a registered device (M3-T23).

Revision ID: iamdevice0001
Revises: iamrls0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "iamdevice0001"
down_revision = "iamrls0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "sessions",
        sa.Column("bound_device_id", postgresql.UUID(as_uuid=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("sessions", "bound_device_id")
