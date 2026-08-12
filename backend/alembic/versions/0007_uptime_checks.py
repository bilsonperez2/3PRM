"""Vendor availability monitoring — uptime_checks table.

Append-only and high-volume relative to everything else in the schema (one
row per vendor per polling interval), so it carries a composite index on the
only access pattern that matters — a vendor's checks within a time window —
and is pruned on a retention window by the scheduler rather than kept
indefinitely.

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-11

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "uptime_checks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vendor_id",
            UUID(as_uuid=True),
            sa.ForeignKey("vendors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "checked_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("reachable", sa.Boolean, nullable=False),
        sa.Column("status_code", sa.Integer),
        sa.Column("response_time_ms", sa.Integer),
        sa.Column("error", sa.String(255)),
    )
    op.create_index(
        "ix_uptime_checks_vendor_checked_at", "uptime_checks", ["vendor_id", "checked_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_uptime_checks_vendor_checked_at", table_name="uptime_checks")
    op.drop_table("uptime_checks")
