"""Add vendors.is_internal_brand — separates "our own domain" (brand
protection / typosquat monitoring of the organization) from third-party
vendors, without a parallel schema. See app/models/vendor.py for why.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-11

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vendors",
        sa.Column("is_internal_brand", sa.Boolean, nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("vendors", "is_internal_brand")
