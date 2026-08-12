"""Add vendors.status_page_url — a link to the vendor's own published status
page (status.vendor.com, trustpage.vendor.com/status, etc).

Analyst-maintained rather than auto-discovered: status pages live at no
standard location and are hosted on a range of platforms (Statuspage.io,
Instatus, Better Stack, vendor trust-page products), so guessing would
produce confident-looking dead links. The UI offers the common patterns as
one-click shortcuts to check, and the analyst records the one that's real.

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-11

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("vendors", sa.Column("status_page_url", sa.String(512), nullable=True))


def downgrade() -> None:
    op.drop_column("vendors", "status_page_url")
