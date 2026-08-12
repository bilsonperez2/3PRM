"""Expand risk_scoring_config with the Phase 4 typosquat_domain_resolves
finding type (typosquat_active_mail already existed as a Phase 3 placeholder).

Config rows are immutable once created (see app.models.risk_score.
RiskScoringConfig) — rather than editing the 2026.1 row in place, this
deactivates it and inserts a new active 2026.2 row, so the prior config
remains in the table for audit/history.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-11

"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OLD_VERSION = "2026.1"
NEW_VERSION = "2026.2"

WEIGHTS = {
    "vulnerabilities": 0.25,
    "external_exposure": 0.20,
    "email_security": 0.15,
    "web_tls_security": 0.15,
    "dns_security": 0.10,
    "typosquatting": 0.10,
    "hygiene": 0.05,
}

DEDUCTIONS = {
    "spf_missing": {"points": 5, "category": "email_security"},
    "spf_permissive": {"points": 8, "category": "email_security"},
    "dmarc_missing": {"points": 8, "category": "email_security"},
    "dmarc_policy_none": {"points": 5, "category": "email_security"},
    "mta_sts_missing": {"points": 2, "category": "email_security"},
    "tls_rpt_missing": {"points": 1, "category": "email_security"},
    "mx_missing": {"points": 0, "category": "email_security"},
    "tls_cert_expiring_soon": {"points": 4, "category": "web_tls_security"},
    "tls_cert_expired": {"points": 10, "category": "web_tls_security"},
    "hsts_missing": {"points": 2, "category": "web_tls_security"},
    "kev_exposure_confirmed": {"points": 25, "category": "vulnerabilities"},
    "exposed_service_passive": {"points": 7, "category": "external_exposure"},
    "typosquat_active_mail": {"points": 3, "category": "typosquatting", "per_finding": True},
    # New in Phase 4: a resolving-but-no-mail lookalike is a much weaker
    # signal than one with active mail — small per-instance deduction.
    "typosquat_domain_resolves": {"points": 1, "category": "typosquatting", "per_finding": True},
}

risk_scoring_config = sa.table(
    "risk_scoring_config",
    sa.column("id", UUID(as_uuid=True)),
    sa.column("version", sa.String),
    sa.column("weights", JSONB),
    sa.column("deductions", JSONB),
    sa.column("active", sa.Boolean),
)


def upgrade() -> None:
    op.execute(
        sa.text("UPDATE risk_scoring_config SET active = false WHERE active = true")
    )
    op.bulk_insert(
        risk_scoring_config,
        [
            {
                "id": uuid.uuid4(),
                "version": NEW_VERSION,
                "weights": WEIGHTS,
                "deductions": DEDUCTIONS,
                "active": True,
            }
        ],
    )


def downgrade() -> None:
    op.execute(
        sa.text("DELETE FROM risk_scoring_config WHERE version = :version").bindparams(
            version=NEW_VERSION
        )
    )
    op.execute(
        sa.text("UPDATE risk_scoring_config SET active = true WHERE version = :version").bindparams(
            version=OLD_VERSION
        )
    )
