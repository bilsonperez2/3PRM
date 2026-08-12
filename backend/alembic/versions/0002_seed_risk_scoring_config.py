"""Seed the default risk_scoring_config row (Phase 3).

Weights match the seven categories from the platform spec (vulnerabilities
25%, external_exposure 20%, email_security 15%, web_tls_security 15%,
dns_security 10%, typosquatting 10%, hygiene 5%). Deduction points cover every
finding_type Phase 2's DNS/email provider actually produces, plus a few
placeholders for finding_types that later phases (Phase 4 typosquatting,
Phase 5 web/TLS + vuln correlation) will start emitting — scorer.py silently
ignores a finding_type it has no rule for, so adding these now is harmless and
saves a migration later.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-11

"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCORING_VERSION = "2026.1"

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
    # Phase 2 — DNS/email security (app/providers/dns_provider.py)
    "spf_missing": {"points": 5, "category": "email_security"},
    "spf_permissive": {"points": 8, "category": "email_security"},
    "dmarc_missing": {"points": 8, "category": "email_security"},
    "dmarc_policy_none": {"points": 5, "category": "email_security"},
    "mta_sts_missing": {"points": 2, "category": "email_security"},
    "tls_rpt_missing": {"points": 1, "category": "email_security"},
    "mx_missing": {"points": 0, "category": "email_security"},
    # Phase 5 placeholders — web/TLS + vulnerability correlation
    "tls_cert_expiring_soon": {"points": 4, "category": "web_tls_security"},
    "tls_cert_expired": {"points": 10, "category": "web_tls_security"},
    "hsts_missing": {"points": 2, "category": "web_tls_security"},
    "kev_exposure_confirmed": {"points": 25, "category": "vulnerabilities"},
    "exposed_service_passive": {"points": 7, "category": "external_exposure"},
    # Phase 4 placeholder — typosquatting; per_finding so each lookalike
    # domain with active mail configured deducts independently.
    "typosquat_active_mail": {"points": 3, "category": "typosquatting", "per_finding": True},
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
    op.bulk_insert(
        risk_scoring_config,
        [
            {
                "id": uuid.uuid4(),
                "version": SCORING_VERSION,
                "weights": WEIGHTS,
                "deductions": DEDUCTIONS,
                "active": True,
            }
        ],
    )


def downgrade() -> None:
    op.execute(
        sa.text("DELETE FROM risk_scoring_config WHERE version = :version").bindparams(
            version=SCORING_VERSION
        )
    )
