"""Trust-center/compliance link fields on vendors, plus scoring rules for the
web/TLS check family.

Two changes bundled because they ship together:
  1. vendors.trust_center_url / security_page_url / compliance_notes —
     analyst-maintained links to the vendor's published security material.
  2. Scoring config 2026.4 adding every web/TLS finding type. These are all
     per_finding: a vendor with a broken certificate on ten hosts is worse off
     than one with a single broken host, and each host is its own finding row.

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-11

"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OLD_VERSION = "2026.3"
NEW_VERSION = "2026.4"

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
    # Email security (Phase 2)
    "spf_missing": {"points": 5, "category": "email_security"},
    "spf_permissive": {"points": 8, "category": "email_security"},
    "dmarc_missing": {"points": 8, "category": "email_security"},
    "dmarc_policy_none": {"points": 5, "category": "email_security"},
    "mta_sts_missing": {"points": 2, "category": "email_security"},
    "tls_rpt_missing": {"points": 1, "category": "email_security"},
    "mx_missing": {"points": 0, "category": "email_security"},
    # Certificate health (Phase 5 web checks)
    "tls_cert_expired": {"points": 15, "category": "web_tls_security", "per_finding": True},
    "tls_cert_hostname_mismatch": {"points": 10, "category": "web_tls_security", "per_finding": True},
    "tls_cert_self_signed": {"points": 10, "category": "web_tls_security", "per_finding": True},
    "tls_cert_untrusted": {"points": 10, "category": "web_tls_security", "per_finding": True},
    "tls_cert_expiring_soon": {"points": 4, "category": "web_tls_security", "per_finding": True},
    "https_not_available": {"points": 8, "category": "web_tls_security", "per_finding": True},
    "http_no_https_redirect": {"points": 5, "category": "web_tls_security", "per_finding": True},
    # Security headers — individually small, collectively meaningful. Kept
    # low per-instance so a vendor with many subdomains missing a header
    # doesn't get buried; the count still shows in the breakdown.
    "hsts_missing": {"points": 2, "category": "web_tls_security", "per_finding": True},
    "csp_missing": {"points": 2, "category": "web_tls_security", "per_finding": True},
    "csp_unsafe": {"points": 1, "category": "web_tls_security", "per_finding": True},
    "clickjacking_protection_missing": {"points": 1, "category": "web_tls_security", "per_finding": True},
    "x_content_type_options_missing": {"points": 1, "category": "web_tls_security", "per_finding": True},
    "referrer_policy_missing": {"points": 0, "category": "hygiene", "per_finding": True},
    "permissions_policy_missing": {"points": 0, "category": "hygiene", "per_finding": True},
    "insecure_cookies": {"points": 2, "category": "web_tls_security", "per_finding": True},
    # Vulnerability intelligence (Phase 5)
    "kev_exposure_confirmed": {"points": 25, "category": "vulnerabilities", "per_finding": True},
    "shodan_known_vulnerability": {"points": 2, "category": "vulnerabilities", "per_finding": True},
    "exposed_service_passive": {"points": 7, "category": "external_exposure", "per_finding": True},
    # Typosquatting (Phase 4, Organization entries only)
    "typosquat_active_mail": {"points": 3, "category": "typosquatting", "per_finding": True},
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
    op.add_column("vendors", sa.Column("trust_center_url", sa.String(512), nullable=True))
    op.add_column("vendors", sa.Column("security_page_url", sa.String(512), nullable=True))
    op.add_column("vendors", sa.Column("compliance_notes", sa.Text, nullable=True))

    op.execute(sa.text("UPDATE risk_scoring_config SET active = false WHERE active = true"))
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
    op.drop_column("vendors", "compliance_notes")
    op.drop_column("vendors", "security_page_url")
    op.drop_column("vendors", "trust_center_url")
