"""Initial Phase 1 schema: vendors, assets, findings, scans, risk_scores,
risk_scoring_config, governance_profiles.

Revision ID: 0001
Revises:
Create Date: 2026-08-10

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.models.enums import (
    AccessLevel,
    AssetType,
    Criticality,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    OwnershipConfidence,
    RiskTier,
    ScanMode,
    ScanStatus,
    TriState,
    VendorCategory,
)

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _enum(python_enum, name: str) -> sa.Enum:
    return sa.Enum(*[member.value for member in python_enum], name=name)


def upgrade() -> None:
    op.create_table(
        "vendors",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("primary_domain", sa.String(255), nullable=False),
        sa.Column("business_owner", sa.String(255)),
        sa.Column(
            "vendor_category",
            _enum(VendorCategory, "vendor_category"),
            nullable=False,
            server_default=VendorCategory.OTHER.value,
        ),
        sa.Column(
            "criticality",
            _enum(Criticality, "criticality"),
            nullable=False,
            server_default=Criticality.MEDIUM.value,
        ),
        sa.Column(
            "data_access_level",
            _enum(AccessLevel, "data_access_level"),
            nullable=False,
            server_default=AccessLevel.NONE.value,
        ),
        sa.Column(
            "system_access_level",
            _enum(AccessLevel, "system_access_level"),
            nullable=False,
            server_default=AccessLevel.NONE.value,
        ),
        sa.Column(
            "risk_tier",
            _enum(RiskTier, "risk_tier"),
            nullable=False,
            server_default=RiskTier.MEDIUM.value,
        ),
        sa.Column(
            "active_scan_authorized", sa.Boolean, nullable=False, server_default=sa.false()
        ),
        sa.Column("renewal_date", sa.Date),
        sa.Column("notes", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_vendors_primary_domain", "vendors", ["primary_domain"])

    op.create_table(
        "assets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vendor_id",
            UUID(as_uuid=True),
            sa.ForeignKey("vendors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("hostname", sa.String(255)),
        sa.Column("ip_address", sa.String(64)),
        sa.Column("asset_type", _enum(AssetType, "asset_type"), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column(
            "ownership_confidence",
            _enum(OwnershipConfidence, "ownership_confidence"),
            nullable=False,
            server_default=OwnershipConfidence.UNVERIFIED.value,
        ),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_assets_vendor_id", "assets", ["vendor_id"])
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"])

    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vendor_id",
            UUID(as_uuid=True),
            sa.ForeignKey("vendors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("finding_type", sa.String(128), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column(
            "severity",
            _enum(FindingSeverity, "finding_severity"),
            nullable=False,
            server_default=FindingSeverity.INFO.value,
        ),
        sa.Column(
            "confidence",
            _enum(FindingConfidence, "finding_confidence"),
            nullable=False,
            server_default=FindingConfidence.MEDIUM.value,
        ),
        sa.Column("evidence", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("remediation", sa.Text),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column(
            "status",
            _enum(FindingStatus, "finding_status"),
            nullable=False,
            server_default=FindingStatus.OPEN.value,
        ),
        sa.Column("suppressed_until", sa.DateTime(timezone=True)),
        sa.Column("analyst_notes", sa.Text),
        sa.Column("risk_points", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_index("ix_findings_vendor_id", "findings", ["vendor_id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_finding_type", "findings", ["finding_type"])

    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vendor_id",
            UUID(as_uuid=True),
            sa.ForeignKey("vendors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scan_type", sa.String(64), nullable=False),
        sa.Column("mode", _enum(ScanMode, "scan_mode"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "status",
            _enum(ScanStatus, "scan_status"),
            nullable=False,
            server_default=ScanStatus.QUEUED.value,
        ),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_scans_vendor_id", "scans", ["vendor_id"])

    op.create_table(
        "risk_scores",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vendor_id",
            UUID(as_uuid=True),
            sa.ForeignKey("vendors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("score", sa.Integer, nullable=False),
        sa.Column("grade", sa.String(2), nullable=False),
        sa.Column("category_scores", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("calculated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("scoring_version", sa.String(32), nullable=False),
    )
    op.create_index("ix_risk_scores_vendor_id", "risk_scores", ["vendor_id"])

    op.create_table(
        "risk_scoring_config",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("version", sa.String(32), nullable=False, unique=True),
        sa.Column("weights", JSONB, nullable=False),
        sa.Column("deductions", JSONB, nullable=False),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Column name -> enum type name, matching app.models.governance.GovernanceProfile
    # exactly so a future `alembic revision --autogenerate` diffs clean against it.
    tri_state_columns = [
        ("soc2_reviewed", "tri_state_soc2"),
        ("iso27001_certified", "tri_state_iso27001"),
        ("dpa_on_file", "tri_state_dpa"),
        ("incident_notification_required", "tri_state_incident_notification"),
        ("cyber_insurance", "tri_state_cyber_insurance"),
        ("mfa_enforced", "tri_state_mfa"),
        ("encryption_at_rest", "tri_state_encryption_at_rest"),
        ("encryption_in_transit", "tri_state_encryption_in_transit"),
        ("bcdr_in_place", "tri_state_bcdr"),
        ("pentest_performed", "tri_state_pentest"),
        ("security_awareness_program", "tri_state_security_awareness"),
        ("vulnerability_mgmt_program", "tri_state_vuln_mgmt"),
        ("patch_mgmt_program", "tri_state_patch_mgmt"),
        ("subprocessor_mgmt", "tri_state_subprocessor_mgmt"),
    ]
    governance_columns = [
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vendor_id",
            UUID(as_uuid=True),
            sa.ForeignKey("vendors.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
    ]
    for column_name, enum_name in tri_state_columns:
        governance_columns.append(
            sa.Column(
                column_name,
                _enum(TriState, enum_name),
                nullable=False,
                server_default=TriState.UNKNOWN.value,
            )
        )
    governance_columns.append(sa.Column("security_questionnaire_status", sa.String(64)))
    governance_columns.append(
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now())
    )
    op.create_table("governance_profiles", *governance_columns)
    op.create_index("ix_governance_profiles_vendor_id", "governance_profiles", ["vendor_id"])


def downgrade() -> None:
    op.drop_table("governance_profiles")
    op.drop_table("risk_scoring_config")
    op.drop_table("risk_scores")
    op.drop_table("scans")
    op.drop_table("findings")
    op.drop_table("assets")
    op.drop_table("vendors")

    for enum_name in [
        "vendor_category",
        "criticality",
        "data_access_level",
        "system_access_level",
        "risk_tier",
        "asset_type",
        "ownership_confidence",
        "finding_severity",
        "finding_confidence",
        "finding_status",
        "scan_mode",
        "scan_status",
        "tri_state_soc2",
        "tri_state_iso27001",
        "tri_state_dpa",
        "tri_state_incident_notification",
        "tri_state_cyber_insurance",
        "tri_state_mfa",
        "tri_state_encryption_at_rest",
        "tri_state_encryption_in_transit",
        "tri_state_bcdr",
        "tri_state_pentest",
        "tri_state_security_awareness",
        "tri_state_vuln_mgmt",
        "tri_state_patch_mgmt",
        "tri_state_subprocessor_mgmt",
    ]:
        sa.Enum(name=enum_name).drop(op.get_bind(), checkfirst=True)
