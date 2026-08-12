import uuid

from pydantic import BaseModel


class RiskTierCounts(BaseModel):
    low: int
    medium: int
    high: int
    critical: int


class FindingSeverityCounts(BaseModel):
    info: int
    low: int
    medium: int
    high: int
    critical: int


class DashboardSummary(BaseModel):
    vendor_count: int
    critical_vendor_count: int
    high_risk_vendor_count: int
    vendors_with_new_findings: int
    vendors_with_kev_findings: int
    vendors_with_typosquatting_findings: int
    open_critical_findings: int
    open_high_findings: int
    recent_scan_count: int
    vendor_risk_tier_counts: RiskTierCounts
    open_finding_severity_counts: FindingSeverityCounts


class VendorScoreSummary(BaseModel):
    vendor_id: uuid.UUID
    vendor_name: str
    latest_score: int | None
    latest_grade: str | None
    previous_score: int | None
    score_change: int | None
