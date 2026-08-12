import uuid
from datetime import datetime

from pydantic import BaseModel


class UptimeDay(BaseModel):
    day: str
    checks: int
    uptime_percent: float | None


class UptimeIncident(BaseModel):
    started_at: datetime
    ended_at: datetime
    duration_minutes: int
    failed_checks: int
    error: str | None


class ReportedStatusComponent(BaseModel):
    name: str
    indicator: str


class ReportedStatusIncident(BaseModel):
    name: str
    impact: str | None
    status: str | None
    started_at: str | None
    url: str | None


class VendorReportedStatus(BaseModel):
    """What the vendor publishes about their own service health, read from
    their status page's API. Absent when they have no status page recorded or
    it isn't on a platform we can read."""

    indicator: str
    description: str
    platform: str
    components: list[ReportedStatusComponent] = []
    active_incidents: list[ReportedStatusIncident] = []
    fetched_at: datetime


class VendorUptime(BaseModel):
    vendor_id: uuid.UUID
    vendor_name: str
    primary_domain: str
    is_internal_brand: bool
    # The vendor's own published status page, if recorded — what they report
    # about themselves, alongside what our probes observed.
    status_page_url: str | None = None
    checks: int
    # None (not 0) when nothing has been recorded yet, so "no data" never
    # renders as "100% down".
    uptime_percent: float | None
    avg_response_time_ms: int | None
    currently_reachable: bool | None
    last_checked_at: datetime | None
    daily: list[UptimeDay] = []
    incidents: list[UptimeIncident] = []
    reported_status: VendorReportedStatus | None = None
