from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    log_level: str = "INFO"

    database_url: str = "postgresql+psycopg://tprm:changeme@localhost:5432/tprm"

    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # Provider request timeout, in seconds. Applied to every outbound provider call
    # (DNS, RDAP, crt.sh, etc.) so a slow/erratic upstream source can't hang a scan.
    scan_timeout_seconds: int = 30

    # Minimum time between two scans of the same vendor, regardless of mode.
    scan_min_interval_minutes: int = 15

    # --- Recurring scan scheduler ---
    # How stale a vendor's last completed scan may get before it's re-scanned.
    scan_interval_days: int = 7
    # The scheduler wakes on this cadence and enqueues at most
    # scheduler_batch_size vendors each time. Spreading the work across many
    # small ticks is what stops a weekly schedule from firing every vendor
    # simultaneously and hammering the shared upstream sources (crt.sh,
    # Shodan, public DNS) with one large burst.
    scheduler_tick_minutes: int = 30
    scheduler_batch_size: int = 2

    # --- Vendor uptime monitoring ---
    # How often every vendor's primary domain is probed. This is the most
    # frequent outbound traffic the platform generates, so it's a single
    # lightweight HEAD request per vendor per tick. Lowering it increases
    # outage-detection resolution at the cost of more requests to vendors.
    uptime_check_interval_minutes: int = 5
    # Raw checks are pruned past this age — the table grows by
    # (vendors × 288/day) at a 5 minute interval.
    uptime_retention_days: int = 90

    shodan_api_key: str | None = None
    nvd_api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
