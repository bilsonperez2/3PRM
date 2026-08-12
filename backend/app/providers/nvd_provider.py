from app.providers.base import RawFinding, VulnerabilityIntelligenceProvider


class NVDProvider(VulnerabilityIntelligenceProvider):
    """NVD vulnerability lookup — secondary/manual-search source only.

    TODO(Phase 5): implement manual CVE/keyword search. Per prior OSINT dashboard
    findings, NVD's free API is unreliable for on-demand multi-query use (tight
    rate limits even with a key, strict date-range formatting, literal keyword
    matching) — do not make this the primary correlation source for scheduled
    scans; prefer Shodan CVEDB there instead. Requires NVD_API_KEY (optional,
    raises the rate-limit tier only).
    """

    name = "nvd"

    async def correlate(self, technology: str, version: str | None) -> list[RawFinding]:
        raise NotImplementedError("NVDProvider.correlate is implemented in Phase 5")
