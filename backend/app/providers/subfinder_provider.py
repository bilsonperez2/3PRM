import asyncio
import json

from app.core.config import get_settings
from app.core.logging import get_logger
from app.providers.base import AssetDiscoveryProvider, Confidence, DiscoveredAsset
from app.schemas.vendor import validate_domain

logger = get_logger(__name__)


class SubfinderProvider(AssetDiscoveryProvider):
    """ProjectDiscovery Subfinder — passive subdomain enumeration.

    Shells out to the `subfinder` binary using an argument list (never
    shell=True, never an f-string-built command), with a hard timeout via
    asyncio.wait_for, and validates `domain` before it ever reaches subprocess
    args. Subfinder only queries passive sources by default (no `-active`
    flag) — that default is never overridden here.

    If the binary isn't installed (e.g. a dev environment that skipped the
    Docker build step, or a stripped-down deployment), this logs a warning and
    returns an empty list rather than failing the whole scan — Subfinder is
    one discovery source among several, not a hard dependency.
    """

    name = "subfinder"

    async def discover(self, domain: str) -> list[DiscoveredAsset]:
        domain = validate_domain(domain)
        settings = get_settings()

        try:
            process = await asyncio.create_subprocess_exec(
                "subfinder",
                "-d",
                domain,
                "-silent",
                "-json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.warning("subfinder binary not found on PATH — skipping this discovery source")
            return []

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=settings.scan_timeout_seconds
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.warning(
                "subfinder timed out after %ss for %s", settings.scan_timeout_seconds, domain
            )
            return []

        if process.returncode != 0:
            logger.warning(
                "subfinder exited %s for %s: %s",
                process.returncode,
                domain,
                stderr.decode(errors="replace")[:500],
            )
            return []

        assets: list[DiscoveredAsset] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = record.get("host")
            if not host:
                continue
            assets.append(
                DiscoveredAsset(
                    hostname=host.rstrip(".").lower(),
                    ip_address=None,
                    asset_type="subdomain",
                    source=f"subfinder:{record.get('source', 'unknown')}",
                    ownership_confidence=Confidence.MEDIUM,
                    metadata={"input": record.get("input")},
                )
            )
        return assets
