"""Provider adapter interfaces.

Every external intelligence source (crt.sh, RDAP, Subfinder, Shodan InternetDB,
NVD, CISA KEV, dnstwist-style generation, ...) implements one of these interfaces.
The scan orchestrator (app/services/scan_orchestrator.py) depends only on these
abstract types, never on a concrete tool — swapping crt.sh for a paid CT API, or
adding a new source such as Censys or GreyNoise, means writing one new adapter
class with no changes above this layer.

All of these are PASSIVE-mode interfaces: they must only perform read-only,
non-intrusive lookups against public/indexed intelligence (DNS, RDAP, CT logs,
existing indexed scan data). Nothing implementing these interfaces may open a
connection to vendor infrastructure that a normal DNS resolver or public API
wouldn't. Authorized active-mode capabilities (port scanning, vulnerability
probing) are intentionally a separate, not-yet-defined interface family — see
Phase 6 in the project roadmap — so there is no code path today capable of active
scanning at all.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class DiscoveredAsset:
    hostname: str | None
    ip_address: str | None
    asset_type: str
    source: str
    ownership_confidence: Confidence
    metadata: dict = field(default_factory=dict)


@dataclass
class RawFinding:
    """A provider's raw observation, before it becomes a Finding row.

    `evidence` must be JSON-serializable and must never contain secrets/API
    credentials — providers are responsible for redacting before returning.
    """

    finding_type: str
    title: str
    description: str | None
    severity: str
    confidence: Confidence
    evidence: dict
    remediation: str | None = None
    asset_hostname: str | None = None


@dataclass
class TyposquatCandidate:
    domain: str
    generation_technique: str
    resolves: bool = False
    mail_configured: bool = False
    certificate_seen: bool = False
    registrar: str | None = None
    registration_date: datetime | None = None
    similarity_score: float | None = None
    evidence: dict = field(default_factory=dict)


class AssetDiscoveryProvider(ABC):
    """Discovers hostnames/IPs plausibly related to a domain (e.g. Subfinder,
    passive subdomain enumeration)."""

    name: str

    @abstractmethod
    async def discover(self, domain: str) -> list[DiscoveredAsset]: ...


class DNSIntelligenceProvider(ABC):
    """Resolves and evaluates DNS/email-security posture: A/AAAA/CNAME/MX/NS/TXT,
    SPF, DMARC, MTA-STS, TLS-RPT."""

    name: str

    @abstractmethod
    async def evaluate(self, domain: str) -> list[RawFinding]: ...


class CertificateTransparencyProvider(ABC):
    """Certificate Transparency log lookups (e.g. crt.sh) for subdomain discovery
    and certificate inventory."""

    name: str

    @abstractmethod
    async def discover(self, domain: str) -> list[DiscoveredAsset]: ...


class WebSecurityProvider(ABC):
    """HTTPS availability, TLS certificate health/expiration, and HTTP security
    headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-
    Policy, frame protections)."""

    name: str

    @abstractmethod
    async def evaluate(self, hostname: str) -> list[RawFinding]: ...


class VulnerabilityIntelligenceProvider(ABC):
    """Public vulnerability intelligence (NVD, CISA KEV). Must attach a
    Confidence level to every result and must never assert a CVE definitely
    affects an asset without corroborating evidence."""

    name: str

    @abstractmethod
    async def correlate(self, technology: str, version: str | None) -> list[RawFinding]: ...


class PortServiceIntelligenceProvider(ABC):
    """Passive, already-indexed internet-facing port/service intelligence (e.g.
    Shodan InternetDB). Must never initiate an active scan of vendor
    infrastructure — only reads existing third-party indexes."""

    name: str

    @abstractmethod
    async def lookup(self, ip_address: str) -> list[RawFinding]: ...


class DomainReputationProvider(ABC):
    """Reputation/threat-intel enrichment for a domain or IP (future: urlscan.io,
    VirusTotal, AbuseIPDB)."""

    name: str

    @abstractmethod
    async def check(self, indicator: str) -> list[RawFinding]: ...


class TyposquattingProvider(ABC):
    """Generates and evaluates look-alike/typosquat domain candidates for a base
    domain."""

    name: str

    @abstractmethod
    async def generate_and_evaluate(self, domain: str) -> list[TyposquatCandidate]: ...
