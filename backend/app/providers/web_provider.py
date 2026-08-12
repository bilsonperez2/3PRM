"""HTTPS availability, TLS certificate health, and HTTP security headers.

This is the check family that produces most of what a commercial ratings
platform shows on a vendor's risk profile. It's passive in the sense the spec
means: an ordinary HTTPS GET, the same request any browser or crawler makes.
It does not port-scan, enumerate paths, or probe for vulnerabilities.

Per host it makes at most three connections:
  1. a TLS handshake to read the certificate,
  2. an HTTPS GET to read security headers,
  3. an HTTP (plaintext) GET, redirects NOT followed, to see whether the site
     upgrades the connection.

Certificate validation uses a strict context, so a bad chain/hostname/expiry
raises rather than silently passing. The specific reason is then read from
OpenSSL's structured `verify_code` on the exception — preferred over
string-matching the error message, and it avoids needing a second permissive
handshake just to learn why the first one failed.
"""

import asyncio
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.providers.base import Confidence, RawFinding

logger = get_logger(__name__)

# Certificates inside this window are still valid but close enough that a
# renewal failure would become an outage — worth flagging before it breaks.
_EXPIRY_WARNING_DAYS = 30

# OpenSSL X509 verification codes we can report specifically.
_VERIFY_CERT_HAS_EXPIRED = 10
_VERIFY_SELF_SIGNED = 18
_VERIFY_SELF_SIGNED_IN_CHAIN = 19
_VERIFY_HOSTNAME_MISMATCH = 62

# Web checks only make sense against hosts that plausibly serve HTTP. Mail
# servers and nameservers are inventoried as assets but aren't websites.
WEB_CHECKABLE_ASSET_TYPES = {"subdomain", "web_asset"}

# Every finding_type this module can emit — used by the ingestion layer to
# know which still-open findings may be auto-remediated when a later scan
# reaches the same host successfully and no longer sees the problem.
WEB_CHECK_FINDING_TYPES = {
    "https_not_available",
    "tls_cert_expired",
    "tls_cert_expiring_soon",
    "tls_cert_hostname_mismatch",
    "tls_cert_self_signed",
    "tls_cert_untrusted",
    "http_no_https_redirect",
    "hsts_missing",
    "csp_missing",
    "csp_unsafe",
    "clickjacking_protection_missing",
    "x_content_type_options_missing",
    "referrer_policy_missing",
    "permissions_policy_missing",
    "insecure_cookies",
}


@dataclass
class CertificateInfo:
    trusted: bool
    not_after: datetime | None = None
    subject_cn: str | None = None
    issuer: str | None = None
    failure_type: str | None = None  # one of the tls_cert_* finding types
    failure_detail: str | None = None


async def _read_certificate(hostname: str, timeout: float) -> CertificateInfo | None:
    """Strict handshake; verification failures are categorised from the
    exception's OpenSSL verify_code. Returns None if the host simply isn't
    reachable on 443 (a connectivity fact, not a certificate finding)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, 443, ssl=ssl.create_default_context()),
            timeout=timeout,
        )
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            cert = ssl_object.getpeercert() if ssl_object else {}
            not_after = None
            if cert and cert.get("notAfter"):
                not_after = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
                )
            subject_cn = None
            for rdn in cert.get("subject", ()) if cert else ():
                for key, value in rdn:
                    if key == "commonName":
                        subject_cn = value
            issuer = None
            for rdn in cert.get("issuer", ()) if cert else ():
                for key, value in rdn:
                    if key == "organizationName":
                        issuer = value
            return CertificateInfo(
                trusted=True, not_after=not_after, subject_cn=subject_cn, issuer=issuer
            )
        finally:
            writer.close()

    except ssl.SSLCertVerificationError as exc:
        code = getattr(exc, "verify_code", None)
        message = getattr(exc, "verify_message", None) or str(exc)
        if code == _VERIFY_CERT_HAS_EXPIRED:
            failure_type = "tls_cert_expired"
        elif code == _VERIFY_HOSTNAME_MISMATCH:
            failure_type = "tls_cert_hostname_mismatch"
        elif code in (_VERIFY_SELF_SIGNED, _VERIFY_SELF_SIGNED_IN_CHAIN):
            failure_type = "tls_cert_self_signed"
        else:
            failure_type = "tls_cert_untrusted"
        return CertificateInfo(trusted=False, failure_type=failure_type, failure_detail=message)

    except (ssl.SSLError, OSError, asyncio.TimeoutError):
        # Not reachable over TLS at all — handled by the caller as
        # https_not_available rather than a certificate problem.
        return None


def _evaluate_certificate(hostname: str, cert: CertificateInfo) -> list[RawFinding]:
    findings: list[RawFinding] = []

    if not cert.trusted:
        titles = {
            "tls_cert_expired": "TLS certificate has expired",
            "tls_cert_hostname_mismatch": "TLS certificate does not match hostname",
            "tls_cert_self_signed": "TLS certificate is self-signed",
            "tls_cert_untrusted": "TLS certificate chain is not trusted",
        }
        findings.append(
            RawFinding(
                finding_type=cert.failure_type,
                title=f"{titles.get(cert.failure_type, 'TLS certificate problem')}: {hostname}",
                description=(
                    f"The TLS certificate presented by {hostname} failed validation: "
                    f"{cert.failure_detail}. Visitors will see browser warnings, and the "
                    "connection cannot be trusted to be free of interception."
                ),
                severity="high",
                confidence=Confidence.CONFIRMED,
                evidence={
                    "instance_key": hostname,
                    "hostname": hostname,
                    "verify_failure": cert.failure_detail,
                },
                remediation="Install a valid certificate from a trusted CA covering this hostname.",
                asset_hostname=hostname,
            )
        )
        return findings

    if cert.not_after:
        days_left = (cert.not_after - datetime.now(timezone.utc)).days
        if 0 <= days_left <= _EXPIRY_WARNING_DAYS:
            findings.append(
                RawFinding(
                    finding_type="tls_cert_expiring_soon",
                    title=f"TLS certificate expires in {days_left} days: {hostname}",
                    description=(
                        f"The certificate for {hostname} expires on "
                        f"{cert.not_after.date().isoformat()}. If renewal fails the site "
                        "becomes unreachable and users see security warnings."
                    ),
                    severity="medium",
                    confidence=Confidence.CONFIRMED,
                    evidence={
                        "instance_key": hostname,
                        "hostname": hostname,
                        "not_after": cert.not_after.isoformat(),
                        "days_remaining": days_left,
                        "issuer": cert.issuer,
                    },
                    remediation="Renew the certificate before it expires.",
                    asset_hostname=hostname,
                )
            )
    return findings


def evaluate_security_headers(hostname: str, headers: dict, set_cookie_values: list[str]) -> list[RawFinding]:
    """Pure logic, split out so it's unit-testable with no network access.
    `headers` should be a case-insensitively-accessible mapping (httpx.Headers
    works, and a plain lowercase dict works in tests).
    """
    findings: list[RawFinding] = []

    def _finding(finding_type, title, description, severity, remediation, extra_evidence=None):
        return RawFinding(
            finding_type=finding_type,
            title=f"{title}: {hostname}",
            description=description,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            evidence={"instance_key": hostname, "hostname": hostname, **(extra_evidence or {})},
            remediation=remediation,
            asset_hostname=hostname,
        )

    def _get(name: str) -> str | None:
        for key, value in headers.items():
            if key.lower() == name:
                return value
        return None

    if not _get("strict-transport-security"):
        findings.append(
            _finding(
                "hsts_missing",
                "HSTS not enforced",
                f"{hostname} does not send a Strict-Transport-Security header, so browsers "
                "may still attempt an initial plaintext connection that can be intercepted "
                "and downgraded.",
                "medium",
                "Send Strict-Transport-Security with a max-age of at least 31536000.",
            )
        )

    csp = _get("content-security-policy")
    if not csp:
        findings.append(
            _finding(
                "csp_missing",
                "Content-Security-Policy not implemented",
                f"{hostname} does not send a Content-Security-Policy header, which is the "
                "primary defence against cross-site scripting.",
                "medium",
                "Define and send a Content-Security-Policy header.",
            )
        )
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        findings.append(
            _finding(
                "csp_unsafe",
                "Content-Security-Policy implemented unsafely",
                f"The CSP on {hostname} allows 'unsafe-inline' and/or 'unsafe-eval', which "
                "substantially weakens its protection against cross-site scripting.",
                "low",
                "Remove 'unsafe-inline'/'unsafe-eval' and use nonces or hashes instead.",
                {"csp": csp[:500]},
            )
        )

    xfo = (_get("x-frame-options") or "").strip().lower()
    frame_ancestors_set = bool(csp and "frame-ancestors" in csp)
    if xfo not in {"deny", "sameorigin"} and not frame_ancestors_set:
        findings.append(
            _finding(
                "clickjacking_protection_missing",
                "Clickjacking protection not set",
                f"{hostname} sets neither X-Frame-Options (DENY/SAMEORIGIN) nor a CSP "
                "frame-ancestors directive, so the page can be framed by a third party for "
                "clickjacking.",
                "low",
                "Set X-Frame-Options: SAMEORIGIN, or a CSP frame-ancestors directive.",
                {"x_frame_options": xfo or None},
            )
        )

    if (_get("x-content-type-options") or "").strip().lower() != "nosniff":
        findings.append(
            _finding(
                "x_content_type_options_missing",
                "X-Content-Type-Options not set to nosniff",
                f"{hostname} does not send X-Content-Type-Options: nosniff, allowing browsers "
                "to MIME-sniff responses.",
                "low",
                "Send X-Content-Type-Options: nosniff.",
            )
        )

    if not _get("referrer-policy"):
        findings.append(
            _finding(
                "referrer_policy_missing",
                "Referrer-Policy not set",
                f"{hostname} does not send a Referrer-Policy header, so full URLs may leak to "
                "third-party sites via the Referer header.",
                "info",
                "Send a Referrer-Policy such as strict-origin-when-cross-origin.",
            )
        )

    if not _get("permissions-policy"):
        findings.append(
            _finding(
                "permissions_policy_missing",
                "Permissions-Policy not set",
                f"{hostname} does not send a Permissions-Policy header controlling access to "
                "browser features such as camera, microphone and geolocation.",
                "info",
                "Send a Permissions-Policy header restricting unused browser features.",
            )
        )

    insecure_cookies = [c.split("=", 1)[0] for c in set_cookie_values if "secure" not in c.lower()]
    if insecure_cookies:
        findings.append(
            _finding(
                "insecure_cookies",
                "Cookies set without the Secure flag",
                f"{hostname} sets {len(insecure_cookies)} cookie(s) without the Secure "
                "attribute, so they may be transmitted over plaintext connections.",
                "low",
                "Add the Secure (and HttpOnly/SameSite where appropriate) attributes.",
                {"cookie_names": insecure_cookies[:10]},
            )
        )

    return findings


class WebSecurityProvider:
    name = "web"

    async def evaluate(self, hostname: str) -> list[RawFinding]:
        settings = get_settings()
        timeout = float(settings.scan_timeout_seconds)
        findings: list[RawFinding] = []

        cert = await _read_certificate(hostname, timeout)

        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                response = await client.get(f"https://{hostname}")
        except httpx.HTTPError:
            response = None

        if cert is None and response is None:
            # Nothing answered on 443. Only report this for hosts that look
            # like they're meant to serve web traffic — plenty of valid
            # subdomains legitimately have no website.
            findings.append(
                RawFinding(
                    finding_type="https_not_available",
                    title=f"HTTPS not available: {hostname}",
                    description=(
                        f"{hostname} did not accept an HTTPS connection on port 443. If this "
                        "host is meant to serve web content, traffic to it cannot be "
                        "encrypted."
                    ),
                    severity="medium",
                    confidence=Confidence.MEDIUM,
                    evidence={"instance_key": hostname, "hostname": hostname, "port": 443},
                    remediation="Serve this host over HTTPS with a valid certificate.",
                    asset_hostname=hostname,
                )
            )
            return findings

        if cert is not None:
            findings.extend(_evaluate_certificate(hostname, cert))

        if response is not None:
            set_cookies = response.headers.get_list("set-cookie") if response.headers else []
            findings.extend(evaluate_security_headers(hostname, dict(response.headers), set_cookies))

        # Plaintext HTTP should redirect to HTTPS. Redirects deliberately not
        # followed — we're checking whether the upgrade happens, not where it
        # lands.
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                http_response = await client.get(f"http://{hostname}")
            location = http_response.headers.get("location", "")
            redirects_to_https = (
                http_response.status_code in {301, 302, 307, 308}
                and location.lower().startswith("https://")
            )
            if not redirects_to_https:
                findings.append(
                    RawFinding(
                        finding_type="http_no_https_redirect",
                        title=f"HTTP does not redirect to HTTPS: {hostname}",
                        description=(
                            f"http://{hostname} returned {http_response.status_code} without "
                            "redirecting to HTTPS. Users reaching the site over plaintext stay "
                            "on an unencrypted connection."
                        ),
                        severity="medium",
                        confidence=Confidence.CONFIRMED,
                        evidence={
                            "instance_key": hostname,
                            "hostname": hostname,
                            "status_code": http_response.status_code,
                            "location": location or None,
                        },
                        remediation="Return a 301 redirect from http:// to https:// for all paths.",
                        asset_hostname=hostname,
                    )
                )
        except httpx.HTTPError:
            # No plaintext listener at all is fine — nothing to downgrade.
            pass

        return findings
