"""Look-alike/typosquat domain generation and evaluation.

Candidates are generated with pure-Python string transforms — no `dnstwist`
subprocess dependency — mirroring what was already proven out client-side in
the prior OSINT dashboard prototype's Brand Protection tab: character
omission/repetition, adjacent transposition, keyboard-adjacent substitution/
insertion, homoglyph substitution, common phishing prefixes/suffixes, and
alternate-TLD swaps.

Only resolving candidates are enriched further (MX presence, RDAP), and only
resolving candidates are ever returned — a candidate that doesn't resolve is
just a string, not a finding. This deliberately does not fetch content from
any candidate domain, and keeps concurrency conservative (a handful of
requests at a time) per the "do not generate excessive traffic" requirement.
"""

import asyncio

from app.core.logging import get_logger
from app.providers.base import TyposquatCandidate, TyposquattingProvider
from app.providers.dns_provider import _resolve
from app.providers.rdap_provider import RDAPProvider

logger = get_logger(__name__)

_CONCURRENCY = 8

_KEYBOARD_NEIGHBORS = {
    "q": "wa", "w": "qesa", "e": "wrsd", "r": "etdf", "t": "ryfg", "y": "tugh",
    "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
}

_HOMOGLYPHS = [
    ("o", "0"), ("l", "1"), ("i", "1"), ("rn", "m"), ("vv", "w"),
    ("e", "3"), ("a", "4"), ("s", "5"),
]

_PHISHING_PREFIXES = ["secure-", "login-", "verify-", "account-", "my-"]
_PHISHING_SUFFIXES = ["-support", "-portal", "-secure", "-login", "-verify"]

_ALT_TLDS = [
    "net", "org", "info", "biz", "co", "io", "us", "cc", "online", "site",
    "xyz", "top", "shop", "club", "app", "vip",
]


def _split_domain(domain: str) -> tuple[str, str]:
    name, _, tld = domain.rpartition(".")
    return name, tld


def generate_candidates(domain: str) -> list[tuple[str, str]]:
    """Returns (candidate_domain, generation_technique) pairs. Pure string
    generation, no network calls — kept as a standalone function so it's
    unit-testable without any infrastructure.
    """
    name, tld = _split_domain(domain)
    if not name or not tld:
        return []

    candidates: dict[str, str] = {}

    def add(new_name: str, technique: str) -> None:
        if new_name and new_name != name:
            candidates.setdefault(f"{new_name}.{tld}", technique)

    for i in range(len(name)):
        add(name[:i] + name[i + 1 :], "omission")

    for i in range(len(name)):
        add(name[: i + 1] + name[i] + name[i + 1 :], "repetition")

    for i in range(len(name) - 1):
        chars = list(name)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        add("".join(chars), "transposition")

    for i, ch in enumerate(name):
        for neighbor in _KEYBOARD_NEIGHBORS.get(ch, ""):
            add(name[:i] + neighbor + name[i + 1 :], "keyboard_substitution")
            add(name[:i] + neighbor + name[i:], "keyboard_insertion")

    for original, replacement in _HOMOGLYPHS:
        if original in name:
            add(name.replace(original, replacement, 1), "homoglyph")

    for prefix in _PHISHING_PREFIXES:
        add(f"{prefix}{name}", "phishing_prefix")
    for suffix in _PHISHING_SUFFIXES:
        add(f"{name}{suffix}", "phishing_suffix")

    for alt_tld in _ALT_TLDS:
        if alt_tld != tld:
            candidates.setdefault(f"{name}.{alt_tld}", "tld_swap")

    return list(candidates.items())


class TyposquatProvider(TyposquattingProvider):
    name = "typosquat"

    async def generate_and_evaluate(self, domain: str) -> list[TyposquatCandidate]:
        pairs = generate_candidates(domain)
        logger.info("typosquat: generated %s candidates for %s", len(pairs), domain)

        semaphore = asyncio.Semaphore(_CONCURRENCY)

        async def _check(candidate_domain: str, technique: str) -> TyposquatCandidate | None:
            async with semaphore:
                # retries=0 here (unlike the vendor's own domain checks): this
                # runs once per candidate across 100+ candidates, so keeping
                # per-request volume down matters more than catching every
                # transient blip — a missed candidate just isn't reported,
                # it's not treated as a negative finding either way.
                a_records = await _resolve(candidate_domain, "A", retries=0)
            if not a_records:
                return None

            async with semaphore:
                mx_records = await _resolve(candidate_domain, "MX", retries=0)
            mail_configured = bool(mx_records)

            rdap_info = await RDAPProvider().lookup(candidate_domain)

            return TyposquatCandidate(
                domain=candidate_domain,
                generation_technique=technique,
                resolves=True,
                mail_configured=mail_configured,
                certificate_seen=False,
                registrar=rdap_info.get("registrar") if rdap_info else None,
                registration_date=None,
                similarity_score=None,
                evidence={"technique": technique, "a_records": a_records, "rdap": rdap_info},
            )

        results = await asyncio.gather(*(_check(d, t) for d, t in pairs))
        return [r for r in results if r is not None]
