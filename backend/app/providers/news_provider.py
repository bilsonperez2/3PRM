"""Recent news mentioning a vendor.

Two source types, merged and de-duplicated:

1. A small set of well-known security news RSS feeds (fetched once, shared,
   cached — see _FEEDS), then filtered by keyword match. This is the same
   free-RSS approach already proven out in the prior OSINT dashboard
   prototype's "Cybersecurity News" tab.
2. Google News' RSS *search* endpoint (news.google.com/rss/search) — a
   per-vendor query, not a fixed feed. This is NOT Google's official Custom
   Search API (which needs a paid/keyed setup); it's a stable, widely-relied-
   upon RSS endpoint that returns clean XML for a search query. It is,
   however, undocumented/unofficial — unlike CISA KEV or NVD, Google could
   change or remove it without notice. It is deliberately NOT HTML scraping
   of google.com/search results, which would risk violating Google's terms of
   service and would be far more fragile.

Both source types feed the same word-boundary, case-insensitive match against
the vendor's name before being returned — Google's search relevance is not
trusted blindly. This lives outside the scan pipeline entirely: it's a live,
on-demand read, not something to re-fetch per vendor per scan.

Known limitation, same caveat as typosquat candidates: keyword matching on a
short/common vendor name (a company literally named "Cloud" or "Wall") will
produce false-positive matches. These are candidate mentions for a human to
check, not a verdict.
"""

import asyncio
import html
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from app.core.logging import get_logger
from app.providers.http_utils import fetch_text

logger = get_logger(__name__)

_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Record": "https://therecord.media/feed/",
    "Help Net Security": "https://www.helpnetsecurity.com/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
}

_GOOGLE_NEWS_SEARCH_URL = "https://news.google.com/rss/search"

# Shared across every vendor lookup — a 15 minute cache means viewing several
# vendors' news back-to-back fetches each fixed feed once, not once per
# vendor. Google News is cached per vendor name instead, since it's a search
# query rather than a fixed feed.
_CACHE_TTL_SECONDS = 900
_fixed_feed_cache: dict[str, tuple[float, list["NewsItem"]]] = {}
_google_news_cache: dict[str, tuple[float, list["NewsItem"]]] = {}

_USER_AGENT = "Mozilla/5.0 (compatible; TPRM-Platform/1.0; +internal risk monitoring tool)"


@dataclass
class NewsItem:
    title: str
    link: str
    source: str
    published_at: str | None
    description: str | None


def _strip_html(raw: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", raw)).strip()


async def _fetch_feed(source: str, url: str) -> list[NewsItem]:
    try:
        raw = await fetch_text(url, retries=1, headers={"User-Agent": _USER_AGENT})
    except Exception:
        logger.warning("news feed fetch failed for %s (%s)", source, url)
        return []

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        logger.warning("news feed parse failed for %s", source)
        return []

    items: list[NewsItem] = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        if not title or not link:
            continue
        description = (item.findtext("description") or "").strip()
        items.append(
            NewsItem(
                title=title,
                link=link,
                source=source,
                published_at=item.findtext("pubDate"),
                description=description[:300] or None,
            )
        )
    return items


async def _gather_all_fixed_feed_items() -> list[NewsItem]:
    now = time.time()
    cached = _fixed_feed_cache.get("all")
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    results = await asyncio.gather(*(_fetch_feed(source, url) for source, url in _FEEDS.items()))
    all_items = [item for feed_items in results for item in feed_items]
    _fixed_feed_cache["all"] = (now, all_items)
    return all_items


async def _fetch_google_news(vendor_name: str) -> list[NewsItem]:
    now = time.time()
    cached = _google_news_cache.get(vendor_name)
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    try:
        raw = await fetch_text(
            _GOOGLE_NEWS_SEARCH_URL,
            retries=1,
            headers={"User-Agent": _USER_AGENT},
            params={"q": vendor_name, "hl": "en-US", "gl": "US", "ceid": "US:en"},
        )
    except Exception:
        logger.warning("Google News search failed for %r", vendor_name)
        return []

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        logger.warning("Google News RSS parse failed for %r", vendor_name)
        return []

    items: list[NewsItem] = []
    for item in root.iter("item"):
        raw_title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        if not raw_title or not link:
            continue
        # Google News titles are "Article Title - Publisher Name".
        if " - " in raw_title:
            title, source = raw_title.rsplit(" - ", 1)
        else:
            title, source = raw_title, "Google News"
        description = _strip_html(item.findtext("description") or "")
        items.append(
            NewsItem(
                title=title.strip(),
                link=link,
                source=source.strip(),
                published_at=item.findtext("pubDate"),
                description=description[:300] or None,
            )
        )

    _google_news_cache[vendor_name] = (now, items)
    return items


def _dedupe_by_link(items: list[NewsItem]) -> list[NewsItem]:
    seen: set[str] = set()
    deduped = []
    for item in items:
        if item.link in seen:
            continue
        seen.add(item.link)
        deduped.append(item)
    return deduped


def parse_published_at(raw: str | None) -> datetime | None:
    """Parses an RSS pubDate (RFC 822) string. Public — reused wherever a raw
    published_at string needs to become a comparable datetime, including
    outside this module (e.g. sorting/filtering a cross-vendor news list in
    app/api/v1/dashboard.py)."""
    if not raw:
        return None
    try:
        parsed = parsedate_to_datetime(raw)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _recency_key(item: NewsItem) -> datetime:
    return parse_published_at(item.published_at) or datetime.min.replace(tzinfo=timezone.utc)


class NewsProvider:
    """Not one of the AssetDiscoveryProvider/etc. ABCs — this doesn't discover
    infrastructure or evaluate a security posture check, it's a keyword-
    filtered read over shared, cached feed/search data. Kept standalone, same
    as RDAPProvider.
    """

    name = "news"

    async def find_mentions(
        self,
        vendor_name: str,
        limit: int = 10,
        since: datetime | None = None,
    ) -> list[NewsItem]:
        pattern = re.compile(rf"\b{re.escape(vendor_name)}\b", re.IGNORECASE)

        fixed_items, google_items = await asyncio.gather(
            _gather_all_fixed_feed_items(), _fetch_google_news(vendor_name)
        )

        candidates = fixed_items + google_items
        matches = [
            item
            for item in candidates
            if pattern.search(item.title) or (item.description and pattern.search(item.description))
        ]

        if since is not None:
            # An item with no parseable date can't be confirmed to fall
            # inside the window, so it's excluded rather than assumed recent.
            matches = [item for item in matches if (parse_published_at(item.published_at) or datetime.min.replace(tzinfo=timezone.utc)) >= since]

        matches.sort(key=_recency_key, reverse=True)
        return _dedupe_by_link(matches)[:limit]
