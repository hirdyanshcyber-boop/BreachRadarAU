import hashlib
import feedparser
import requests
from datetime import datetime, timezone
from typing import Generator

ACSC_FEEDS = [
    "https://www.cyber.gov.au/rss/alerts",
    "https://www.cyber.gov.au/rss/advisories",
]

ACSC_SECTOR_KEYWORDS = {
    "health": ["hospital", "health", "medical", "aihw", "ahpra", "medicare"],
    "finance": ["bank", "financial", "apra", "asic", "super", "insurance"],
    "government": ["government", "ato", "defence", "parliament", "council"],
    "education": ["university", "school", "tafe", "education"],
    "critical_infrastructure": ["power", "water", "transport", "telco", "telecom"],
}

ESSENTIAL_EIGHT_KEYWORDS = {
    "patch_applications": ["patch", "unpatched", "cve", "vulnerability", "exploit"],
    "patch_os": ["operating system", "windows", "linux", "kernel", "os patch"],
    "multi_factor_auth": ["mfa", "2fa", "multi-factor", "authentication", "credential"],
    "restrict_admin": ["admin", "privilege", "lateral movement", "escalation"],
    "application_control": ["malware", "ransomware", "executable", "payload"],
    "restrict_macros": ["macro", "office", "excel", "word", "vba"],
    "user_application_hardening": ["browser", "javascript", "flash", "java", "pdf"],
    "regular_backups": ["backup", "ransomware", "data recovery", "restore"],
}


def _detect_sectors(text: str) -> list[str]:
    text_lower = text.lower()
    return [
        sector
        for sector, keywords in ACSC_SECTOR_KEYWORDS.items()
        if any(kw in text_lower for kw in keywords)
    ]


def _detect_essential_eight(text: str) -> list[str]:
    text_lower = text.lower()
    return [
        control
        for control, keywords in ESSENTIAL_EIGHT_KEYWORDS.items()
        if any(kw in text_lower for kw in keywords)
    ]


def _make_event_id(source_url: str, title: str, published: str) -> str:
    raw = f"{source_url}|{title}|{published}"
    return hashlib.sha256(raw.encode()).hexdigest()


def fetch() -> Generator[dict, None, None]:
    for feed_url in ACSC_FEEDS:
        try:
            feed = feedparser.parse(feed_url)
        except Exception:
            continue

        for entry in feed.entries:
            title = entry.get("title", "")
            link = entry.get("link", "")
            summary = entry.get("summary", entry.get("description", ""))
            published = entry.get("published", datetime.now(timezone.utc).isoformat())
            full_text = f"{title} {summary}"

            yield {
                "event_id": _make_event_id(feed_url, title, published),
                "source": "ACSC",
                "source_url": link,
                "title": title,
                "description": summary[:2000],
                "published_at": published,
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "severity_raw": _estimate_severity(full_text),
                "sectors": _detect_sectors(full_text),
                "essential_eight_hints": _detect_essential_eight(full_text),
                "apra_flagged": any(
                    kw in full_text.lower()
                    for kw in ["bank", "insurer", "super fund", "financial institution", "apra"]
                ),
                "enriched": False,
            }


def _estimate_severity(text: str) -> str:
    text_lower = text.lower()
    if any(w in text_lower for w in ["critical", "actively exploited", "ransomware", "emergency"]):
        return "Critical"
    if any(w in text_lower for w in ["high", "urgent", "significant", "widespread"]):
        return "High"
    if any(w in text_lower for w in ["medium", "moderate", "advisory"]):
        return "Medium"
    return "Low"
