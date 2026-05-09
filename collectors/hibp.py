import hashlib
import requests
from datetime import datetime, timezone
from typing import Generator

HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"

AU_INDICATORS = [
    "australia", "australian", ".com.au", "commonwealth", "woolworths",
    "medibank", "optus", "telstra", "latitude", "myhealth", "mygovid",
    "services australia", "centrelink", "ato", "asic", "apra",
]


def _make_event_id(breach_name: str, breach_date: str) -> str:
    raw = f"hibp|{breach_name}|{breach_date}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _is_au_relevant(breach: dict) -> bool:
    searchable = " ".join([
        breach.get("Name", ""),
        breach.get("Title", ""),
        breach.get("Domain", ""),
        breach.get("Description", ""),
    ]).lower()
    return any(ind in searchable for ind in AU_INDICATORS)


def _estimate_severity(pwn_count: int, data_classes: list[str]) -> str:
    sensitive_classes = {"Passwords", "Financial data", "Credit cards", "Health records", "Government IDs"}
    has_sensitive = bool(sensitive_classes.intersection(set(data_classes)))

    if pwn_count > 10_000_000 or (has_sensitive and pwn_count > 1_000_000):
        return "Critical"
    if pwn_count > 1_000_000 or has_sensitive:
        return "High"
    if pwn_count > 100_000:
        return "Medium"
    return "Low"


def fetch(api_key: str | None = None) -> Generator[dict, None, None]:
    headers = {"User-Agent": "BreachRadarAU/1.0"}
    if api_key:
        headers["hibp-api-key"] = api_key

    try:
        resp = requests.get(HIBP_BREACHES_URL, headers=headers, timeout=30)
        resp.raise_for_status()
        breaches = resp.json()
    except Exception:
        return

    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    for breach in breaches:
        breach_date_str = breach.get("BreachDate", "")
        added_date_str = breach.get("AddedDate", "")

        try:
            added_date = datetime.fromisoformat(added_date_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue

        if added_date < cutoff:
            continue

        name = breach.get("Name", "")
        title = breach.get("Title", name)
        domain = breach.get("Domain", "")
        pwn_count = breach.get("PwnCount", 0)
        data_classes = breach.get("DataClasses", [])
        description = breach.get("Description", "")
        is_verified = breach.get("IsVerified", False)
        is_sensitive = breach.get("IsSensitive", False)

        severity = _estimate_severity(pwn_count, data_classes)
        if is_sensitive:
            severity = max(["Low", "Medium", "High", "Critical"],
                           key=["Low", "Medium", "High", "Critical"].index)

        au_relevant = _is_au_relevant(breach)
        if au_relevant and severity == "Medium":
            severity = "High"

        yield {
            "event_id": _make_event_id(name, breach_date_str),
            "source": "HIBP",
            "source_url": f"https://haveibeenpwned.com/PwnedWebsites#{name}",
            "title": f"[BREACH] {title} — {pwn_count:,} accounts exposed",
            "description": description[:2000],
            "published_at": added_date.isoformat(),
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "severity_raw": severity,
            "sectors": [],
            "essential_eight_hints": ["multi_factor_auth"] if "Passwords" in data_classes else [],
            "apra_flagged": au_relevant and any(
                kw in title.lower() for kw in ["bank", "finance", "super", "insurer"]
            ),
            "pwn_count": pwn_count,
            "data_classes": data_classes,
            "domain": domain,
            "breach_date": breach_date_str,
            "is_verified": is_verified,
            "au_relevant": au_relevant,
            "enriched": False,
        }
