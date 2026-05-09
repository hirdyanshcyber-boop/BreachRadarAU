import hashlib
import requests
from datetime import datetime, timezone
from typing import Generator

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

AU_VENDOR_RELEVANCE = [
    "microsoft", "cisco", "vmware", "fortinet", "citrix", "palo alto",
    "atlassian", "ivanti", "apache", "google", "apple", "adobe",
]


def _make_event_id(cve_id: str, date_added: str) -> str:
    raw = f"cisa_kev|{cve_id}|{date_added}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _au_relevance_score(vendor: str, product: str) -> bool:
    combined = f"{vendor} {product}".lower()
    return any(v in combined for v in AU_VENDOR_RELEVANCE)


def fetch() -> Generator[dict, None, None]:
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return

    vulnerabilities = data.get("vulnerabilities", [])
    # Only yield vulnerabilities added in the last 30 days to avoid re-ingesting old KEVs
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    for vuln in vulnerabilities:
        date_added_str = vuln.get("dateAdded", "")
        try:
            date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            date_added = datetime.now(timezone.utc)

        if date_added < cutoff:
            continue

        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        vuln_name = vuln.get("vulnerabilityName", "")
        description = vuln.get("shortDescription", "")
        due_date = vuln.get("dueDate", "")
        ransomware_use = vuln.get("knownRansomwareCampaignUse", "Unknown")

        severity = "Critical" if ransomware_use == "Known" else "High"
        title = f"[KEV] {cve_id} — {vendor} {product}: {vuln_name}"

        yield {
            "event_id": _make_event_id(cve_id, date_added_str),
            "source": "CISA_KEV",
            "source_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "title": title,
            "description": description[:2000],
            "published_at": date_added.isoformat(),
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "severity_raw": severity,
            "sectors": [],
            "essential_eight_hints": ["patch_applications"],
            "apra_flagged": False,
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "cisa_due_date": due_date,
            "ransomware_campaign": ransomware_use,
            "au_relevant": _au_relevance_score(vendor, product),
            "enriched": False,
        }
