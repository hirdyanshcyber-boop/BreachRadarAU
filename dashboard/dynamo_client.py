import os
import boto3
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime, timezone, timedelta
from typing import Optional

EVENTS_TABLE = os.environ.get("DYNAMO_EVENTS_TABLE", "breach_events")
OAIC_TABLE = os.environ.get("DYNAMO_OAIC_TABLE", "oaic_stats")
VENDORS_TABLE = os.environ.get("DYNAMO_VENDORS_TABLE", "vendor_watchlist")
AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-2")

_db = None


def _get_db():
    global _db
    if _db is None:
        _db = boto3.resource("dynamodb", region_name=AWS_REGION)
    return _db


def get_recent_events(days: int = 30, limit: int = 500) -> list[dict]:
    table = _get_db().Table(EVENTS_TABLE)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    resp = table.scan(
        FilterExpression=Attr("ingested_at").gte(cutoff),
        Limit=limit,
    )
    items = resp.get("Items", [])

    # Sort by published_at descending
    items.sort(key=lambda x: x.get("published_at", ""), reverse=True)
    return items


def get_events_by_severity(severity: str, days: int = 7) -> list[dict]:
    table = _get_db().Table(EVENTS_TABLE)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    resp = table.scan(
        FilterExpression=Attr("severity").eq(severity) & Attr("ingested_at").gte(cutoff),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: x.get("published_at", ""), reverse=True)
    return items


def get_apra_flagged(days: int = 7) -> list[dict]:
    table = _get_db().Table(EVENTS_TABLE)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    resp = table.scan(
        FilterExpression=Attr("apra_flagged").eq(True) & Attr("ingested_at").gte(cutoff),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: x.get("published_at", ""), reverse=True)
    return items


def get_oaic_stats() -> list[dict]:
    table = _get_db().Table(OAIC_TABLE)
    resp = table.scan()
    items = resp.get("Items", [])
    items.sort(key=lambda x: x.get("period", ""), reverse=True)
    return items


def get_vendor_watchlist() -> list[str]:
    table = _get_db().Table(VENDORS_TABLE)
    resp = table.scan()
    return [item["vendor_name"] for item in resp.get("Items", [])]


def add_vendor(vendor_name: str):
    table = _get_db().Table(VENDORS_TABLE)
    table.put_item(Item={
        "vendor_name": vendor_name,
        "added_at": datetime.now(timezone.utc).isoformat(),
    })


def remove_vendor(vendor_name: str):
    table = _get_db().Table(VENDORS_TABLE)
    table.delete_item(Key={"vendor_name": vendor_name})


def get_essential_eight_counts(days: int = 30) -> dict:
    events = get_recent_events(days=days)
    counts = {}
    for event in events:
        for control in event.get("essential_eight_controls", []):
            counts[control] = counts.get(control, 0) + 1
    return counts


def get_severity_counts(days: int = 30) -> dict:
    events = get_recent_events(days=days)
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for event in events:
        sev = event.get("severity", "Medium")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def get_source_counts(days: int = 30) -> dict:
    events = get_recent_events(days=days)
    counts = {}
    for event in events:
        src = event.get("source", "Unknown")
        counts[src] = counts.get(src, 0) + 1
    return counts


# Demo data for local dev / screenshots without live AWS
DEMO_EVENTS = [
    {
        "event_id": "demo001",
        "source": "ACSC",
        "title": "[CRITICAL] Active exploitation of Fortinet FortiOS SSL-VPN — Australian networks targeted",
        "description": "The ACSC has observed active exploitation of CVE-2024-21762 in Australian government and critical infrastructure networks.",
        "severity": "Critical",
        "published_at": "2025-05-08T03:14:00+00:00",
        "ingested_at": "2025-05-08T03:29:00+00:00",
        "affected_sectors": ["government", "critical_infrastructure", "finance"],
        "essential_eight_controls": ["patch_applications", "patch_os"],
        "mitre_techniques": ["T1190", "T1133"],
        "apra_flagged": True,
        "au_relevant": True,
        "ai_summary": "ACSC confirmed active exploitation of a critical Fortinet FortiOS vulnerability (CVE-2024-21762) targeting Australian organisations. Attackers are using the flaw to gain initial access without authentication. Immediate patching to FortiOS 7.4.3 or later is required.",
        "recommended_action": "Patch all FortiOS devices immediately to version 7.4.3+. Review VPN logs for anomalous authentication events since 1 January 2025. If compromise suspected, invoke your APRA CPS 234 notification process within 72 hours.",
        "au_impact": "Multiple Australian government agencies and financial institutions confirmed affected.",
        "enriched": True,
    },
    {
        "event_id": "demo002",
        "source": "HIBP",
        "title": "[BREACH] Medibank Private — 9,700,000 accounts exposed",
        "description": "Customer data including names, dates of birth, Medicare numbers, and health claim details were exfiltrated.",
        "severity": "Critical",
        "published_at": "2025-05-07T12:00:00+00:00",
        "ingested_at": "2025-05-07T12:15:00+00:00",
        "affected_sectors": ["health", "finance"],
        "essential_eight_controls": ["multi_factor_auth", "restrict_admin_privileges"],
        "mitre_techniques": ["T1078", "T1041"],
        "apra_flagged": True,
        "au_relevant": True,
        "pwn_count": 9700000,
        "ai_summary": "Medibank Private suffered a catastrophic data breach exposing health records of 9.7 million Australians. Stolen data includes sensitive Medicare and claims information. This is one of the largest Australian healthcare breaches on record.",
        "recommended_action": "If Medibank customer, monitor Medicare account for fraudulent claims. Organisations should review third-party health insurer data sharing arrangements and audit access controls.",
        "au_impact": "Largest Australian healthcare breach. Affects ~37% of the Australian population.",
        "enriched": True,
    },
    {
        "event_id": "demo003",
        "source": "CISA_KEV",
        "title": "[KEV] CVE-2025-21334 — Microsoft Windows Hyper-V: Privilege Escalation — Ransomware Campaign",
        "description": "Actively exploited in ransomware campaigns. Allows local attacker to gain SYSTEM privileges.",
        "severity": "High",
        "published_at": "2025-05-06T00:00:00+00:00",
        "ingested_at": "2025-05-06T00:30:00+00:00",
        "affected_sectors": ["government", "finance", "education"],
        "essential_eight_controls": ["patch_os", "restrict_admin_privileges"],
        "mitre_techniques": ["T1068", "T1486"],
        "apra_flagged": False,
        "au_relevant": True,
        "cve_id": "CVE-2025-21334",
        "vendor": "Microsoft",
        "product": "Windows Hyper-V",
        "ransomware_campaign": "Known",
        "cisa_due_date": "2025-05-20",
        "ai_summary": "Microsoft Windows Hyper-V privilege escalation vulnerability actively used in ransomware campaigns. Local attacker achieves SYSTEM privileges via integer overflow in the Hyper-V host partition driver. CISA mandates patching by 20 May 2025.",
        "recommended_action": "Apply Microsoft January 2025 Patch Tuesday updates immediately. Prioritise Hyper-V hosts running production workloads. Ensure backup integrity before patching.",
        "au_impact": "Widely deployed across Australian enterprise and government virtualisation infrastructure.",
        "enriched": True,
    },
    {
        "event_id": "demo004",
        "source": "ACSC",
        "title": "Advisory: BEC campaigns targeting Australian small-to-medium businesses — tax season surge",
        "description": "Increased business email compromise activity targeting Australian SMBs ahead of EOFY. Attackers impersonating ATO and accountants.",
        "severity": "High",
        "published_at": "2025-05-05T07:00:00+00:00",
        "ingested_at": "2025-05-05T07:20:00+00:00",
        "affected_sectors": ["finance", "retail", "legal"],
        "essential_eight_controls": ["multi_factor_auth", "user_application_hardening"],
        "mitre_techniques": ["T1566.002", "T1534"],
        "apra_flagged": False,
        "au_relevant": True,
        "ai_summary": "ACSC warns of surge in BEC attacks targeting Australian businesses ahead of end of financial year. Attackers impersonate the ATO and accounting firms to redirect payments. Losses averaging AUD $50,000 per incident.",
        "recommended_action": "Enable MFA on all email accounts. Implement call-back verification for payment instruction changes. Train staff on BEC indicators before EOFY period.",
        "au_impact": "Seasonal spike affects thousands of AU SMBs. EOFY period (May–July) is peak BEC season.",
        "enriched": True,
    },
    {
        "event_id": "demo005",
        "source": "ACSC",
        "title": "Advisory: Midnight Blizzard targeting Australian research institutions via Teams phishing",
        "description": "Russian state-sponsored actor Midnight Blizzard conducting Teams-based phishing against universities and defence research organisations.",
        "severity": "High",
        "published_at": "2025-05-04T01:00:00+00:00",
        "ingested_at": "2025-05-04T01:15:00+00:00",
        "affected_sectors": ["education", "government"],
        "essential_eight_controls": ["multi_factor_auth", "user_application_hardening", "patch_applications"],
        "mitre_techniques": ["T1566", "T1199", "T1078.004"],
        "apra_flagged": False,
        "au_relevant": True,
        "ai_summary": "Russian APT Midnight Blizzard is targeting Australian research institutions with Microsoft Teams-based social engineering attacks. Attackers pose as IT support staff to capture MFA tokens. University defence research programs are primary targets.",
        "recommended_action": "Restrict Teams external access to approved domains only. Enable phishing-resistant MFA (FIDO2). Audit Teams external communication logs for suspicious domains.",
        "au_impact": "Australian universities with defence research contracts at elevated risk. ASD Essential Eight Maturity Level 2 minimum recommended.",
        "enriched": True,
    },
    {
        "event_id": "demo006",
        "source": "HIBP",
        "title": "[BREACH] Canvas LMS — 826,000 accounts exposed",
        "description": "Educational platform Canvas suffered breach exposing student and educator login credentials.",
        "severity": "Medium",
        "published_at": "2025-05-03T09:00:00+00:00",
        "ingested_at": "2025-05-03T09:20:00+00:00",
        "affected_sectors": ["education"],
        "essential_eight_controls": ["multi_factor_auth"],
        "mitre_techniques": ["T1078"],
        "apra_flagged": False,
        "au_relevant": True,
        "pwn_count": 826000,
        "ai_summary": "Canvas LMS breach exposed credentials of 826,000 students and educators across 45 universities. Compromised data includes email addresses, password hashes, and course enrolment data. Australian universities using Canvas are directly affected.",
        "recommended_action": "Force password reset for all Canvas accounts. Enable MFA on Canvas. Notify affected students per Privacy Act NDB scheme if Australian university.",
        "au_impact": "Major Australian universities including UNSW, UoM, and ANU use Canvas as primary LMS.",
        "enriched": True,
    },
]
