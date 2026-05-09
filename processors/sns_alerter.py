"""
Sends SNS email alerts for Critical and High severity events.
Email formatted as a real security alert — sector context, Essential Eight controls, APRA flag.
"""
import json
import os
import boto3

SEVERITY_EMOJI = {
    "Critical": "🔴 CRITICAL",
    "High": "🟠 HIGH",
    "Medium": "🟡 MEDIUM",
    "Low": "🟢 LOW",
}

ESSENTIAL_EIGHT_LABELS = {
    "patch_applications": "Patch Applications",
    "patch_os": "Patch Operating Systems",
    "multi_factor_auth": "Multi-Factor Authentication",
    "restrict_admin_privileges": "Restrict Admin Privileges",
    "application_control": "Application Control",
    "restrict_macros": "Restrict Microsoft Office Macros",
    "user_application_hardening": "User Application Hardening",
    "regular_backups": "Regular Backups",
}


class SNSAlerter:
    def __init__(self):
        self.topic_arn = os.environ.get("SNS_ALERT_TOPIC_ARN")
        if not self.topic_arn:
            raise ValueError("SNS_ALERT_TOPIC_ARN not set")
        region = os.environ.get("AWS_REGION", "ap-southeast-2")
        self.client = boto3.client("sns", region_name=region)

    def should_alert(self, event: dict) -> bool:
        return event.get("severity") in ("Critical", "High")

    def send_alert(self, event: dict) -> bool:
        if not self.should_alert(event):
            return False

        severity = event.get("severity", "High")
        subject = f"[BreachRadarAU] {SEVERITY_EMOJI.get(severity, severity)}: {event.get('title', 'Security Event')[:80]}"

        e8_controls = event.get("essential_eight_controls", [])
        e8_formatted = "\n".join(
            f"  • {ESSENTIAL_EIGHT_LABELS.get(c, c)}" for c in e8_controls
        ) or "  • None identified"

        sectors = ", ".join(s.title() for s in event.get("affected_sectors", [])) or "Unspecified"
        mitre = ", ".join(event.get("mitre_techniques", [])) or "Not identified"

        apra_block = ""
        if event.get("apra_flagged"):
            apra_block = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  APRA CPS 234 FLAG
This event may affect an APRA-regulated entity.
Obligation: Notify APRA within 72 hours of becoming aware of a material information security incident.
Review your APRA notification obligations immediately.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

        privacy_act = event.get("privacy_act_obligation", "")
        privacy_block = f"\nPrivacy Act / NDB Obligation:\n  {privacy_act}\n" if privacy_act else ""

        au_impact = event.get("au_impact", "")
        au_block = f"\nAustralian Impact:\n  {au_impact}\n" if au_impact else ""

        body = f"""
════════════════════════════════════════════════════
BreachRadar AU — Security Alert
════════════════════════════════════════════════════

Severity:  {SEVERITY_EMOJI.get(severity, severity)}
Source:    {event.get('source', 'Unknown')}
Sectors:   {sectors}
Published: {event.get('published_at', 'Unknown')}
{apra_block}
SUMMARY
-------
{event.get('ai_summary', event.get('description', '')[:500])}
{au_block}
MITRE ATT&CK TECHNIQUES
------------------------
{mitre}

ESSENTIAL EIGHT CONTROLS RELEVANT
-----------------------------------
{e8_formatted}
{privacy_block}
RECOMMENDED ACTION
-------------------
{event.get('recommended_action', 'Review event and apply relevant controls.')}

SOURCE
------
{event.get('source_url', 'N/A')}

════════════════════════════════════════════════════
BreachRadar AU | Australian Cybersecurity Intelligence
Powered by ACSC • HIBP • CISA KEV • OAIC NDB
════════════════════════════════════════════════════
""".strip()

        try:
            self.client.publish(
                TopicArn=self.topic_arn,
                Subject=subject[:100],
                Message=body,
                MessageAttributes={
                    "severity": {
                        "DataType": "String",
                        "StringValue": severity,
                    },
                    "source": {
                        "DataType": "String",
                        "StringValue": event.get("source", "unknown"),
                    },
                },
            )
            return True
        except Exception:
            return False
