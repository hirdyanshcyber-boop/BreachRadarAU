"""
Enriches raw breach events with Gemma 4 via Google AI API.
Outputs structured analysis: severity, MITRE ATT&CK, Essential Eight, APRA flags.
"""
import json
import os
import re
import time
from tenacity import retry, stop_after_attempt, wait_exponential

import google.generativeai as genai

ESSENTIAL_EIGHT = [
    "patch_applications",
    "patch_os",
    "multi_factor_auth",
    "restrict_admin_privileges",
    "application_control",
    "restrict_macros",
    "user_application_hardening",
    "regular_backups",
]

APRA_SECTORS = ["banking", "insurance", "superannuation", "financial services", "credit union"]

ENRICHMENT_PROMPT = """You are a senior Australian cybersecurity analyst. Analyze this security event and return ONLY valid JSON.

EVENT:
Title: {title}
Source: {source}
Description: {description}

Return this exact JSON structure with no markdown, no commentary:
{{
  "severity": "<Critical|High|Medium|Low>",
  "mitre_techniques": ["<ATT&CK ID: T1xxx>"],
  "essential_eight_controls": ["<one or more: patch_applications|patch_os|multi_factor_auth|restrict_admin_privileges|application_control|restrict_macros|user_application_hardening|regular_backups>"],
  "summary": "<3-sentence plain English summary for an Australian organisation>",
  "recommended_action": "<1-paragraph specific action for an Australian IT team>",
  "apra_flagged": <true|false>,
  "privacy_act_obligation": "<relevant Privacy Act / NDB obligation or null>",
  "affected_sectors": ["<health|finance|government|education|retail|critical_infrastructure|technology|other>"],
  "vendor_mentions": ["<any vendor/product names mentioned>"],
  "au_impact": "<brief statement on Australian-specific impact or relevance>"
}}"""


class GemmaEnricher:
    def __init__(self):
        api_key = os.environ.get("GOOGLE_AI_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_AI_API_KEY not set")
        genai.configure(api_key=api_key)
        model_name = os.environ.get("GEMMA_MODEL", "gemma-4-27b-it")
        self.model = genai.GenerativeModel(model_name)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def enrich(self, event: dict) -> dict:
        prompt = ENRICHMENT_PROMPT.format(
            title=event.get("title", ""),
            source=event.get("source", ""),
            description=event.get("description", "")[:1500],
        )

        response = self.model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                max_output_tokens=1024,
            ),
        )

        raw = response.text.strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

        try:
            analysis = json.loads(raw)
        except json.JSONDecodeError:
            analysis = _fallback_analysis(event)

        return {
            **event,
            "severity": analysis.get("severity", event.get("severity_raw", "Medium")),
            "mitre_techniques": analysis.get("mitre_techniques", []),
            "essential_eight_controls": analysis.get("essential_eight_controls",
                                                      event.get("essential_eight_hints", [])),
            "ai_summary": analysis.get("summary", ""),
            "recommended_action": analysis.get("recommended_action", ""),
            "apra_flagged": analysis.get("apra_flagged", event.get("apra_flagged", False)),
            "privacy_act_obligation": analysis.get("privacy_act_obligation"),
            "affected_sectors": analysis.get("affected_sectors", event.get("sectors", [])),
            "vendor_mentions": analysis.get("vendor_mentions", []),
            "au_impact": analysis.get("au_impact", ""),
            "enriched": True,
            "enriched_at": _now_iso(),
        }


def _fallback_analysis(event: dict) -> dict:
    """Minimal fallback when Gemma call fails."""
    return {
        "severity": event.get("severity_raw", "Medium"),
        "mitre_techniques": [],
        "essential_eight_controls": event.get("essential_eight_hints", []),
        "summary": event.get("description", "")[:300],
        "recommended_action": "Review the event details and apply relevant Essential Eight controls.",
        "apra_flagged": event.get("apra_flagged", False),
        "privacy_act_obligation": None,
        "affected_sectors": event.get("sectors", []),
        "vendor_mentions": [],
        "au_impact": "",
    }


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
