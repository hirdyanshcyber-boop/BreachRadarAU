import re
import streamlit as st
from datetime import datetime, timezone

BG_CARD  = "#0f1629"
BG_CARD2 = "#131c35"
ACCENT   = "#00d4ff"
BORDER   = "#1e2d50"
TEXT_DIM = "#7986a8"
TEXT_PRI = "#e8eaf6"
APRA_COLOR = "#bf5af2"
WARN_COLOR = "#ff8800"
CRIT_COLOR = "#ff2d55"
OK_COLOR   = "#00cc66"

NOTIFICATION_TEMPLATE = """\
DRAFT APRA CPS 234 INCIDENT NOTIFICATION

To: APRA (notification@apra.gov.au)
Subject: CPS 234 Notification — [ENTITY NAME] — [DATE]

Dear APRA,

Pursuant to Section 36 of CPS 234 (Information Security), [ENTITY NAME] (ABN: [ABN])
notifies APRA of an information security incident as follows:

1. DATE/TIME OF DETECTION: [INSERT]
2. NATURE OF INCIDENT: {title}
3. SYSTEMS/DATA AFFECTED: [INSERT]
4. CUSTOMER IMPACT (actual or potential): [INSERT]
5. REGULATORY OBLIGATIONS: Privacy Act NDB scheme notification considered — [YES/NO]
6. IMMEDIATE CONTAINMENT ACTIONS TAKEN:
   - [INSERT]
7. ONGOING INVESTIGATION: [INSERT]
8. CONTACT PERSON: [Name, Title, Phone, Email]

This notification is provided within 72 hours of detection as required by CPS 234 s.36.

[AUTHORISED SIGNATORY]
[TITLE]
[ENTITY NAME]
[DATE]"""


def _md(html: str) -> None:
    clean = re.sub(r'\n[ \t]*\n', '\n', html.strip())
    st.markdown(clean, unsafe_allow_html=True)


def _hours_since(published_at: str) -> float | None:
    try:
        if published_at.endswith("Z"):
            published_at = published_at[:-1] + "+00:00"
        pub = datetime.fromisoformat(published_at)
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - pub).total_seconds() / 3600
    except Exception:
        return None


def _countdown_html(hours_elapsed: float) -> tuple[str, float]:
    remaining = max(0, 72.0 - hours_elapsed)
    pct_elapsed = min(100, int((hours_elapsed / 72.0) * 100))
    if remaining <= 0:
        color, status = CRIT_COLOR, "⚠ DEADLINE PASSED"
    elif remaining <= 12:
        color, status = CRIT_COLOR, f"⚠ {remaining:.0f}h remaining"
    elif remaining <= 24:
        color, status = WARN_COLOR, f"⚡ {remaining:.0f}h remaining"
    else:
        color, status = OK_COLOR, f"✓ {remaining:.0f}h remaining"
    html = (
        f'<div style="margin:6px 0">'
        f'<div style="display:flex;justify-content:space-between;margin-bottom:4px">'
        f'<span style="color:{TEXT_DIM};font-size:0.68rem">72-hour CPS 234 notification window</span>'
        f'<span style="color:{color};font-size:0.72rem;font-weight:600">{status}</span>'
        f'</div>'
        f'<div style="background:{BORDER};border-radius:3px;height:6px;overflow:hidden">'
        f'<div style="background:{color};width:{pct_elapsed}%;height:100%;border-radius:3px"></div>'
        f'</div>'
        f'</div>'
    )
    return html, remaining


def render(events: list[dict]):
    _md(
        f'<div style="margin-bottom:1.25rem">'
        f'<div style="font-size:0.95rem;font-weight:600;color:{TEXT_PRI};margin-bottom:4px">APRA CPS 234 Obligation Tracker</div>'
        f'<div style="font-size:0.78rem;color:{TEXT_DIM}">Breach events affecting APRA-regulated entities (banks, insurers, super funds). CPS 234 requires notification within 72 hours of awareness of a material incident.</div>'
        f'</div>'
    )

    apra_events = [e for e in events if e.get("apra_flagged")]

    col_events, col_info = st.columns([3, 2])

    with col_events:
        if not apra_events:
            _md(
                f'<div style="background:{OK_COLOR}12;border:1px solid {OK_COLOR}33;border-radius:6px;'
                f'padding:2.5rem;text-align:center">'
                f'<div style="color:{OK_COLOR};font-size:1.5rem;margin-bottom:0.5rem">✓</div>'
                f'<div style="color:{TEXT_PRI};font-size:0.88rem;margin-bottom:4px">No APRA-flagged events in current range</div>'
                f'<div style="color:{TEXT_DIM};font-size:0.75rem">Monitor continues — all data sources live</div>'
                f'</div>'
            )
        else:
            _md(
                f'<div style="background:{APRA_COLOR}18;border:1px solid {APRA_COLOR}44;border-radius:5px;'
                f'padding:0.6rem 0.9rem;margin-bottom:0.9rem;display:flex;align-items:center;gap:10px">'
                f'<span style="color:{APRA_COLOR};font-size:1rem">⚠</span>'
                f'<span style="color:{TEXT_PRI};font-size:0.82rem;font-weight:500">'
                f'{len(apra_events)} event{"s" if len(apra_events)!=1 else ""} may trigger APRA CPS 234 notification obligations</span>'
                f'</div>'
            )

            for event in apra_events:
                sev = event.get("severity", "High")
                sev_color = {"Critical": CRIT_COLOR, "High": WARN_COLOR, "Medium": "#ffcc00", "Low": OK_COLOR}.get(sev, TEXT_DIM)
                title = event.get("title", "")
                published = event.get("published_at", "")[:10]
                summary = event.get("ai_summary", event.get("description", ""))[:350]
                sectors = event.get("affected_sectors", [])
                action = event.get("recommended_action", "")
                privacy_ob = event.get("privacy_act_obligation", "")
                au_impact = event.get("au_impact", "")

                # Precompute all conditional HTML blocks
                hours_elapsed = _hours_since(event.get("published_at", ""))
                if hours_elapsed is not None:
                    c_html, remaining = _countdown_html(hours_elapsed)
                    if remaining <= 0 or remaining <= 12:
                        card_border, card_bg = CRIT_COLOR, f"{CRIT_COLOR}06"
                    elif remaining <= 24:
                        card_border, card_bg = WARN_COLOR, f"{WARN_COLOR}06"
                    else:
                        card_border, card_bg = APRA_COLOR, BG_CARD
                else:
                    c_html, card_border, card_bg = "", APRA_COLOR, BG_CARD

                sector_pills = "".join(
                    f'<span style="background:{ACCENT}15;color:{ACCENT};border:1px solid {ACCENT}33;'
                    f'padding:1px 6px;border-radius:3px;font-size:0.65rem">{s.title()}</span>'
                    for s in sectors
                )
                sectors_block = f'<div style="margin-top:6px">{sector_pills}</div>' if sectors else ""
                action_block = (
                    f'<div style="margin-top:8px;padding-top:8px;border-top:1px solid {BORDER};'
                    f'color:{OK_COLOR};font-size:0.75rem;line-height:1.5">'
                    f'<b style="color:{OK_COLOR}">Recommended action:</b> {action[:250]}</div>'
                ) if action else ""
                privacy_block = (
                    f'<div style="margin-top:6px;color:{APRA_COLOR};font-size:0.73rem">'
                    f'<b>Privacy Act:</b> {privacy_ob}</div>'
                ) if privacy_ob else ""
                au_block = (
                    f'<div style="margin-top:6px;color:{WARN_COLOR};font-size:0.73rem">'
                    f'<b>AU impact:</b> {au_impact}</div>'
                ) if au_impact else ""

                _md(
                    f'<div style="background:{card_bg};border:1px solid {card_border}66;border-left:3px solid {card_border};'
                    f'border-radius:6px;padding:0.9rem 1rem;margin-bottom:10px">'
                    f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
                    f'<span style="background:{sev_color}22;color:{sev_color};border:1px solid {sev_color}55;'
                    f'padding:2px 8px;border-radius:3px;font-size:0.68rem;font-weight:600;font-family:\'JetBrains Mono\',monospace">{sev.upper()}</span>'
                    f'<span style="background:{APRA_COLOR}22;color:{APRA_COLOR};border:1px solid {APRA_COLOR}44;'
                    f'padding:2px 8px;border-radius:3px;font-size:0.68rem;font-weight:600">APRA CPS 234</span>'
                    f'<span style="color:{TEXT_DIM};font-size:0.7rem;font-family:\'JetBrains Mono\',monospace">{published}</span>'
                    f'</div>'
                    f'<div style="color:{TEXT_PRI};font-size:0.85rem;font-weight:500;margin-bottom:6px">{title}</div>'
                    f'{c_html}'
                    f'<div style="color:{TEXT_DIM};font-size:0.78rem;line-height:1.5;margin-top:6px">{summary}</div>'
                    f'{sectors_block}'
                    f'{action_block}'
                    f'{privacy_block}'
                    f'{au_block}'
                    f'</div>'
                )

                with st.expander("▸ Generate draft CPS 234 notification"):
                    draft = NOTIFICATION_TEMPLATE.format(title=title)
                    st.code(draft, language="text")
                    _md(f"<div style='color:{TEXT_DIM};font-size:0.72rem'>⚠ Draft template only. Have your legal/compliance team review before submission. Notify APRA at notification@apra.gov.au</div>")

    with col_info:
        _md(
            f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:6px;padding:1rem;margin-bottom:0.75rem">'
            f'<div style="color:{APRA_COLOR};font-size:0.7rem;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.75rem">CPS 234 Key Obligations</div>'
            f'<div style="color:{TEXT_PRI};font-size:0.78rem;line-height:1.8">'
            f'<div style="display:flex;gap:8px;margin-bottom:6px"><span style="color:{CRIT_COLOR};font-weight:700;min-width:28px">72h</span><span style="color:{TEXT_DIM}">Notify APRA after material incident (s.36)</span></div>'
            f'<div style="display:flex;gap:8px;margin-bottom:6px"><span style="color:{WARN_COLOR};font-weight:700;min-width:28px">10d</span><span style="color:{TEXT_DIM}">Notify APRA of exploitable control weakness (s.37)</span></div>'
            f'<div style="display:flex;gap:8px;margin-bottom:6px"><span style="color:{OK_COLOR};font-weight:700;min-width:28px">∞</span><span style="color:{TEXT_DIM}">Maintain IS policy framework proportionate to risk (s.29)</span></div>'
            f'</div></div>'
        )
        _md(
            f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:6px;padding:1rem;margin-bottom:0.75rem">'
            f'<div style="color:{APRA_COLOR};font-size:0.7rem;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.75rem">Who Is Regulated</div>'
            f'<div style="font-size:0.77rem;color:{TEXT_DIM};line-height:1.7">'
            f'<div>◉ <span style="color:{TEXT_PRI}">ADIs</span> — authorised deposit-taking institutions (banks, credit unions)</div>'
            f'<div>◉ <span style="color:{TEXT_PRI}">General insurers</span> and life insurers</div>'
            f'<div>◉ <span style="color:{TEXT_PRI}">RSE licensees</span> — superannuation fund trustees</div>'
            f'<div>◉ <span style="color:{TEXT_PRI}">Private health insurers</span></div>'
            f'<div>◉ <span style="color:{TEXT_PRI}">Third parties</span> — material service providers to regulated entities</div>'
            f'</div></div>'
        )
        _md(
            f'<div style="background:{CRIT_COLOR}08;border:1px solid {CRIT_COLOR}33;border-radius:6px;padding:1rem">'
            f'<div style="color:{CRIT_COLOR};font-size:0.7rem;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.5rem">Non-Compliance Exposure</div>'
            f'<div style="color:{TEXT_PRI};font-size:1rem;font-weight:700;font-family:\'JetBrains Mono\',monospace">AUD $50M</div>'
            f'<div style="color:{TEXT_DIM};font-size:0.72rem;margin-top:2px">or 30% of adjusted turnover<br>Privacy Act non-compliance penalty</div>'
            f'<div style="margin-top:0.75rem"><a href="https://www.apra.gov.au/information-security" target="_blank" style="color:{APRA_COLOR};font-size:0.72rem;text-decoration:none">↗ APRA CPS 234 Guidance</a></div>'
            f'</div>'
        )
