import re
import streamlit as st

BG_CARD  = "#0f1629"
BG_CARD2 = "#131c35"
ACCENT   = "#00d4ff"
BORDER   = "#1e2d50"
TEXT_DIM = "#7986a8"
TEXT_PRI = "#e8eaf6"
SEV_COLOR = {"Critical": "#ff2d55", "High": "#ff8800", "Medium": "#ffcc00", "Low": "#00cc66"}

DEFAULT_VENDORS = [
    "Canvas", "Salesforce", "Microsoft", "Atlassian", "Okta",
    "Cisco", "Fortinet", "VMware", "ServiceNow", "Vimeo",
]


def _md(html: str) -> None:
    clean = re.sub(r'\n[ \t]*\n', '\n', html.strip())
    st.markdown(clean, unsafe_allow_html=True)


def _matches_vendor(event: dict, vendor: str) -> bool:
    vendor_lower = vendor.lower()
    fields = [
        event.get("title", ""),
        event.get("description", ""),
        event.get("ai_summary", ""),
        " ".join(event.get("vendor_mentions", [])),
        event.get("vendor", ""),
        event.get("product", ""),
    ]
    return any(vendor_lower in f.lower() for f in fields)


def render(events: list[dict], demo_mode: bool):
    _md(
        f'<div style="margin-bottom:1.25rem">'
        f'<div style="font-size:0.95rem;font-weight:600;color:{TEXT_PRI};margin-bottom:4px">Vendor Watch List</div>'
        f'<div style="font-size:0.78rem;color:{TEXT_DIM}">Monitor your SaaS and infrastructure vendors for breach events. Flagged events surface automatically when any watched vendor appears in breach data.</div>'
        f'</div>'
    )

    col_list, col_events = st.columns([1, 3])

    with col_list:
        _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.75rem'>Watched Vendors</div>")

        if "vendor_list" not in st.session_state:
            st.session_state.vendor_list = DEFAULT_VENDORS.copy()

        for vendor in st.session_state.vendor_list:
            hit_count = sum(1 for e in events if _matches_vendor(e, vendor))
            has_critical = any(
                _matches_vendor(e, vendor) and e.get("severity") == "Critical"
                for e in events
            )
            row_color = "#ff2d5518" if has_critical else BG_CARD
            border_color = "#ff2d5544" if has_critical else BORDER
            count_color = "#ff2d55" if has_critical else (ACCENT if hit_count > 0 else TEXT_DIM)
            _md(
                f'<div style="background:{row_color};border:1px solid {border_color};border-radius:5px;'
                f'padding:0.5rem 0.75rem;margin-bottom:5px;display:flex;align-items:center;justify-content:space-between">'
                f'<span style="color:{TEXT_PRI};font-size:0.82rem">{vendor}</span>'
                f'<span style="color:{count_color};font-size:0.78rem;font-weight:600;font-family:\'JetBrains Mono\',monospace">{hit_count}</span>'
                f'</div>'
            )

        st.markdown("<div style='margin-top:0.75rem'></div>", unsafe_allow_html=True)
        new_vendor = st.text_input("Add vendor", placeholder="e.g. Crowdstrike", label_visibility="collapsed", key="new_vendor_input")
        if st.button("＋ Add", key="add_vendor_btn"):
            if new_vendor and new_vendor not in st.session_state.vendor_list:
                st.session_state.vendor_list.append(new_vendor)
                st.rerun()

        if st.session_state.vendor_list:
            remove_sel = st.selectbox("Remove", ["— select —"] + st.session_state.vendor_list, label_visibility="collapsed", key="remove_vendor_sel")
            if st.button("✕ Remove", key="remove_vendor_btn") and remove_sel != "— select —":
                st.session_state.vendor_list.remove(remove_sel)
                st.rerun()

    with col_events:
        matched_events = []
        for event in events:
            matched = [v for v in st.session_state.vendor_list if _matches_vendor(event, v)]
            if matched:
                matched_events.append((event, matched))

        matched_events.sort(
            key=lambda x: ["Critical", "High", "Medium", "Low"].index(x[0].get("severity", "Low"))
        )

        if not matched_events:
            _md(
                f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:6px;'
                f'padding:3rem;text-align:center;color:{TEXT_DIM}">'
                f'<div style="font-size:1.5rem;margin-bottom:0.5rem">✓</div>'
                f'<div>No watched vendors found in current breach data.</div>'
                f'<div style="font-size:0.75rem;margin-top:0.5rem">Add vendors to your watch list to monitor them.</div>'
                f'</div>'
            )
        else:
            for event, matched_vendors in matched_events:
                sev = event.get("severity", "Medium")
                border_color = SEV_COLOR.get(sev, TEXT_DIM)
                vendor_pills = "".join(
                    f'<span style="background:{ACCENT}15;color:{ACCENT};border:1px solid {ACCENT}33;'
                    f'padding:1px 7px;border-radius:3px;font-size:0.68rem;font-weight:600">{v}</span>'
                    for v in matched_vendors
                )
                sev_pill = (
                    f'<span style="background:{border_color}22;color:{border_color};'
                    f'border:1px solid {border_color}55;padding:2px 8px;border-radius:3px;'
                    f"font-size:0.7rem;font-weight:600;font-family:'JetBrains Mono',monospace\">"
                    f'{sev.upper()}</span>'
                )
                summary = event.get("ai_summary", event.get("description", ""))[:250]
                action = event.get("recommended_action", "")
                action_block = (
                    f'<div style="margin-top:0.5rem;padding-top:0.5rem;border-top:1px solid {BORDER};'
                    f'color:#00cc66;font-size:0.75rem;line-height:1.5">'
                    f'<b style="color:#00cc66">Action:</b> {action[:200]}</div>'
                ) if action else ""

                _md(
                    f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-left:3px solid {border_color};'
                    f'border-radius:6px;padding:0.9rem 1rem;margin-bottom:8px">'
                    f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">'
                    f'{sev_pill}'
                    f'<span style="color:{TEXT_DIM};font-size:0.7rem">{event.get("source","")}</span>'
                    f'<span style="color:{TEXT_DIM};font-size:0.7rem">·</span>'
                    f'<span style="color:{TEXT_DIM};font-size:0.7rem">{event.get("published_at","")[:10]}</span>'
                    f'<span style="color:{TEXT_DIM};font-size:0.7rem">·</span>'
                    f'<span style="color:{TEXT_DIM};font-size:0.68rem">matched:</span>'
                    f'{vendor_pills}'
                    f'</div>'
                    f'<div style="color:{TEXT_PRI};font-size:0.85rem;font-weight:500;margin-bottom:6px">{event.get("title","")}</div>'
                    f'<div style="color:{TEXT_DIM};font-size:0.78rem;line-height:1.5">{summary}</div>'
                    f'{action_block}'
                    f'</div>'
                )
