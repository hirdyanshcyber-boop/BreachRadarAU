import re
import streamlit as st
import plotly.graph_objects as go


def _md(html: str) -> None:
    clean = re.sub(r'\n[ \t]*\n', '\n', html.strip())
    st.markdown(clean, unsafe_allow_html=True)


BG_CARD  = "#0f1629"
BG_CARD2 = "#131c35"
ACCENT   = "#00d4ff"
BORDER   = "#1e2d50"
TEXT_DIM = "#7986a8"
TEXT_PRI = "#e8eaf6"
SEV_COLOR = {"Critical": "#ff2d55", "High": "#ff8800", "Medium": "#ffcc00", "Low": "#00cc66"}

E8_META = {
    "patch_applications":        {"label": "Patch Applications",            "number": 1, "description": "Patch or mitigate security vulnerabilities in applications within appropriate timeframes.", "color": "#ff2d55"},
    "patch_os":                  {"label": "Patch Operating Systems",        "number": 2, "description": "Patch or mitigate security vulnerabilities in operating systems within appropriate timeframes.", "color": "#ff8800"},
    "multi_factor_auth":         {"label": "Multi-Factor Authentication",    "number": 3, "description": "MFA for remote access solutions, internet-facing services, and privileged accounts.", "color": "#ffcc00"},
    "restrict_admin_privileges": {"label": "Restrict Admin Privileges",      "number": 4, "description": "Restrict admin privileges to operating systems and applications based on user duties.", "color": "#30d158"},
    "application_control":       {"label": "Application Control",            "number": 5, "description": "Control the execution of executables, software libraries, scripts, and installers.", "color": "#00d4ff"},
    "restrict_macros":           {"label": "Restrict Microsoft Office Macros","number": 6, "description": "Block macros from internet, disable for users who do not require them.", "color": "#bf5af2"},
    "user_application_hardening":{"label": "User Application Hardening",    "number": 7, "description": "Configure browsers to block ads, disable Flash, Java, and web ads.", "color": "#5e5ce6"},
    "regular_backups":           {"label": "Regular Backups",                "number": 8, "description": "Backup data, software, and configuration settings; test restoration regularly.", "color": "#64d2ff"},
}


def render(events: list[dict]):
    _md(
        f'<div style="margin-bottom:1.25rem">'
        f'<div style="font-size:0.95rem;font-weight:600;color:{TEXT_PRI};margin-bottom:4px">Essential Eight Control Coverage</div>'
        f'<div style="font-size:0.78rem;color:{TEXT_DIM}">Each breach event is mapped to the ASD Essential Eight controls that would have prevented or reduced impact. Based on ACSC Essential Eight Maturity Model — the Australian standard for baseline cyber security.</div>'
        f'</div>'
    )

    control_counts: dict[str, int] = {k: 0 for k in E8_META}
    control_sev: dict[str, dict] = {k: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0} for k in E8_META}

    for event in events:
        for control in event.get("essential_eight_controls", []):
            if control in E8_META:
                control_counts[control] += 1
                sev = event.get("severity", "Medium")
                control_sev[control][sev] += 1

    sorted_controls = sorted(E8_META.keys(), key=lambda k: control_counts[k], reverse=True)
    max_count = max(control_counts.values()) if any(control_counts.values()) else 1

    radar_labels = [E8_META[k]["label"].replace(" ", "<br>") for k in sorted(E8_META.keys(), key=lambda k: E8_META[k]["number"])]
    radar_values = [control_counts[k] for k in sorted(E8_META.keys(), key=lambda k: E8_META[k]["number"])]

    chart_col, legend_col = st.columns([3, 2])

    with chart_col:
        fig = go.Figure()
        fig.add_trace(go.Scatterpolar(
            r=radar_values + [radar_values[0]],
            theta=radar_labels + [radar_labels[0]],
            fill="toself",
            fillcolor="rgba(0,212,255,0.13)",
            line=dict(color=ACCENT, width=2),
            marker=dict(color=ACCENT, size=7),
            name="Event count",
        ))
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            polar=dict(
                bgcolor="rgba(0,0,0,0)",
                radialaxis=dict(visible=True, gridcolor=BORDER, color=TEXT_DIM, tickfont=dict(size=9)),
                angularaxis=dict(gridcolor=BORDER, color=TEXT_DIM, tickfont=dict(size=9, color=TEXT_PRI)),
            ),
            font=dict(family="Inter", color=TEXT_PRI, size=10),
            margin=dict(l=60, r=60, t=40, b=40),
            height=380,
            showlegend=False,
            title=dict(text="Essential Eight — breach exposure map", font=dict(size=12, color=TEXT_DIM), x=0.5),
        )
        st.plotly_chart(fig, use_container_width=True)

    with legend_col:
        _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.75rem'>Highest exposure controls</div>")
        for control in sorted_controls[:4]:
            meta = E8_META[control]
            count = control_counts[control]
            if count == 0:
                continue
            color = meta["color"]
            pct = int((count / max_count) * 100)
            _md(
                f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-left:3px solid {color};'
                f'border-radius:6px;padding:0.75rem 0.9rem;margin-bottom:8px">'
                f'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">'
                f'<span style="color:{TEXT_PRI};font-size:0.82rem;font-weight:500">{meta["label"]}</span>'
                f'<span style="color:{color};font-size:1rem;font-weight:700;font-family:\'JetBrains Mono\',monospace">{count}</span>'
                f'</div>'
                f'<div style="background:{BORDER};border-radius:2px;height:3px;margin-bottom:6px">'
                f'<div style="background:{color};width:{pct}%;height:100%;border-radius:2px"></div>'
                f'</div>'
                f'<div style="font-size:0.68rem;color:{TEXT_DIM};line-height:1.4">{meta["description"]}</div>'
                f'</div>'
            )

    _md(f"<hr style='border-color:{BORDER};margin:1rem 0'>")
    _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.75rem'>All eight controls — event breakdown</div>")

    cols = st.columns(4)
    for i, control in enumerate(sorted(E8_META.keys(), key=lambda k: E8_META[k]["number"])):
        meta = E8_META[control]
        count = control_counts[control]
        sev_data = control_sev[control]
        color = meta["color"]

        # Precompute sev pills — no blank lines risk
        sev_row = "".join(
            f'<span style="background:{sc}22;color:{sc};border:1px solid {sc}44;'
            f"padding:1px 5px;border-radius:3px;font-size:0.62rem;margin-right:2px;font-family:'JetBrains Mono',monospace\">{sn}:{sv}</span>"
            for sn, sv, sc in [
                ("C", sev_data["Critical"], "#ff2d55"),
                ("H", sev_data["High"],     "#ff8800"),
                ("M", sev_data["Medium"],   "#ffcc00"),
                ("L", sev_data["Low"],      "#00cc66"),
            ]
            if sv > 0
        )

        border_col = f"{color}44" if count > 0 else BORDER
        top_col    = color if count > 0 else BORDER
        num_col    = color if count > 0 else TEXT_DIM
        lbl_col    = TEXT_PRI if count > 0 else TEXT_DIM

        with cols[i % 4]:
            _md(
                f'<div style="background:{BG_CARD};border:1px solid {border_col};border-top:2px solid {top_col};'
                f'border-radius:6px;padding:0.75rem;margin-bottom:8px;min-height:110px">'
                f'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">'
                f'<span style="color:{TEXT_DIM};font-size:0.65rem;font-family:\'JetBrains Mono\',monospace">E{meta["number"]}</span>'
                f'<span style="color:{num_col};font-size:1rem;font-weight:700;font-family:\'JetBrains Mono\',monospace">{count}</span>'
                f'</div>'
                f'<div style="color:{lbl_col};font-size:0.78rem;font-weight:500;margin-bottom:6px;line-height:1.3">{meta["label"]}</div>'
                f'<div>{sev_row}</div>'
                f'</div>'
            )

    _md(f"<hr style='border-color:{BORDER};margin:1rem 0'>")

    e8_active = sum(1 for c in E8_META if control_counts[c] > 0)
    critical_controls_hit = any(
        control_counts[c] > 0
        for c in ["patch_applications", "patch_os", "multi_factor_auth", "restrict_admin_privileges"]
    )

    if critical_controls_hit:
        rec_level, rec_color = "ML2 minimum", "#ff8800"
        rec_text = "Critical Essential Eight controls are being exploited in current breach data. Australian organisations should be targeting Maturity Level 2 or above for these controls as a minimum baseline."
    elif e8_active >= 4:
        rec_level, rec_color = "ML1 recommended", "#ffcc00"
        rec_text = "Multiple Essential Eight controls are represented in current breach data. Review Maturity Level 1 compliance across all eight controls."
    else:
        rec_level, rec_color = "Current posture adequate", "#00cc66"
        rec_text = "Low Essential Eight exposure in current breach data. Maintain existing controls and monitor for changes."

    _md(
        f'<div style="background:{rec_color}12;border:1px solid {rec_color}33;border-radius:6px;padding:0.9rem 1.1rem">'
        f'<div style="color:{rec_color};font-size:0.7rem;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:4px">ASD Maturity Recommendation</div>'
        f'<div style="color:{TEXT_PRI};font-size:0.85rem;font-weight:600;margin-bottom:4px">{rec_level}</div>'
        f'<div style="color:{TEXT_DIM};font-size:0.78rem;line-height:1.5">{rec_text}</div>'
        f'<div style="margin-top:6px"><a href="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model" target="_blank" style="color:{rec_color};font-size:0.72rem;text-decoration:none">↗ ACSC Essential Eight Maturity Model</a></div>'
        f'</div>'
    )
