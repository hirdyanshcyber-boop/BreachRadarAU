import re
import streamlit as st
import plotly.graph_objects as go
import pandas as pd

BG_CARD   = "#0f1629"
BG_CARD2  = "#131c35"
ACCENT    = "#00d4ff"
BORDER    = "#1e2d50"
TEXT_DIM  = "#7986a8"
TEXT_PRI  = "#e8eaf6"

SEV_COLOR = {"Critical": "#ff2d55", "High": "#ff8800", "Medium": "#ffcc00", "Low": "#00cc66"}
SOURCE_COLOR = {"ACSC": "#00d4ff", "HIBP": "#bf5af2", "CISA_KEV": "#ff8800", "OAIC": "#00cc66"}

ESSENTIAL_EIGHT_LABELS = {
    "patch_applications": "Patch Apps",
    "patch_os": "Patch OS",
    "multi_factor_auth": "MFA",
    "restrict_admin_privileges": "Restrict Admin",
    "application_control": "App Control",
    "restrict_macros": "Restrict Macros",
    "user_application_hardening": "App Hardening",
    "regular_backups": "Backups",
}


def _md(html: str) -> None:
    """Remove blank lines so the markdown parser never terminates an HTML block early."""
    clean = re.sub(r'\n[ \t]*\n', '\n', html.strip())
    st.markdown(clean, unsafe_allow_html=True)


def _sev_badge(s: str) -> str:
    c = SEV_COLOR.get(s, TEXT_DIM)
    return (f'<span style="background:{c}22;color:{c};border:1px solid {c}55;'
            f'padding:2px 8px;border-radius:3px;font-size:0.7rem;font-weight:600;'
            f"letter-spacing:0.05em;font-family:'JetBrains Mono',monospace\">{s.upper()}</span>")


def _src_badge(s: str) -> str:
    c = SOURCE_COLOR.get(s, TEXT_DIM)
    return (f'<span style="background:{c}18;color:{c};border:1px solid {c}40;'
            f'padding:2px 8px;border-radius:3px;font-size:0.68rem;font-weight:600;'
            f"letter-spacing:0.05em;font-family:'JetBrains Mono',monospace\">{s}</span>")


def render(events: list[dict]):
    if not events:
        _md(f"<div style='color:{TEXT_DIM};padding:3rem;text-align:center'>No events in selected range.</div>")
        return

    df = pd.DataFrame(events)
    df["date"] = pd.to_datetime(df["published_at"], errors="coerce", utc=True).dt.date

    chart_col, stat_col = st.columns([3, 1])

    with chart_col:
        sev_counts = df.groupby(["date", "severity"]).size().reset_index(name="count")
        fig = go.Figure()
        for sev, color in SEV_COLOR.items():
            d = sev_counts[sev_counts["severity"] == sev]
            if not d.empty:
                fig.add_trace(go.Scatter(
                    x=d["date"], y=d["count"],
                    name=sev, mode="lines+markers",
                    line=dict(color=color, width=2),
                    marker=dict(size=5),
                    fill="tozeroy",
                    fillcolor=_hex_rgba(color, 0.09),
                ))
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter", color=TEXT_PRI, size=11),
            margin=dict(l=0, r=0, t=30, b=0),
            height=200,
            title=dict(text="Event volume by severity", font=dict(size=12, color=TEXT_DIM), x=0),
            legend=dict(orientation="h", y=-0.15, bgcolor="rgba(0,0,0,0)"),
            xaxis=dict(gridcolor=BORDER, showgrid=True),
            yaxis=dict(gridcolor=BORDER, showgrid=True),
        )
        st.plotly_chart(fig, use_container_width=True)

    with stat_col:
        src_counts = df["source"].value_counts()
        fig2 = go.Figure(go.Pie(
            labels=src_counts.index.tolist(),
            values=src_counts.values.tolist(),
            hole=0.65,
            marker=dict(colors=[SOURCE_COLOR.get(s, ACCENT) for s in src_counts.index]),
            textinfo="none",
        ))
        fig2.add_annotation(
            text=f"<b>{len(events)}</b><br><span style='font-size:10px'>events</span>",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=18, color=TEXT_PRI),
        )
        fig2.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=30, b=0),
            height=200,
            title=dict(text="By source", font=dict(size=12, color=TEXT_DIM), x=0),
            showlegend=True,
            legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=10)),
            font=dict(family="Inter", color=TEXT_PRI),
        )
        st.plotly_chart(fig2, use_container_width=True)

    _md(f"<hr style='border-color:{BORDER};margin:0.5rem 0 1rem 0'>")

    for event in events:
        sev = event.get("severity", "Medium")
        src = event.get("source", "")
        title = event.get("title", "Untitled")
        published = event.get("published_at", "")[:10]
        apra = event.get("apra_flagged", False)
        au = event.get("au_relevant", False)
        e8 = event.get("essential_eight_controls", [])
        summary = event.get("ai_summary", event.get("description", ""))[:400]
        mitre = event.get("mitre_techniques", [])
        sectors = event.get("affected_sectors", [])
        action = event.get("recommended_action", "")
        au_impact = event.get("au_impact", "")

        # Precompute all conditional HTML fragments — NO blank lines in f-string
        e8_pills = "".join(
            f'<span style="background:#00d4ff15;color:{ACCENT};border:1px solid {ACCENT}33;'
            f'padding:1px 6px;border-radius:3px;font-size:0.65rem;margin-right:3px">'
            f'{ESSENTIAL_EIGHT_LABELS.get(c, c)}</span>'
            for c in e8[:4]
        )
        apra_pill = (
            '<span style="background:#bf5af222;color:#bf5af2;border:1px solid #bf5af244;'
            'padding:1px 6px;border-radius:3px;font-size:0.65rem;margin-left:4px">APRA</span>'
        ) if apra else ""
        au_pill = (
            '<span style="background:#00cc6618;color:#00cc66;border:1px solid #00cc6633;'
            'padding:1px 6px;border-radius:3px;font-size:0.65rem;margin-left:4px">AU</span>'
        ) if au else ""

        border_c = SEV_COLOR.get(sev, TEXT_DIM)
        summary_short = summary[:200] + ("…" if len(summary) > 200 else "")

        _md(
            f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-left:3px solid {border_c};'
            f'border-radius:6px;padding:0.85rem 1rem;margin-bottom:4px">'
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">'
            f'{_sev_badge(sev)}{_src_badge(src)}{apra_pill}{au_pill}'
            f'<span style="color:{TEXT_DIM};font-size:0.7rem;font-family:\'JetBrains Mono\',monospace">{published}</span>'
            f'</div>'
            f'<div style="color:{TEXT_PRI};font-size:0.88rem;font-weight:500;line-height:1.4;margin-bottom:6px">{title}</div>'
            f'<div style="color:{TEXT_DIM};font-size:0.78rem;line-height:1.5">{summary_short}</div>'
            f'<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:4px">{e8_pills}</div>'
            f'</div>'
        )

        with st.expander("▸ Full analysis", expanded=False):
            col_l, col_r = st.columns([3, 2])
            with col_l:
                if summary:
                    _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:6px'>AI Analysis</div>")
                    _md(f"<div style='color:{TEXT_PRI};font-size:0.82rem;line-height:1.6;background:{BG_CARD2};padding:0.75rem;border-radius:4px;border:1px solid {BORDER}'>{summary}</div>")
                if action:
                    _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin:0.75rem 0 6px 0'>Recommended Action</div>")
                    _md(f"<div style='color:{TEXT_PRI};font-size:0.82rem;line-height:1.6;background:{BG_CARD2};padding:0.75rem;border-radius:4px;border:1px solid {BORDER}'>{action}</div>")
                if au_impact:
                    _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin:0.75rem 0 6px 0'>Australian Impact</div>")
                    _md(f"<div style='color:#00cc66;font-size:0.82rem;line-height:1.6;background:#00cc6608;padding:0.75rem;border-radius:4px;border:1px solid #00cc6622'>{au_impact}</div>")

            with col_r:
                if mitre:
                    _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:6px'>MITRE ATT&CK</div>")
                    mitre_html = "".join(
                        f'<span style="background:#ff880018;color:#ff8800;border:1px solid #ff880033;'
                        f"padding:2px 8px;border-radius:3px;font-size:0.72rem;font-family:'JetBrains Mono',monospace;margin:2px\">{t}</span>"
                        for t in mitre
                    )
                    _md(mitre_html)
                if e8:
                    _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin:0.75rem 0 6px 0'>Essential Eight Controls</div>")
                    for c in e8:
                        label = ESSENTIAL_EIGHT_LABELS.get(c, c)
                        _md(f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px"><span style="color:{ACCENT};font-size:0.8rem">◉</span><span style="color:{TEXT_PRI};font-size:0.78rem">{label}</span></div>')
                if sectors:
                    _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin:0.75rem 0 6px 0'>Affected Sectors</div>")
                    sector_html = "".join(
                        f'<span style="background:{ACCENT}15;color:{ACCENT};border:1px solid {ACCENT}33;'
                        f'padding:2px 8px;border-radius:3px;font-size:0.7rem;margin:2px">{s.title()}</span>'
                        for s in sectors
                    )
                    _md(sector_html)
                url = event.get("source_url", "")
                if url:
                    _md(f"<div style='margin-top:0.75rem'><a href='{url}' target='_blank' style='color:{TEXT_DIM};font-size:0.72rem;text-decoration:none'>↗ Source</a></div>")


def _hex_rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"
