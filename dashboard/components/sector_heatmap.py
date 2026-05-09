import re
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

BG_CARD  = "#0f1629"
BG_CARD2 = "#131c35"
ACCENT   = "#00d4ff"
BORDER   = "#1e2d50"
TEXT_DIM = "#7986a8"
TEXT_PRI = "#e8eaf6"
SEV_COLOR = {"Critical": "#ff2d55", "High": "#ff8800", "Medium": "#ffcc00", "Low": "#00cc66"}

SECTOR_ICONS = {
    "health": "🏥", "finance": "🏦", "government": "🏛️",
    "education": "🎓", "retail": "🛒", "legal": "⚖️",
    "insurance": "🛡️", "critical_infrastructure": "⚡",
    "technology": "💻", "other": "◆",
}

SECTOR_COLORS = {
    "health": "#ff2d55",
    "finance": "#ff8800",
    "government": "#bf5af2",
    "education": "#00d4ff",
    "retail": "#ffcc00",
    "legal": "#30d158",
    "insurance": "#64d2ff",
    "critical_infrastructure": "#ff6961",
    "technology": "#5e5ce6",
    "other": "#636366",
}


def _md(html: str) -> None:
    clean = re.sub(r'\n[ \t]*\n', '\n', html.strip())
    st.markdown(clean, unsafe_allow_html=True)


def _pill(n: int, hex_color: str) -> str:
    if n == 0:
        return ""
    return (
        f'<span style="background:{hex_color}22;color:{hex_color};border:1px solid {hex_color}44;'
        f"padding:1px 6px;border-radius:3px;font-size:0.65rem;font-family:'JetBrains Mono',monospace\">{n}</span>"
    )


def render(events: list[dict], oaic_data: list[dict]):
    _md(
        f'<div style="margin-bottom:1.25rem">'
        f'<div style="font-size:0.95rem;font-weight:600;color:{TEXT_PRI};margin-bottom:4px">Australian Sector Heatmap</div>'
        f'<div style="font-size:0.78rem;color:{TEXT_DIM}">Breach activity by industry sector — live feed events + OAIC Notifiable Data Breaches statistics. Health and Finance sectors consistently account for 35%+ of Australian NDB notifications.</div>'
        f'</div>'
    )

    sector_counts: dict[str, int] = {}
    for event in events:
        for sector in event.get("affected_sectors", []):
            sector_counts[sector] = sector_counts.get(sector, 0) + 1

    sector_sev: dict[str, dict] = {}
    for event in events:
        for sector in event.get("affected_sectors", []):
            if sector not in sector_sev:
                sector_sev[sector] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            sev = event.get("severity", "Medium")
            sector_sev[sector][sev] = sector_sev[sector].get(sev, 0) + 1

    col_heat, col_oaic = st.columns([3, 2])

    with col_heat:
        _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.75rem'>Live feed — sector breakdown</div>")

        if sector_counts:
            sorted_sectors = sorted(sector_counts.items(), key=lambda x: x[1], reverse=True)
            max_count = sorted_sectors[0][1] if sorted_sectors else 1

            for sector, total in sorted_sectors:
                sev_data = sector_sev.get(sector, {})
                critical_n = sev_data.get("Critical", 0)
                high_n = sev_data.get("High", 0)
                med_n = sev_data.get("Medium", 0)
                low_n = sev_data.get("Low", 0)
                bar_pct = int((total / max_count) * 100)
                icon = SECTOR_ICONS.get(sector, "◆")
                sector_label = sector.replace("_", " ").title()
                dominant_color = SECTOR_COLORS.get(sector, ACCENT)

                # Precompute all pill HTML — no blank lines possible in final f-string
                pills_html = (
                    _pill(critical_n, "#ff2d55") +
                    _pill(high_n, "#ff8800") +
                    _pill(med_n, "#ffcc00") +
                    _pill(low_n, "#00cc66")
                )

                _md(
                    f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:6px;padding:0.7rem 0.9rem;margin-bottom:6px">'
                    f'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">'
                    f'<div style="display:flex;align-items:center;gap:8px">'
                    f'<span style="font-size:1rem">{icon}</span>'
                    f'<span style="color:{TEXT_PRI};font-size:0.85rem;font-weight:500">{sector_label}</span>'
                    f'</div>'
                    f'<div style="display:flex;align-items:center;gap:4px">'
                    f'{pills_html}'
                    f'<span style="color:{TEXT_PRI};font-size:0.82rem;font-weight:600;font-family:\'JetBrains Mono\',monospace;margin-left:6px">{total}</span>'
                    f'</div>'
                    f'</div>'
                    f'<div style="background:{BORDER};border-radius:2px;height:4px;overflow:hidden">'
                    f'<div style="background:{dominant_color};width:{bar_pct}%;height:100%;border-radius:2px"></div>'
                    f'</div>'
                    f'</div>'
                )
        else:
            _md(f"<div style='color:{TEXT_DIM};padding:2rem;text-align:center'>No sector data in current filter range.</div>")

    with col_oaic:
        _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.75rem'>OAIC NDB — latest quarter</div>")

        if oaic_data:
            latest = sorted(oaic_data, key=lambda x: x.get("period", ""), reverse=True)[0]
            sectors_oaic = latest.get("sectors", {})
            period_label = latest.get("period_label", latest.get("period", ""))
            total_breaches = latest.get("total_breaches", 0)
            malicious_pct = latest.get("malicious_attacks_pct", 0)

            _md(
                f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:6px;padding:0.9rem;margin-bottom:0.75rem">'
                f'<div style="color:{TEXT_DIM};font-size:0.7rem;margin-bottom:4px">{period_label}</div>'
                f'<div style="display:flex;justify-content:space-between;align-items:center">'
                f'<div><div style="color:{ACCENT};font-size:1.8rem;font-weight:700;font-family:\'JetBrains Mono\',monospace">{total_breaches}</div>'
                f'<div style="color:{TEXT_DIM};font-size:0.7rem">NDB notifications</div></div>'
                f'<div style="text-align:right"><div style="color:#ff2d55;font-size:1.4rem;font-weight:700;font-family:\'JetBrains Mono\',monospace">{malicious_pct}%</div>'
                f'<div style="color:{TEXT_DIM};font-size:0.7rem">malicious attacks</div></div>'
                f'</div></div>'
            )

            sectors_filtered = {k: v for k, v in sectors_oaic.items() if k != "other" and v > 0}
            other_val = sectors_oaic.get("other", 0)
            labels = [s.title() for s in sectors_filtered.keys()] + ["Other"]
            values = list(sectors_filtered.values()) + [other_val]
            colors = [SECTOR_COLORS.get(s, "#636366") for s in sectors_filtered.keys()] + ["#636366"]

            fig = go.Figure(go.Pie(
                labels=labels, values=values, hole=0.6,
                marker=dict(colors=colors, line=dict(color=BG_CARD, width=2)),
                textinfo="label+percent",
                textfont=dict(size=10, color=TEXT_PRI),
                insidetextorientation="radial",
            ))
            fig.add_annotation(
                text="<b>OAIC</b><br>NDB Data",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=10, color=TEXT_DIM),
            )
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=0, r=0, t=0, b=0),
                height=250,
                showlegend=False,
                font=dict(family="Inter", color=TEXT_PRI),
            )
            st.plotly_chart(fig, use_container_width=True)

            breach_types = latest.get("top_breach_types", [])
            if breach_types:
                _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:6px;margin-top:0.5rem'>Top breach types</div>")
                for i, bt in enumerate(breach_types[:5], 1):
                    _md(
                        f'<div style="color:{TEXT_PRI};font-size:0.78rem;padding:3px 0;border-bottom:1px solid {BORDER}">'
                        f'<span style="color:{TEXT_DIM};font-family:\'JetBrains Mono\',monospace;font-size:0.7rem;margin-right:8px">{i:02d}</span>'
                        f'{bt}</div>'
                    )

            src_note = latest.get("source", "OAIC NDB Report")
            _md(f"<div style='color:{TEXT_DIM};font-size:0.65rem;margin-top:0.75rem'>Source: {src_note}</div>")

    if oaic_data and len(oaic_data) > 1:
        _md(f"<hr style='border-color:{BORDER};margin:1.5rem 0'>")
        _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.75rem'>OAIC sector trend — all periods</div>")

        trend_rows = []
        for stat in sorted(oaic_data, key=lambda x: x.get("period", "")):
            period_l = stat.get("period_label", stat.get("period", ""))
            for sector, count in stat.get("sectors", {}).items():
                if sector != "other":
                    trend_rows.append({"Period": period_l, "Sector": sector.title(), "Breaches": count})

        if trend_rows:
            trend_df = pd.DataFrame(trend_rows)
            fig2 = px.bar(
                trend_df, x="Period", y="Breaches", color="Sector",
                color_discrete_map={s.title(): c for s, c in SECTOR_COLORS.items()},
                barmode="group",
            )
            fig2.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter", color=TEXT_PRI, size=11),
                margin=dict(l=0, r=0, t=10, b=0),
                height=280,
                legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=10)),
                xaxis=dict(gridcolor=BORDER),
                yaxis=dict(gridcolor=BORDER, title="NDB Notifications"),
            )
            st.plotly_chart(fig2, use_container_width=True)
