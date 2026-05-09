import os
import re
import sys
from datetime import datetime, timezone

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.dynamo_client import (
    get_recent_events, get_oaic_stats,
    get_vendor_watchlist, add_vendor, remove_vendor,
    DEMO_EVENTS,
)
from collectors.oaic_scraper import KNOWN_STATS

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="BreachRadar AU",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme ─────────────────────────────────────────────────────────────────────
BG_BASE      = "#0a0e1a"
BG_CARD      = "#0f1629"
BG_CARD2     = "#131c35"
ACCENT_CYAN  = "#00d4ff"
ACCENT_GREEN = "#00cc66"
SEV_CRITICAL = "#ff2d55"
SEV_HIGH     = "#ff8800"
SEV_MEDIUM   = "#ffcc00"
SEV_LOW      = "#00cc66"
TEXT_PRIMARY = "#e8eaf6"
TEXT_DIM     = "#7986a8"
BORDER       = "#1e2d50"


def _md(html: str) -> None:
    """Strip blank/whitespace-only lines before passing to st.markdown.
    Prevents CommonMark parser from terminating HTML blocks at blank lines."""
    clean = re.sub(r'\n[ \t]*\n', '\n', html.strip())
    st.markdown(clean, unsafe_allow_html=True)


# ── Global CSS ────────────────────────────────────────────────────────────────
# <style> blocks are HTML type 1 — safe to use triple-quote here
st.markdown(f"""<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  html, body, [class*="css"] {{ font-family: 'Inter', sans-serif; background-color: {BG_BASE}; color: {TEXT_PRIMARY}; }}
  .main .block-container {{ background-color: {BG_BASE}; padding: 1.5rem 2rem 3rem 2rem; max-width: 100%; }}
  [data-testid="stSidebar"] {{ background-color: {BG_CARD} !important; border-right: 1px solid {BORDER}; }}
  [data-testid="stSidebar"] * {{ color: {TEXT_PRIMARY} !important; }}
  [data-testid="stSidebarNav"] {{ display: none; }}
  #MainMenu, footer, header {{ visibility: hidden; }}
  .stDeployButton {{ display: none; }}
  .stTabs [data-baseweb="tab-list"] {{ background-color: {BG_CARD}; border-bottom: 1px solid {BORDER}; gap: 0; }}
  .stTabs [data-baseweb="tab"] {{ background-color: transparent; color: {TEXT_DIM}; border: none; padding: 0.75rem 1.5rem; font-size: 0.85rem; font-weight: 500; letter-spacing: 0.03em; }}
  .stTabs [aria-selected="true"] {{ color: {ACCENT_CYAN} !important; border-bottom: 2px solid {ACCENT_CYAN} !important; background-color: transparent !important; }}
  .stTabs [data-baseweb="tab-panel"] {{ background-color: {BG_BASE}; padding: 1.5rem 0; }}
  .stButton > button {{ background-color: transparent; border: 1px solid {BORDER}; color: {TEXT_PRIMARY}; border-radius: 4px; font-size: 0.8rem; padding: 0.4rem 1rem; }}
  .stButton > button:hover {{ border-color: {ACCENT_CYAN}; color: {ACCENT_CYAN}; background-color: rgba(0,212,255,0.06); }}
  .stTextInput > div > div > input, .stSelectbox > div > div > div, .stMultiSelect > div > div > div {{ background-color: {BG_CARD2} !important; border: 1px solid {BORDER} !important; color: {TEXT_PRIMARY} !important; border-radius: 4px !important; }}
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: {BG_BASE}; }}
  ::-webkit-scrollbar-thumb {{ background: {BORDER}; border-radius: 3px; }}
  hr {{ border-color: {BORDER}; margin: 1.5rem 0; }}
  [data-testid="stExpander"] {{ background-color: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 6px; }}
  [data-testid="stExpander"] summary {{ color: {TEXT_PRIMARY}; }}
</style>""", unsafe_allow_html=True)


# ── KPI card helper ───────────────────────────────────────────────────────────
def kpi_card(label: str, value: str, sub: str = "", color: str = ACCENT_CYAN) -> str:
    return (
        f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-top:2px solid {color};'
        f'border-radius:6px;padding:1.1rem 1.25rem;min-height:90px">'
        f'<div style="color:{TEXT_DIM};font-size:0.7rem;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.5rem">{label}</div>'
        f'<div style="color:{color};font-size:1.9rem;font-weight:700;font-family:\'JetBrains Mono\',monospace;line-height:1">{value}</div>'
        f'<div style="color:{TEXT_DIM};font-size:0.72rem;margin-top:0.4rem">{sub}</div>'
        f'</div>'
    )


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    _md(
        f'<div style="padding:1rem 0 1.5rem 0">'
        f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:0.25rem">'
        f'<div style="width:8px;height:8px;border-radius:50%;background:{SEV_CRITICAL};box-shadow:0 0 8px {SEV_CRITICAL}"></div>'
        f'<span style="font-size:0.65rem;color:{SEV_CRITICAL};letter-spacing:0.12em;font-weight:600">LIVE</span>'
        f'</div>'
        f'<div style="font-size:1.3rem;font-weight:700;color:{TEXT_PRIMARY};letter-spacing:-0.01em">'
        f'BreachRadar <span style="color:{ACCENT_CYAN}">AU</span></div>'
        f'<div style="font-size:0.7rem;color:{TEXT_DIM};margin-top:2px">Australian Cyber Intelligence</div>'
        f'</div>'
    )

    demo_mode = st.toggle("Demo mode (no AWS required)", value=True)
    _md(f"<div style='color:{TEXT_DIM};font-size:0.7rem;margin-top:-0.5rem;margin-bottom:1rem'>Uses sample breach data</div>")

    _md(f"<div style='color:{TEXT_DIM};font-size:0.65rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.5rem'>Filters</div>")
    filter_days = st.selectbox("Time range", [7, 14, 30, 90], index=2, format_func=lambda x: f"Last {x} days")
    filter_severity = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
    filter_sources = st.multiselect("Sources", ["ACSC", "HIBP", "CISA_KEV"], default=["ACSC", "HIBP", "CISA_KEV"])

    st.markdown("---")
    _md(
        f'<div style="font-size:0.65rem;color:{TEXT_DIM}">'
        f'<div style="margin-bottom:4px"><span style="color:{ACCENT_CYAN}">●</span> ACSC RSS — 15 min</div>'
        f'<div style="margin-bottom:4px"><span style="color:#bf5af2">●</span> HIBP API — 15 min</div>'
        f'<div style="margin-bottom:4px"><span style="color:{SEV_HIGH}">●</span> CISA KEV — 15 min</div>'
        f'<div style="margin-bottom:4px"><span style="color:{ACCENT_GREEN}">●</span> OAIC NDB — monthly</div>'
        f'</div>'
    )
    st.markdown("---")
    _md(f"<div style='color:{TEXT_DIM};font-size:0.65rem'>Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>")


# ── Load data ─────────────────────────────────────────────────────────────────
@st.cache_data(ttl=300)
def load_events(demo: bool, days: int) -> list[dict]:
    if demo:
        return DEMO_EVENTS
    try:
        return get_recent_events(days=days)
    except Exception:
        return DEMO_EVENTS


@st.cache_data(ttl=300)
def load_oaic(demo: bool) -> list[dict]:
    if demo:
        return list(KNOWN_STATS.values())
    try:
        return get_oaic_stats()
    except Exception:
        return list(KNOWN_STATS.values())


events = load_events(demo_mode, filter_days)
events = [e for e in events if e.get("severity") in filter_severity and e.get("source") in filter_sources]
oaic_data = load_oaic(demo_mode)


# ── Header ────────────────────────────────────────────────────────────────────
_md(
    f'<div style="display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid {BORDER};padding-bottom:1.25rem;margin-bottom:1.5rem">'
    f'<div>'
    f'<h1 style="margin:0;font-size:1.6rem;font-weight:700;color:{TEXT_PRIMARY}">Security Intelligence Dashboard</h1>'
    f'<div style="color:{TEXT_DIM};font-size:0.8rem;margin-top:4px">Australian threat landscape · Essential Eight · APRA CPS 234 · NDB Scheme</div>'
    f'</div>'
    f'<div style="display:flex;gap:8px;align-items:center">'
    f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:4px;padding:6px 12px;font-size:0.7rem;color:{TEXT_DIM}">Region: <span style="color:{ACCENT_CYAN}">ap-southeast-2</span></div>'
    f'<div style="background:{SEV_CRITICAL}18;border:1px solid {SEV_CRITICAL}44;border-radius:4px;padding:6px 12px;font-size:0.7rem;color:{SEV_CRITICAL};font-weight:600">● LIVE MONITOR</div>'
    f'</div>'
    f'</div>'
)


# ── KPI row ───────────────────────────────────────────────────────────────────
critical_count = sum(1 for e in events if e.get("severity") == "Critical")
high_count     = sum(1 for e in events if e.get("severity") == "High")
apra_count     = sum(1 for e in events if e.get("apra_flagged"))
au_count       = sum(1 for e in events if e.get("au_relevant", True))
e8_events      = sum(1 for e in events if e.get("essential_eight_controls"))

k1, k2, k3, k4, k5 = st.columns(5)
with k1:
    _md(kpi_card("Critical Events", str(critical_count), f"Last {filter_days} days", SEV_CRITICAL))
with k2:
    _md(kpi_card("High Severity",   str(high_count),     f"Last {filter_days} days", SEV_HIGH))
with k3:
    _md(kpi_card("APRA Flagged",    str(apra_count),     "72-hr notification risk",  "#bf5af2"))
with k4:
    _md(kpi_card("AU-Relevant",     str(au_count),       f"of {len(events)} total events", ACCENT_CYAN))
with k5:
    _md(kpi_card("Essential Eight", str(e8_events),      "Events with E8 mapping",   ACCENT_GREEN))

st.markdown("<div style='margin-top:1.5rem'></div>", unsafe_allow_html=True)


# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "  📡  Live Timeline  ",
    "  🏢  Vendor Watch  ",
    "  🗺️  AU Sector Heatmap  ",
    "  🛡️  Essential Eight  ",
    "  ⚖️  APRA Tracker  ",
])

with tab1:
    from dashboard.components.timeline import render
    render(events)

with tab2:
    from dashboard.components.vendor_watch import render
    render(events, demo_mode)

with tab3:
    from dashboard.components.sector_heatmap import render
    render(events, oaic_data)

with tab4:
    from dashboard.components.essential_eight import render
    render(events)

with tab5:
    from dashboard.components.apra_tracker import render
    render(events)
