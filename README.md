# BreachRadar AU

> Real-time Australian cybersecurity breach intelligence — Essential Eight aligned, APRA CPS 234 aware, powered by Gemma 4.

BreachRadar AU monitors Australian and global cybersecurity breach feeds every 15 minutes, enriches every event with AI analysis mapped to the ASD Essential Eight and APRA CPS 234, and delivers plain-English alerts and a SOC-grade dashboard purpose-built for Australian organisations.

---

## Why this exists

In FY2024–25, the ACSC notified Australian organisations more than **1,700 times** of potentially malicious cyber activity — an **83% increase** year-on-year. The OAIC received **532 Notifiable Data Breach notifications** in just the first half of 2025 alone, with malicious attacks accounting for 59% of them.

No existing free tool aggregates Australian government security feeds alongside global sources, maps events to the Essential Eight, and flags APRA regulatory obligations in one place. BreachRadar AU fills that gap.

---

## Dashboard

Dark SOC-grade Streamlit dashboard — five views:

| View | What it shows |
|---|---|
| **Live Timeline** | All events sorted by date with severity, source, and AI analysis expandable per event |
| **Vendor Watch** | User-configured vendor list — flags any breach event mentioning a watched vendor |
| **AU Sector Heatmap** | Live event sector distribution + OAIC NDB quarterly statistics by industry |
| **Essential Eight** | Radar chart + control breakdown showing which ASD controls are most exposed |
| **APRA Tracker** | APRA-flagged events with 72-hour CPS 234 countdown + draft notification template |

---

## Australian data sources (what makes this different)

| Source | Feed | Cadence |
|---|---|---|
| **ACSC** | `cyber.gov.au/rss/alerts` + `/rss/advisories` | 15 min |
| **OAIC NDB** | Quarterly PDF reports — sector breach breakdown | Monthly |
| **HIBP** | `haveibeenpwned.com/api/v3/breaches` | 15 min |
| **CISA KEV** | `cisa.gov/known-exploited-vulnerabilities.json` | 15 min |

**ACSC** — Australian Signals Directorate's public advisory feed. Every alert the ASD publishes for actively exploited vulnerabilities and threats targeting Australian networks.

**OAIC NDB** — Office of the Australian Information Commissioner Notifiable Data Breaches scheme. Sector-level statistics showing which Australian industries are most affected each quarter.

---

## Sample alert (SNS email)

```
════════════════════════════════════════════════════
BreachRadar AU — Security Alert
════════════════════════════════════════════════════

Severity:  🔴 CRITICAL
Source:    ACSC
Sectors:   Government, Critical Infrastructure, Finance
Published: 2025-05-08T03:14:00+00:00

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  APRA CPS 234 FLAG
This event may affect an APRA-regulated entity.
Obligation: Notify APRA within 72 hours.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUMMARY
-------
ACSC confirmed active exploitation of a critical Fortinet FortiOS vulnerability
targeting Australian organisations. Attackers gain initial access without
authentication. Immediate patching to FortiOS 7.4.3+ is required.

MITRE ATT&CK TECHNIQUES
------------------------
T1190, T1133

ESSENTIAL EIGHT CONTROLS RELEVANT
-----------------------------------
  • Patch Applications
  • Patch Operating Systems

RECOMMENDED ACTION
-------------------
Patch all FortiOS devices immediately to version 7.4.3+. Review VPN logs for
anomalous authentication events. If compromise suspected, invoke your APRA CPS 234
notification process within 72 hours.
```

---

## Tech stack

```
AWS Lambda          — serverless collector, 15-min EventBridge trigger
AWS DynamoDB        — breach_events / oaic_stats / vendor_watchlist
AWS SNS             — Critical/High severity email alerts
Google AI API       — Gemma 4 (gemma-4-27b-it) enrichment
Streamlit           — SOC-grade dark dashboard
feedparser          — ACSC RSS ingestion
requests            — HIBP + CISA KEV API
PyMuPDF             — OAIC NDB PDF parsing
boto3               — AWS SDK
plotly              — Dark theme charts and radar plots
```

---

## Quick start

### 1. Clone and install

```bash
git clone https://github.com/yourusername/BreachRadarAU
cd BreachRadarAU
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — add AWS credentials, GOOGLE_AI_API_KEY, ALERT_EMAIL
```

### 3. Run dashboard locally (demo mode — no AWS required)

```bash
streamlit run dashboard/app.py
```

Toggle **Demo mode** in the sidebar to explore with sample breach data without any AWS setup.

### 4. Set up AWS infrastructure (production)

```bash
python infrastructure/setup_aws.py
```

Creates DynamoDB tables, SNS topic, and IAM role. Prints next steps for Lambda deployment.

### 5. Deploy Lambda

```bash
pip install -r requirements.txt -t package/
cp -r collectors processors lambda_handler.py package/
cd package && zip -r ../breach_radar.zip . && cd ..

aws lambda create-function \
  --function-name BreachRadarAU \
  --runtime python3.12 \
  --handler lambda_handler.handler \
  --role arn:aws:iam::ACCOUNT:role/BreachRadarAU-Lambda-Role \
  --zip-file fileb://breach_radar.zip \
  --timeout 300 \
  --memory-size 512 \
  --environment Variables="{GOOGLE_AI_API_KEY=...,SNS_ALERT_TOPIC_ARN=...}" \
  --region ap-southeast-2
```

---

## Architecture

```
EventBridge (15 min)
       │
       ▼
  Lambda handler
  ┌────────────────────────────────────┐
  │  collectors/acsc_rss.py           │  ← ACSC RSS alerts + advisories
  │  collectors/hibp.py               │  ← HIBP breach list
  │  collectors/cisa_kev.py           │  ← CISA Known Exploited Vulnerabilities
  │  collectors/oaic_scraper.py       │  ← OAIC NDB quarterly stats
  └────────────┬───────────────────────┘
               │ SHA-256 deduplicate
               ▼
  processors/gemma_enricher.py        ← Gemma 4: severity / MITRE / E8 / APRA
               │
       ┌───────┴────────┐
       ▼                ▼
  DynamoDB          SNS (Critical/High)
  breach_events     → email alert
  oaic_stats
  vendor_watchlist
       │
       ▼
  Streamlit dashboard
  (5 views, dark SOC UI)
```

---

## Australian regulatory context

**Essential Eight** — ASD's baseline cyber security controls for Australian organisations. Every breach event is tagged with which controls would have prevented or reduced impact.

**APRA CPS 234** — mandatory information security standard for Australian banks, insurers, and super funds. APRA-regulated entities must notify APRA within 72 hours of a material incident. The APRA tracker view generates a draft notification template per flagged event.

**Privacy Act 1988 / NDB scheme** — the OAIC administers mandatory breach notification for Australian organisations handling personal information. Non-compliance penalties reach AUD $50 million or 30% of adjusted turnover.

---

## Project structure

```
BreachRadarAU/
├── lambda_handler.py           # Lambda entry point
├── requirements.txt
├── .env.example
├── collectors/
│   ├── acsc_rss.py             # ACSC advisory RSS feed
│   ├── hibp.py                 # Have I Been Pwned API
│   ├── cisa_kev.py             # CISA KEV catalogue
│   └── oaic_scraper.py         # OAIC NDB statistics
├── processors/
│   ├── gemma_enricher.py       # Gemma 4 AI analysis
│   └── sns_alerter.py          # Email alerts
├── dashboard/
│   ├── app.py                  # Streamlit main app
│   ├── dynamo_client.py        # DynamoDB queries + demo data
│   └── components/
│       ├── timeline.py         # Live breach timeline
│       ├── vendor_watch.py     # Vendor monitoring
│       ├── sector_heatmap.py   # AU sector + OAIC heatmap
│       ├── essential_eight.py  # Essential Eight radar
│       └── apra_tracker.py     # APRA CPS 234 tracker
└── infrastructure/
    └── setup_aws.py            # One-time AWS setup
```

---

## Environment variables

| Variable | Description |
|---|---|
| `AWS_REGION` | AWS region (default: `ap-southeast-2`) |
| `DYNAMO_EVENTS_TABLE` | DynamoDB events table name |
| `DYNAMO_OAIC_TABLE` | DynamoDB OAIC stats table |
| `DYNAMO_VENDORS_TABLE` | DynamoDB vendor watchlist table |
| `GOOGLE_AI_API_KEY` | Google AI API key for Gemma 4 |
| `GEMMA_MODEL` | Model ID (default: `gemma-4-27b-it`) |
| `SNS_ALERT_TOPIC_ARN` | SNS topic ARN for email alerts |
| `HIBP_API_KEY` | HIBP API key (optional — public endpoint used if not set) |
| `ALERT_EMAIL` | Email to subscribe to SNS alerts |

---

*Built to demonstrate Australian cybersecurity intelligence tooling — ACSC, OAIC NDB, APRA CPS 234, and ASD Essential Eight integration.*
