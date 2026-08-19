```markdown
# CTI Feed Aggregator & Analytics Engine

A containerized Cyber Threat Intelligence (CTI) pipeline that ingests, correlates, enriches, and stores Indicators of Compromise (IoCs) from OSINT threat feeds. The system features real-time deduplication, a multi-source Threat Scoring algorithm, GeoIP infrastructure enrichment, PostgreSQL persistence, Telegram alert dispatching with alert fatigue prevention, and an on-demand SQL analytics CLI tool.

---

## Architecture

```text
  [ Feodo Tracker API ] ──┐
                          ├──> [ Ingestion & Normalization ] ──> [ GeoIP Lookup ]
  [ ThreatFox / Feed ]  ──┘                │
                                           ├──> [ PostgreSQL 15 ] (Stateful Persistence)
                                           ├──> [ Telegram Bot ]  (Threshold-based Alerts)
                                           └──> [ Analytics CLI ] (Aggregation Reports)

```

---

## Key Features

* **Multi-Feed Ingestion:** Ingests live malicious indicators from public OSINT feeds (Feodo Tracker, ThreatFox/Blocklist).
* **Correlation & Threat Scoring:** Deduplicates indicators across sources and calculates a dynamic Threat Score (0–100) based on source reliability and cross-feed correlation.
* **Data Enrichment:** Performs automated GeoIP lookups for country of origin and ISP/ASN mapping.
* **PostgreSQL Persistence:** Stores normalized data using `UPSERT` operations (`ON CONFLICT DO UPDATE`) with a notification tracking state to prevent alert fatigue.
* **Real-Time Alerting:** Automated Telegram push notifications for critical threats (Score >= 70) with deduplication check.
* **CLI Analytics Report:** Standalone tool (`analytics.py`) providing aggregated statistical metrics (average threat score, top threat countries).
* **Dual-Stream Logging:** Simultaneous console output and file-based audit trails (`cti_engine.log`).
* **Containerized Orchestration:** Multi-container deployment managed via Docker Compose.

---

## Tech Stack

* **Backend:** Python 3.10
* **Database:** PostgreSQL 15
* **Containerization:** Docker & Docker Compose
* **Libraries:** `requests`, `psycopg2-binary`, `schedule`, `python-dotenv`
* **External APIs:** Telegram Bot API, IP-API (GeoIP)

---

## Project Structure

```text
├── alerts.py         # Alert evaluation and Telegram dispatching
├── analytics.py      # Standalone CLI for SQL metrics and aggregation
├── config.py         # Application settings, source weights, and logging
├── database.py       # Database schema, connection handling, and UPSERT logic
├── enrichment.py     # Feed ingestion, GeoIP enrichment, and risk scoring
├── main.py           # Core execution loop and scheduler
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example

```

---

## Getting Started

### 1. Prerequisites

* Docker Desktop installed and running.
* A Telegram Bot token and Chat ID (for live alerts).

### 2. Configuration

Create a `.env` file in the project root:

```env
DB_HOST=db
DB_PORT=5432
DB_NAME=cti_db
DB_USER=cti_user
DB_PASSWORD=cti_password
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here

```

### 3. Build & Run

Start the multi-container stack:

```bash
docker-compose up --build

```

### 4. Run Analytics Report

Execute the standalone analytics tool inside the running Python container:

```bash
docker exec -it cti-python-app python analytics.py

```

### 5. Inspect the Database

Query PostgreSQL directly:

```bash
docker exec -it cti-postgres-db psql -U cti_user -d cti_db -c "\pset pager off" -c "SELECT * FROM iocs LIMIT 20;"

```

```

```