# CTIR — Central Threat Intelligence Repository

End-to-end threat intelligence ingestion pipeline built with **FastAPI**, **MySQL**, and **ThreatFox** as the live feed.

```
ThreatFox API ──► Connector ──► Parser/Validator ──► Dedup Engine ──► MySQL (CTIR)
                                                                          │
                                                    FastAPI REST API ◄────┘
```

---

## Architecture

| Layer | File | Responsibility |
|---|---|---|
| **Feed Connector** | `app/services/connectors/threatfox.py` | Auth, HTTP retry, raw fetch, field mapping |
| **Parser** | `app/services/parsers/parser.py` | Schema validation, error collection |
| **Dedup Engine** | `app/services/deduplication/engine.py` | Idempotent upsert, conflict resolution |
| **Ingestion Service** | `app/services/ingestion_service.py` | Pipeline orchestration + job metrics |
| **Scheduler** | `app/core/scheduler.py` | APScheduler interval trigger |
| **API** | `app/api/routes/` | IOC CRUD, manual trigger, stats |
| **Models** | `app/models/models.py` | SQLAlchemy ORM |
| **Schema** | `app/schemas/schemas.py` | Pydantic models (NormalizedIoc + API) |
| **DB** | `app/db/database.py` | Async engine, session factory, health check |

---

## Quick Start

### 1. Prerequisites
- Docker + Docker Compose
- A free ThreatFox API key → https://threatfox.abuse.ch/api/

### 2. Configure
```bash
cp .env.example .env
# Edit .env — at minimum set THREATFOX_API_KEY
```

### 3. Start
```bash
docker compose up -d
```

The API is available at **http://localhost:8000**
Interactive docs: **http://localhost:8000/docs**

### 4. Trigger first ingestion manually
```bash
# Via API
curl -X POST http://localhost:8000/api/v1/ingestion/trigger

# Via convenience script
python scripts/trigger_ingestion.py
```

### 5. Run tests
```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## API Reference

### System
| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness + DB probe |
| `GET` | `/stats` | Aggregate IOC + job statistics |

### IOCs
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/iocs` | List IOCs (filterable, paginated) |
| `GET` | `/api/v1/iocs/{id}` | Get single IOC |
| `GET` | `/api/v1/iocs/search/{value}` | Search by IOC value |

**Query params for `/api/v1/iocs`:**
- `ioc_type` — `ip`, `domain`, `url`, `hash_md5`, `hash_sha256`, …
- `severity` — `critical`, `high`, `medium`, `low`, `info`
- `malware_family` — partial match
- `is_active` — `true` / `false`
- `page`, `page_size`

### Ingestion
| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/ingestion/trigger` | Manual run (async, 202) |
| `GET` | `/api/v1/ingestion/jobs` | List recent jobs |
| `GET` | `/api/v1/ingestion/jobs/{id}` | Job detail + metrics |

---

## CTIR Normalized Schema

Every feed record is mapped to this common shape before storage:

```json
{
  "ioc_value":      "192.168.1.1",
  "ioc_type":       "ip",
  "malware_family": "Emotet",
  "threat_type":    "botnet_cc",
  "confidence":     85,
  "severity":       "critical",
  "tags":           ["emotet", "botnet"],
  "source_ioc_id":  "tf-12345",
  "first_seen_at":  "2024-01-15T10:00:00Z",
  "last_seen_at":   "2024-01-16T12:00:00Z",
  "expires_at":     null
}
```

**Supported IOC types:** `ip`, `domain`, `url`, `hash_md5`, `hash_sha1`, `hash_sha256`, `email`, `filename`, `other`

---

## Deduplication Logic

- **Canonical key:** `SHA-256(ioc_type + ':' + lower(ioc_value))`
- **On collision:**
  - Keep **higher confidence** score
  - Keep **more severe** rating (`critical > high > medium > low > info`)
  - Update `last_seen_at` if newer
  - Merge tags (union, no duplicates)
  - Append to `merged_sources[]` for attribution (if not already present)
  - Increment `source_count`
- Re-running the same feed data produces **zero net-new rows** (idempotent).

---

## Ingestion Job Metrics

Each run records:

| Field | Description |
|---|---|
| `records_fetched` | Raw records from ThreatFox |
| `records_parsed` | Records passed to validator |
| `records_valid` | Passed schema validation |
| `records_invalid` | Failed validation (stored in `parse_errors`) |
| `records_new` | Net-new IOCs inserted |
| `records_updated` | Existing IOCs updated (conflict resolved) |
| `records_dupes` | Exact duplicates (no change needed) |
| `latency_ms` | Total pipeline wall-clock time |

---

## Database Schema

```
ioc_types        — lookup table: ip, domain, url, hash_*, email, filename, other
feeds            — registered feed sources (ThreatFox seeded on init)
iocs             — normalized, deduplicated IOC store (main table)
ingestion_jobs   — per-run metrics and status
parse_errors     — malformed records with structured error info
```

---

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `MYSQL_*` | see `.env.example` | DB credentials |
| `THREATFOX_API_KEY` | *(required)* | abuse.ch API key |
| `THREATFOX_QUERY_DAYS` | `1` | Days of history per ingestion run |
| `INGESTION_SCHEDULE_MINUTES` | `60` | Scheduler interval |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

---

## Extending with a Second Feed

1. Create `app/services/connectors/your_feed.py` implementing `fetch_recent()` and `normalize_record()`.
2. Insert a row into the `feeds` table.
3. Call `parse_and_validate(raw, connector.normalize_record)` → `DeduplicationEngine.bulk_upsert(valid)` — the rest of the pipeline is feed-agnostic.