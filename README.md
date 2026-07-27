<div align="center">

# Advanced Proxy Scraper v3.0

### The Definitive Python Proxy Intelligence Platform

Async pipeline architecture · Concurrent source fetching · Decoupled enrichment · SQLite persistence · Proxy rotation API · Background health monitoring · CLI + GUI

[Features](#-features) · [Quick Start](#-quick-start) · [CLI Reference](#-cli-reference) · [Rotation API](#-proxy-rotation-api) · [Architecture](#-architecture) · [Configuration](#-configuration) · [Scoring](#-quality-scoring-system)

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-3.0-39ff88)
![Sources](https://img.shields.io/badge/Sources-80+-44aaff)
![Protocols](https://img.shields.io/badge/Protocols-HTTP%20%7C%20HTTPS%20%7C%20SOCKS4%20%7C%20SOCKS5-19c56b)

</div>

---

## Overview

Advanced Proxy Scraper v3.0 is a production-grade proxy collection, validation, and intelligence system written in pure Python. It aggregates proxies from **80+ public sources**, validates them through a high-concurrency async pipeline, enriches each proxy with anonymity classification and GeoIP data, scores them on a 0–100 quality scale, and persists everything to a SQLite database with historical tracking.

It runs as both a **desktop GUI** (CustomTkinter) and a **headless CLI** with five subcommands. A built-in **HTTP rotation API** lets your tools fetch fresh, scored proxies programmatically.

> **What makes this different from a "proxy list downloader"**
>
> Most proxy tools scrape a list, check if each proxy responds, and dump the survivors to a text file. v3 treats proxies as a **living dataset** — it tracks uptime percentage across scans, decays scores for stale proxies, auto-disables dead sources, categorizes failures, and exposes a queryable API so your downstream tools always get the best available proxy.

---

## Features

### Engine

| Feature | Description |
|---|---|
| **Single async pipeline** | One persistent event loop drives the entire scan — no per-batch event loop creation overhead |
| **Concurrent source fetching** | All 80+ sources downloaded in parallel with bounded `asyncio.Semaphore(15)` concurrency |
| **Decoupled enrichment** | Proxies are validated and displayed immediately; anonymity/GeoIP enrichment runs in a background thread pool |
| **Batched SQLite transactions** | All DB writes (upserts + failures) are batched into single `BEGIN/COMMIT` transactions — 10–50x faster than per-row writes |
| **HTTPS CONNECT tunneling** | HTTPS-labeled proxies are tested via `http://ip:port` CONNECT tunneling (correct behavior) while still exported as HTTPS |
| **SOCKS support** | Native SOCKS4/SOCKS5 async validation via `aiohttp-socks`; sync fallback via `requests[socks]` |
| **Error categorization** | Failures classified as `timeout`, `connection_refused`, `dns_failure`, `ssl_error`, `bad_protocol`, `blocked`, `rate_limited`, `socks_auth_failure` |
| **Stop / Pause / Resume** | Full cancellation with partial-result saving; pause halts between batches without losing progress |

### Intelligence

| Feature | Description |
|---|---|
| **Anonymity detection** | Classifies each proxy as `elite` (no proxy headers leaked), `anonymous` (headers present, IP hidden), or `transparent` (real IP visible). Fetches your real public IP first for accurate transparent detection |
| **GeoIP enrichment** | Resolves country, country code, city, and ISP for each proxy's exit IP via ip-api.com (free, no API key). Results are cached by external IP to eliminate duplicate lookups |
| **Quality scoring (0–100)** | Weighted score from latency (35%), anonymity level (30%), reliability/uptime (20%), and protocol type (15%) |
| **Source reliability tracking** | Each source tracks fetched/unique/working counts, consecutive failures, and last success timestamp. Sources are auto-disabled after 3 consecutive failures and persist across runs |
| **Background health monitoring** | Optional background thread re-validates stale proxies every 5 minutes, applies 10% score decay for proxies unseen for 6+ hours, and marks health status as `fresh` / `stale` / `unstable` / `dead` |
| **Historical tracking** | SQLite stores `times_seen`, `times_checked`, `times_working`, `uptime_pct`, `first_seen`, `last_seen` per proxy — enabling trend analysis across scans |

### Interface

| Feature | Description |
|---|---|
| **GUI mode** | Dark-themed CustomTkinter desktop app with live results table, statistics dashboard, terminal log, and control panel |
| **CLI mode** | Full headless operation via `argparse` — `scan`, `serve`, `health-check`, `stats`, `export` |
| **Proxy rotation API** | Built-in HTTP server (`aiohttp.web`) serving filtered proxy queries as JSON |
| **Sortable results table** | Click any column header to sort by proxy, scheme, latency, score, anonymity, country, city, ISP, or health status |
| **Live search** | Filter the results table in real-time by proxy address, country code, ISP, or anonymity level |
| **Context menu** | Right-click any proxy row to copy `ip:port`, copy `scheme://proxy`, or view full validation history from SQLite |
| **Settings persistence** | Last-used workers, toggles, filters, and output format are saved to `settings.json` and restored on launch |
| **ETA & throughput** | Real-time estimated time remaining, proxies/second throughput, and latency p50/p90/p95 percentiles |
| **Statistics dashboard** | Live protocol distribution, anonymity distribution, health distribution, and top 10 countries by proxy count |

### Export

| Format | Content |
|---|---|
| `plain` | Text files per protocol (`http.txt`, `https.txt`, `socks4.txt`, `socks5.txt`), plus `elite.txt`, `anonymous.txt`, `working_all.txt` |
| `json` | Full metadata for every proxy (latency, score, anonymity, country, city, ISP, external IP, source, health status) |
| `csv` | Spreadsheet-ready with all fields as columns |
| `schemed` | `scheme://ip:port` format for tools that require protocol-prefixed proxies |
| `sqlite` | Copy of the full database with historical data |
| `all` | All of the above in a timestamped folder on your Desktop |

Exports support **filters**: protocol, anonymity level, minimum score, and maximum latency.

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- Windows (recommended for GUI), Linux, or macOS

### Installation

```bash
git clone https://github.com/yourusername/advanced-proxy-scraper.git
cd advanced-proxy-scraper
pip install -r requirements.txt
```

Or install dependencies manually:

```bash
pip install customtkinter requests "requests[socks]" aiohttp aiohttp-socks beautifulsoup4 psutil
```

> All dependencies are optional — the code degrades gracefully:
> - No `aiohttp` → falls back to sync validation
> - No `aiohttp-socks` → SOCKS proxies validated via sync path
> - No `psutil` → memory monitoring disabled
> - No `beautifulsoup4` → HTML sources use regex fallback
> - No `customtkinter` → CLI mode still fully functional

### Launch GUI

```bash
python proxy_scraper_v3.py
```

No arguments = GUI mode. The interface opens with a dark theme, ready to scan.

### Launch CLI

```bash
python proxy_scraper_v3.py scan --workers 300
```

---

## CLI Reference

### `scan` — Run a proxy scan

```bash
python proxy_scraper_v3.py scan [options]
```

| Flag | Default | Description |
|---|---|---|
| `--workers N` | Auto (CPU × 8, max 300) | Number of concurrent validation workers |
| `--no-async` | False | Use synchronous validation instead of async |
| `--no-enrich` | False | Skip anonymity detection and GeoIP enrichment |
| `--no-persist` | False | Skip SQLite database writes |
| `--export FORMAT` | `all` | Export format: `plain`, `json`, `csv`, `schemed`, `sqlite`, `all` |
| `--elite-only` | False | Export only elite anonymity proxies |
| `--min-score N` | 0 | Minimum quality score (0–100) for export |
| `--max-latency N` | 5000 | Maximum latency in milliseconds |
| `--scheme TYPE` | None | Filter export by protocol: `http`, `https`, `socks4`, `socks5` |

**Examples:**

```bash
# Full scan with all features, 300 workers
python proxy_scraper_v3.py scan --workers 300

# Fast scan, no enrichment, export only elite proxies as JSON
python proxy_scraper_v3.py scan --no-enrich --elite-only --export json

# SOCKS5 only, minimum score 70, max latency 2s, CSV export
python proxy_scraper_v3.py scan --scheme socks5 --min-score 70 --max-latency 2000 --export csv

# Sync mode (no aiohttp), no persistence, plain text only
python proxy_scraper_v3.py scan --no-async --no-persist --export plain
```

### `serve` — Start the proxy rotation API

```bash
python proxy_scraper_v3.py serve [--host 127.0.0.1] [--port 8888]
```

Starts an HTTP server that serves proxy queries as JSON. See the [Rotation API](#-proxy-rotation-api) section below.

### `export` — Export from database

```bash
python proxy_scraper_v3.py export [options]
```

| Flag | Default | Description |
|---|---|---|
| `--format FORMAT` | `all` | Export format: `plain`, `json`, `csv`, `schemed`, `sqlite`, `all` |
| `--scheme TYPE` | None | Filter by protocol |
| `--country CC` | None | Filter by country code (e.g., `RO`, `US`, `DE`) |
| `--anonymity LEVEL` | None | Filter by anonymity: `elite`, `anonymous`, `transparent` |
| `--min-score N` | 0 | Minimum quality score |
| `--max-latency N` | 9999 | Maximum latency in ms |
| `--limit N` | 1000 | Maximum number of proxies to export |

**Examples:**

```bash
# Export top 500 elite proxies from Romania as CSV
python proxy_scraper_v3.py export --anonymity elite --country RO --limit 500 --format csv

# Export all SOCKS5 proxies with score > 80
python proxy_scraper_v3.py export --scheme socks5 --min-score 80 --format json

# Export full database copy
python proxy_scraper_v3.py export --format sqlite
```

### `stats` — Show database statistics

```bash
python proxy_scraper_v3.py stats
```

Displays total stored proxies, working count, average score/latency, breakdowns by protocol, anonymity, health status, top countries, and recent scan history.

### `health-check` — Re-validate stored proxies

```bash
python proxy_scraper_v3.py health-check
```

Runs a single health check cycle: applies score decay to stale proxies, then re-validates `stale` and `unstable` proxies from the database.

---

## Proxy Rotation API

Start the server:

```bash
python proxy_scraper_v3.py serve --port 8888
```

### Endpoints

#### `GET /proxy/best`

Returns the highest-scored proxies matching your filters.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | int | 1 | Number of proxies to return |
| `scheme` | string | — | Filter by protocol: `http`, `https`, `socks4`, `socks5` |
| `country` | string | — | Filter by country code (e.g., `RO`) |
| `anonymity` | string | — | Filter by anonymity: `elite`, `anonymous`, `transparent` |
| `min_score` | int | 0 | Minimum quality score |
| `max_latency` | int | 9999 | Maximum latency in ms |

```bash
# Get 10 best HTTP proxies with score >= 80
curl "http://127.0.0.1:8888/proxy/best?limit=10&scheme=http&min_score=80"

# Get top 5 elite proxies from Romania
curl "http://127.0.0.1:8888/proxy/best?limit=5&country=RO&anonymity=elite"
```

**Response:**
```json
{
  "count": 5,
  "proxies": [
    {
      "proxy": "203.0.113.42:8080",
      "scheme": "http",
      "latency": 234,
      "score": 92,
      "anonymity": "elite",
      "country": "Romania",
      "country_code": "RO",
      "city": "Bucharest",
      "isp": "Romtelecom",
      "uptime_pct": 100.0,
      "times_seen": 3,
      "health_status": "fresh"
    }
  ]
}
```

#### `GET /proxy/random`

Returns a single random proxy matching filters (same parameters as `/proxy/best`).

```bash
curl "http://127.0.0.1:8888/proxy/random?country=DE&min_score=70"
```

#### `GET /stats`

Returns full database statistics as JSON.

```bash
curl "http://127.0.0.1:8888/stats"
```

#### `GET /health`

Simple health check endpoint.

```bash
curl "http://127.0.0.1:8888/health"
```

```json
{
  "status": "ok",
  "working_proxies": 1284
}
```

### Using the API in Python

```python
import requests

# Get the best proxy
r = requests.get("http://127.0.0.1:8888/proxy/best?limit=1&min_score=80&anonymity=elite")
proxy = r.json()["proxies"][0]
proxy_url = f"{proxy['scheme']}://{proxy['proxy']}"

# Use it
response = requests.get("https://httpbin.org/ip", proxies={"http": proxy_url, "https": proxy_url})
print(response.json())
```

### Using the API with curl in a loop

```bash
# Rotate through proxies for a scraping task
for i in $(seq 1 100); do
  PROXY=$(curl -s "http://127.0.0.1:8888/proxy/random?min_score=70" | python -c "import sys,json; d=json.load(sys.stdin); print(f\"{d['scheme']}://{d['proxy']}\")")
  curl -x "$PROXY" "https://target-site.com/page/$i"
  sleep 1
done
```

---

## Architecture

### Pipeline Stages

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SCAN ENGINE (async)                              │
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │  Phase 1     │    │  Phase 2     │    │  Phase 3     │              │
│  │  SOURCE      │───▶│  VALIDATION  │───▶│  PERSISTENCE │              │
│  │  FETCH       │    │  + ENRICH    │    │  + EXPORT    │              │
│  │  (concurrent)│    │  (decoupled) │    │  (batched)   │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│         │                   │                    │                      │
│    80+ sources        Validate first       SQLite batch write            │
│    in parallel        → display             → export files              │
│    via aiohttp        → enrich in BG        → scan history              │
│                       → score calc          → score decay               │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │              UI QUEUE (thread-safe, via queue.Queue)            │   │
│  │  log · status · progress · table_refresh · proto · anon · ETA  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

**Why one event loop instead of per-batch loops?**
v2 created a new `asyncio.new_event_loop()` for each 300-proxy batch. This means connection pools, DNS caches, and connector state were destroyed and recreated 50+ times per scan. v3 runs one persistent loop with a single `aiohttp.ClientSession` that maintains connection pooling and DNS caching across all batches.

**Why decouple enrichment from validation?**
Anonymity detection and GeoIP lookup require additional HTTP requests through each proxy (to `httpbin.org/headers`, `api.ipify.org`, `ip-api.com`). These are slow and rate-limited. By validating first and enriching in a background `ThreadPoolExecutor`, working proxies appear in the UI immediately instead of waiting for enrichment to complete.

**Why batched SQLite transactions?**
Writing one `INSERT` per proxy means 50,000+ individual transactions per scan. SQLite's WAL mode helps, but the `fsync` overhead per transaction is significant. Batching all upserts and failures into `BEGIN/COMMIT` blocks reduces this to ~170 transactions for 50,000 proxies.

**Why HTTPS CONNECT tunneling?**
Many proxy lists label proxies as "HTTPS" meaning they support HTTPS traffic via CONNECT tunneling — not that you connect to them via `https://proxy:port`. Testing them as `http://proxy:port` (which then establishes a CONNECT tunnel to the target HTTPS site) is the correct behavior. Using `https://proxy:port` would fail for the vast majority of proxies.

### Project Structure

```
advanced-proxy-scraper/
├── proxy_scraper_v3.py          # Main application (GUI + CLI + engine)
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── LICENSE                      # MIT
└── proxy_config/                # Auto-created on first run
    ├── sources.json             # Source list (editable without code changes)
    ├── settings.json            # Persisted user settings
    └── proxy_database.db        # SQLite database (proxy history, scans, source stats)
```

### Data Model

**`proxies` table:**

| Column | Type | Description |
|---|---|---|
| `proxy` | TEXT UNIQUE | `ip:port` |
| `scheme` | TEXT | `http`, `https`, `socks4`, `socks5` |
| `latency` | INTEGER | Response time in ms |
| `country` | TEXT | Country name |
| `country_code` | TEXT | ISO country code (e.g., `RO`) |
| `city` | TEXT | City name |
| `isp` | TEXT | ISP / organization |
| `anonymity` | TEXT | `elite`, `anonymous`, `transparent`, `unknown` |
| `score` | INTEGER | Quality score 0–100 |
| `times_seen` | INTEGER | Times this proxy was found working |
| `times_checked` | INTEGER | Total times this proxy was tested |
| `times_working` | INTEGER | Times this proxy responded successfully |
| `uptime_pct` | REAL | `times_working / times_checked × 100` |
| `first_seen` | REAL | Unix timestamp of first discovery |
| `last_seen` | REAL | Unix timestamp of last successful check |
| `last_checked` | REAL | Unix timestamp of last test (success or failure) |
| `external_ip` | TEXT | The proxy's exit IP address |
| `source` | TEXT | URL of the source that provided this proxy |
| `last_error` | TEXT | Last error category if it failed |
| `health_status` | TEXT | `fresh`, `stale`, `unstable`, `dead`, `unknown` |

---

## Quality Scoring System

Each proxy receives a **0–100 score** calculated from four weighted components:

| Component | Weight | Formula |
|---|---|---|
| **Latency** | 35% | `max(0, 100 - (latency_ms / 5000 × 100))` |
| **Anonymity** | 30% | Elite = 100, Anonymous = 70, Unknown = 40, Transparent = 20 |
| **Reliability** | 20% | `uptime_pct` (historical success rate across scans) |
| **Protocol** | 15% | SOCKS5 = 100, HTTPS = 85, SOCKS4 = 75, HTTP = 60 |

**Score decay:** Proxies not checked in 6+ hours have their score multiplied by 0.9 on each health check cycle, gradually pushing stale proxies down the ranking.

---

## Configuration

### Adding Custom Sources

Edit `proxy_config/sources.json` (auto-created on first run):

```json
{
  "plain_sources": [
    {"url": "https://your-source.com/proxies.txt", "scheme": "http"},
    {"url": "https://your-source.com/socks.txt", "scheme": "socks5"}
  ],
  "html_sources": [
    {
      "url": "https://your-site.com/proxy-list",
      "scheme": "auto",
      "parser": "spys_one"
    }
  ]
}
```

Supported schemes: `http`, `https`, `socks4`, `socks5`, `auto` (tries both HTTP and HTTPS).

Available HTML parsers: `spys_one`, `hidemy_name`, `fate0`.

### Tunable Constants

All tuning constants are at the top of `proxy_scraper_v3.py`:

| Constant | Default | Description |
|---|---|---|
| `CONNECT_TIMEOUT` | 2.0s | TCP connection timeout |
| `READ_TIMEOUT` | 6.0s | Response read timeout |
| `FAST_THRESHOLD_MS` | 5000ms | Maximum acceptable latency |
| `BATCH_SIZE` | 300 | Proxies per validation batch |
| `SOURCE_FETCH_CONCURRENCY` | 15 | Max concurrent source downloads |
| `ENRICH_CONCURRENCY` | 20 | Max concurrent enrichment threads |
| `GEOIP_RATE_LIMIT_MS` | 200ms | Minimum interval between ip-api.com requests |
| `SOURCE_FAILURE_THRESHOLD` | 3 | Consecutive failures before auto-disable |
| `SCORE_DECAY_HOURS` | 6 | Hours before score decay applies |
| `HEALTH_CHECK_INTERVAL` | 300s | Background re-validation interval |
| `MAX_MEMORY_MB` | 512 | Memory limit before GC trigger |

---

## GUI Guide

### Control Panel (Left)

- **Workers slider** — Set concurrent validation workers (10–300)
- **Toggles** — Async I/O, Anonymity + GeoIP enrichment, SQLite persistence, Background health monitor
- **Export filters** — Protocol, anonymity level, minimum score, maximum latency
- **Output format** — `plain`, `json`, `csv`, `schemed`, `sqlite`, `all`
- **Buttons** — Start, Stop (cancel), Pause/Resume
- **Status** — Real-time scan progress bar and phase indicator
- **ETA** — Estimated time remaining, throughput (proxies/sec), latency percentiles
- **Stats** — Sources loaded, unique proxies, working count, elite count, average score/latency, DB total

### Results Table (Center)

- **Sortable** — Click any column header to sort (toggle ascending/descending)
- **Searchable** — Type in the search bar to filter by proxy, country, ISP, or anonymity
- **Context menu** — Right-click any row: copy `ip:port`, copy `scheme://proxy`, view full history
- **Color-coded** — Green (high score/elite/fresh), Yellow (medium/stale), Red (low/transparent/dead)
- **Health column** — Shows `fresh`, `stale`, `unstable`, or `dead` status

### Statistics Dashboard (Right)

- **By Protocol** — Live count of working HTTP/HTTPS/SOCKS4/SOCKS5 proxies
- **By Anonymity** — Live count of elite/anonymous/transparent/unknown
- **By Health** — Live count of fresh/stale/unstable/dead
- **Top Countries** — Top 10 countries by proxy count
- **Live Terminal** — Real-time log of downloads, validations, enrichment, errors, and stats

---

## Requirements

```
customtkinter>=5.2.0      # GUI framework (optional — CLI works without it)
requests>=2.31.0          # HTTP client for sync validation + enrichment
requests[socks]            # SOCKS proxy support for sync validation
aiohttp>=3.9.0             # Async HTTP for concurrent source fetching + validation
aiohttp-socks>=0.8.0       # Async SOCKS4/SOCKS5 proxy support
beautifulsoup4>=4.12.0    # HTML parsing for structured proxy sources
psutil>=5.9.0             # Memory monitoring (optional)
```

Create `requirements.txt`:

```txt
customtkinter>=5.2.0
requests>=2.31.0
requests[socks]
aiohttp>=3.9.0
aiohttp-socks>=0.8.0
beautifulsoup4>=4.12.0
psutil>=5.9.0
```

---

## Use Cases

### Web Scraping with Proxy Rotation

```python
import requests

# Start the API server first: python proxy_scraper_v3.py serve

def get_proxy():
    r = requests.get("http://127.0.0.1:8888/proxy/random?min_score=70&anonymity=elite")
    data = r.json()
    return f"{data['scheme']}://{data['proxy']}"

for url in urls_to_scrape:
    proxy = get_proxy()
    try:
        response = requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=10)
        # Process response
    except Exception:
        continue  # Proxy failed, get a new one next iteration
```

### Automated Cron Scans

```bash
# crontab -e
# Run a scan every 6 hours, export elite proxies only
0 */6 * * * cd /path/to/proxy-scraper && python proxy_scraper_v3.py scan --elite-only --export json --no-enrich
```

### Health Monitoring Daemon

```bash
# Keep the rotation API running with continuous health checks
python proxy_scraper_v3.py serve --port 8888 &
python proxy_scraper_v3.py health-check
```

### Pipeline Integration

```bash
# Scan → filter → use in downstream tools
python proxy_scraper_v3.py scan --scheme socks5 --min-score 80 --export plain
cat ~/Desktop/proxy_export_*/socks5.txt | while read proxy; do
    curl -x "socks5://$proxy" https://target.com
done
```

---

## Supported Protocols

| Protocol | Async Support | Sync Support | Notes |
|---|---|---|---|
| HTTP | Native `aiohttp` | Native `requests` | Most common, lowest quality |
| HTTPS | Native `aiohttp` (CONNECT) | Native `requests` (CONNECT) | Tested via `http://` CONNECT tunnel |
| SOCKS4 | `aiohttp-socks` | `requests[socks]` (PySocks) | No authentication support |
| SOCKS5 | `aiohttp-socks` | `requests[socks]` (PySocks) | Supports username/password auth |

---

## Anonymity Levels

| Level | Score | Description |
|---|---|---|
| **Elite** | 100 | No proxy headers (`Via`, `X-Forwarded-For`, `Forwarded`) are sent. The target server cannot detect you are using a proxy. |
| **Anonymous** | 70 | Proxy headers are present, but your real IP is not leaked. The target knows you're using a proxy but cannot identify you. |
| **Transparent** | 20 | Your real public IP is visible in `X-Forwarded-For` or `Forwarded` headers. The target server sees both your real IP and the proxy IP. Useless for anonymity. |
| **Unknown** | 40 | Enrichment failed or was skipped. Treated as medium-priority. |

Detection works by:
1. Fetching your real public IP via `api.ipify.org` before the scan
2. Making a request through the proxy to `httpbin.org/headers`
3. Comparing the returned headers against your real IP and checking for proxy-indicating headers

---

## Source List

The scraper aggregates from **80 sources** including:

- TheSpeedX/PROXY-List (HTTP, HTTPS, SOCKS4, SOCKS5)
- proxifly/free-proxy-list
- monosans/proxy-list
- jetkai/proxy-list
- officialputuid/KangProxy
- proxyscrape.com API (v1 + v4)
- proxy-list.download API
- ShiftyTR/Proxy-List
- roosterkid/openproxylist
- VPSLabCloud
- iplocate/free-proxy-list
- spys.one (HTML parsed)
- hidemy.name (HTML parsed)
- fate0/proxylist (JSONL parsed)
- And 60+ more GitHub-hosted lists and APIs

Sources are auto-disabled after 3 consecutive failures and re-enabled only when the failure counter resets (manual edit of `sources.json` or database). Source reliability statistics are tracked in the `source_stats` SQLite table.

---

## Performance

Typical performance on a modern machine (8-core CPU, 32GB RAM, 100 Mbps connection):

| Metric | Value |
|---|---|
| Source download time | 5–15 seconds (80 sources in parallel) |
| Proxies fetched | 30,000–80,000 (before deduplication) |
| Unique proxies after dedup | 15,000–50,000 |
| Validation throughput | 200–500 proxies/sec (async) |
| Full scan duration | 2–5 minutes |
| Working proxies found | 500–3,000 (varies by time of day) |
| Memory usage | 150–400 MB |
| Database size per scan | +2–10 MB |

Performance depends heavily on:
- Number of workers (more = faster, but watch for OS socket limits)
- Network bandwidth and latency
- Proxy quality at scan time (more dead proxies = more timeouts)
- Whether enrichment is enabled (GeoIP rate limiting adds ~200ms per unique exit IP)

---

## Limitations

- **Free proxies are unreliable.** Most public proxy lists have a working rate of 2–10%. This tool finds the ones that work and tracks them over time, but no free proxy should be trusted for anything critical.
- **GeoIP rate limiting.** ip-api.com's free tier allows 45 requests/minute. The tool rate-limits automatically, but enriching 1,000+ working proxies with unique exit IPs takes time. Cached IPs from previous scans are reused.
- **No proxy chaining.** v3 validates individual proxies only. Proxy chaining (routing through multiple proxies in sequence) is not supported.
- **No authentication testing.** SOCKS5 proxies requiring username/password are not tested with credentials. They will be marked as failed.
- **Desktop export path.** GUI mode exports to `~/Desktop/proxy_export_TIMESTAMP/`. CLI mode also defaults to Desktop. Modify `get_desktop()` if you need a different path.

---

## License

MIT License. See [LICENSE](LICENSE) file for details.

---

## Contributing

Contributions are welcome. Areas of particular interest:

- Additional HTML source parsers
- Performance optimizations for the validation pipeline
- Alternative GeoIP providers (MaxMind, IPinfo)
- SOCKS5 authentication support
- Additional export formats (SQL INSERT statements, YAML, protocol buffers)

---

<div align="center">

**If this project helped you, consider giving it a star.**

</div>
