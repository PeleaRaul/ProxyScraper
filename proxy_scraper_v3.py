#!/usr/bin/env python3
"""
Advanced Proxy Scraper v3.0 - By Pelea Raul-Daniel
===========================================================
Architecture: Single async pipeline with stages:
  Concurrent Source Fetch → Validate → Enrich → DB Write → UI Update

Features:
  - Async pipeline with one persistent event loop (no per-batch loop creation)
  - Concurrent source downloading (70+ sources in parallel)
  - Decoupled enrichment (validate first, enrich in background)
  - Batched SQLite transactions
  - Error categorization (timeout, refused, DNS, SSL, bad protocol, blocked)
  - HTTPS CONNECT tunneling semantics (test as http:// but label as https)
  - CLI/headless mode (scan, export, serve, health-check)
  - Local proxy rotation API server (GET /proxy/best, /proxy/random, filtered)
  - Settings persistence (remembers last config)
  - Search/filter in results table + context menu
  - ETA, throughput (proxies/sec), latency p50/p90/p95
  - Background health monitoring with score decay (fresh/stale/dead/unstable)
  - Anonymity detection (transparent/anonymous/elite) with real IP comparison
  - GeoIP via ip-api.com with caching + rate limiting
  - Quality scoring (0-100)
  - Source reliability tracking with cross-run auto-disable
  - Stop/pause/cancel
  - Advanced exports (CSV, JSON, SQLite, plain, schemed, filtered)

  **TO BE USED IN EDUCATIONAL ENVOIRMENTS ONLY! 
    ME OR AACGUARD.COM ARE NOT LIABLE FOR ANY 
    MISCONDUCT WHILE USING THIS PYTHON APPLICATION. 
"""

import argparse
import asyncio
import csv
import gc
import ipaddress
import json
import os
import queue
import re
import sqlite3
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# --- Optional imports with graceful degradation ---
try:
    import aiohttp
    from aiohttp import ClientSession, ClientTimeout, TCPConnector
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    from aiohttp_socks import ProxyConnector, ProxyType
    HAS_AIOHTTP_SOCKS = True
except ImportError:
    HAS_AIOHTTP_SOCKS = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from aiohttp import web as aiohttp_web
    HAS_AIOHTTP_WEB = True
except ImportError:
    HAS_AIOHTTP_WEB = False

# GUI is only imported when not in CLI mode
_GUI_MODE = False

# ==========================
# CONFIG
# ==========================

APP_NAME = "Advanced Proxy Scraper"
APP_VERSION = "3.0"
APP_DIR = Path(__file__).parent if "__file__" in dir() else Path.cwd()
CONFIG_DIR = APP_DIR / "proxy_config"
CONFIG_DIR.mkdir(exist_ok=True)

CONNECT_TIMEOUT = 2.0
READ_TIMEOUT = 6.0
FAST_THRESHOLD_MS = 5000
MAX_MEMORY_MB = 512
BATCH_SIZE = 300
GEOIP_RATE_LIMIT_MS = 200
SOURCE_FETCH_TIMEOUT = 15
SOURCE_FETCH_CONCURRENCY = 15  # Max concurrent source downloads
ENRICH_CONCURRENCY = 20  # Max concurrent enrichment tasks

DB_PATH = CONFIG_DIR / "proxy_database.db"
SOURCES_PATH = CONFIG_DIR / "sources.json"
SETTINGS_PATH = CONFIG_DIR / "settings.json"

ANONYMITY_CHECK_URL = "http://httpbin.org/headers"
GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,query"

TEST_URLS = [
    "https://api.ipify.org",
    "https://httpbin.org/ip",
    "https://icanhazip.com",
    "https://www.google.com",
    "https://cloudflare.com",
]

SCORE_LATENCY_WEIGHT = 35
SCORE_ANONYMITY_WEIGHT = 30
SCORE_RELIABILITY_WEIGHT = 20
SCORE_TYPE_WEIGHT = 15

ANONYMITY_SCORES = {"elite": 100, "anonymous": 70, "transparent": 20, "unknown": 40}
PROTOCOL_SCORES = {"socks5": 100, "socks4": 75, "https": 85, "http": 60}
SOURCE_FAILURE_THRESHOLD = 3

# Score decay: after this many hours, score starts decaying
SCORE_DECAY_HOURS = 6
# Health check interval (seconds)
HEALTH_CHECK_INTERVAL = 300  # 5 minutes

# ==========================
# ERROR CATEGORIZATION
# ==========================

class ProxyError:
    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    DNS_FAILURE = "dns_failure"
    SSL_ERROR = "ssl_error"
    BAD_PROTOCOL = "bad_protocol"
    BLOCKED = "blocked"
    RATE_LIMITED = "rate_limited"
    SOCKS_AUTH = "socks_auth_failure"
    UNKNOWN = "unknown"

    @staticmethod
    def categorize(exception: Exception) -> str:
        """Categorize a proxy validation error."""
        err_str = str(exception).lower()
        err_type = type(exception).__name__.lower()

        if "timeout" in err_str or "timed out" in err_str:
            return ProxyError.TIMEOUT
        elif "connection refused" in err_str:
            return ProxyError.CONNECTION_REFUSED
        elif "name or service not known" in err_str or "dns" in err_str or "getaddrinfo" in err_str:
            return ProxyError.DNS_FAILURE
        elif "ssl" in err_str or "certificate" in err_str:
            return ProxyError.SSL_ERROR
        elif "socks" in err_str and ("auth" in err_str or "authentication" in err_str):
            return ProxyError.SOCKS_AUTH
        elif "403" in err_str or "forbidden" in err_str:
            return ProxyError.BLOCKED
        elif "429" in err_str or "too many" in err_str:
            return ProxyError.RATE_LIMITED
        elif "protocol" in err_str or "handshake" in err_str:
            return ProxyError.BAD_PROTOCOL
        else:
            return ProxyError.UNKNOWN

# ==========================
# DATA STRUCTURES
# ==========================

@dataclass
class ProxyResult:
    proxy: str
    scheme: str
    latency: int
    url: str
    timestamp: float = field(default_factory=time.time)
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    anonymity: Optional[str] = None
    score: int = 0
    uptime_pct: float = 0.0
    times_seen: int = 1
    source: Optional[str] = None
    external_ip: Optional[str] = None
    error_type: Optional[str] = None
    health_status: str = "fresh"  # fresh, stale, dead, unstable

    def to_dict(self):
        return asdict(self)

@dataclass
class SourceStats:
    name: str
    url: str
    scheme: str
    total_fetched: int = 0
    unique_added: int = 0
    working_count: int = 0
    consecutive_failures: int = 0
    last_success: Optional[float] = None
    enabled: bool = True
    last_error: Optional[str] = None

@dataclass
class ScanStats:
    """Real-time scan statistics for ETA and throughput."""
    start_time: float = field(default_factory=time.time)
    total_proxies: int = 0
    processed: int = 0
    working: int = 0
    failed: int = 0
    latencies: List[int] = field(default_factory=list)
    errors: Counter = field(default_factory=Counter)

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def throughput(self) -> float:
        if self.elapsed > 0:
            return self.processed / self.elapsed
        return 0.0

    @property
    def eta_seconds(self) -> Optional[float]:
        if self.throughput > 0 and self.total_proxies > 0:
            remaining = self.total_proxies - self.processed
            return remaining / self.throughput
        return None

    @property
    def p50(self) -> Optional[int]:
        return self._percentile(50)

    @property
    def p90(self) -> Optional[int]:
        return self._percentile(90)

    @property
    def p95(self) -> Optional[int]:
        return self._percentile(95)

    def _percentile(self, p: int) -> Optional[int]:
        if not self.latencies:
            return None
        sorted_l = sorted(self.latencies)
        idx = int(len(sorted_l) * p / 100)
        idx = min(idx, len(sorted_l) - 1)
        return sorted_l[idx]

    def format_eta(self) -> str:
        eta = self.eta_seconds
        if eta is None:
            return "--"
        if eta < 60:
            return f"{eta:.0f}s"
        elif eta < 3600:
            return f"{eta/60:.1f}m"
        else:
            return f"{eta/3600:.1f}h"

# ==========================
# CPU DETECTION
# ==========================

def detect_logical_threads():
    try:
        if hasattr(os, "process_cpu_count"):
            count = os.process_cpu_count()
            if count:
                return count
    except Exception:
        pass
    try:
        count = os.cpu_count()
        if count:
            return count
    except Exception:
        pass
    return 4

LOGICAL_THREADS = detect_logical_threads()
DEFAULT_WORKERS = min(max(LOGICAL_THREADS * 8, 20), 300)

# ==========================
# SETTINGS PERSISTENCE
# ==========================

DEFAULT_SETTINGS = {
    "workers": DEFAULT_WORKERS,
    "use_async": True,
    "do_enrich": True,
    "do_persist": True,
    "output_format": "all",
    "filter_scheme": "all",
    "filter_anonymity": "all",
    "min_score": 0,
    "max_latency": 5000,
    "memory_limit": MAX_MEMORY_MB,
}

class Settings:
    """Persistent settings that survive between runs."""

    def __init__(self, path=SETTINGS_PATH):
        self.path = path
        self.data = dict(DEFAULT_SETTINGS)
        self.load()

    def load(self):
        if self.path.exists():
            try:
                with open(self.path, "r") as f:
                    self.data.update(json.load(f))
            except Exception:
                pass

    def save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self.data, f, indent=2)
        except Exception:
            pass

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        self.save()

SETTINGS = Settings()

# ==========================
# SQLITE DATABASE
# ==========================

class ProxyDatabase:
    """SQLite database with batched transaction support."""

    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS proxies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proxy TEXT UNIQUE NOT NULL,
                scheme TEXT,
                latency INTEGER DEFAULT 9999,
                country TEXT,
                country_code TEXT,
                city TEXT,
                isp TEXT,
                anonymity TEXT,
                score INTEGER DEFAULT 0,
                times_seen INTEGER DEFAULT 1,
                times_checked INTEGER DEFAULT 1,
                times_working INTEGER DEFAULT 0,
                uptime_pct REAL DEFAULT 0.0,
                first_seen REAL,
                last_seen REAL,
                last_checked REAL,
                external_ip TEXT,
                source TEXT,
                last_error TEXT,
                health_status TEXT DEFAULT 'unknown'
            );
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time REAL,
                total_fetched INTEGER,
                total_working INTEGER,
                duration_sec REAL,
                avg_latency REAL,
                throughput REAL,
                by_protocol TEXT,
                by_country TEXT,
                by_anonymity TEXT,
                by_error TEXT
            );
            CREATE TABLE IF NOT EXISTS source_stats (
                url TEXT PRIMARY KEY,
                scheme TEXT,
                total_fetched INTEGER DEFAULT 0,
                unique_added INTEGER DEFAULT 0,
                working_count INTEGER DEFAULT 0,
                consecutive_failures INTEGER DEFAULT 0,
                last_success REAL,
                enabled INTEGER DEFAULT 1,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_proxies_scheme ON proxies(scheme);
            CREATE INDEX IF NOT EXISTS idx_proxies_country ON proxies(country_code);
            CREATE INDEX IF NOT EXISTS idx_proxies_score ON proxies(score);
            CREATE INDEX IF NOT EXISTS idx_proxies_latency ON proxies(latency);
            CREATE INDEX IF NOT EXISTS idx_proxies_anonymity ON proxies(anonymity);
            CREATE INDEX IF NOT EXISTS idx_proxies_health ON proxies(health_status);
        """)

    def upsert_proxy(self, result: ProxyResult):
        conn = self._get_conn()
        now = time.time()
        conn.execute("""
            INSERT INTO proxies (proxy, scheme, latency, country, country_code, city, isp,
                                  anonymity, score, times_seen, times_checked, times_working,
                                  uptime_pct, first_seen, last_seen, last_checked, external_ip,
                                  source, last_error, health_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 1, 100.0, ?, ?, ?, ?, ?, NULL, 'fresh')
            ON CONFLICT(proxy) DO UPDATE SET
                scheme=excluded.scheme,
                latency=excluded.latency,
                country=COALESCE(excluded.country, proxies.country),
                country_code=COALESCE(excluded.country_code, proxies.country_code),
                city=COALESCE(excluded.city, proxies.city),
                isp=COALESCE(excluded.isp, proxies.isp),
                anonymity=COALESCE(excluded.anonymity, proxies.anonymity),
                score=excluded.score,
                times_seen=proxies.times_seen + 1,
                times_checked=proxies.times_checked + 1,
                times_working=proxies.times_working + 1,
                uptime_pct=CAST(proxies.times_working + 1 AS REAL) / (proxies.times_checked + 1) * 100,
                last_seen=excluded.last_seen,
                last_checked=excluded.last_checked,
                external_ip=COALESCE(excluded.external_ip, proxies.external_ip),
                source=COALESCE(excluded.source, proxies.source),
                health_status='fresh'
        """, (result.proxy, result.scheme, result.latency, result.country, result.country_code,
              result.city, result.isp, result.anonymity, result.score, now, now, now,
              result.external_ip, result.source))

    def batch_upsert_proxies(self, results: List[ProxyResult]):
        """Batch upsert multiple proxies in a single transaction."""
        conn = self._get_conn()
        now = time.time()
        conn.execute("BEGIN")
        try:
            for result in results:
                conn.execute("""
                    INSERT INTO proxies (proxy, scheme, latency, country, country_code, city, isp,
                                          anonymity, score, times_seen, times_checked, times_working,
                                          uptime_pct, first_seen, last_seen, last_checked, external_ip,
                                          source, last_error, health_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 1, 100.0, ?, ?, ?, ?, ?, NULL, 'fresh')
                    ON CONFLICT(proxy) DO UPDATE SET
                        scheme=excluded.scheme,
                        latency=excluded.latency,
                        country=COALESCE(excluded.country, proxies.country),
                        country_code=COALESCE(excluded.country_code, proxies.country_code),
                        city=COALESCE(excluded.city, proxies.city),
                        isp=COALESCE(excluded.isp, proxies.isp),
                        anonymity=COALESCE(excluded.anonymity, proxies.anonymity),
                        score=excluded.score,
                        times_seen=proxies.times_seen + 1,
                        times_checked=proxies.times_checked + 1,
                        times_working=proxies.times_working + 1,
                        uptime_pct=CAST(proxies.times_working + 1 AS REAL) / (proxies.times_checked + 1) * 100,
                        last_seen=excluded.last_seen,
                        last_checked=excluded.last_checked,
                        external_ip=COALESCE(excluded.external_ip, proxies.external_ip),
                        source=COALESCE(excluded.source, proxies.source),
                        health_status='fresh'
                """, (result.proxy, result.scheme, result.latency, result.country, result.country_code,
                      result.city, result.isp, result.anonymity, result.score, now, now, now,
                      result.external_ip, result.source))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def batch_mark_failed(self, proxy_strs: List[str]):
        """Batch mark multiple proxies as failed in a single transaction."""
        conn = self._get_conn()
        now = time.time()
        conn.execute("BEGIN")
        try:
            for proxy_str in proxy_strs:
                conn.execute("""
                    INSERT INTO proxies (proxy, scheme, latency, times_seen, times_checked, times_working,
                                         uptime_pct, first_seen, last_seen, last_checked, score, health_status)
                    VALUES (?, 'unknown', 9999, 1, 1, 0, 0.0, ?, ?, ?, 0, 'dead')
                    ON CONFLICT(proxy) DO UPDATE SET
                        times_checked=proxies.times_checked + 1,
                        uptime_pct=CAST(proxies.times_working AS REAL) / (proxies.times_checked + 1) * 100,
                        last_checked=?,
                        health_status=CASE
                            WHEN CAST(proxies.times_working AS REAL) / (proxies.times_checked + 1) < 0.1 THEN 'dead'
                            ELSE 'unstable'
                        END
                """, (proxy_str, now, now, now, now))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def update_source_stats(self, stats: SourceStats):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO source_stats (url, scheme, total_fetched, unique_added, working_count,
                                      consecutive_failures, last_success, enabled, last_error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                scheme=excluded.scheme,
                total_fetched=excluded.total_fetched,
                unique_added=excluded.unique_added,
                working_count=excluded.working_count,
                consecutive_failures=excluded.consecutive_failures,
                last_success=excluded.last_success,
                enabled=excluded.enabled,
                last_error=excluded.last_error
        """, (stats.url, stats.scheme, stats.total_fetched, stats.unique_added,
              stats.working_count, stats.consecutive_failures, stats.last_success,
              int(stats.enabled), stats.last_error))

    def record_scan(self, total_fetched, total_working, duration, avg_latency, throughput,
                    by_protocol, by_country, by_anonymity, by_error):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO scan_history (scan_time, total_fetched, total_working, duration_sec,
                                       avg_latency, throughput, by_protocol, by_country, by_anonymity, by_error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (time.time(), total_fetched, total_working, duration, avg_latency, throughput,
              json.dumps(by_protocol), json.dumps(by_country), json.dumps(by_anonymity), json.dumps(by_error)))

    def get_best_proxies(self, limit=100, scheme=None, country=None, anonymity=None,
                         min_score=0, max_latency=9999, health_status=None):
        conn = self._get_conn()
        query = "SELECT * FROM proxies WHERE score >= ? AND latency <= ?"
        params = [min_score, max_latency]
        if scheme:
            query += " AND scheme = ?"
            params.append(scheme)
        if country:
            query += " AND country_code = ?"
            params.append(country)
        if anonymity:
            query += " AND anonymity = ?"
            params.append(anonymity)
        if health_status:
            query += " AND health_status = ?"
            params.append(health_status)
        query += " ORDER BY score DESC, latency ASC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_random_proxy(self, scheme=None, country=None, min_score=0):
        conn = self._get_conn()
        query = "SELECT * FROM proxies WHERE score >= ? AND latency < 9999"
        params = [min_score]
        if scheme:
            query += " AND scheme = ?"
            params.append(scheme)
        if country:
            query += " AND country_code = ?"
            params.append(country)
        query += " ORDER BY RANDOM() LIMIT 1"
        row = conn.execute(query, params).fetchone()
        return dict(row) if row else None

    def get_stats_summary(self):
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM proxies").fetchone()[0]
        working = conn.execute("SELECT COUNT(*) FROM proxies WHERE latency < 9999").fetchone()[0]
        avg_score = conn.execute("SELECT AVG(score) FROM proxies WHERE latency < 9999").fetchone()[0] or 0
        avg_latency = conn.execute("SELECT AVG(latency) FROM proxies WHERE latency < 9999").fetchone()[0] or 0
        by_scheme = dict(conn.execute("SELECT scheme, COUNT(*) FROM proxies WHERE latency < 9999 GROUP BY scheme").fetchall())
        by_country = dict(conn.execute("SELECT country_code, COUNT(*) FROM proxies WHERE latency < 9999 AND country_code IS NOT NULL GROUP BY country_code ORDER BY COUNT(*) DESC LIMIT 20").fetchall())
        by_anon = dict(conn.execute("SELECT anonymity, COUNT(*) FROM proxies WHERE latency < 9999 GROUP BY anonymity").fetchall())
        by_health = dict(conn.execute("SELECT health_status, COUNT(*) FROM proxies GROUP BY health_status").fetchall())
        scans = conn.execute("SELECT * FROM scan_history ORDER BY scan_time DESC LIMIT 10").fetchall()
        return {
            "total_stored": total, "total_working": working,
            "avg_score": round(avg_score, 1), "avg_latency": round(avg_latency, 0),
            "by_scheme": by_scheme, "by_country": by_country,
            "by_anonymity": by_anon, "by_health": by_health,
            "recent_scans": [dict(s) for s in scans],
        }

    def get_proxy_history(self, proxy_str):
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM proxies WHERE proxy = ?", (proxy_str,)).fetchone()
        return dict(row) if row else None

    def get_source_stats(self):
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM source_stats ORDER BY unique_added DESC").fetchall()
        return [dict(r) for r in rows]

    def apply_score_decay(self):
        """Decay scores for proxies not seen recently. Mark stale/dead."""
        conn = self._get_conn()
        now = time.time()
        decay_seconds = SCORE_DECAY_HOURS * 3600

        # Mark proxies as stale if not checked recently
        conn.execute("""
            UPDATE proxies SET health_status = 'stale'
            WHERE last_checked < ? AND health_status = 'fresh'
        """, (now - decay_seconds,))

        # Decay scores
        conn.execute("""
            UPDATE proxies SET score = CAST(score * 0.9 AS INTEGER)
            WHERE last_checked < ? AND score > 0
        """, (now - decay_seconds,))

# ==========================
# QUALITY SCORING
# ==========================

def calculate_score(result: ProxyResult, uptime_pct: float = 100.0, times_seen: int = 1) -> int:
    latency_score = max(0, 100 - (result.latency / FAST_THRESHOLD_MS * 100))
    latency_score = min(100, latency_score)
    anon_score = ANONYMITY_SCORES.get(result.anonymity or "unknown", 40)
    reliability_score = min(100, uptime_pct)
    proto_score = PROTOCOL_SCORES.get(result.scheme, 50)
    total = (
        latency_score * SCORE_LATENCY_WEIGHT +
        anon_score * SCORE_ANONYMITY_WEIGHT +
        reliability_score * SCORE_RELIABILITY_WEIGHT +
        proto_score * SCORE_TYPE_WEIGHT
    ) / 100.0
    return int(round(min(100, max(0, total))))

# ==========================
# ANONYMITY + GEOIP
# ==========================

_REAL_IP_CACHE: Optional[str] = None
_GEOIP_CACHE: Dict[str, Tuple] = {}
_LAST_GEOIP_REQUEST: float = 0.0

def get_real_ip(session) -> Optional[str]:
    global _REAL_IP_CACHE
    if _REAL_IP_CACHE:
        return _REAL_IP_CACHE
    if not HAS_REQUESTS:
        return None
    try:
        r = session.get("https://api.ipify.org?format=json", timeout=(5, 10))
        if r.status_code == 200:
            _REAL_IP_CACHE = r.json().get("ip")
            return _REAL_IP_CACHE
    except Exception:
        pass
    return None

def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except Exception:
        return False

def detect_anonymity(proxy_str, scheme, session, real_ip=None):
    if not HAS_REQUESTS:
        return "unknown", None
    # For "https" labeled proxies, test via http:// CONNECT tunnel
    connect_scheme = "http" if scheme == "https" else scheme
    proxy_url = f"{connect_scheme}://{proxy_str}"
    try:
        r = session.get(
            ANONYMITY_CHECK_URL,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
        )
        if r.status_code != 200:
            return "unknown", None
        data = r.json()
        headers = data.get("headers", {})
        external_ip = None
        if "X-Forwarded-For" in headers:
            external_ip = headers["X-Forwarded-For"].split(",")[0].strip()
        elif "X-Real-Ip" in headers:
            external_ip = headers["X-Real-Ip"].strip()
        elif "Forwarded" in headers:
            fwd = headers["Forwarded"]
            for part in fwd.split(";"):
                if "for=" in part:
                    external_ip = part.split("for=")[1].strip().strip('"')
        proxy_headers = [h.lower() for h in headers.keys()]
        has_via = any("via" in h for h in proxy_headers)
        has_xforwarded = any("x-forwarded" in h or "forwarded" in h for h in proxy_headers)
        has_proxy_connection = any("proxy" in h for h in proxy_headers)
        if real_ip and external_ip and external_ip == real_ip:
            return "transparent", external_ip
        if external_ip and _is_public_ip(external_ip):
            return "transparent", external_ip
        elif has_via or has_xforwarded or has_proxy_connection:
            return "anonymous", external_ip
        else:
            return "elite", None
    except Exception:
        return "unknown", None

def detect_geoip(proxy_str, scheme, session):
    global _GEOIP_CACHE, _LAST_GEOIP_REQUEST
    if not HAS_REQUESTS:
        return None, None, None, None
    connect_scheme = "http" if scheme == "https" else scheme
    proxy_url = f"{connect_scheme}://{proxy_str}"
    try:
        r = session.get(
            "https://api.ipify.org?format=json",
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
        )
        if r.status_code != 200:
            return None, None, None, None
        external_ip = r.json().get("ip")
        if not external_ip:
            return None, None, None, None
        if external_ip in _GEOIP_CACHE:
            return _GEOIP_CACHE[external_ip]
        elapsed = time.time() - _LAST_GEOIP_REQUEST
        if elapsed < (GEOIP_RATE_LIMIT_MS / 1000.0):
            time.sleep(GEOIP_RATE_LIMIT_MS / 1000.0 - elapsed)
        _LAST_GEOIP_REQUEST = time.time()
        geo_r = session.get(GEOIP_URL.format(ip=external_ip), timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        if geo_r.status_code != 200:
            return None, None, None, None
        data = geo_r.json()
        if data.get("status") != "success":
            return None, None, None, None
        result = (data.get("country"), data.get("countryCode"),
                  data.get("city"), data.get("isp") or data.get("org"))
        _GEOIP_CACHE[external_ip] = result
        return result
    except Exception:
        return None, None, None, None

def enrich_proxy(result, db, real_ip=None):
    if not HAS_REQUESTS:
        return result
    thread_local = getattr(enrich_proxy, '_local', threading.local())
    if not hasattr(thread_local, 'session'):
        thread_local.session = requests.Session()
        adapter = HTTPAdapter(max_retries=0, pool_connections=20, pool_maxsize=20)
        thread_local.session.mount("http://", adapter)
        thread_local.session.mount("https://", adapter)
        thread_local.session.headers.update({"User-Agent": "Mozilla/5.0"})
    enrich_proxy._local = thread_local
    session = thread_local.session

    history = db.get_proxy_history(result.proxy)
    uptime_pct = 100.0
    times_seen = 1
    if history:
        uptime_pct = history.get("uptime_pct", 100.0)
        times_seen = history.get("times_seen", 1) + 1

    try:
        anonymity, external_ip = detect_anonymity(result.proxy, result.scheme, session, real_ip=real_ip)
        result.anonymity = anonymity
        result.external_ip = external_ip
    except Exception:
        result.anonymity = "unknown"

    if history and history.get("country"):
        result.country = history.get("country")
        result.country_code = history.get("country_code")
        result.city = history.get("city")
        result.isp = history.get("isp")
    else:
        try:
            country, cc, city, isp = detect_geoip(result.proxy, result.scheme, session)
            result.country = country
            result.country_code = cc
            result.city = city
            result.isp = isp
        except Exception:
            pass

    result.score = calculate_score(result, uptime_pct, times_seen)
    result.times_seen = times_seen
    result.uptime_pct = uptime_pct
    return result

# ==========================
# CONFIG / SOURCES
# ==========================

DEFAULT_SOURCES = [
    ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt", "auto"),
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "http"),
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt", "https"),
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/oxylabs/free-proxy-list/main/http.txt", "http"),
    ("https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", "auto"),
    ("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "socks5"),
    ("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt", "http"),
    ("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt", "https"),
    ("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt", "http"),
    ("https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt", "https"),
    ("https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks4/socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt", "http"),
    ("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", "http"),
    ("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt", "https"),
    ("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "http"),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/https.txt", "https"),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "https"),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt", "socks4"),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "socks5"),
    ("https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt", "http"),
    ("https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/https.txt", "https"),
    ("https://raw.githubusercontent.com/database64128/proxy-checker/main/proxies/http.txt", "http"),
    ("https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt", "auto"),
    ("https://raw.githubusercontent.com/zloi-user/hideip.me/master/https.txt", "https"),
    ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt", "http"),
    ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/https/data.txt", "https"),
    ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt", "socks4"),
    ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt", "socks5"),
    ("https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt", "https"),
    ("https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/http.txt", "http"),
    ("https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/https.txt", "https"),
    ("https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/iplocate/free-proxy-list/main/http.txt", "http"),
    ("https://raw.githubusercontent.com/iplocate/free-proxy-list/main/https.txt", "https"),
    ("https://raw.githubusercontent.com/iplocate/free-proxy-list/main/socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/iplocate/free-proxy-list/main/socks5.txt", "socks5"),
    ("https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/http.txt", "http"),
    ("https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/https.txt", "https"),
    ("https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/socks5.txt", "socks5"),
    ("https://api.proxyscrape.com/?request=getproxies&proxytype=http", "http"),
    ("https://api.proxyscrape.com/?request=getproxies&proxytype=socks4", "socks4"),
    ("https://api.proxyscrape.com/?request=getproxies&proxytype=socks5", "socks5"),
    ("https://www.proxy-list.download/api/v1/get?type=http", "http"),
    ("https://www.proxy-list.download/api/v1/get?type=https", "https"),
    ("https://www.proxy-list.download/api/v1/get?type=socks4", "socks4"),
    ("https://www.proxy-list.download/api/v1/get?type=socks5", "socks5"),
    ("http://pubproxy.com/api/proxy?limit=20&format=txt", "auto"),
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text", "auto"),
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&protocol=http", "http"),
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&protocol=https", "https"),
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&protocol=socks4", "socks4"),
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&protocol=socks5", "socks5"),
    ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt", "http"),
    ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/main/http.txt", "http"),
    ("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/main/https.txt", "https"),
    ("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/main/socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/main/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/gnxD3RfTT2WE/public-proxy-list/main/proxies.txt", "auto"),
    ("https://raw.githubusercontent.com/yael-ka/Free-Proxy-List/main/proxy_list.json", "auto"),
    ("https://proxylist.icu/proxy.txt", "auto"),
    ("https://free-proxy-list.net/anonymous-proxy.html", "auto"),
    ("https://www.sslproxies.org/proxy-list", "https"),
    ("https://www.us-proxy.org/proxy-list", "http"),
]

HTML_SOURCES = [
    {"url": "https://spys.one/free-proxy-list/ALL/", "scheme": "auto", "parser": "spys_one"},
    {"url": "https://hidemy.name/en/proxy-list/", "scheme": "auto", "parser": "hidemy_name"},
    {"url": "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list", "scheme": "auto", "parser": "fate0"},
]

# ==========================
# HTML PARSERS
# ==========================

def parse_spys_one(html_content):
    proxies = []
    if not HAS_BS4:
        proxy_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*:\s*(\d+)')
        for match in proxy_pattern.finditer(html_content):
            proxies.append((f"{match.group(1)}:{match.group(2)}", "auto"))
        return proxies
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        table = soup.find('table', {'id': 'proxylist'}) or soup.find('table', class_=re.compile('proxy|table'))
        if table:
            for row in table.find_all('tr')[1:]:
                cols = row.find_all('td')
                if len(cols) >= 3:
                    ip, port = cols[0].get_text(strip=True), cols[1].get_text(strip=True)
                    if ip and port:
                        scheme = "auto"
                        if len(cols) > 2:
                            t = cols[2].get_text(strip=True).lower()
                            scheme = "socks5" if "socks5" in t else "socks4" if "socks4" in t else "https" if "https" in t else "http" if "http" in t else "auto"
                        proxies.append((f"{ip}:{port}", scheme))
        if not proxies:
            proxy_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*:\s*(\d+)')
            for match in proxy_pattern.finditer(html_content):
                proxies.append((f"{match.group(1)}:{match.group(2)}", "auto"))
    except Exception:
        pass
    return proxies

def parse_hidemy_name(html_content):
    proxies = []
    if not HAS_BS4:
        proxy_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:;]\s*(\d+)')
        for match in proxy_pattern.finditer(html_content):
            proxies.append((f"{match.group(1)}:{match.group(2)}", "auto"))
        return proxies
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        table = soup.find('table', class_=re.compile('proxy|table|list')) or soup.find('table', {'id': 'list'})
        if table:
            for row in table.find_all('tr')[1:]:
                cols = row.find_all('td')
                if len(cols) >= 3:
                    ip, port = cols[0].get_text(strip=True), cols[1].get_text(strip=True)
                    if ip and port:
                        scheme = "auto"
                        if len(cols) > 2:
                            t = cols[2].get_text(strip=True).lower()
                            scheme = "socks5" if "socks5" in t else "socks4" if "socks4" in t else "https" if "https" in t else "http" if "http" in t else "auto"
                        proxies.append((f"{ip}:{port}", scheme))
        if not proxies:
            proxy_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:;]\s*(\d+)')
            for match in proxy_pattern.finditer(html_content):
                proxies.append((f"{match.group(1)}:{match.group(2)}", "auto"))
    except Exception:
        pass
    return proxies

def parse_fate0(html_content):
    proxies = []
    try:
        for line in html_content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                host, port = row.get("host"), row.get("port")
                ptype = str(row.get("type", "")).lower()
                if host and port:
                    scheme = "socks5" if "socks5" in ptype else "socks4" if "socks4" in ptype else "https" if "https" in ptype else "http" if "http" in ptype else "auto"
                    proxies.append((f"{host}:{port}", scheme))
            except Exception:
                pass
    except Exception:
        pass
    return proxies

PARSER_MAP = {"spys_one": parse_spys_one, "hidemy_name": parse_hidemy_name, "fate0": parse_fate0}

# ==========================
# HELPERS
# ==========================

def get_desktop():
    for p in [Path.home() / "Desktop", Path.home() / "OneDrive" / "Desktop"]:
        if p.exists():
            return p
    return Path.home()

def normalize_proxy(line):
    line = line.strip()
    if not line:
        return None
    for prefix in ("http://", "https://", "socks4://", "socks5://"):
        line = line.replace(prefix, "")
    line = line.strip().strip("/")
    if ":" not in line:
        return None
    host, port = line.rsplit(":", 1)
    host, port = host.strip(), port.strip()
    if not host or not port.isdigit():
        return None
    return f"{host}:{port}"

def fmt_num(n):
    try:
        return f"{int(n):,}"
    except Exception:
        return str(n)

def candidate_schemes(source_scheme):
    if source_scheme == "auto":
        return ["http", "https"]
    return [source_scheme]

def chunk_list(lst, size=BATCH_SIZE):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]

def load_sources():
    if SOURCES_PATH.exists():
        with open(SOURCES_PATH, "r") as f:
            return json.load(f)
    config = {
        "plain_sources": [{"url": u, "scheme": s} for u, s in DEFAULT_SOURCES],
        "html_sources": HTML_SOURCES,
    }
    with open(SOURCES_PATH, "w") as f:
        json.dump(config, f, indent=2)
    return config

# ==========================
# CONCURRENT SOURCE DOWNLOADER (async)
# ==========================

class AsyncSourceDownloader:
    """Download all sources concurrently with aiohttp."""

    def __init__(self, db, log_func=None, cancel_event=None):
        self.db = db
        self.log = log_func or (lambda x: None)
        self.cancel = cancel_event or threading.Event()
        self.source_stats = {}

    async def fetch_source(self, session, url, scheme, is_html=False, parser_name=None):
        """Fetch a single source and return parsed proxies."""
        stats = SourceStats(name=url.split("/")[-1][:40], url=url, scheme=scheme)
        # Load previous stats from DB
        try:
            prev = self.db.get_source_stats()
            for p in prev:
                if p.get("url") == url:
                    stats.consecutive_failures = p.get("consecutive_failures", 0)
                    stats.enabled = p.get("enabled", 1) == 1
                    break
        except Exception:
            pass

        if not stats.enabled:
            self.log(f"[SKIP] {url} (auto-disabled)")
            self.source_stats[url] = stats
            return []

        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=SOURCE_FETCH_TIMEOUT)) as r:
                r.raise_for_status()
                text = await r.text()

            if is_html and parser_name:
                parser = PARSER_MAP.get(parser_name)
                parsed = parser(text) if parser else []
            else:
                parsed = [(normalize_proxy(line), scheme) for line in text.splitlines()]
                parsed = [(p, s) for p, s in parsed if p]

            stats.total_fetched = len(parsed)
            stats.consecutive_failures = 0
            stats.last_success = time.time()
            stats.enabled = True
            self.log(f"[OK] +{len(parsed)} from {url.split('/')[-1]}")
            return parsed
        except Exception as e:
            stats.consecutive_failures += 1
            stats.last_error = str(e)[:200]
            stats.enabled = stats.consecutive_failures < SOURCE_FAILURE_THRESHOLD
            self.log(f"[FAIL] {url.split('/')[-1]}: {str(e)[:60]}")
            return []
        finally:
            self.source_stats[url] = stats
            self.db.update_source_stats(stats)

    async def download_all(self, config):
        """Download all sources concurrently."""
        semaphore = asyncio.Semaphore(SOURCE_FETCH_CONCURRENCY)
        timeout = aiohttp.ClientTimeout(total=SOURCE_FETCH_TIMEOUT)
        connector = TCPConnector(limit=SOURCE_FETCH_CONCURRENCY, limit_per_host=5, ttl_dns_cache=300, enable_cleanup_closed=True)
        headers = {"User-Agent": "Mozilla/5.0"}

        all_proxies = {}  # (proxy, scheme) -> source_url

        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            tasks = []

            # HTML sources
            for src in config.get("html_sources", []):
                if self.cancel.is_set():
                    break
                async def fetch_html(s, url=src["url"], scheme=src["scheme"], parser=src["parser"]):
                    async with semaphore:
                        return await self.fetch_source(s, url, scheme, is_html=True, parser_name=parser)
                tasks.append(fetch_html(session))

            # Plain sources
            for src in config.get("plain_sources", []):
                if self.cancel.is_set():
                    break
                async def fetch_plain(s, url=src["url"], scheme=src["scheme"]):
                    async with semaphore:
                        return await self.fetch_source(s, url, scheme)
                tasks.append(fetch_plain(session))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Deduplicate
        for result in results:
            if isinstance(result, list):
                for proxy, scheme in result:
                    key = (proxy, scheme)
                    if key not in all_proxies:
                        all_proxies[key] = None  # source tracking done separately

        # Update unique counts
        for url, stats in self.source_stats.items():
            stats.unique_added = sum(1 for (p, s) in all_proxies if s == stats.scheme)
            self.db.update_source_stats(stats)

        return [(proxy, scheme) for (proxy, scheme) in all_proxies]

# ==========================
# ASYNC PROXY VALIDATOR
# ==========================

class AsyncProxyValidator:
    """Validate proxies with proper SOCKS support and HTTPS CONNECT semantics."""

    def __init__(self, max_connections=100, cancel_event=None):
        self.max_connections = max_connections
        self.cancel = cancel_event or threading.Event()
        self.timeout = ClientTimeout(
            total=CONNECT_TIMEOUT + READ_TIMEOUT,
            connect=CONNECT_TIMEOUT,
        )

    async def validate_proxy(self, proxy, scheme, source_url=None) -> Optional[ProxyResult]:
        """Validate a single proxy against all test URLs."""
        schemes = ["http", "https"] if scheme == "auto" else [scheme]

        for proto in schemes:
            if self.cancel.is_set():
                return None

            # For "https" labeled proxies, connect via http:// (CONNECT tunnel)
            connect_proto = "http" if proto == "https" else proto
            proxy_url = f"{connect_proto}://{proxy}"
            start = time.perf_counter()

            try:
                if connect_proto in ("socks4", "socks5") and HAS_AIOHTTP_SOCKS:
                    # SOCKS via aiohttp_socks
                    socks_url = f"socks4://{proxy}" if connect_proto == "socks4" else f"socks5://{proxy}"
                    connector = ProxyConnector.from_url(socks_url)
                    async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as sock_session:
                        async with sock_session.get(TEST_URLS[0]) as response:
                            latency = int((time.perf_counter() - start) * 1000)
                            if response.status == 200 and latency <= FAST_THRESHOLD_MS:
                                return ProxyResult(
                                    proxy=proxy, scheme=proto, latency=latency,
                                    url=TEST_URLS[0], source=source_url,
                                )
                else:
                    # HTTP/HTTPS proxy (requests uses CONNECT for https:// targets)
                    async with aiohttp.ClientSession(timeout=self.timeout) as http_session:
                        async with http_session.get(
                            TEST_URLS[0], proxy=proxy_url,
                        ) as response:
                            latency = int((time.perf_counter() - start) * 1000)
                            if response.status == 200 and latency <= FAST_THRESHOLD_MS:
                                return ProxyResult(
                                    proxy=proxy, scheme=proto, latency=latency,
                                    url=TEST_URLS[0], source=source_url,
                                )
            except Exception:
                continue

        # Try remaining test URLs with the first working scheme (if any)
        # Already tried all schemes against URL[0], now try other URLs
        found_scheme = schemes[0] if schemes else "http"
        for url in TEST_URLS[1:]:
            if self.cancel.is_set():
                return None
            connect_proto = "http" if found_scheme == "https" else found_scheme
            proxy_url = f"{connect_proto}://{proxy}"
            start = time.perf_counter()
            try:
                async with aiohttp.ClientSession(timeout=self.timeout) as http_session:
                    async with http_session.get(url, proxy=proxy_url) as response:
                        latency = int((time.perf_counter() - start) * 1000)
                        if response.status == 200 and latency <= FAST_THRESHOLD_MS:
                            return ProxyResult(
                                proxy=proxy, scheme=found_scheme, latency=latency,
                                url=url, source=source_url,
                            )
            except Exception:
                continue

        return None

    async def validate_batch(self, proxy_batch, semaphore):
        """Validate a batch of proxies with bounded concurrency."""
        tasks = []
        for item in proxy_batch:
            proxy, scheme = item[0], item[1]
            source_url = item[2] if len(item) > 2 else None

            async def validate_one(p=proxy, s=scheme, src=source_url):
                async with semaphore:
                    return await self.validate_proxy(p, s, src)

            tasks.append(validate_one())

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid = []
        for result in results:
            if isinstance(result, ProxyResult):
                valid.append(result)
        return valid

# ==========================
# SYNC FALLBACK VALIDATOR
# ==========================

thread_local = threading.local()

def _get_thread_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        adapter = HTTPAdapter(max_retries=0, pool_connections=20, pool_maxsize=20)
        thread_local.session.mount("http://", adapter)
        thread_local.session.mount("https://", adapter)
        thread_local.session.headers.update({"User-Agent": "Mozilla/5.0"})
    return thread_local.session

def validate_proxy_sync(proxy, scheme, source_url=None, cancel_event=None):
    if not HAS_REQUESTS:
        return None
    session = _get_thread_session()
    for proto in candidate_schemes(scheme):
        if cancel_event and cancel_event.is_set():
            return None
        # HTTPS proxies connect via http:// CONNECT tunnel
        connect_proto = "http" if proto == "https" else proto
        proxy_url = f"{connect_proto}://{proxy}"
        start = time.perf_counter()
        try:
            r = session.get(
                TEST_URLS[0],
                proxies={"http": proxy_url, "https": proxy_url},
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            latency = int((time.perf_counter() - start) * 1000)
            if r.status_code == 200 and latency <= FAST_THRESHOLD_MS:
                return ProxyResult(proxy=proxy, scheme=proto, latency=latency, url=TEST_URLS[0], source=source_url)
        except Exception:
            pass
    # Try remaining URLs
    for url in TEST_URLS[1:]:
        if cancel_event and cancel_event.is_set():
            return None
        proto = candidate_schemes(scheme)[0]
        connect_proto = "http" if proto == "https" else proto
        proxy_url = f"{connect_proto}://{proxy}"
        start = time.perf_counter()
        try:
            r = session.get(
                url,
                proxies={"http": proxy_url, "https": proxy_url},
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            latency = int((time.perf_counter() - start) * 1000)
            if r.status_code == 200 and latency <= FAST_THRESHOLD_MS:
                return ProxyResult(proxy=proxy, scheme=proto, latency=latency, url=url, source=source_url)
        except Exception:
            pass
    return None

# ==========================
# ADVANCED EXPORT
# ==========================

def save_results_advanced(results, format_type="all", filters=None):
    results.sort(key=lambda x: (-x.score, x.latency))
    if filters:
        results = apply_filters(results, filters)

    desktop = get_desktop()
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_dir = desktop / f"proxy_export_{timestamp}"
    output_dir.mkdir(exist_ok=True)
    files_saved = []
    grouped = defaultdict(list)
    for result in results:
        grouped[result.scheme].append(result.proxy)

    if format_type in ["plain", "all"]:
        plain_files = {
            "working_all.txt": [r.proxy for r in results],
            "http.txt": grouped.get("http", []),
            "https.txt": grouped.get("https", []),
            "socks4.txt": grouped.get("socks4", []),
            "socks5.txt": grouped.get("socks5", []),
            "elite.txt": [r.proxy for r in results if r.anonymity == "elite"],
            "anonymous.txt": [r.proxy for r in results if r.anonymity == "anonymous"],
        }
        for name, data in plain_files.items():
            path = output_dir / name
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(data))
            files_saved.append(str(path))

    if format_type in ["json", "all"]:
        json_path = output_dir / "proxy_results.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in results], f, indent=2, default=str)
        files_saved.append(str(json_path))

    if format_type in ["csv", "all"]:
        csv_path = output_dir / "proxy_results.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "proxy", "scheme", "latency", "score", "anonymity",
                "country", "country_code", "city", "isp",
                "external_ip", "source", "health_status", "timestamp"
            ])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "proxy": r.proxy, "scheme": r.scheme, "latency": r.latency,
                    "score": r.score, "anonymity": r.anonymity or "unknown",
                    "country": r.country or "", "country_code": r.country_code or "",
                    "city": r.city or "", "isp": r.isp or "",
                    "external_ip": r.external_ip or "", "source": r.source or "",
                    "health_status": r.health_status, "timestamp": r.timestamp,
                })
        files_saved.append(str(csv_path))

    if format_type in ["schemed", "all"]:
        schemed_path = output_dir / "proxy_schemed.txt"
        with open(schemed_path, "w", encoding="utf-8") as f:
            f.write("\n".join(f"{r.scheme}://{r.proxy}" for r in results))
        files_saved.append(str(schemed_path))

    if format_type in ["sqlite", "all"]:
        import shutil
        db_export_path = output_dir / "proxy_database.db"
        shutil.copy2(str(DB_PATH), str(db_export_path))
        files_saved.append(str(db_export_path))

    return output_dir, files_saved

def apply_filters(results, filters):
    filtered = results
    if filters.get("scheme"):
        filtered = [r for r in filtered if r.scheme == filters["scheme"]]
    if filters.get("country"):
        filtered = [r for r in filtered if r.country_code == filters["country"]]
    if filters.get("anonymity"):
        filtered = [r for r in filtered if r.anonymity == filters["anonymity"]]
    if filters.get("min_score"):
        filtered = [r for r in filtered if r.score >= filters["min_score"]]
    if filters.get("max_latency"):
        filtered = [r for r in filtered if r.latency <= filters["max_latency"]]
    return filtered

# ==========================
# PROXY ROTATION API SERVER
# ==========================

class ProxyRotationServer:
    """Local HTTP API server for proxy rotation."""

    def __init__(self, db, host="127.0.0.1", port=8888):
        self.db = db
        self.host = host
        self.port = port

    async def handle_get_proxy(self, request):
        """GET /proxy/best?limit=10&scheme=http&country=RO&min_score=80&anonymity=elite"""
        params = request.query
        limit = int(params.get("limit", 1))
        scheme = params.get("scheme")
        country = params.get("country")
        anonymity = params.get("anonymity")
        min_score = int(params.get("min_score", 0))
        max_latency = int(params.get("max_latency", 9999))
        random = params.get("random", "false").lower() == "true"

        if random:
            proxy = self.db.get_random_proxy(scheme=scheme, country=country, min_score=min_score)
            if proxy:
                return aiohttp_web.json_response(proxy)
            return aiohttp_web.json_response({"error": "no proxies found"}, status=404)
        else:
            proxies = self.db.get_best_proxies(
                limit=limit, scheme=scheme, country=country,
                anonymity=anonymity, min_score=min_score, max_latency=max_latency,
            )
            return aiohttp_web.json_response({"count": len(proxies), "proxies": proxies})

    async def handle_stats(self, request):
        """GET /stats"""
        return aiohttp_web.json_response(self.db.get_stats_summary())

    async def handle_health(self, request):
        """GET /health"""
        summary = self.db.get_stats_summary()
        return aiohttp_web.json_response({"status": "ok", "working_proxies": summary["total_working"]})

    def start(self):
        """Start the API server (blocking)."""
        if not HAS_AIOHTTP_WEB:
            print("[ERROR] aiohttp.web not available for API server")
            return

        app = aiohttp_web.Application()
        app.router.add_get("/proxy/best", self.handle_get_proxy)
        app.router.add_get("/proxy/random", self.handle_get_proxy)
        app.router.add_get("/proxy", self.handle_get_proxy)
        app.router.add_get("/stats", self.handle_stats)
        app.router.add_get("/health", self.handle_health)

        print(f"[API] Proxy rotation server starting on http://{self.host}:{self.port}")
        print(f"[API] Endpoints:")
        print(f"[API]   GET /proxy/best?limit=10&scheme=http&min_score=80")
        print(f"[API]   GET /proxy/random?country=RO&anonymity=elite")
        print(f"[API]   GET /stats")
        print(f"[API]   GET /health")
        aiohttp_web.run_app(app, host=self.host, port=self.port, print=lambda *a: None)

# ==========================
# CORE SCAN ENGINE (async pipeline)
# ==========================

class ScanEngine:
    """Async pipeline scan engine with decoupled enrichment."""

    def __init__(self, db, settings, log_func=None, ui_callback=None, cancel_event=None, pause_event=None):
        self.db = db
        self.settings = settings
        self.log = log_func or (lambda x: None)
        self.ui_callback = ui_callback  # Called with (event_type, data) tuples
        self.cancel = cancel_event or threading.Event()
        self.pause = pause_event or threading.Event()
        self.pause.set()  # not paused
        self.scan_stats = ScanStats()
        self.working_results: List[ProxyResult] = []
        self.real_ip: Optional[str] = None

    def _emit(self, event_type, data):
        if self.ui_callback:
            self.ui_callback(event_type, data)

    async def run_scan(self, use_async=True, do_enrich=True, do_persist=True, output_format="all"):
        """Run the full scan pipeline."""
        scan_start = time.time()
        config = load_sources()
        total_sources = len(config.get("plain_sources", [])) + len(config.get("html_sources", []))

        self.log("=" * 60)
        self.log(f"[BOOT] {APP_NAME} v{APP_VERSION}")
        self.log(f"[CPU] Threads: {LOGICAL_THREADS} | Workers: {self.settings.get('workers')}")
        self.log(f"[CFG] Async: {use_async} | Enrich: {do_enrich} | Persist: {do_persist}")
        self.log(f"[CFG] Output: {output_format}")
        self.log("=" * 60)

        # Fetch real IP
        if do_enrich and HAS_REQUESTS:
            self.log("[INFO] Fetching real IP for anonymity detection...")
            try:
                s = requests.Session()
                self.real_ip = get_real_ip(s)
                if self.real_ip:
                    self.log(f"[INFO] Real IP: {self.real_ip}")
            except Exception:
                self.log("[WARN] Real IP fetch failed")

        if use_async and not HAS_AIOHTTP_SOCKS:
            self.log("[WARN] aiohttp_socks not installed - SOCKS async will use HTTP fallback")
        if not HAS_AIOHTTP:
            self.log("[WARN] aiohttp not installed - falling back to sync mode")
            use_async = False

        # Phase 1: Concurrent source download
        self.log("[PHASE 1] Downloading sources concurrently...")
        self._emit("status", "DOWNLOADING SOURCES")

        if use_async and HAS_AIOHTTP:
            downloader = AsyncSourceDownloader(self.db, self.log, self.cancel)
            proxies = await downloader.download_all(config)
        else:
            # Sync fallback download
            proxies = self._download_sources_sync(config)

        total = len(proxies)
        self.scan_stats.total_proxies = total
        self._emit("sources", total_sources)
        self._emit("proxies", total)
        self.log(f"[INFO] Total unique proxies: {fmt_num(total)}")

        if total == 0:
            self.log("[ABORT] No proxies found")
            self._emit("status", "NO PROXIES FOUND")
            return

        if self.cancel.is_set():
            self.log("[STOP] Cancelled")
            self._emit("status", "CANCELLED")
            return

        # Phase 2: Validation (async or sync)
        self.log("[PHASE 2] Validating proxies...")
        self._emit("status", "VALIDATING")

        if use_async and HAS_AIOHTTP:
            await self._validate_async(proxies, do_enrich, do_persist)
        else:
            self._validate_sync(proxies, do_enrich, do_persist)

        if self.cancel.is_set():
            self.log("[STOP] Stopped. Saving partial results...")

        # Phase 3: Batch DB persistence
        if do_persist and self.working_results:
            self.log("[DB] Batch saving to SQLite...")
            try:
                self.db.batch_upsert_proxies(self.working_results)
                self.log(f"[DB] Saved {len(self.working_results)} proxies (batched)")
            except Exception as e:
                self.log(f"[DB ERR] Batch save failed, trying individual: {e}")
                for result in self.working_results:
                    try:
                        self.db.upsert_proxy(result)
                    except Exception:
                        pass

        # Phase 4: Export
        self.log("[PHASE 4] Exporting results...")
        filters = self._build_filters()
        output_dir, files = save_results_advanced(self.working_results, output_format, filters if filters else None)
        self._emit("saved", f"{len(files)} files")
        self.log(f"[SAVE] Exported to: {output_dir}")

        # Record scan
        duration = time.time() - scan_start
        if do_persist:
            proto_counts = Counter(r.scheme for r in self.working_results)
            country_counts = Counter(r.country_code for r in self.working_results if r.country_code)
            anon_counts = Counter(r.anonymity or "unknown" for r in self.working_results)
            error_counts = dict(self.scan_stats.errors)
            avg_latency = sum(r.latency for r in self.working_results) / len(self.working_results) if self.working_results else 0
            throughput = self.scan_stats.throughput

            self.db.record_scan(
                total_fetched=total, total_working=len(self.working_results),
                duration=duration, avg_latency=avg_latency, throughput=throughput,
                by_protocol=dict(proto_counts), by_country=dict(country_counts),
                by_anonymity=dict(anon_counts), by_error=error_counts,
            )

        # Apply score decay
        if do_persist:
            self.db.apply_score_decay()

        self.log("=" * 60)
        self.log(f"[DONE] Working: {len(self.working_results)} | Time: {duration:.1f}s")
        self.log(f"[STATS] Throughput: {self.scan_stats.throughput:.0f}/s | ETA was: {self.scan_stats.format_eta()}")
        if self.scan_stats.latencies:
            self.log(f"[STATS] Latency p50: {self.scan_stats.p50}ms | p90: {self.scan_stats.p90}ms | p95: {self.scan_stats.p95}ms")
        elite_count = sum(1 for r in self.working_results if r.anonymity == "elite")
        self.log(f"[STATS] Elite: {elite_count} | Errors: {dict(self.scan_stats.errors)}")
        self.log("=" * 60)
        self._emit("status", f"COMPLETE - {len(self.working_results)} WORKING")
        self._emit("progress", 1.0)

    async def _validate_async(self, proxies, do_enrich, do_persist):
        """Async validation pipeline with decoupled enrichment."""
        workers = self.settings.get("workers", DEFAULT_WORKERS)
        semaphore = asyncio.Semaphore(workers)
        validator = AsyncProxyValidator(max_connections=workers, cancel_event=self.cancel)

        # Process in batches
        batches = list(chunk_list(proxies, BATCH_SIZE))
        total_batches = len(batches)

        for batch_idx, batch in enumerate(batches):
            if self.cancel.is_set():
                break
            self.pause.wait()  # Block if paused

            self.log(f"[BATCH] {batch_idx + 1}/{total_batches} (async, {len(batch)} proxies)")

            # Validate batch
            results = await validator.validate_batch(batch, semaphore)

            # Update working results immediately (before enrichment)
            for result in results:
                self.working_results.append(result)
                self.scan_stats.working += 1
                self.scan_stats.latencies.append(result.latency)
                self._emit("working", len(self.working_results))
                self._emit("result", result)

                anon_str = result.anonymity or "unknown"
                cc_str = result.country_code or "??"
                self.log(f"[OK] {result.proxy}  {result.latency}ms  [{result.scheme}]  {anon_str}  {cc_str}")

            # Update processed count
            self.scan_stats.processed += len(batch)
            self._emit("progress", self.scan_stats.processed / self.scan_stats.total_proxies)
            self._emit("eta", self.scan_stats.format_eta())
            self._emit("throughput", f"{self.scan_stats.throughput:.0f}/s")
            self._emit("status", f"SCANNING {fmt_num(self.scan_stats.processed)}/{fmt_num(self.scan_stats.total_proxies)}")

            # Live stats update
            proto_counts = Counter(r.scheme for r in self.working_results)
            anon_counts = Counter(r.anonymity or "unknown" for r in self.working_results)
            country_counts = Counter(r.country_code for r in self.working_results if r.country_code)
            self._emit("proto", dict(proto_counts))
            self._emit("anon", dict(anon_counts))
            self._emit("country", dict(country_counts))

            if self.working_results:
                avg_score = sum(r.score for r in self.working_results) / len(self.working_results)
                avg_latency = sum(r.latency for r in self.working_results) / len(self.working_results)
                self._emit("avg_score", f"{avg_score:.0f}")
                self._emit("avg_latency", f"{avg_latency:.0f}")

            # Update table (thread-safe via emit)
            self._emit("table_refresh", list(self.working_results))

            # Mark failed proxies in batch (batched DB write)
            if do_persist:
                working_set = {r.proxy for r in self.working_results}
                checked = {item[0] for item in batch}
                failed = list(checked - working_set)
                if failed:
                    try:
                        self.db.batch_mark_failed(failed)
                    except Exception:
                        pass
                self.scan_stats.failed += len(failed)

            # Decoupled enrichment (in background thread pool)
            if do_enrich and results:
                enrich_pool = ThreadPoolExecutor(max_workers=min(ENRICH_CONCURRENCY, len(results)))
                enrich_futures = []
                for result in results:
                    future = enrich_pool.submit(enrich_proxy, result, self.db, None, self.real_ip)
                    enrich_futures.append(future)

                for future in enrich_futures:
                    try:
                        future.result(timeout=15)
                    except Exception:
                        pass
                enrich_pool.shutdown(wait=False)

                # Re-emit enriched results
                self._emit("table_refresh", list(self.working_results))

            # Memory cleanup
            try:
                if HAS_PSUTIL:
                    process = psutil.Process()
                    mem_mb = process.memory_info().rss / 1024 / 1024
                    if mem_mb > self.settings.get("memory_limit", MAX_MEMORY_MB):
                        self.log("[MEM] Clearing cache...")
                        gc.collect()
            except Exception:
                pass

    def _validate_sync(self, proxies, do_enrich, do_persist):
        """Sync validation fallback."""
        workers = self.settings.get("workers", DEFAULT_WORKERS)
        batches = list(chunk_list(proxies, BATCH_SIZE))
        total_batches = len(batches)

        for batch_idx, batch in enumerate(batches):
            if self.cancel.is_set():
                break
            self.pause.wait()

            self.log(f"[BATCH] {batch_idx + 1}/{total_batches} (sync, {len(batch)} proxies)")

            results = []
            with ThreadPoolExecutor(max_workers=workers) as executor:
                jobs = {}
                for item in batch:
                    proxy, scheme = item[0], item[1]
                    source_url = item[2] if len(item) > 2 else None
                    job = executor.submit(validate_proxy_sync, proxy, scheme, source_url, self.cancel)
                    jobs[job] = (proxy, scheme)

                for job in as_completed(jobs):
                    if self.cancel.is_set():
                        break
                    try:
                        result = job.result()
                        if result:
                            results.append(result)
                    except Exception:
                        continue

            for result in results:
                self.working_results.append(result)
                self.scan_stats.working += 1
                self.scan_stats.latencies.append(result.latency)
                self._emit("working", len(self.working_results))
                self._emit("result", result)
                self.log(f"[OK] {result.proxy}  {result.latency}ms  [{result.scheme}]")

            self.scan_stats.processed += len(batch)
            self._emit("progress", self.scan_stats.processed / self.scan_stats.total_proxies)
            self._emit("eta", self.scan_stats.format_eta())
            self._emit("throughput", f"{self.scan_stats.throughput:.0f}/s")
            self._emit("status", f"SCANNING {fmt_num(self.scan_stats.processed)}/{fmt_num(self.scan_stats.total_proxies)}")

            # Live stats
            proto_counts = Counter(r.scheme for r in self.working_results)
            anon_counts = Counter(r.anonymity or "unknown" for r in self.working_results)
            country_counts = Counter(r.country_code for r in self.working_results if r.country_code)
            self._emit("proto", dict(proto_counts))
            self._emit("anon", dict(anon_counts))
            self._emit("country", dict(country_counts))
            self._emit("table_refresh", list(self.working_results))

            # Batch mark failed
            if do_persist:
                working_set = {r.proxy for r in self.working_results}
                checked = {item[0] for item in batch}
                failed = list(checked - working_set)
                if failed:
                    try:
                        self.db.batch_mark_failed(failed)
                    except Exception:
                        pass

            # Enrichment
            if do_enrich and results:
                enrich_pool = ThreadPoolExecutor(max_workers=min(ENRICH_CONCURRENCY, len(results)))
                for result in results:
                    enrich_pool.submit(enrich_proxy, result, self.db, None, self.real_ip)
                enrich_pool.shutdown(wait=True)
                self._emit("table_refresh", list(self.working_results))

    def _download_sources_sync(self, config):
        """Sequential source download fallback."""
        proxies = set()
        if not HAS_REQUESTS:
            return []
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=0, pool_connections=10, pool_maxsize=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": "Mozilla/5.0"})

        # HTML sources
        for src in config.get("html_sources", []):
            if self.cancel.is_set():
                break
            url, scheme, parser_name = src["url"], src["scheme"], src["parser"]
            try:
                self.log(f"[DB] {url}")
                r = session.get(url, timeout=(10, 20))
                r.raise_for_status()
                parser = PARSER_MAP.get(parser_name)
                parsed = parser(r.text) if parser else []
                for proxy, detected_scheme in parsed:
                    actual = detected_scheme if detected_scheme != "auto" else scheme
                    proxies.add((proxy, actual))
                self.log(f"[OK] +{len(parsed)} from {url}")
            except Exception as e:
                self.log(f"[FAIL] {url}: {str(e)[:60]}")

        # Plain sources
        for src in config.get("plain_sources", []):
            if self.cancel.is_set():
                break
            url, scheme = src["url"], src["scheme"]
            try:
                self.log(f"[DB] {url}")
                r = session.get(url, timeout=(4, 10))
                r.raise_for_status()
                for line in r.text.splitlines():
                    proxy = normalize_proxy(line)
                    if proxy:
                        proxies.add((proxy, scheme))
                self.log(f"[OK] +{len(r.text.splitlines())} from {url}")
            except Exception as e:
                self.log(f"[FAIL] {url}: {str(e)[:60]}")

        return list(proxies)

    def _build_filters(self):
        filters = {}
        scheme = self.settings.get("filter_scheme", "all")
        anon = self.settings.get("filter_anonymity", "all")
        min_score = self.settings.get("min_score", 0)
        max_lat = self.settings.get("max_latency", 5000)
        if scheme and scheme != "all":
            filters["scheme"] = scheme
        if anon and anon != "all":
            filters["anonymity"] = anon
        if min_score and min_score > 0:
            filters["min_score"] = min_score
        if max_lat and max_lat < 5000:
            filters["max_latency"] = max_lat
        return filters

# ==========================
# BACKGROUND HEALTH MONITOR
# ==========================

class HealthMonitor:
    """Background thread that re-validates stored proxies periodically."""

    def __init__(self, db, interval=HEALTH_CHECK_INTERVAL, log_func=None):
        self.db = db
        self.interval = interval
        self.log = log_func or (lambda x: None)
        self._thread = None
        self._running = False
        self.cancel = threading.Event()

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.log(f"[HEALTH] Background monitor started (interval: {self.interval}s)")

    def stop(self):
        self._running = False
        self.cancel.set()

    def _run(self):
        while self._running and not self.cancel.is_set():
            time.sleep(self.interval)
            if self.cancel.is_set():
                break
            try:
                self.log("[HEALTH] Running health check on stored proxies...")
                # Apply score decay
                self.db.apply_score_decay()
                # Get stale proxies
                conn = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level=None)
                conn.row_factory = sqlite3.Row
                stale = conn.execute(
                    "SELECT proxy, scheme FROM proxies WHERE health_status IN ('stale', 'unstable') LIMIT 100"
                ).fetchall()
                conn.close()

                if stale and HAS_REQUESTS:
                    session = requests.Session()
                    adapter = HTTPAdapter(max_retries=0, pool_connections=10, pool_maxsize=10)
                    session.mount("http://", adapter)
                    session.mount("https://", adapter)

                    revalidated = 0
                    for row in stale:
                        if self.cancel.is_set():
                            break
                        proxy_str = row["proxy"]
                        scheme = row["scheme"]
                        result = validate_proxy_sync(proxy_str, scheme, None, self.cancel)
                        if result:
                            self.db.upsert_proxy(result)
                            revalidated += 1
                        else:
                            self.db.batch_mark_failed([proxy_str])

                    self.log(f"[HEALTH] Revalidated {revalidated}/{len(stale)} stale proxies")
            except Exception as e:
                self.log(f"[HEALTH] Error: {e}")

# ==========================
# CLI MODE
# ==========================

def cli_main():
    """Command-line interface for headless operation."""
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{APP_VERSION} - CLI mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python proxy_scraper_v3.py scan --workers 300 --elite-only
  python proxy_scraper_v3.py scan --export csv --min-score 70
  python proxy_scraper_v3.py serve --port 8888
  python proxy_scraper_v3.py health-check
  python proxy_scraper_v3.py stats
  python proxy_scraper_v3.py export --format all --scheme socks5
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run a proxy scan")
    scan_parser.add_argument("--workers", type=int, default=SETTINGS.get("workers"), help="Number of worker threads")
    scan_parser.add_argument("--no-async", action="store_true", help="Use sync mode instead of async")
    scan_parser.add_argument("--no-enrich", action="store_true", help="Skip anonymity/GeoIP enrichment")
    scan_parser.add_argument("--no-persist", action="store_true", help="Skip SQLite persistence")
    scan_parser.add_argument("--export", choices=["plain", "json", "csv", "schemed", "sqlite", "all"], default="all", help="Export format")
    scan_parser.add_argument("--elite-only", action="store_true", help="Export only elite anonymity proxies")
    scan_parser.add_argument("--min-score", type=int, default=0, help="Minimum quality score (0-100)")
    scan_parser.add_argument("--max-latency", type=int, default=5000, help="Maximum latency in ms")
    scan_parser.add_argument("--scheme", choices=["http", "https", "socks4", "socks5"], help="Filter by protocol")

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start proxy rotation API server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    serve_parser.add_argument("--port", type=int, default=8888, help="Port")

    # Health check command
    subparsers.add_parser("health-check", help="Run health check on stored proxies")

    # Stats command
    subparsers.add_parser("stats", help="Show database statistics")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export proxies from database")
    export_parser.add_argument("--format", choices=["plain", "json", "csv", "schemed", "sqlite", "all"], default="all")
    export_parser.add_argument("--scheme", choices=["http", "https", "socks4", "socks5"])
    export_parser.add_argument("--country", help="Filter by country code (e.g. RO)")
    export_parser.add_argument("--anonymity", choices=["elite", "anonymous", "transparent"])
    export_parser.add_argument("--min-score", type=int, default=0)
    export_parser.add_argument("--max-latency", type=int, default=9999)
    export_parser.add_argument("--limit", type=int, default=1000)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    db = ProxyDatabase()
    log = lambda msg: print(f"[{time.strftime('%H:%M:%S')}] {msg}")

    if args.command == "scan":
        # Update settings
        SETTINGS.set("workers", args.workers)
        SETTINGS.set("use_async", not args.no_async)
        SETTINGS.set("do_enrich", not args.no_enrich)
        SETTINGS.set("do_persist", not args.no_persist)
        SETTINGS.set("output_format", args.export)

        cancel_event = threading.Event()
        pause_event = threading.Event()
        pause_event.set()

        engine = ScanEngine(
            db=db, settings=SETTINGS, log_func=log,
            cancel_event=cancel_event, pause_event=pause_event,
        )

        try:
            if not args.no_async and HAS_AIOHTTP:
                asyncio.run(engine.run_scan(
                    use_async=not args.no_async,
                    do_enrich=not args.no_enrich,
                    do_persist=not args.no_persist,
                    output_format=args.export,
                ))
            else:
                # Run sync pipeline in a thread with event loop wrapper
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(engine.run_scan(
                    use_async=False,
                    do_enrich=not args.no_enrich,
                    do_persist=not args.no_persist,
                    output_format=args.export,
                ))
                loop.close()
        except KeyboardInterrupt:
            log("[STOP] Interrupted by user")
            cancel_event.set()

    elif args.command == "serve":
        if not HAS_AIOHTTP_WEB:
            print("[ERROR] aiohttp is required for the API server. Install with: pip install aiohttp")
            return
        server = ProxyRotationServer(db, args.host, args.port)
        try:
            server.start()
        except KeyboardInterrupt:
            print("\n[STOP] Server stopped")

    elif args.command == "health-check":
        log("[HEALTH] Running health check...")
        monitor = HealthMonitor(db, interval=1, log_func=log)
        monitor._run()  # Run once
        log("[HEALTH] Done")

    elif args.command == "stats":
        summary = db.get_stats_summary()
        print(f"\n{'='*50}")
        print(f"  {APP_NAME} v{APP_VERSION} - Database Stats")
        print(f"{'='*50}")
        print(f"  Total stored:  {fmt_num(summary['total_stored'])}")
        print(f"  Working:       {fmt_num(summary['total_working'])}")
        print(f"  Avg score:     {summary['avg_score']}")
        print(f"  Avg latency:   {summary['avg_latency']}ms")
        print(f"\n  By Protocol:")
        for scheme, count in sorted(summary.get("by_scheme", {}).items(), key=lambda x: -x[1]):
            print(f"    {scheme:10s}  {count}")
        print(f"\n  By Anonymity:")
        for anon, count in sorted(summary.get("by_anonymity", {}).items(), key=lambda x: -x[1]):
            print(f"    {anon or 'unknown':15s}  {count}")
        print(f"\n  By Health:")
        for health, count in sorted(summary.get("by_health", {}).items(), key=lambda x: -x[1]):
            print(f"    {health or 'unknown':15s}  {count}")
        print(f"\n  Top Countries:")
        for cc, count in list(summary.get("by_country", {}).items())[:10]:
            print(f"    {cc:5s}  {count}")
        print(f"\n  Recent Scans: {len(summary.get('recent_scans', []))}")
        print(f"{'='*50}\n")

    elif args.command == "export":
        proxies = db.get_best_proxies(
            limit=args.limit,
            scheme=args.scheme,
            country=args.country,
            anonymity=args.anonymity,
            min_score=args.min_score,
            max_latency=args.max_latency,
        )
        if not proxies:
            print("No proxies found matching criteria.")
            return

        desktop = get_desktop()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_dir = desktop / f"proxy_export_{timestamp}"
        output_dir.mkdir(exist_ok=True)

        if args.format in ["plain", "all"]:
            path = output_dir / "proxies.txt"
            with open(path, "w") as f:
                f.write("\n".join(p["proxy"] for p in proxies))
            print(f"Saved {len(proxies)} proxies to {path}")

        if args.format in ["json", "all"]:
            path = output_dir / "proxies.json"
            with open(path, "w") as f:
                json.dump(proxies, f, indent=2, default=str)
            print(f"Saved JSON to {path}")

        if args.format in ["csv", "all"]:
            path = output_dir / "proxies.csv"
            with open(path, "w", newline="") as f:
                if proxies:
                    writer = csv.DictWriter(f, fieldnames=proxies[0].keys())
                    writer.writeheader()
                    writer.writerows(proxies)
            print(f"Saved CSV to {path}")

        if args.format in ["schemed", "all"]:
            path = output_dir / "proxies_schemed.txt"
            with open(path, "w") as f:
                f.write("\n".join(f"{p.get('scheme', 'http')}://{p['proxy']}" for p in proxies))
            print(f"Saved schemed to {path}")

        if args.format in ["sqlite", "all"]:
            import shutil
            path = output_dir / "proxy_database.db"
            shutil.copy2(str(DB_PATH), str(path))
            print(f"Copied database to {path}")

        print(f"\nExport complete: {output_dir}")

# ==========================
# GUI MODE
# ==========================

def gui_main():
    """Launch the GUI application."""
    global _GUI_MODE
    _GUI_MODE = True

    try:
        import customtkinter as ctk
    except ImportError:
        print("[ERROR] CustomTkinter is not installed.")
        print("Install with: pip install customtkinter")
        print("Or use CLI mode: python proxy_scraper_v3.py scan")
        return

    # ---- Colors ----
    BG = "#070b07"
    PANEL = "#0d1410"
    PANEL_2 = "#101a14"
    BORDER = "#163322"
    GREEN = "#39ff88"
    GREEN_2 = "#19c56b"
    TEXT = "#d8ffe8"
    MUTED = "#7cb895"
    RED = "#ff4458"
    YELLOW = "#ffc944"
    BLUE = "#44aaff"

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    app = ctk.CTk()
    app.geometry("1500x950")
    app.minsize(1200, 800)
    app.title(f"{APP_NAME} v{APP_VERSION}")

    app.configure(fg_color=BG)
    ui_queue = queue.Queue()
    scan_running = False
    cancel_event = threading.Event()
    pause_event = threading.Event()
    pause_event.set()

    DB = ProxyDatabase()

    # ---- Health monitor ----
    health_monitor = HealthMonitor(DB, interval=HEALTH_CHECK_INTERVAL, log_func=lambda msg: ui_queue.put(("log", msg)))

    # ---- Header ----
    header = ctk.CTkFrame(app, fg_color=PANEL, corner_radius=18, border_width=1, border_color=BORDER)
    header.pack(fill="x", padx=18, pady=(18, 10))

    ctk.CTkLabel(
        header, text=f"{APP_NAME.upper()} v{APP_VERSION}",
        font=ctk.CTkFont(family="Consolas", size=24, weight="bold"), text_color=GREEN
    ).pack(anchor="w", padx=18, pady=(12, 2))

    ctk.CTkLabel(
        header, text="async pipeline • concurrent fetch • decoupled enrichment • rotation API • health monitoring",
        font=ctk.CTkFont(family="Consolas", size=11), text_color=MUTED
    ).pack(anchor="w", padx=18, pady=(0, 10))

    # ---- Main Layout ----
    main = ctk.CTkFrame(app, fg_color="transparent")
    main.pack(fill="both", expand=True, padx=18, pady=(0, 18))

    left = ctk.CTkFrame(main, fg_color=PANEL, corner_radius=18, border_width=1, border_color=BORDER)
    left.pack(side="left", fill="y", padx=(0, 8))
    center = ctk.CTkFrame(main, fg_color=PANEL, corner_radius=18, border_width=1, border_color=BORDER)
    center.pack(side="left", fill="both", expand=True, padx=(0, 8))
    right = ctk.CTkFrame(main, fg_color=PANEL, corner_radius=18, border_width=1, border_color=BORDER)
    right.pack(side="right", fill="y")

    # ============ LEFT PANEL ============
    ctk.CTkLabel(left, text="CONTROL PANEL", font=ctk.CTkFont(family="Consolas", size=15, weight="bold"), text_color=GREEN).pack(anchor="w", padx=16, pady=(14, 4))
    ctk.CTkLabel(left, text=f"CPU: {LOGICAL_THREADS} | DB: {fmt_num(DB.get_stats_summary()['total_stored'])} stored", font=ctk.CTkFont(family="Consolas", size=10), text_color=MUTED).pack(anchor="w", padx=16, pady=2)

    # Workers
    threads_val = ctk.CTkLabel(left, text=f"Workers: {SETTINGS.get('workers')}", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), text_color=GREEN)
    threads_val.pack(anchor="w", padx=16, pady=(10, 2))
    threads_slider = ctk.CTkSlider(left, from_=10, to=300, number_of_steps=58, width=220,
        command=lambda v: threads_val.configure(text=f"Workers: {int(v)}"),
        progress_color=GREEN_2, button_color=GREEN, button_hover_color="#7affb0", fg_color="#1a241d")
    threads_slider.set(SETTINGS.get("workers"))
    threads_slider.pack(anchor="w", padx=16, pady=(0, 6))

    # Toggles
    toggles = ctk.CTkFrame(left, fg_color=PANEL_2, corner_radius=10, border_width=1, border_color=BORDER)
    toggles.pack(fill="x", padx=16, pady=4)

    async_var = ctk.StringVar(value="on" if SETTINGS.get("use_async") else "off")
    enrich_var = ctk.StringVar(value="on" if SETTINGS.get("do_enrich") else "off")
    persist_var = ctk.StringVar(value="on" if SETTINGS.get("do_persist") else "off")
    health_var = ctk.StringVar(value="off")

    for text, var, on, off in [
        ("Async I/O pipeline", async_var, "on", "off"),
        ("Anonymity + GeoIP", enrich_var, "on", "off"),
        ("SQLite persistence", persist_var, "on", "off"),
        ("Background health monitor", health_var, "on", "off"),
    ]:
        ctk.CTkCheckBox(toggles, text=text, variable=var, onvalue=on, offvalue=off,
            text_color=TEXT, fg_color=GREEN_2, hover_color="#0fa85a", border_color=BORDER,
            font=ctk.CTkFont(family="Consolas", size=10)).pack(anchor="w", padx=8, pady=3)

    # Filters
    fframe = ctk.CTkFrame(left, fg_color=PANEL_2, corner_radius=10, border_width=1, border_color=BORDER)
    fframe.pack(fill="x", padx=16, pady=4)
    ctk.CTkLabel(fframe, text="EXPORT FILTERS", font=ctk.CTkFont(family="Consolas", size=10, weight="bold"), text_color=MUTED).pack(anchor="w", padx=8, pady=(6, 2))

    filter_scheme_var = ctk.StringVar(value=SETTINGS.get("filter_scheme", "all"))
    filter_anon_var = ctk.StringVar(value=SETTINGS.get("filter_anonymity", "all"))
    min_score_var = ctk.StringVar(value=str(SETTINGS.get("min_score", 0)))
    max_lat_var = ctk.StringVar(value=str(SETTINGS.get("max_latency", 5000)))

    ctk.CTkOptionMenu(fframe, values=["all", "http", "https", "socks4", "socks5"], variable=filter_scheme_var,
        width=90, height=24, fg_color=PANEL, button_color=GREEN_2, button_hover_color="#0fa85a",
        font=ctk.CTkFont(family="Consolas", size=10)).pack(anchor="w", padx=8, pady=2)
    ctk.CTkOptionMenu(fframe, values=["all", "elite", "anonymous", "transparent"], variable=filter_anon_var,
        width=90, height=24, fg_color=PANEL, button_color=GREEN_2, button_hover_color="#0fa85a",
        font=ctk.CTkFont(family="Consolas", size=10)).pack(anchor="w", padx=8, pady=2)
    ctk.CTkEntry(fframe, textvariable=min_score_var, width=90, height=24, placeholder_text="Min score",
        font=ctk.CTkFont(family="Consolas", size=10)).pack(anchor="w", padx=8, pady=2)
    ctk.CTkEntry(fframe, textvariable=max_lat_var, width=90, height=24, placeholder_text="Max latency (ms)",
        font=ctk.CTkFont(family="Consolas", size=10)).pack(anchor="w", padx=8, pady=2)

    # Output format
    oframe = ctk.CTkFrame(left, fg_color=PANEL_2, corner_radius=10, border_width=1, border_color=BORDER)
    oframe.pack(fill="x", padx=16, pady=4)
    ctk.CTkLabel(oframe, text="OUTPUT FORMAT", font=ctk.CTkFont(family="Consolas", size=10, weight="bold"), text_color=MUTED).pack(anchor="w", padx=8, pady=(6, 2))
    format_var = ctk.StringVar(value=SETTINGS.get("output_format", "all"))
    ctk.CTkOptionMenu(oframe, values=["plain", "json", "csv", "schemed", "sqlite", "all"], variable=format_var,
        width=90, height=24, fg_color=PANEL, button_color=GREEN_2, button_hover_color="#0fa85a",
        font=ctk.CTkFont(family="Consolas", size=10)).pack(anchor="w", padx=8, pady=(0, 6))

    # Buttons
    bframe = ctk.CTkFrame(left, fg_color="transparent")
    bframe.pack(fill="x", padx=16, pady=6)

    start_btn = ctk.CTkButton(bframe, text="START", width=90, height=34, corner_radius=8,
        fg_color=GREEN_2, hover_color="#0fa85a", text_color="#041109",
        font=ctk.CTkFont(family="Consolas", size=12, weight="bold"))
    start_btn.pack(side="left", padx=(0, 3))

    stop_btn = ctk.CTkButton(bframe, text="STOP", width=55, height=34, corner_radius=8,
        fg_color="#553333", hover_color="#664444", text_color="#ffcccc",
        font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), state="disabled")
    stop_btn.pack(side="left", padx=3)

    pause_btn = ctk.CTkButton(bframe, text="PAUSE", width=55, height=34, corner_radius=8,
        fg_color="#555533", hover_color="#666644", text_color="#ffffcc",
        font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), state="disabled")
    pause_btn.pack(side="left", padx=3)

    # Status + progress
    status_lbl = ctk.CTkLabel(left, text="STATUS: READY", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color=TEXT)
    status_lbl.pack(anchor="w", padx=16, pady=(4, 2))

    progress_bar = ctk.CTkProgressBar(left, width=220, height=12, corner_radius=6, border_width=1,
        border_color=BORDER, fg_color="#17221b", progress_color=GREEN)
    progress_bar.pack(anchor="w", padx=16, pady=(0, 4))
    progress_bar.set(0)

    # ETA + throughput
    eta_var = ctk.StringVar(value="ETA: -- | Speed: -- | p50/p90/p95: --")
    ctk.CTkLabel(left, textvariable=eta_var, font=ctk.CTkFont(family="Consolas", size=10), text_color=MUTED).pack(anchor="w", padx=16, pady=2)

    # Stats
    sframe = ctk.CTkFrame(left, fg_color=PANEL_2, corner_radius=10, border_width=1, border_color=BORDER)
    sframe.pack(fill="x", padx=16, pady=6)

    stat_vars = {
        "sources": ctk.StringVar(value="Sources: 0"),
        "proxies": ctk.StringVar(value="Proxies: 0"),
        "working": ctk.StringVar(value="Working: 0"),
        "elite": ctk.StringVar(value="Elite: 0"),
        "avg_score": ctk.StringVar(value="Avg score: --"),
        "avg_latency": ctk.StringVar(value="Avg latency: --"),
        "saved": ctk.StringVar(value="Saved: pending"),
        "db_total": ctk.StringVar(value=f"DB total: {fmt_num(DB.get_stats_summary()['total_stored'])}"),
    }
    for var in stat_vars.values():
        ctk.CTkLabel(sframe, textvariable=var, font=ctk.CTkFont(family="Consolas", size=10), text_color=TEXT).pack(anchor="w", padx=8, pady=2)

    # ============ CENTER PANEL - RESULTS TABLE ============
    ctk.CTkLabel(center, text="WORKING PROXIES", font=ctk.CTkFont(family="Consolas", size=13, weight="bold"), text_color=GREEN).pack(anchor="w", padx=12, pady=(12, 2))
    ctk.CTkLabel(center, text="click headers to sort • right-click for context menu", font=ctk.CTkFont(family="Consolas", size=9), text_color=MUTED).pack(anchor="w", padx=12, pady=(0, 4))

    # Search bar
    search_frame = ctk.CTkFrame(center, fg_color="transparent")
    search_frame.pack(fill="x", padx=12, pady=4)
    search_var = ctk.StringVar(value="")
    search_entry = ctk.CTkEntry(search_frame, textvariable=search_var, width=300, height=26,
        placeholder_text="Search proxy, country, ISP...", font=ctk.CTkFont(family="Consolas", size=10))
    search_entry.pack(side="left", padx=(0, 4))
    search_entry.bind("<KeyRelease>", lambda e: render_table())

    table_container = ctk.CTkScrollableFrame(center, fg_color="#050805", corner_radius=10, border_width=1, border_color=BORDER)
    table_container.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    table_results: List[ProxyResult] = []
    sort_column = "score"
    sort_reverse = True

    def render_table(results=None):
        if results is not None:
            table_results.clear()
            table_results.extend(results)
        for w in table_container.winfo_children():
            w.destroy()

        display = sort_results(table_results)

        # Apply search filter
        search_text = search_var.get().lower().strip()
        if search_text:
            display = [r for r in display if search_text in r.proxy.lower() or
                       search_text in (r.country_code or "").lower() or
                       search_text in (r.isp or "").lower() or
                       search_text in (r.anonymity or "").lower()]

        if not display:
            ctk.CTkLabel(table_container, text="No results yet." if not search_text else "No matches.",
                font=ctk.CTkFont(family="Consolas", size=12), text_color=MUTED).pack(pady=30)
            return

        # Header
        hrow = ctk.CTkFrame(table_container, fg_color="transparent")
        hrow.pack(fill="x", padx=4, pady=(4, 2))
        headers = [("Proxy", "proxy"), ("Type", "scheme"), ("Lat", "latency"), ("Score", "score"),
                   ("Anon", "anonymity"), ("CC", "country_code"), ("City", "city"), ("ISP", "isp"), ("Health", "health_status")]
        for label, key in headers:
            arrow = " ▼" if key == sort_column and sort_reverse else (" ▲" if key == sort_column else "")
            ctk.CTkButton(hrow, text=label + arrow, width=80, height=20, corner_radius=3, fg_color="transparent",
                hover_color="#1a241d", text_color=GREEN_2, font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                command=lambda k=key: toggle_sort(k)).pack(side="left", padx=1)

        # Rows
        for i, r in enumerate(display[:500]):
            row = ctk.CTkFrame(table_container, fg_color="#0a0f0a" if i % 2 == 0 else "#0d130d", corner_radius=3)
            row.pack(fill="x", padx=4, pady=1)

            sc = GREEN if r.score >= 75 else YELLOW if r.score >= 50 else RED
            ac = GREEN if r.anonymity == "elite" else YELLOW if r.anonymity == "anonymous" else RED if r.anonymity == "transparent" else MUTED
            hc = GREEN if r.health_status == "fresh" else YELLOW if r.health_status == "stale" else RED

            for text, color, width in [
                (r.proxy, TEXT, 140), (r.scheme, BLUE, 50), (f"{r.latency}ms", TEXT, 50),
                (str(r.score), sc, 40), (r.anonymity or "?", ac, 70),
                (r.country_code or "--", TEXT, 40), ((r.city or "--")[:10], MUTED, 80),
                ((r.isp or "--")[:12], MUTED, 90), (r.health_status or "?", hc, 50),
            ]:
                ctk.CTkLabel(row, text=text, width=width, font=ctk.CTkFont(family="Consolas", size=9),
                    text_color=color, anchor="w").pack(side="left", padx=1, pady=1)

            # Right-click context menu
            def make_context_menu(proxy_str=r.proxy, scheme=r.scheme):
                def copy_proxy():
                    app.clipboard_clear()
                    app.clipboard_append(proxy_str)
                def copy_schemed():
                    app.clipboard_clear()
                    app.clipboard_append(f"{scheme}://{proxy_str}")
                def view_history():
                    hist = DB.get_proxy_history(proxy_str)
                    if hist:
                        msg = "\n".join(f"{k}: {v}" for k, v in hist.items())
                        ui_queue.put(("log", f"[HISTORY] {proxy_str}\n{msg}"))
                    else:
                        ui_queue.put(("log", f"[HISTORY] No history for {proxy_str}"))
                return [("Copy ip:port", copy_proxy), ("Copy scheme://proxy", copy_schemed), ("View history", view_history)]

            def on_right_click(event, menu_items=make_context_menu()):
                # Create a simple popup
                popup = ctk.CTkToplevel(row)
                popup.overrideredirect(True)
                popup.geometry(f"+{event.x_root}+{event.y_root}")
                for label, cmd in menu_items():
                    btn = ctk.CTkButton(popup, text=label, width=150, height=28, corner_radius=4,
                        fg_color=PANEL_2, hover_color="#1a241d", text_color=TEXT,
                        font=ctk.CTkFont(family="Consolas", size=10),
                        command=lambda c=cmd, p=popup: [c(), p.destroy()])
                    btn.pack(fill="x", padx=2, pady=1)
                popup.bind("<FocusOut>", lambda e: popup.destroy())
                popup.focus_set()

            row.bind("<Button-3>", on_right_click)

    def sort_results(results):
        if not results:
            return results
        key_map = {
            "proxy": lambda r: r.proxy, "scheme": lambda r: r.scheme,
            "latency": lambda r: r.latency, "score": lambda r: r.score,
            "anonymity": lambda r: r.anonymity or "zzz",
            "country_code": lambda r: r.country_code or "zzz",
            "city": lambda r: r.city or "zzz", "isp": lambda r: r.isp or "zzz",
            "health_status": lambda r: r.health_status or "zzz",
        }
        return sorted(results, key=key_map.get(sort_column, lambda r: r.score), reverse=sort_reverse)

    def toggle_sort(key):
        nonlocal sort_column, sort_reverse
        if sort_column == key:
            sort_reverse = not sort_reverse
        else:
            sort_column = key
            sort_reverse = True
        render_table()

    # ============ RIGHT PANEL - STATS + TERMINAL ============
    ctk.CTkLabel(right, text="STATISTICS", font=ctk.CTkFont(family="Consolas", size=13, weight="bold"), text_color=GREEN).pack(anchor="w", padx=12, pady=(12, 4))

    # Protocol
    pframe = ctk.CTkFrame(right, fg_color=PANEL_2, corner_radius=10, border_width=1, border_color=BORDER)
    pframe.pack(fill="x", padx=10, pady=3)
    ctk.CTkLabel(pframe, text="BY PROTOCOL", font=ctk.CTkFont(family="Consolas", size=9, weight="bold"), text_color=MUTED).pack(anchor="w", padx=8, pady=(4, 2))
    proto_vars = {}
    for proto, color in [("http", BLUE), ("https", GREEN), ("socks4", YELLOW), ("socks5", GREEN_2)]:
        var = ctk.StringVar(value=f"{proto}: 0")
        proto_vars[proto] = var
        ctk.CTkLabel(pframe, textvariable=var, font=ctk.CTkFont(family="Consolas", size=10), text_color=color).pack(anchor="w", padx=8, pady=1)

    # Anonymity
    aframe = ctk.CTkFrame(right, fg_color=PANEL_2, corner_radius=10, border_width=1, border_color=BORDER)
    aframe.pack(fill="x", padx=10, pady=3)
    ctk.CTkLabel(aframe, text="BY ANONYMITY", font=ctk.CTkFont(family="Consolas", size=9, weight="bold"), text_color=MUTED).pack(anchor="w", padx=8, pady=(4, 2))
    anon_vars = {}
    for anon, color in [("elite", GREEN), ("anonymous", YELLOW), ("transparent", RED), ("unknown", MUTED)]:
        var = ctk.StringVar(value=f"{anon}: 0")
        anon_vars[anon] = var
        ctk.CTkLabel(aframe, textvariable=var, font=ctk.CTkFont(family="Consolas", size=10), text_color=color).pack(anchor="w", padx=8, pady=1)

    # Health
    hframe = ctk.CTkFrame(right, fg_color=PANEL_2, corner_radius=10, border_width=1, border_color=BORDER)
    hframe.pack(fill="x", padx=10, pady=3)
    ctk.CTkLabel(hframe, text="BY HEALTH", font=ctk.CTkFont(family="Consolas", size=9, weight="bold"), text_color=MUTED).pack(anchor="w", padx=8, pady=(4, 2))
    health_vars = {}
    for h, color in [("fresh", GREEN), ("stale", YELLOW), ("unstable", RED), ("dead", RED), ("unknown", MUTED)]:
        var = ctk.StringVar(value=f"{h}: 0")
        health_vars[h] = var
        ctk.CTkLabel(hframe, textvariable=var, font=ctk.CTkFont(family="Consolas", size=10), text_color=color).pack(anchor="w", padx=8, pady=1)

    # Countries
    cframe = ctk.CTkFrame(right, fg_color=PANEL_2, corner_radius=10, border_width=1, border_color=BORDER)
    cframe.pack(fill="x", padx=10, pady=3)
    ctk.CTkLabel(cframe, text="TOP COUNTRIES", font=ctk.CTkFont(family="Consolas", size=9, weight="bold"), text_color=MUTED).pack(anchor="w", padx=8, pady=(4, 2))
    country_container = ctk.CTkFrame(cframe, fg_color="transparent")
    country_container.pack(fill="x", padx=8, pady=(0, 4))

    # Terminal
    ctk.CTkLabel(right, text="LIVE TERMINAL", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color=GREEN).pack(anchor="w", padx=12, pady=(6, 2))
    console = ctk.CTkTextbox(right, fg_color="#050805", text_color=GREEN, border_width=1, border_color=BORDER,
        corner_radius=10, font=ctk.CTkFont(family="Consolas", size=9), wrap="none", width=280)
    console.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    # ============ UI QUEUE PROCESSOR ============
    def log(text):
        ui_queue.put(("log", text))
    def set_status(text):
        ui_queue.put(("status", text))
    def set_progress(val):
        ui_queue.put(("progress", val))
    def set_stat(name, val):
        ui_queue.put(("stat", (name, val)))

    def process_queue():
        try:
            while True:
                kind, value = ui_queue.get_nowait()
                if kind == "log":
                    console.insert("end", value + "\n")
                    console.see("end")
                elif kind == "status":
                    status_lbl.configure(text=value)
                elif kind == "progress":
                    progress_bar.set(value)
                elif kind == "stat":
                    key, val = value
                    if key in stat_vars:
                        stat_vars[key].set(val)
                elif kind == "result":
                    # Don't render per-result, wait for table_refresh
                    pass
                elif kind == "table_refresh":
                    render_table(value)
                elif kind == "proto":
                    for p, c in value.items():
                        if p in proto_vars:
                            proto_vars[p].set(f"{p}: {c}")
                elif kind == "anon":
                    for a, c in value.items():
                        if a in anon_vars:
                            anon_vars[a].set(f"{a}: {c}")
                elif kind == "country":
                    for w in country_container.winfo_children():
                        w.destroy()
                    for cc, c in list(value.items())[:10]:
                        ctk.CTkLabel(country_container, text=f"{cc}: {c}",
                            font=ctk.CTkFont(family="Consolas", size=9), text_color=TEXT).pack(anchor="w", pady=1)
                elif kind == "eta":
                    pass  # ETA handled below
                elif kind == "throughput":
                    pass
                elif kind == "working":
                    stat_vars["working"].set(f"Working: {fmt_num(value)}")
                elif kind == "sources":
                    stat_vars["sources"].set(f"Sources: {value}")
                elif kind == "proxies":
                    stat_vars["proxies"].set(f"Proxies: {fmt_num(value)}")
                elif kind == "saved":
                    stat_vars["saved"].set(f"Saved: {value}")
                elif kind == "avg_score":
                    stat_vars["avg_score"].set(f"Avg score: {value}")
                elif kind == "avg_latency":
                    stat_vars["avg_latency"].set(f"Avg latency: {value}ms")
        except queue.Empty:
            pass
        app.after(80, process_queue)

    # ============ SCAN LAUNCHER ============
    def ui_callback(event_type, data):
        """Bridge from ScanEngine to UI queue."""
        ui_queue.put((event_type, data))

    def start_scan():
        nonlocal scan_running
        if scan_running:
            return
        scan_running = True
        cancel_event.clear()
        pause_event.set()
        start_btn.configure(state="disabled")
        stop_btn.configure(state="normal")
        pause_btn.configure(state="normal")
        threads_slider.configure(state="disabled")
        console.delete("1.0", "end")
        progress_bar.set(0)

        # Save settings
        SETTINGS.set("workers", int(threads_slider.get()))
        SETTINGS.set("use_async", async_var.get() == "on")
        SETTINGS.set("do_enrich", enrich_var.get() == "on")
        SETTINGS.set("do_persist", persist_var.get() == "on")
        SETTINGS.set("output_format", format_var.get())
        SETTINGS.set("filter_scheme", filter_scheme_var.get())
        SETTINGS.set("filter_anonymity", filter_anon_var.get())
        try:
            SETTINGS.set("min_score", int(min_score_var.get()) if min_score_var.get().isdigit() else 0)
        except Exception:
            pass
        try:
            SETTINGS.set("max_latency", int(max_lat_var.get()) if max_lat_var.get().isdigit() else 5000)
        except Exception:
            pass

        # Start health monitor if enabled
        if health_var.get() == "on":
            health_monitor.start()

        set_status("STATUS: INITIALIZING")

        # Run scan in background thread with event loop
        def run_thread():
            engine = ScanEngine(
                db=DB, settings=SETTINGS, log_func=log,
                ui_callback=ui_callback, cancel_event=cancel_event, pause_event=pause_event,
            )
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(engine.run_scan(
                    use_async=async_var.get() == "on",
                    do_enrich=enrich_var.get() == "on",
                    do_persist=persist_var.get() == "on",
                    output_format=format_var.get(),
                ))
                loop.close()
            except Exception as e:
                log(f"[FATAL] {e}")
                import traceback
                log(traceback.format_exc())
            finally:
                ui_queue.put(("stat", ("db_total", f"DB total: {fmt_num(DB.get_stats_summary()['total_stored'])}")))

        threading.Thread(target=run_thread, daemon=True).start()

    def stop_scan():
        cancel_event.set()
        pause_event.set()
        log("[USER] Stop requested...")
        stop_btn.configure(state="disabled")
        pause_btn.configure(state="disabled")
        set_status("STATUS: STOPPING...")

    def toggle_pause():
        if pause_event.is_set():
            pause_event.clear()
            pause_btn.configure(text="RESUME")
            set_status("STATUS: PAUSED")
            log("[USER] Paused")
        else:
            pause_event.set()
            pause_btn.configure(text="PAUSE")
            set_status("STATUS: RESUMING...")
            log("[USER] Resumed")

    start_btn.configure(command=start_scan)
    stop_btn.configure(command=stop_scan)
    pause_btn.configure(command=toggle_pause)

    # ============ INIT ============
    log(f"[INIT] {APP_NAME} v{APP_VERSION}")
    log(f"[INIT] DB: {DB_PATH} ({fmt_num(DB.get_stats_summary()['total_stored'])} proxies stored)")
    log(f"[INIT] Sources config: {SOURCES_PATH}")
    log(f"[INIT] Settings: {SETTINGS_PATH}")
    log(f"[INIT] CPU threads: {LOGICAL_THREADS}")
    log(f"[INIT] aiohttp: {'yes' if HAS_AIOHTTP else 'NO'} | aiohttp_socks: {'yes' if HAS_AIOHTTP_SOCKS else 'NO'}")
    if not HAS_AIOHTTP or not HAS_AIOHTTP_SOCKS:
        log("[INIT] Install: pip install aiohttp aiohttp-socks")
    log("")
    log("CLI mode also available:")
    log("  python proxy_scraper_v3.py scan --workers 300 --elite-only")
    log("  python proxy_scraper_v3.py serve --port 8888")
    log("  python proxy_scraper_v3.py stats")
    log("")

    process_queue()
    app.mainloop()

# ==========================
# MAIN ENTRY POINT
# ==========================

if __name__ == "__main__":
    # If no CLI args, launch GUI; otherwise run CLI
    if len(sys.argv) > 1:
        cli_main()
    else:
        gui_main()
