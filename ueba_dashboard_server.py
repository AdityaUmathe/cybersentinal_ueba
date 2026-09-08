#!/usr/bin/env python3
"""
ueba_dashboard_server.py
─────────────────────────
CyberSentinel UEBA — Dashboard API Server

Serves ueba_alerts.jsonl data as JSON endpoints for the dashboard.

Run:
    python3 ueba_dashboard_server.py
    python3 ueba_dashboard_server.py --config ueba_config.yaml
    python3 ueba_dashboard_server.py --port 3026 --alerts /path/to/ueba_alerts.jsonl

Configuration is sourced (in priority order) from:
    1. CLI flags
    2. The `dashboard:` block in ueba_config.yaml
    3. Built-in defaults (matches the historical hard-coded values)

The Anthropic API key for the AI Security Analyst is taken from the
ANTHROPIC_API_KEY environment variable. If unset, the dashboard falls back to
a locally-generated summary.
"""

import argparse
import gzip
import json
import os
import re
import time
import uuid
import zipfile
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

# orjson parses JSON ~2.5x faster than the stdlib (measured on real archives:
# 6.4s -> 2.6s per day-file) and is already installed in the venv. It's the hot
# path for both live-tail and archive ingestion, so use it when present and fall
# back to stdlib json transparently otherwise. orjson returns bytes from dumps.
try:
    import orjson as _orjson

    def _jloads(b):
        return _orjson.loads(b)

    def _jdumps(o) -> bytes:
        return _orjson.dumps(o)
except Exception:  # pragma: no cover - orjson should be present, but degrade gracefully
    _orjson = None

    def _jloads(b):
        return json.loads(b)

    def _jdumps(o) -> bytes:
        return json.dumps(o).encode("utf-8")

from flask import (
    Flask, jsonify, request, send_from_directory, Response,
    stream_with_context, has_request_context,
)
from flask_cors import CORS

# SSO / session layer. Optional in the same way orjson and yaml are: if the
# module (or PyJWT under it) is missing the dashboard still serves, just with
# no authentication — which is exactly what it did before this existed.
try:
    import ueba_auth  # type: ignore
    AUTH_MODULE_AVAILABLE = True
except ImportError:
    ueba_auth = None
    AUTH_MODULE_AVAILABLE = False

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # config file is optional

try:
    import requests  # type: ignore
except ImportError:
    requests = None  # AI proxy will degrade gracefully


# ── Defaults (used when config file or keys are missing) ──────────────────────
_DEFAULTS = {
    "host":            "0.0.0.0",
    "port":            3026,
    "alerts_file":     "/root/NEW_DRIVE/aditya_ueba/ueba_alerts.jsonl",
    "agents_registry": "/root/NEW_DRIVE/aditya_ueba/agents.json",
    "false_positives_file": "/root/NEW_DRIVE/aditya_ueba/false_positives.json",
    "fp_patterns_file":     "/root/NEW_DRIVE/aditya_ueba/fp_patterns.json",
    # The engine rotates ueba_alerts.jsonl at midnight, zipping each day to
    # archive_dir as ueba_alerts_YYYY-MM-DD.jsonl.zip. The dashboard reads the
    # live file PLUS these archives so the timeline windows (24H…90D / All) have
    # history to show — without them, "All" would only ever show today.
    "archive_dir":     "/root/NEW_DRIVE/aditya_ueba/archive",
    "max_alerts":      500000,
    "cache_ttl_secs":  10,
    # Timeline-window loading. `history_days` bounds the "All"/90D lookback into
    # the archives; `max_feed_alerts` caps how many alerts a single windowed
    # request returns (most-recent kept).
    #
    # The cap is large (500k) on purpose. To keep a window that big from shipping
    # a ~1 GB firehose, the bulk /api/feed payload OMITS each alert's `evidence`
    # blob (~77% of per-alert bytes) — the dashboard lazy-loads it per row via
    # /api/evidence/<event_id> only when an analyst expands that row. So 500k
    # alerts cost ~0.5 KB each on the wire (~260 MB worst case) instead of ~2.3 KB.
    "history_days":    95,
    "max_feed_alerts": 500000,
    # /api/feed table payload cap. The feed table + client-side charts only ever
    # need the most-recent slice; on a high-volume feed a wide window can hold
    # tens of thousands of alerts, and shipping all of them (tens of MB) freezes
    # the browser parsing/aggregating them. The bulk feed returns at most this
    # many newest rows. Window TOTALS stay accurate via /api/stats (which counts
    # the full window up to max_feed_alerts), so this only bounds the table feed.
    "feed_row_cap":    5000,
    # Live threat map (firewall geoIP). The /api/geofeed endpoint tails recent
    # FIREWALL events from the enriched feed, geolocates each external source IP
    # via a local MaxMind GeoLite2 DB (fully offline, no API key), and serves
    # source→datacenter arcs to the globe.gl panel. If the GeoLite2 DB or the
    # geoip2 lib is absent the endpoint degrades to empty (geo_ok=false).
    "enriched_file": "/root/NEW_DRIVE/aditya_ueba/enriched.jsonl",
    "geoip_city_db": "",   # explicit path; empty → auto-detect from known locations
    "geoip_asn_db":  "",
    "threatmap": {
        "window_bytes": 12582912,   # tail this many bytes of enriched.jsonl (~last few min)
        "max_arcs":     400,        # cap arcs returned per poll (most-recent kept)
        "dc_ip":        "103.76.143.84",   # WAN/DC anchor IP — geolocated for the arc target
        "dc_lat":       21.1463,    # fallback DC coords (Nagpur, IN) if dc_ip won't resolve
        "dc_lng":       79.0849,
        "dc_label":     "VG Datacenter",
    },
    "ai_analyst": {
        "enabled":     True,
        "model":       "claude-sonnet-4-6",
        "max_tokens":  1000,
        "timeout_secs": 20,
    },
    # Agent auto-discovery — periodically reads the Wazuh manager's
    # `client.keys` to keep agents.json in sync with the SOC inventory.
    #
    # Reading the bind-mounted client.keys requires NO permission changes
    # on the SOC server: the file is plain-text and world-readable by the
    # `soc` user. If you ever want to switch to `agent_control -l`
    # (richer: includes connection status), set remote_command to
    # `docker exec cybersentinel-manager /var/ossec/bin/agent_control -l`
    # and grant docker access. The poller auto-detects the format.
    "agent_sync": {
        "enabled":            True,
        "poll_interval_secs": 60,
        "ssh_host":           "soc@localhost",
        "ssh_port":           2222,
        "ssh_key":            "/root/.ssh/id_ueba",
        "remote_command":     "cat /var/ossec/etc/client.keys",
        "ssh_timeout_secs":   20,
    },
}


def load_dashboard_config(config_path: str | None) -> dict:
    """Load the `dashboard:` block from ueba_config.yaml, layered on defaults."""
    cfg = dict(_DEFAULTS)
    cfg["ai_analyst"] = dict(_DEFAULTS["ai_analyst"])
    if not config_path or not yaml:
        return cfg
    p = Path(config_path)
    if not p.exists():
        return cfg
    try:
        with open(p, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[dashboard] failed to read {config_path}: {e}")
        return cfg
    dash = (raw.get("dashboard") or {}) if isinstance(raw, dict) else {}
    for k, v in dash.items():
        if k == "ai_analyst" and isinstance(v, dict):
            cfg["ai_analyst"].update(v)
        elif k == "agent_sync" and isinstance(v, dict):
            cfg.setdefault("agent_sync", dict(_DEFAULTS["agent_sync"]))
            cfg["agent_sync"].update(v)
        else:
            cfg[k] = v
    return cfg


def load_raw_config(config_path: str | None) -> dict:
    """Whole parsed ueba_config.yaml — the auth layer reads its own `auth:` block."""
    if not config_path or not yaml:
        return {}
    p = Path(config_path)
    if not p.exists():
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[dashboard] failed to read {config_path}: {e}")
        return {}


_SERVER_STARTED_AT = datetime.now(timezone.utc).isoformat()


# ── App + runtime config (populated in main()) ────────────────────────────────
# The dashboard is served from one of two places, in priority order:
#   1. dashboard/dist/         — built by `cd dashboard && npm run build`
#   2. dashboard/index.html    — legacy single-file fallback
# The decision is per-request so flipping between builds doesn't need a restart.
DASHBOARD_DIR     = Path(__file__).resolve().parent / "dashboard"
DASHBOARD_DIST    = DASHBOARD_DIR / "dist"
DASHBOARD_LEGACY  = DASHBOARD_DIR / "index.html"

app = Flask(__name__, static_folder=None)


def _configure_cors(auth_cfg: dict) -> str:
    """Apply the CORS policy.

    Historically this was a bare `CORS(app)` — `Access-Control-Allow-Origin: *`
    for every route. That is preserved verbatim while the dashboard is
    unauthenticated, so nothing changes for existing deployments. Once auth is
    enabled AND an explicit origin allowlist is configured, we switch to that
    allowlist with credentials enabled, because "wildcard origin" plus "session
    cookie" is the combination that lets any page a logged-in analyst visits
    read the alert feed.
    """
    origins = list(auth_cfg.get("cors_origins") or [])
    if auth_cfg.get("enabled") and origins:
        CORS(app, origins=origins, supports_credentials=True)
        return f"restricted to {len(origins)} origin(s)"
    CORS(app)
    return "open (*) — no origin allowlist configured"


# ── Response gzip ──
# The feed/charts are rendered entirely client-side from raw /api/feed rows, so a
# wide window ships tens of MB of highly-repetitive JSON. gzip cuts that ~10x on
# the wire (28MB → ~3MB) with no behaviour change. Stdlib only (no flask-compress
# dependency); kicks in only when the client advertises gzip and the body is big
# enough to be worth it, and never double-encodes a streamed/already-encoded body.
_GZIP_MIN_BYTES = 1024


@app.after_request
def _gzip_response(resp: "Response") -> "Response":
    try:
        accept = (request.headers.get("Accept-Encoding") or "")
        if "gzip" not in accept.lower():
            return resp
        # Skip streamed bodies (e.g. /api/stream SSE) and anything already encoded.
        if resp.direct_passthrough or resp.headers.get("Content-Encoding"):
            return resp
        ctype = (resp.content_type or "")
        if not (ctype.startswith("application/json") or ctype.startswith("text/")):
            return resp
        data = resp.get_data()
        if len(data) < _GZIP_MIN_BYTES:
            return resp
        resp.set_data(gzip.compress(data, 6))
        resp.headers["Content-Encoding"] = "gzip"
        resp.headers["Content-Length"] = str(len(resp.get_data()))
        vary = resp.headers.get("Vary")
        if not vary:
            resp.headers["Vary"] = "Accept-Encoding"
        elif "accept-encoding" not in vary.lower():
            resp.headers["Vary"] = vary + ", Accept-Encoding"
    except Exception:
        # Compression is a best-effort optimisation — never break a response over it.
        return resp
    return resp

CFG: dict = dict(_DEFAULTS)
CFG["ai_analyst"] = dict(_DEFAULTS["ai_analyst"])
ALERTS_FILE: Path     = Path(_DEFAULTS["alerts_file"])
AGENTS_REGISTRY: Path = Path(_DEFAULTS["agents_registry"])
FP_FILE: Path         = Path(_DEFAULTS["false_positives_file"])
FP_PATTERNS_FILE: Path = Path(_DEFAULTS["fp_patterns_file"])

# ── Alert cache — avoids reading the full file on every API request ──
# The live alerts file is append-only and grows large (hundreds of MB). The
# engine appends every second, so an mtime-keyed cache never hits — instead we
# track the byte offset we've parsed up to and incrementally parse only the
# newly-appended lines, keeping a trimmed in-memory list. Inode + size guard a
# rotation/truncation (midnight rollover) by forcing a full re-read.
_alert_cache: list = []
_alert_cache_mtime: float = 0.0   # retained for compatibility (unused by the tail reader)
_alert_cache_off: int = 0         # byte offset parsed up to in the live file
_alert_cache_inode: int = 0       # inode of the file the offset belongs to
# Single-flight lock: during a cold window (engine rewrote the file → new inode)
# a burst of parallel API requests would otherwise each trigger a full re-parse
# of the hundreds-of-MB live file at once (thundering herd) and corrupt the shared
# cache via interleaved global mutation. Serialize the cache read/update so only
# one thread re-parses; the rest reuse the warm cache.
_alert_read_lock = __import__("threading").Lock()

# ── Archive cache — historical daily alert zips, keyed by path → (mtime, alerts).
# Daily archives are written once at the midnight rotation and never change, so
# a parsed file is cached until its mtime changes (which it never should). Only
# files inside the requested window are ever opened, so a 7-day view touches ~7
# small zips and an "All" view touches at most `history_days` of them — once.
_archive_lock = __import__("threading").Lock()
_archive_cache: dict = {}        # str(path) -> (mtime, [alerts])
_archive_warn_at: float = 0.0    # rate-limit malformed-archive warnings (epoch secs)
_last_window_total: int = 0      # pre-cap count of the most recent windowed read
_MIN_DT = datetime.min.replace(tzinfo=timezone.utc)
_ARCHIVE_RE = re.compile(r"ueba_alerts_(\d{4}-\d{2}-\d{2})\.jsonl\.zip$")

# ── Slim projection ──────────────────────────────────────────────────────────
# Every dashboard consumer (stats/users/campaigns/incidents/agents/feed and the
# per-user/agent drilldowns) reads only a small, fixed set of fields. The full
# engine alert is a fat nested record (~8-10KB) dominated by `evidence` and
# `context.raw_event`, which exist only to (a) render the lazy evidence panel and
# (b) derive the user + MITRE tags. Retaining the full record for the whole
# history window is what pushed the dashboard to ~40GB RSS and made cold window
# builds slow. We instead project each alert to a slim record AT INGEST — keeping
# just the consumed fields and pre-resolving the user + MITRE lists — and drop
# the heavy blobs. Measured: retained memory 3.9GB -> 0.11GB per archive day
# (~3%). Evidence is no longer in RAM; /api/evidence lazy-loads it from disk by
# event_id (rare, single-row action). Bump _SLIM_VER when the kept field set
# changes so stale on-disk slim caches are rebuilt instead of served incomplete.
_SLIM_VER = 1


def _slim(a: dict) -> dict:
    """Project a full engine alert to the compact record the dashboard actually
    reads. Pre-resolves user + MITRE so subject/object/context.raw_event/evidence
    can be dropped. `_resolve_user`/get_user and `_alert_ts` still work because
    the resolved user is stored under the same `__user` memo key they check, and
    the timestamp is recomputed lazily from the retained processed_at/event_time."""
    ueba = a.get("ueba") or {}
    sec  = a.get("security") or {}
    host = a.get("host") or {}
    rev  = (a.get("context") or {}).get("raw_event") or {}
    ev   = a.get("evidence") or {}
    return {
        "event_id":   a.get("event_id"),
        "event_time": a.get("event_time"),
        "ueba": {
            "risk_verdict":    ueba.get("risk_verdict"),
            "combined_score":  ueba.get("combined_score"),
            "campaign_id":     ueba.get("campaign_id"),
            "anomaly_reasons": ueba.get("anomaly_reasons") or [],
            "processed_at":    ueba.get("processed_at"),
        },
        "security": {
            "signature":    sec.get("signature"),
            "signature_id": sec.get("signature_id"),
            "severity":     sec.get("severity"),
        },
        "host": {"name": host.get("name"), "ip": host.get("ip")},
        # Pre-resolved (see get_user memo) so builders never touch the dropped
        # subject/object/raw_event blobs again.
        "__user": _resolve_user(a),
        "__mitre_tactic":     ((rev.get("rule") or {}).get("mitre") or {}).get("tactic") or [],
        "__mitre_techniques": ((ev.get("signature") or {}).get("mitre_techniques")) or [],
    }

# ── False-positive store — in-memory dict, persisted to FP_FILE atomically ──
# Maps event_id -> {"event_id": ..., "reason": "...", "marked_at": "..."}
_fp_lock = __import__("threading").Lock()
_fp_dict: dict = {}

# ── False-positive pattern store ─────────────────────────────────────────────
# Each pattern auto-suppresses any future alert whose rule description
# (security.signature) matches `rule_description`. Comparison is whitespace-
# trimmed and case-insensitive so analysts don't have to worry about minor
# string normalisation differences between the SIEM source and the alert
# stream. Persisted to FP_PATTERNS_FILE atomically.
_fp_pat_lock = __import__("threading").Lock()
_fp_patterns: list = []  # list of dicts: {id, rule_description, reason, marked_at}


def _norm_desc(s) -> str:
    """Normalise a rule description for matching: trim + lowercase."""
    return (str(s or "")).strip().lower()


def _parse_iso(ts) -> datetime | None:
    """Parse an ISO-8601 timestamp; return None if missing/unparseable."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None

# ── Agent sync state (populated by the background poller) ────────────────────
_agent_sync_last_at: str = ""           # ISO timestamp of last successful poll
_agent_sync_last_error: str = ""        # last error message (for /api/health)
_agent_sync_lock = __import__("threading").Lock()


def _parse_client_keys(stdout: str) -> list[dict]:
    """Parse a Wazuh `client.keys` file into [{id, name, ip}].

    Format is one agent per line: `<id> <name> <ip|"any"> <key>`. Lines
    starting with `#` or `!` (revoked) are skipped. IDs `000` / `0` are
    the manager itself and are skipped too.
    """
    out: list[dict] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        agent_id, name, ip = parts[0], parts[1], parts[2]
        if agent_id in ("000", "0"):
            continue
        # `any` is Wazuh's placeholder when no fixed IP was configured.
        if ip.lower() == "any":
            ip = ""
        else:
            ip = ip.split("/")[0]   # drop /netmask if present
        out.append({
            "id":     agent_id,
            "name":   name,
            "ip":     ip,
            "status": "",            # client.keys doesn't carry status
        })
    return out


def _parse_agent_control_l(stdout: str) -> list[dict]:
    """Parse the output of `agent_control -l` into a list of {id, name, ip} dicts.

    Wazuh's typical output format:

        Wazuh agent_control. List of available agents:
           ID: 000, Name: cybersentinel-manager (server), IP: 127.0.0.1, Active/Local
           ID: 001, Name: Sparta1, IP: 10.200.11.106/any, Active
           ID: 002, Name: KAFKA_ME_P, IP: 10.200.10.174, Disconnected
        ...

    Server-self entry (ID 000) is skipped — it isn't a real endpoint.
    """
    import re as _re
    line_re = _re.compile(
        r"ID:\s*(?P<id>\S+)\s*,\s*"
        r"Name:\s*(?P<name>.+?)(?:\s*\([^)]+\))?\s*,\s*"
        r"IP:\s*(?P<ip>[^,\s]+)\s*,\s*"
        r"(?P<status>.+?)\s*$"
    )
    out: list[dict] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or not line.lstrip().startswith("ID:"):
            continue
        m = line_re.match(line)
        if not m:
            continue
        agent_id = m.group("id").strip()
        if agent_id in ("000", "0"):
            continue                                # skip the manager itself
        ip = m.group("ip").split("/")[0]            # strip /any or /netmask
        out.append({
            "id":     agent_id,
            "name":   m.group("name").strip(),
            "ip":     ip,
            "status": m.group("status").strip().lower(),
        })
    return out


def _fetch_agents_from_soc() -> tuple[list[dict] | None, str]:
    """SSH to the SOC server and run `agent_control -l`, parse the result.

    Returns (agents, error_message). On success error_message is "".
    On failure agents is None and error_message describes the problem.
    """
    cfg = CFG.get("agent_sync") or _DEFAULTS["agent_sync"]
    cmd = [
        "ssh",
        "-p", str(cfg["ssh_port"]),
        "-i", cfg["ssh_key"],
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={int(cfg['ssh_timeout_secs'])}",
        cfg["ssh_host"],
        cfg["remote_command"],
    ]
    try:
        import subprocess
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=int(cfg["ssh_timeout_secs"]) + 5,
        )
    except Exception as e:
        return None, f"ssh failed: {e}"
    if r.returncode != 0:
        # Surface stderr (first line) so the operator can fix permissions.
        err = (r.stderr or "").strip().splitlines()[:1]
        return None, f"remote command rc={r.returncode}: {' / '.join(err)}"
    # Auto-detect the output format. client.keys lines start with the
    # agent id followed by a space; agent_control lines start with "ID:".
    stdout = r.stdout
    agents = _parse_client_keys(stdout)
    if not agents:
        agents = _parse_agent_control_l(stdout)
    if not agents:
        return None, "remote command returned no parseable agents"
    return agents, ""


def _merge_agents(fresh: list[dict], existing_path: Path) -> list[dict]:
    """Merge `fresh` (from agent_control) with existing agents.json entries.

    Preserves fields the CLI doesn't return — most importantly `os` — by
    keying on agent id. New agents picked up from Wazuh just won't have
    those fields until the operator fills them in (or we extend the
    poller to call `agent_control -i <id>` for OS info).
    """
    by_id: dict = {}
    if existing_path.exists():
        try:
            for rec in json.loads(existing_path.read_text(encoding="utf-8") or "[]"):
                if isinstance(rec, dict) and rec.get("id"):
                    by_id[str(rec["id"])] = dict(rec)
        except Exception:
            pass
    fresh_ids: set = set()
    out: list[dict] = []
    for a in fresh:
        aid = str(a["id"])
        fresh_ids.add(aid)
        merged = dict(by_id.get(aid, {}))
        # Always trust the manager for id + name. For ip/status, only
        # overwrite when fresh has a real value — client.keys can return
        # empty strings (e.g. when an agent's IP is configured as "any"
        # or status isn't available from the file).
        merged["id"]   = aid
        merged["name"] = a["name"]
        if a.get("ip"):
            merged["ip"] = a["ip"]
        elif "ip" not in merged:
            merged["ip"] = ""
        if a.get("status"):
            merged["status"] = a["status"]
        out.append(merged)
    # Sort by numeric id for stable ordering.
    out.sort(key=lambda r: (int(r["id"]) if str(r["id"]).isdigit() else 9999, r["id"]))
    return out


def _write_agents_atomically(path: Path, agents: list[dict]) -> None:
    """Write agents.json with a tmp+rename so a reader never sees a half file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(agents, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _agent_sync_poll() -> None:
    """One round of the agent sync — runs in the background thread."""
    global _agent_sync_last_at, _agent_sync_last_error
    fresh, err = _fetch_agents_from_soc()
    with _agent_sync_lock:
        if err:
            _agent_sync_last_error = err
            print(f"[agent-sync] failed: {err}", flush=True)
            return
        try:
            merged = _merge_agents(fresh, AGENTS_REGISTRY)
            _write_agents_atomically(AGENTS_REGISTRY, merged)
            _agent_sync_last_at    = datetime.now(timezone.utc).isoformat()
            _agent_sync_last_error = ""
            print(f"[agent-sync] wrote {len(merged)} agents to {AGENTS_REGISTRY}", flush=True)
        except Exception as e:
            _agent_sync_last_error = f"write failed: {e}"
            print(f"[agent-sync] write failed: {e}", flush=True)


def _start_agent_sync_thread() -> None:
    """Spawn the agent-sync background thread (daemon, won't block shutdown)."""
    import threading
    cfg = CFG.get("agent_sync") or _DEFAULTS["agent_sync"]
    if not cfg.get("enabled"):
        print("[agent-sync] disabled in config")
        return
    interval = max(15, int(cfg.get("poll_interval_secs", 60)))

    def _loop():
        # Do one fetch immediately so first request after startup is fresh.
        _agent_sync_poll()
        while True:
            time.sleep(interval)
            _agent_sync_poll()

    t = threading.Thread(target=_loop, name="agent-sync", daemon=True)
    t.start()
    print(f"[agent-sync] polling every {interval}s — `{cfg['remote_command']}`")


def load_fps() -> None:
    """Load FPs from disk into _fp_dict. Safe to call multiple times."""
    global _fp_dict
    if not FP_FILE.exists():
        _fp_dict = {}
        return
    try:
        data = json.loads(FP_FILE.read_text(encoding="utf-8") or "[]")
        if isinstance(data, list):
            _fp_dict = {r["event_id"]: r for r in data if isinstance(r, dict) and r.get("event_id")}
        else:
            _fp_dict = {}
    except Exception as e:
        print(f"[dashboard] failed to load FP file {FP_FILE}: {e}")
        _fp_dict = {}


def save_fps() -> None:
    """Atomically write _fp_dict to FP_FILE."""
    tmp = FP_FILE.with_suffix(FP_FILE.suffix + ".tmp")
    try:
        FP_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(list(_fp_dict.values()), indent=2), encoding="utf-8")
        tmp.replace(FP_FILE)
    except Exception as e:
        print(f"[dashboard] failed to persist FPs to {FP_FILE}: {e}")
    # FP state changed → cached aggregations now include alerts that should be
    # filtered (or vice-versa). Drop them so the next request recomputes fresh and
    # the analyst sees their FP mark take effect immediately, not after the TTL.
    _invalidate_result_cache()


def load_fp_patterns() -> None:
    """Load FP patterns from disk into _fp_patterns.

    Accepts both the new shape (`rule_description`) and the legacy shape
    (`signature_id` + optional `user`/`agent`). Legacy entries are dropped
    with a warning since they can't be migrated without alert context — the
    analyst will need to re-mark a representative alert FP to recreate them.
    """
    global _fp_patterns
    if not FP_PATTERNS_FILE.exists():
        _fp_patterns = []
        return
    try:
        data = json.loads(FP_PATTERNS_FILE.read_text(encoding="utf-8") or "[]")
        if isinstance(data, list):
            kept, dropped = [], 0
            for p in data:
                if isinstance(p, dict) and (p.get("rule_description") or "").strip():
                    kept.append(p)
                elif isinstance(p, dict) and p.get("signature_id"):
                    dropped += 1
            _fp_patterns = kept
            if dropped:
                print(f"[dashboard] dropped {dropped} legacy sig-based FP pattern(s) — re-mark to recreate")
        else:
            _fp_patterns = []
    except Exception as e:
        print(f"[dashboard] failed to load FP patterns {FP_PATTERNS_FILE}: {e}")
        _fp_patterns = []


def save_fp_patterns() -> None:
    """Atomically write _fp_patterns to FP_PATTERNS_FILE."""
    tmp = FP_PATTERNS_FILE.with_suffix(FP_PATTERNS_FILE.suffix + ".tmp")
    try:
        FP_PATTERNS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(_fp_patterns, indent=2), encoding="utf-8")
        tmp.replace(FP_PATTERNS_FILE)
    except Exception as e:
        print(f"[dashboard] failed to persist FP patterns to {FP_PATTERNS_FILE}: {e}")
    _invalidate_result_cache()


def _alert_matches_pattern(alert: dict, pattern: dict) -> bool:
    """Return True iff alert's rule description matches the pattern's
    rule_description (trim + case-insensitive) AND the alert arrived after
    the pattern was created. The time guard keeps historical alerts visible
    — patterns only suppress NEW alerts going forward.
    """
    sec = alert.get("security", {}) or {}
    if _norm_desc(sec.get("signature")) != _norm_desc(pattern.get("rule_description")):
        return False
    # Time guard: pattern.marked_at must exist; alert must have been *emitted
    # by the engine* strictly later. Compare against ueba.processed_at (engine
    # time) rather than event_time (source time) — a backlog replay can produce
    # alerts whose event_time is days old but whose processed_at is "now".
    p_at = _parse_iso(pattern.get("marked_at"))
    ueba = alert.get("ueba", {}) or {}
    a_at = _parse_iso(ueba.get("processed_at") or alert.get("event_time"))
    if p_at is None or a_at is None:
        return False
    return a_at > p_at


def _matching_pattern(alert: dict):
    """Return the first FP pattern matching this alert, or None."""
    if not _fp_patterns:
        return None
    for p in _fp_patterns:
        if _alert_matches_pattern(alert, p):
            return p
    return None


def _pattern_from_alert(alert: dict, reason: str) -> dict | None:
    """Build an FP pattern record from an alert's rule description.

    The pattern suppresses every future alert whose rule description (the
    human-readable rule name, `security.signature`) matches — regardless of
    user, host, or even signature_id. This is the broad "this kind of activity
    is benign here" semantic.

    Returns None if the alert has no rule description.
    """
    sec = alert.get("security", {}) or {}
    desc = (str(sec.get("signature") or "")).strip()
    if not desc:
        return None
    return {
        "id":               "fpp-" + uuid.uuid4().hex[:10],
        "rule_description": desc,
        "reason":           reason or "auto-suppress from analyst FP mark",
        "marked_at":        datetime.now(timezone.utc).isoformat(),
    }


def _add_pattern_if_new(candidate: dict | None):
    """Append candidate to _fp_patterns unless an identical rule_description
    already exists. Returns (record, was_new). If candidate is None or has no
    rule_description, returns (None, False).
    """
    if not candidate or not (candidate.get("rule_description") or "").strip():
        return None, False
    cand_norm = _norm_desc(candidate["rule_description"])
    with _fp_pat_lock:
        for p in _fp_patterns:
            if _norm_desc(p.get("rule_description")) == cand_norm:
                return p, False
        _fp_patterns.append(candidate)
        save_fp_patterns()
        return candidate, True


def _remove_patterns_for_descriptions(descriptions) -> int:
    """Drop every FP pattern whose rule_description matches any in the given
    iterable (whitespace-trimmed, case-insensitive). Persists once if anything
    changed. Returns the number of patterns removed.

    Used by the FP restore flow so that un-marking an alert also tears down
    the auto-suppression pattern that was created when it was marked. Without
    this, Restore only frees the single event from the FP filter while the
    pattern keeps suppressing every other alert with the same signature —
    surprising the analyst and starving the engine of those alerts.
    """
    targets = {_norm_desc(d) for d in descriptions if d}
    if not targets:
        return 0
    removed = 0
    with _fp_pat_lock:
        keep = []
        for p in _fp_patterns:
            if _norm_desc(p.get("rule_description")) in targets:
                removed += 1
                continue
            keep.append(p)
        if removed:
            _fp_patterns[:] = keep
            save_fp_patterns()
    return removed


def _read_live_alerts(n: int | None = None) -> list:
    """Read the live ueba_alerts.jsonl (today's alerts), newest `n`, oldest-first
    (no FP filtering).

    The file is append-only and large (hundreds of MB of fat records), and the
    engine appends to it every second — so re-reading the whole file per request
    (and an mtime-keyed cache, which never hits because mtime keeps changing) made
    every API call re-parse the entire file and take minutes. Instead we keep a
    parsed cache and only read the bytes appended since the last call, tracking a
    byte offset; inode + a shrink check force a full re-read on midnight rotation.
    """
    global _alert_cache, _alert_cache_off, _alert_cache_inode
    if n is None:
        n = CFG["max_alerts"]
    if not ALERTS_FILE.exists():
        return []
    try:
        st = ALERTS_FILE.stat()
    except Exception:
        return _alert_cache[-n:] if n else _alert_cache

    # Serialize cache update so a burst of parallel requests during a cold window
    # doesn't trigger N concurrent full re-parses (thundering herd) or corrupt the
    # shared cache. One thread re-parses; the others wait then reuse the warm cache.
    with _alert_read_lock:
        # Detect rotation/truncation (midnight rollover replaces the file, or it
        # shrinks): drop the cache and re-read from the top.
        if st.st_ino != _alert_cache_inode or st.st_size < _alert_cache_off:
            _alert_cache = []
            _alert_cache_off = 0
            _alert_cache_inode = st.st_ino

        # Parse only the newly-appended bytes (if any) since the last read.
        if st.st_size > _alert_cache_off:
            try:
                with open(ALERTS_FILE, "rb") as f:
                    f.seek(_alert_cache_off)
                    chunk = f.read()
            except Exception:
                return _alert_cache[-n:] if n else _alert_cache
            # Consume up to the last complete line; a trailing partial line (engine
            # mid-append) is left for the next call.
            nl = chunk.rfind(b"\n")
            if nl != -1:
                complete = chunk[:nl + 1]
                _alert_cache_off += len(complete)
                for raw in complete.split(b"\n"):
                    if not raw.strip():
                        continue
                    try:
                        _alert_cache.append(_slim(_jloads(raw)))
                    except Exception:
                        continue
                cap = int(CFG.get("max_alerts", 500000) or 500000)
                if len(_alert_cache) > cap:
                    del _alert_cache[:len(_alert_cache) - cap]

        return _alert_cache[-n:] if n else _alert_cache


def _alert_ts(a: dict) -> datetime | None:
    """Best-effort timestamp for windowing/sorting: engine processed_at, else
    source event_time. Mirrors the client-side timeline filter.

    The parsed datetime is memoised on the alert dict under "__ts" because the
    same dicts live for a long time in the archive/live caches and were being
    re-parsed (datetime.fromisoformat) on every windowed request — hundreds of
    thousands of ISO strings per API call. Parse once, reuse forever; only newly
    appended alerts ever pay the parse. A separate sentinel distinguishes
    "not computed yet" from a legitimately unparseable timestamp (cached as None)."""
    cached = a.get("__ts", _TS_UNSET)
    # Valid memo states: a datetime, or None (a cached "unparseable" result).
    # Anything else (notably a str — which is what orjson would produce if a
    # datetime memo ever got serialized into a persisted slim cache) is treated
    # as "not computed" and recomputed, so a poisoned memo can never leak a str
    # into the datetime comparisons in the builders.
    if cached is None or isinstance(cached, datetime):
        return cached
    ueba = a.get("ueba") or {}
    ts = _parse_iso(ueba.get("processed_at") or a.get("event_time"))
    a["__ts"] = ts
    return ts


def _parse_archive_zip(path: Path) -> list | None:
    """Unzip a daily archive and parse its JSONL into a list of SLIM alert dicts
    (see _slim). Returns None on a hard failure (corrupt zip / unreadable) so the
    caller can skip it without aborting the whole window.

    Daily archives are immutable after the midnight rotation, so the first parse
    also writes a compact on-disk slim cache (`<archive>.slimN`) next to the zip;
    subsequent restarts load that directly — no unzip, no re-parse of the fat
    records, no re-projection. Measured: cold archive warm 295s -> a few seconds
    once the slim caches exist."""
    slim_path = path.with_suffix(".slim%d" % _SLIM_VER)
    # Fast path: a fresh slim cache already exists.
    try:
        if slim_path.exists() and slim_path.stat().st_mtime >= path.stat().st_mtime:
            data = _jloads(slim_path.read_bytes())
            if isinstance(data, list):
                return data
    except Exception:
        pass  # fall through to a full parse/rebuild
    try:
        alerts: list = []
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if n.endswith(".jsonl")] or zf.namelist()
            for name in names:
                with zf.open(name) as fh:
                    for raw in fh:
                        if not raw.strip():
                            continue
                        try:
                            alerts.append(_slim(_jloads(raw)))
                        except Exception:
                            continue
        # Persist the slim projection for the next restart (best-effort, atomic).
        try:
            tmp = slim_path.with_suffix(slim_path.suffix + ".tmp")
            tmp.write_bytes(_jdumps(alerts))
            tmp.replace(slim_path)
        except Exception:
            pass
        return alerts
    except Exception:
        return None


def _read_archived_alerts(cutoff: datetime) -> list:
    """Alerts from daily archive zips whose date is on/after `cutoff`'s date.
    Each archive is parsed once and cached by mtime (archives never change after
    the midnight rotation), and only files inside the window are ever opened."""
    global _archive_warn_at
    adir = Path(CFG.get("archive_dir") or "")
    if not adir.is_dir():
        return []
    cutoff_date = cutoff.date()
    out: list = []
    try:
        entries = sorted(adir.glob("ueba_alerts_*.jsonl.zip"))
    except Exception:
        return []
    for path in entries:
        m = _ARCHIVE_RE.search(path.name)
        if not m:
            continue
        try:
            fdate = datetime.strptime(m.group(1), "%Y-%m-%d").date()
        except ValueError:
            continue
        if fdate < cutoff_date:
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        with _archive_lock:
            cached = _archive_cache.get(str(path))
            if cached and cached[0] == mtime:
                out.extend(cached[1])
                continue
        # Parse outside the lock (unzip can be slow); store under the lock after.
        alerts = _parse_archive_zip(path)
        if alerts is None:
            now = time.time()
            if now - _archive_warn_at > 300:
                _archive_warn_at = now
                print(f"[dashboard] WARNING: could not read archive {path.name}; skipping")
            continue
        with _archive_lock:
            _archive_cache[str(path)] = (mtime, alerts)
        out.extend(alerts)
    return out


# Sentinel for the per-alert timestamp memo in _alert_ts (None is a valid,
# cached "unparseable" result, so it can't double as "not computed yet").
_TS_UNSET = object()

# ── Windowed snapshot cache (with thundering-herd protection) ────────────────
# Building a window (merge archives+live, decorate, sort, cap) is the single
# hottest path in the dashboard: every boot fires 5+ endpoints (stats/feed/users/
# campaigns/agents/health) that each call load_alerts() for the SAME window, and
# the 30s auto-refresh repeats it. Without coordination those requests rebuild
# the same multi-hundred-thousand-row list *concurrently* — saturating every core
# AND allocating N copies of the decorated list at once (which is exactly how a
# restart-time burst ballooned RSS toward OOM). Two-part fix:
#   1. Memoise the built window keyed by `hours` for a short TTL.
#   2. Serialise the *build* behind the lock so a cold-cache burst does ONE build
#      and every other caller waits for it and reuses the snapshot — never N
#      parallel builds. The lock is held during the build; that's intentional
#      (callers should wait, not pile up). TTL is well under the 30s refresh and
#      the live SSE stream still pushes new alerts in real time, so the brief
#      staleness is invisible.
_window_cache: dict = {}        # hours -> (built_at, list, window_total)
_window_cache_lock = __import__("threading").RLock()
_WINDOW_TTL = 5.0               # seconds


def _read_alerts_windowed(hours: int, n: int | None = None) -> list:
    """Live + archived alerts within the requested window, oldest-first, capped
    at `max_feed_alerts` (most-recent kept). hours==0 → full `history_days`.

    Records with an unparseable timestamp are kept (never silently dropped) and
    sorted as oldest. The pre-cap in-window total is stashed in
    `_last_window_total` so /api/stats can tell the analyst when a wide window
    was truncated.

    Results are memoised for `_WINDOW_TTL` seconds keyed by `hours`, and the build
    is serialised (see the herd note above) so a burst of concurrent endpoints
    reuses one snapshot instead of each rebuilding it. `n` is not part of the key:
    every API caller uses the default (max_alerts), so it never varies."""
    global _last_window_total

    def _fresh():
        hit = _window_cache.get(hours)
        if hit is not None and (time.time() - hit[0]) < _WINDOW_TTL:
            return hit
        return None

    # Fast path: a fresh snapshot already exists — return it without building.
    with _window_cache_lock:
        hit = _fresh()
        if hit is not None:
            _last_window_total = hit[2]
            return hit[1]

        # Cold/stale. Build while holding the lock so concurrent callers block
        # here and then fall through to reuse what we store — one build, not N.
        # (Re-check first in case we raced another builder that just finished.)
        hit = _fresh()
        if hit is not None:
            _last_window_total = hit[2]
            return hit[1]

        history_days = int(CFG.get("history_days", 95) or 95)
        cap = int(CFG.get("max_feed_alerts", 10000) or 10000)
        now = datetime.now(timezone.utc)
        cutoff = now - (timedelta(hours=hours) if hours and hours > 0
                        else timedelta(days=history_days))

        combined = _read_archived_alerts(cutoff) + _read_live_alerts(n)
        decorated = []
        for a in combined:
            ts = _alert_ts(a)
            if ts is None or ts >= cutoff:
                decorated.append((ts or _MIN_DT, a))
        decorated.sort(key=lambda t: t[0])
        window_total = len(decorated)
        if len(decorated) > cap:
            decorated = decorated[-cap:]
        result = [a for _, a in decorated]

        _last_window_total = window_total
        _window_cache[hours] = (time.time(), result, window_total)
        return result


def _read_all_alerts_for_lookup() -> list:
    """Live + ALL archived alerts within history_days, UNCAPPED. Used only by the
    FP mutators to resolve an alert (or campaign) by id — they must find any
    alert the analyst can currently see, including ones loaded from archives."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(CFG.get("history_days", 95) or 95))
    return _read_archived_alerts(cutoff) + _read_live_alerts()


def _window_hours() -> int:
    """Timeline window (hours) requested via ?hours=N. 0 / absent / invalid → 0
    ('All', bounded server-side to history_days), matching the default view."""
    if not has_request_context():
        return 0
    v = (request.args.get("hours") or "").strip()
    if not v:
        return 0
    try:
        h = int(v)
        return h if h > 0 else 0
    except (TypeError, ValueError):
        return 0


def load_alerts(n: int | None = None, include_fp: bool = False,
                hours: int | None = None) -> list:
    """Load alerts for the current timeline window. By default filters out any
    alert that is FP-marked, either by event_id (per-instance) or by a stored
    fingerprint pattern (signature_id + user + agent). Pass include_fp=True to
    opt out (used by the "show FPs" feed view and by /api/false-positives).

    The window comes from the request's ?hours=N (0 = All) unless `hours` is
    passed explicitly. Spans live + archived alerts so the timeline filters
    actually have history to show.
    """
    if hours is None:
        hours = _window_hours()
    raw = _read_alerts_windowed(hours, n)
    if include_fp:
        return raw
    if not _fp_dict and not _fp_patterns:
        return raw
    out = []
    for a in raw:
        if a.get("event_id") in _fp_dict:
            continue
        if _matching_pattern(a) is not None:
            continue
        out.append(a)
    return out


def _wants_include_fp() -> bool:
    """Read ?include_fp=1 from the current request."""
    v = (request.args.get("include_fp") or "").strip().lower()
    return v in ("1", "true", "yes", "y")


# ── Endpoint result cache + background warmer ────────────────────────────────
# The window snapshot cache (above) makes *loading* a window cheap, but each
# heavy endpoint (stats/users/campaigns/agents/feed) still iterates the whole
# window to AGGREGATE its answer — and for the wide "All" window that's 300k+
# alerts per endpoint. Python's GIL serialises those CPU-bound aggregations, so a
# boot burst of 5 endpoints runs them back-to-back (~13s on "All"). Two parts:
#   1. Cache each endpoint's computed JSON value keyed by (name, hours, include_fp)
#      so a refresh / extra browser tab / multi-analyst fleet returns instantly.
#   2. A background warmer recomputes the cache for *actively-viewed* windows every
#      few seconds, so a window someone is watching is always pre-aggregated and
#      its next load is instant — the heavy aggregation happens off the request
#      path. Idle windows stop being refreshed and age out, so we never burn CPU
#      aggregating a window nobody is looking at.
# Staleness is bounded by the warm interval (seconds) and is invisible: the feed
# table auto-refreshes every 30s and the live SSE stream pushes new alerts in
# real time regardless.
# Reads of _result_cache never block: dict get/set are atomic under the GIL, and
# readers serve the last cached value while the warmer refreshes it in the
# background. Builds are coordinated by *per-key* locks so (a) two threads never
# build the same key at once and (b) one slow endpoint's build never blocks a
# different endpoint or window. The big shared alert list is built once by the
# window cache (with its own herd lock), so concurrent per-endpoint aggregations
# operate on that shared list and don't each duplicate it — memory stays bounded.
_result_cache: dict = {}            # (name, hours, include_fp) -> (built_at, value)
_active_windows: dict = {}          # (hours, include_fp) -> last_requested (epoch)
_result_build_locks: dict = {}      # key -> Lock (one builder per key)
_result_locks_guard = __import__("threading").Lock()
_RESULT_TTL = 45.0                  # a value newer than this is served as-is
_STALE_SERVE_MAX = 600.0            # serve an older value rather than block, up to this
_RESULT_REFRESH_AGE = 18.0          # warmer rebuilds an entry only once it's older than this
_WARM_TICK = 5.0                    # how often the warmer wakes to check freshness
_ACTIVE_WINDOW_TTL = 180.0          # keep warming a window seen within this long
_ENDPOINT_BUILDERS: dict = {}       # name -> builder(alerts) -> JSON value


def _build_lock_for(key):
    """Per-key build lock so only one thread (re)builds a given cache entry, while
    other keys build freely in parallel."""
    with _result_locks_guard:
        lk = _result_build_locks.get(key)
        if lk is None:
            lk = __import__("threading").Lock()
            _result_build_locks[key] = lk
        return lk


def _invalidate_result_cache() -> None:
    """Drop all cached endpoint results (e.g. after a false-positive change) so the
    next request recomputes against the new FP state instead of serving a stale
    aggregation. Safe to call from any thread / request handler."""
    _result_cache.clear()


def _build_and_store(name: str, builder, hours: int, include_fp: bool):
    """(Re)build one cache entry under its per-key lock and store it. Returns the
    fresh value. If another thread built it while we waited for the lock, reuse
    that instead of rebuilding."""
    key = (name, hours, include_fp)
    with _build_lock_for(key):
        hit = _result_cache.get(key)
        if hit is not None and (time.time() - hit[0]) < _RESULT_TTL:
            return hit[1]
        alerts = load_alerts(include_fp=include_fp, hours=hours)
        value = builder(alerts)
        _result_cache[key] = (time.time(), value)
        return value


def _endpoint_result(name: str, builder, hours: int, include_fp: bool):
    """Return the cached value for (name, hours, include_fp). Fresh hits return
    instantly with no lock. A slightly-stale value is also returned immediately
    (the warmer keeps active windows fresh in the background); we only block to
    build when there is no usable cached value at all (first-ever request for the
    window, or right after a cache invalidation)."""
    key = (name, hours, include_fp)
    now = time.time()
    _active_windows[(hours, include_fp)] = now
    hit = _result_cache.get(key)
    if hit is not None:
        age = now - hit[0]
        if age < _RESULT_TTL:
            return hit[1]                       # fresh — instant
        if age < _STALE_SERVE_MAX:
            return hit[1]                       # serve stale now; warmer will refresh
    # No usable cached value → build it (per-key lock; concurrent callers for the
    # same key wait once and then reuse).
    return _build_and_store(name, builder, hours, include_fp)


def _cached_endpoint(name: str, builder):
    """Request-context entry point: resolve the window from the request, register
    it as active (so the warmer keeps it hot), and return the cached/built value."""
    return _endpoint_result(name, builder, _window_hours(), _wants_include_fp())


def _warm_results_loop() -> None:
    """Daemon: keep the result cache hot for windows analysts are actively viewing
    so their loads stay instant. The heavy aggregation runs here, off the request
    path; each (endpoint, window) is rebuilt under its own per-key lock so it never
    blocks a live request for a different endpoint/window."""
    while True:
        try:
            time.sleep(_WARM_TICK)
            now = time.time()
            windows = [w for w, seen in list(_active_windows.items())
                       if (now - seen) < _ACTIVE_WINDOW_TTL]
            for (hours, include_fp) in windows:
                for name, builder in list(_ENDPOINT_BUILDERS.items()):
                    try:
                        key = (name, hours, include_fp)
                        # Only rebuild entries that are getting stale — skip ones
                        # still fresh so the warmer doesn't peg a core recomputing
                        # the heavy "All" window every tick for no benefit.
                        hit = _result_cache.get(key)
                        if hit is not None and (now - hit[0]) < _RESULT_REFRESH_AGE:
                            continue
                        with _build_lock_for(key):
                            alerts = load_alerts(include_fp=include_fp, hours=hours)
                            _result_cache[key] = (time.time(), builder(alerts))
                    except Exception:
                        pass  # never let one bad build kill the warmer
        except Exception:
            time.sleep(_WARM_TICK)


def _looks_like_request(v) -> bool:
    """True if a string looks like an HTTP request path / URL / query rather than
    a username. Web-attack decoders (SQLi/XSS scans on /search.php?q=...) put the
    raw request in object.name, which must NEVER be shown as a 'user' — otherwise
    every unique attack payload becomes its own bogus user in the risk view.
    Real usernames (incl. DOMAIN\\user) never start with '/' or contain '?'/'%2'."""
    if not isinstance(v, str):
        return False
    s = v.strip()
    if not s:
        return False
    return (s.startswith("/") or s.startswith("http://") or s.startswith("https://")
            or "?" in s or "%2" in s or "../" in s or "<" in s)


def get_user(alert: dict) -> str:
    """Resolve the most meaningful username from an alert, memoised on the dict.

    The resolution (below) is non-trivial — many nested lookups plus a regex
    request-shape check at every step — and it's called once per alert by stats,
    users, campaigns, agents AND the per-user/agent drilldowns, which each scan
    the whole window. Caching the result on the dict (`__user`) makes a repeat
    scan a dict.get instead of re-resolving 300k+ times. Same dicts live in the
    alert caches, so the memo persists; only new alerts pay the resolution."""
    cached = alert.get("__user", _TS_UNSET)
    if cached is not _TS_UNSET:
        return cached
    u = _resolve_user(alert)
    alert["__user"] = u
    return u


def _resolve_user(alert: dict) -> str:
    """Resolve the most meaningful username from an alert.
    Priority: subject.name > raw_event user fields > object.name (if not a URL)
              > host/agent name > subject.ip > ae model (if personal) > 'unknown'

    Request-like values (URLs/paths/queries from web-attack events) are rejected
    at every step, and user-less events fall back to the AGENT name rather than a
    raw IP — so web scans group under their target agent (e.g. 'Agent-70') instead
    of flooding the view with one 'user' per attack payload.
    """
    sub  = alert.get("subject", {}) or {}
    obj  = alert.get("object", {}) or {}
    ueba = alert.get("ueba", {}) or {}
    host = alert.get("host", {}) or {}
    raw  = (alert.get("context", {}) or {}).get("raw_event", {}) or {}
    win  = (raw.get("data", {}) or {}).get("win", {}) or {}
    wed  = (win.get("eventdata", {}) or {})
    raw_data = raw.get("data", {}) or {}

    def _ok(v):
        return v and v not in ("", "-", None) and not _looks_like_request(v)

    if _ok(sub.get("name")):
        return sub["name"]

    for field in ("subjectUserName", "targetUserName", "subjectDomainName"):
        if _ok(wed.get(field)):
            return wed[field]

    for field in ("srcuser", "dstuser", "user", "username", "accountName"):
        if _ok(raw_data.get(field)):
            return raw_data[field]

    if _ok(obj.get("name")):
        return obj["name"]

    # No real username — prefer the AGENT/host name over a bare IP so web-attack
    # scans and other user-less events group under their agent instead of a
    # request URL or a raw IP.
    hname = host.get("name")
    if hname and hname not in ("", None):
        return hname

    ip = sub.get("ip")
    if ip and ip not in ("", None):
        return ip

    model = ueba.get("raw_scores", {}).get("autoencoder", {}).get("model_used", "")
    if model and model not in ("global", "unknown", "", None):
        return model

    return "unknown"


@app.route("/api/stats")
def stats():
    """Overall stats for the stats overview panel."""
    return jsonify(_cached_endpoint("stats", _build_stats))


def _build_stats(alerts):
    if not alerts:
        return {
            "total_alerts": 0, "highly_anomalous": 0, "anomalous": 0,
            "suspicious": 0, "campaigns": 0, "suppressed_noise": 0,
            "unique_users": 0, "alert_rate_1h": 0, "top_reasons": []
        }

    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)

    # Single pass over the window (was 7 separate passes) — for the wide "All"
    # window that's 300k+ alerts, so collapsing the passes makes this ~7x cheaper
    # and keeps the background warmer light.
    total = len(alerts)
    highly = anomalous = suspicious = alert_rate_1h = 0
    campaign_ids: set = set()
    users_seen: set = set()
    reason_counts: dict = defaultdict(int)
    for a in alerts:
        ueba = a.get("ueba", {}) or {}
        verdict = ueba.get("risk_verdict")
        if verdict == "highly_anomalous": highly += 1
        elif verdict == "anomalous":      anomalous += 1
        elif verdict == "suspicious":     suspicious += 1
        cid = ueba.get("campaign_id")
        if cid:
            campaign_ids.add(cid)
        users_seen.add(get_user(a))
        for r in (ueba.get("anomaly_reasons") or []):
            reason_counts[r] += 1
        ts = _alert_ts(a)   # memoised parse
        if ts is not None and ts >= one_hour_ago:
            alert_rate_1h += 1

    campaigns    = len(campaign_ids)
    unique_users = len(users_seen)
    top_reasons  = sorted(reason_counts.items(), key=lambda x: -x[1])[:5]

    cap = int(CFG.get("max_feed_alerts", 10000) or 10000)
    return {
        "total_alerts":    total,
        "highly_anomalous": highly,
        "anomalous":       anomalous,
        "suspicious":      suspicious,
        "campaigns":       campaigns,
        "unique_users":    unique_users,
        "alert_rate_1h":   alert_rate_1h,
        "top_reasons":     [{"reason": r, "count": c} for r, c in top_reasons],
        # Window truncation honesty: when the selected window holds more alerts
        # than the cap, the feed shows the most-recent `cap` and the UI says so.
        "window_total":    _last_window_total,
        "window_cap":      cap,
        "window_capped":   _last_window_total > cap,
    }


def _alert_to_feed_item(a: dict, include_evidence: bool = True) -> dict:
    """Map a raw alert (as written by the engine) to the compact dict shape
    consumed by the dashboard feed table. Used by /api/feed, the SSE
    /api/stream endpoint, and the per-user/per-agent/FP drilldowns.

    `include_evidence=False` (used by the bulk /api/feed) drops the `evidence`
    blob — by far the heaviest field (~77% of the JSON) and only needed when an
    analyst expands a single row. The dashboard then lazy-fetches it via
    /api/evidence/<event_id>. The small `mitre_techniques` list is kept inline
    regardless, because the MITRE heatmap aggregates it across the whole feed
    and can't afford a fetch-per-row.
    """
    ueba = a.get("ueba", {}) or {}
    sec  = a.get("security", {}) or {}
    host = a.get("host", {}) or {}
    ev   = a.get("evidence", {}) or {}
    eid  = a.get("event_id")
    item = {
        "event_id":     eid,
        "event_time":   a.get("event_time"),
        "processed_at": ueba.get("processed_at"),
        "user":         get_user(a),
        "verdict":      ueba.get("risk_verdict"),
        "score":        ueba.get("combined_score"),
        "reasons":      ueba.get("anomaly_reasons", []),
        "campaign_id":  ueba.get("campaign_id"),
        "signature":    (sec.get("signature") or "")[:80],
        "signature_id": sec.get("signature_id"),
        "severity":     sec.get("severity"),
        "host":         host.get("name"),
        "host_ip":      host.get("ip"),
        # Slim records (from the cache) carry MITRE pre-extracted under __mitre_*;
        # full records (the live SSE stream) fall back to the deep raw paths.
        "mitre_tactic": a["__mitre_tactic"] if "__mitre_tactic" in a
            else (a.get("context", {}) or {}).get("raw_event", {}).get("rule", {}).get("mitre", {}).get("tactic", []),
        "mitre_techniques": a["__mitre_techniques"] if "__mitre_techniques" in a
            else (ev.get("signature", {}) or {}).get("mitre_techniques", []),
        "fp":           _fp_dict.get(eid) if eid else None,
        "fp_pattern":   _matching_pattern(a),
    }
    if include_evidence:
        item["evidence"] = ev
    return item


@app.route("/api/feed")
def feed():
    """Live alert feed — all loaded alerts, newest first.
    FP-marked alerts are filtered out unless ?include_fp=1 is passed.

    Evidence is omitted here (see _alert_to_feed_item) so a wide timeline window
    can return up to max_feed_alerts rows without shipping a multi-hundred-MB
    payload; the dashboard lazy-loads each alert's evidence via /api/evidence.
    """
    return jsonify(_cached_endpoint("feed", _build_feed))


def _build_feed(alerts):
    # Cap the table payload to the newest rows so a high-volume window doesn't
    # ship tens of MB and freeze the browser. alerts is oldest-first, so the
    # newest slice is the tail; reverse it to newest-first for the table.
    cap = int(CFG.get("feed_row_cap", 5000) or 5000)
    recent = alerts[-cap:] if len(alerts) > cap else alerts
    return [_alert_to_feed_item(a, include_evidence=False) for a in reversed(recent)]


def _find_evidence(event_id: str) -> dict:
    """Lazy-load one alert's evidence blob from disk by event_id.

    The in-memory caches hold SLIM records (no evidence) to keep RSS small, so a
    panel expand re-reads the source. Live file first (recent, cheapest); then
    archive zips newest-first. A cheap substring pre-filter (`id in raw_line`)
    means only the matching line is ever JSON-parsed, so scanning even a large
    file is fast; a full evidence fetch is a rare, single-row action."""
    if not event_id:
        return {}
    target = event_id.encode("utf-8", "replace")

    def _scan_lines(line_iter):
        for raw in line_iter:
            if target not in raw:
                continue
            try:
                o = _jloads(raw)
            except Exception:
                continue
            if o.get("event_id") == event_id:
                return o.get("evidence") or {}
        return None

    # Live file (raw bytes, most likely target for recent alerts).
    try:
        if ALERTS_FILE.exists():
            with open(ALERTS_FILE, "rb") as f:
                hit = _scan_lines(f)
                if hit is not None:
                    return hit
    except Exception:
        pass

    # Archives, newest day first.
    adir = Path(CFG.get("archive_dir") or "")
    if adir.is_dir():
        try:
            entries = sorted(adir.glob("ueba_alerts_*.jsonl.zip"), reverse=True)
        except Exception:
            entries = []
        for path in entries:
            try:
                with zipfile.ZipFile(path) as zf:
                    names = [n for n in zf.namelist() if n.endswith(".jsonl")] or zf.namelist()
                    for name in names:
                        with zf.open(name) as fh:
                            hit = _scan_lines(fh)
                            if hit is not None:
                                return hit
            except Exception:
                continue
    return {}


@app.route("/api/evidence/<path:event_id>")
def alert_evidence(event_id):
    """Evidence blob for one alert, looked up by event_id from disk. Backs the
    dashboard's lazy evidence panel: /api/feed omits evidence to stay light and
    the caches hold slim records, so this returns it on demand when a row is
    expanded. Returns {} if the alert isn't found or carries no evidence."""
    return jsonify(_find_evidence(event_id) or {})


@app.route("/api/users")
def users():
    """User risk leaderboard — top 20 riskiest users."""
    return jsonify(_cached_endpoint("users", _build_users))


def _build_users(alerts):
    user_stats: dict = defaultdict(lambda: {
        "count": 0, "max_score": 0.0, "verdicts": defaultdict(int),
        "reasons": defaultdict(int), "last_seen": "", "hosts": set()
    })

    for a in alerts:
        user  = get_user(a)
        ueba  = a.get("ueba", {}) or {}
        score = ueba.get("combined_score", 0) or 0
        verdict = ueba.get("risk_verdict", "")
        host = (a.get("host", {}) or {}).get("name", "")

        user_stats[user]["count"] += 1
        user_stats[user]["max_score"] = max(user_stats[user]["max_score"], score)
        user_stats[user]["verdicts"][verdict] += 1
        user_stats[user]["last_seen"] = ueba.get("processed_at", "")
        if host:
            user_stats[user]["hosts"].add(host)
        for r in (ueba.get("anomaly_reasons") or []):
            user_stats[user]["reasons"][r] += 1

    leaderboard = []
    for user, s in user_stats.items():
        if user in ("unknown", "global", ""):
            continue
        risk = s["max_score"] * 0.5 + (s["count"] / 100) * 0.3 + \
               (s["verdicts"].get("highly_anomalous", 0) / max(s["count"], 1)) * 0.2
        leaderboard.append({
            "user":             user,
            "alert_count":      s["count"],
            "max_score":        round(s["max_score"], 3),
            "risk_index":       round(risk, 3),
            "top_verdict":      max(s["verdicts"], key=s["verdicts"].get) if s["verdicts"] else "",
            "top_reason":       max(s["reasons"], key=s["reasons"].get) if s["reasons"] else "",
            "last_seen":        s["last_seen"],
            "hosts":            list(s["hosts"])[:3],
            "highly_anomalous": s["verdicts"].get("highly_anomalous", 0),
        })

    leaderboard.sort(key=lambda x: -x["risk_index"])
    return leaderboard[:20]


@app.route("/api/campaigns")
def campaigns():
    """Campaign timeline data."""
    return jsonify(_cached_endpoint("campaigns", _build_campaigns))


def _build_campaigns(alerts):
    campaign_data: dict = defaultdict(lambda: {
        "alerts": [], "users": set(), "hosts": set(),
        "first_seen": "", "last_seen": "", "verdicts": defaultdict(int),
        "reasons": defaultdict(int), "signatures": set()
    })

    for a in alerts:
        ueba = a.get("ueba", {}) or {}
        cid  = ueba.get("campaign_id")
        if not cid:
            continue
        user = get_user(a)
        host = (a.get("host", {}) or {}).get("name", "")
        t    = ueba.get("processed_at", "")
        sig  = ((a.get("security", {}) or {}).get("signature") or "")[:60]

        cd = campaign_data[cid]
        cd["users"].add(user)
        if host:
            cd["hosts"].add(host)
        cd["verdicts"][ueba.get("risk_verdict", "")] += 1
        for r in (ueba.get("anomaly_reasons") or []):
            cd["reasons"][r] += 1
        if sig:
            cd["signatures"].add(sig)
        if not cd["first_seen"] or t < cd["first_seen"]:
            cd["first_seen"] = t
        if t > cd["last_seen"]:
            cd["last_seen"] = t
        cd["alerts"].append({
            "time":    t,
            "user":    user,
            "score":   ueba.get("combined_score", 0),
            "verdict": ueba.get("risk_verdict", ""),
        })

    result = []
    for cid, cd in campaign_data.items():
        result.append({
            "campaign_id":   cid,
            "alert_count":   len(cd["alerts"]),
            "users":         list(cd["users"]),
            "hosts":         list(cd["hosts"]),
            "first_seen":    cd["first_seen"],
            "last_seen":     cd["last_seen"],
            "top_verdict":   max(cd["verdicts"], key=cd["verdicts"].get) if cd["verdicts"] else "",
            "top_reason":    max(cd["reasons"], key=cd["reasons"].get) if cd["reasons"] else "",
            "signatures":    list(cd["signatures"])[:3],
            "timeline":      sorted(cd["alerts"], key=lambda x: x["time"])[-20:],
            "highly_anomalous": cd["verdicts"].get("highly_anomalous", 0),
        })

    result.sort(key=lambda x: x["last_seen"], reverse=True)
    return result


# Verdict severity ordering, used to pick an incident's worst verdict.
_VERDICT_RANK = {"suspicious": 1, "anomalous": 2, "highly_anomalous": 3}


@app.route("/api/incidents")
def incidents():
    """Entity-behaviour incidents: alerts rolled up by (entity, time-window).

    This is the "calm" UEBA view — instead of one row per raw event (a single
    brute-force can be 1,000+ rows), each abnormal entity gets ONE incident per
    window, with a count and a drill-down list of contributing event_ids (the
    existing /api/evidence/<event_id> renders each one). It is purely additive:
    it reuses load_alerts()/get_user()/_alert_ts() so it matches every other
    panel, and changes nothing about the engine's per-event alert schema.

    Query params: ?hours=N (timeline window, same as the rest of the dashboard),
    ?window=M (rollup bucket in minutes, default 60, clamped 5..1440),
    ?include_fp=1 (show FP-marked alerts).
    """
    try:
        win_min = int(request.args.get("window", 60))
    except (TypeError, ValueError):
        win_min = 60
    win_min = max(5, min(win_min, 1440))
    win_sec = win_min * 60

    alerts = load_alerts(include_fp=_wants_include_fp())

    INCIDENT_CAP = 5000         # incidents returned (newest-first after sort)

    groups: dict = defaultdict(lambda: {
        "count": 0, "max_score": 0.0, "sum_score": 0.0,
        "verdicts": defaultdict(int), "reasons": defaultdict(int),
        "signatures": set(), "campaign_ids": set(), "hosts": set(),
        "first_seen": "", "last_seen": "",
    })

    for a in alerts:
        ts = _alert_ts(a)
        if ts is None:
            continue
        start_epoch = int(ts.timestamp()) // win_sec * win_sec
        window_start = datetime.fromtimestamp(start_epoch, tz=timezone.utc).isoformat()
        entity = get_user(a)
        ueba = a.get("ueba", {}) or {}
        sec  = a.get("security", {}) or {}
        t    = ueba.get("processed_at") or a.get("event_time") or ""

        g = groups[(entity, window_start)]
        g["count"] += 1
        score = float(ueba.get("combined_score") or 0.0)
        g["max_score"] = max(g["max_score"], score)
        g["sum_score"] += score
        g["verdicts"][ueba.get("risk_verdict", "")] += 1
        for r in (ueba.get("anomaly_reasons") or []):
            g["reasons"][r] += 1
        sig = ((sec.get("signature")) or "")[:60]
        if sig:
            g["signatures"].add(sig)
        cid = ueba.get("campaign_id")
        if cid:
            g["campaign_ids"].add(cid)
        host = (a.get("host", {}) or {}).get("name", "")
        if host:
            g["hosts"].add(host)
        if not g["first_seen"] or t < g["first_seen"]:
            g["first_seen"] = t
        if t > g["last_seen"]:
            g["last_seen"] = t

    result = []
    for (entity, window_start), g in groups.items():
        window_end = datetime.fromisoformat(window_start) + timedelta(minutes=win_min)
        # An incident takes the severity of its WORST event, not its most common
        # one — otherwise a burst of low-severity events would bury a single
        # highly-anomalous one inside it and sink the incident's ranking.
        present = [v for v in g["verdicts"] if v]
        top_verdict = max(present, key=lambda v: _VERDICT_RANK.get(v, 0)) if present else ""
        result.append({
            "incident_id":   f"{entity}|{window_start}",
            "entity":        entity,
            "window_start":  window_start,
            "window_end":    window_end.isoformat(),
            "window_minutes": win_min,
            "count":          g["count"],
            "max_score":      round(g["max_score"], 4),
            "avg_score":      round(g["sum_score"] / g["count"], 4) if g["count"] else 0.0,
            "top_verdict":    top_verdict,
            "verdicts":       dict(g["verdicts"]),
            "highly_anomalous": g["verdicts"].get("highly_anomalous", 0),
            "reasons":        [r for r, _ in sorted(g["reasons"].items(), key=lambda x: -x[1])[:5]],
            "signatures":     list(g["signatures"])[:5],
            "campaign_ids":   list(g["campaign_ids"]),
            "hosts":          list(g["hosts"]),
            "first_seen":     g["first_seen"],
            "last_seen":      g["last_seen"],
        })

    # Rank by risk: worst verdict, then peak score, then volume.
    result.sort(key=lambda x: (_VERDICT_RANK.get(x["top_verdict"], 0),
                               x["max_score"], x["count"]), reverse=True)
    total = len(result)
    return jsonify({
        "incidents":     result[:INCIDENT_CAP],
        "incident_total": total,
        "incident_capped": total > INCIDENT_CAP,
        "window_minutes": win_min,
    })


@app.route("/api/agents")
def agents():
    """Agent (endpoint) summary — all registered agents, merged with alert stats."""
    return jsonify(_cached_endpoint("agents", _build_agents))


def _build_agents(alerts):
    registry: list = []
    if AGENTS_REGISTRY.exists():
        try:
            registry = json.loads(AGENTS_REGISTRY.read_text())
        except Exception:
            pass

    agent_stats: dict = defaultdict(lambda: {
        "alert_count": 0, "max_score": 0.0,
        "verdicts": defaultdict(int), "users": set(),
        "reasons": defaultdict(int), "last_seen": "",
        "first_seen": "", "ip": "",
    })

    for a in alerts:
        host = (a.get("host", {}) or {}).get("name", "")
        if not host:
            continue
        ueba    = a.get("ueba", {}) or {}
        score   = ueba.get("combined_score", 0) or 0
        verdict = ueba.get("risk_verdict", "")
        user    = get_user(a)
        t       = ueba.get("processed_at", "")
        ip      = (a.get("host", {}) or {}).get("ip", "")

        s = agent_stats[host]
        s["alert_count"] += 1
        s["max_score"] = max(s["max_score"], score)
        s["verdicts"][verdict] += 1
        s["users"].add(user)
        if ip:
            s["ip"] = ip
        for r in (ueba.get("anomaly_reasons") or []):
            s["reasons"][r] += 1
        if not s["first_seen"] or t < s["first_seen"]:
            s["first_seen"] = t
        if t > s["last_seen"]:
            s["last_seen"] = t

    seen = set()
    result = []
    for reg in registry:
        name = reg["name"]
        seen.add(name)
        s = agent_stats.get(name, {})
        verdicts = s.get("verdicts", {})
        result.append({
            "agent":            name,
            "ip":               s.get("ip") or reg.get("ip", ""),
            "os":               reg.get("os", ""),
            "agent_id":         reg.get("id", ""),
            "alert_count":      s.get("alert_count", 0),
            "max_score":        round(s.get("max_score", 0), 3),
            "top_verdict":      max(verdicts, key=verdicts.get) if verdicts else "",
            "top_reason":       max(s["reasons"], key=s["reasons"].get) if s.get("reasons") else "",
            "users":            list(s.get("users", set()))[:10],
            "last_seen":        s.get("last_seen", ""),
            "first_seen":       s.get("first_seen", ""),
            "highly_anomalous": verdicts.get("highly_anomalous", 0),
            "anomalous":        verdicts.get("anomalous", 0),
            "suspicious":       verdicts.get("suspicious", 0),
        })

    for name, s in agent_stats.items():
        if name in seen:
            continue
        verdicts = s["verdicts"]
        result.append({
            "agent":            name,
            "ip":               s["ip"],
            "os":               "",
            "agent_id":         "",
            "alert_count":      s["alert_count"],
            "max_score":        round(s["max_score"], 0),
            "top_verdict":      max(verdicts, key=verdicts.get) if verdicts else "",
            "top_reason":       max(s["reasons"], key=s["reasons"].get) if s["reasons"] else "",
            "users":            list(s["users"])[:10],
            "last_seen":        s["last_seen"],
            "first_seen":       s["first_seen"],
            "highly_anomalous": verdicts.get("highly_anomalous", 0),
            "anomalous":        verdicts.get("anomalous", 0),
            "suspicious":       verdicts.get("suspicious", 0),
        })

    result.sort(key=lambda x: (-x["highly_anomalous"], -x["max_score"]))
    return result


# Register the heavy endpoint builders so the background warmer keeps the result
# cache hot for actively-viewed windows (see _warm_results_loop).
_ENDPOINT_BUILDERS.update({
    "stats":     _build_stats,
    "feed":      _build_feed,
    "users":     _build_users,
    "campaigns": _build_campaigns,
    "agents":    _build_agents,
})


@app.route("/api/agent/<agent_name>")
def agent_alerts(agent_name):
    """All alerts for a specific agent, newest first.

    Evidence is omitted (include_evidence=False) — exactly like /api/feed — so a
    noisy host (tens of thousands of alerts) doesn't ship a 100MB+ payload. The
    drilldown table lazy-loads each row's evidence on expand via /api/evidence.
    """
    out = []
    for a in reversed(load_alerts(include_fp=_wants_include_fp())):
        if ((a.get("host", {}) or {}).get("name", "")) != agent_name:
            continue
        out.append(_alert_to_feed_item(a, include_evidence=False))
    return jsonify(out)


@app.route("/api/user/<path:username>")
def user_alerts(username):
    """All alerts for a specific user, newest first.

    Evidence is omitted (see agent_alerts) — a single noisy entity can have 80k+
    alerts, and shipping each one's evidence blob made this a ~200MB / 6s response.
    The table lazy-loads evidence per row on expand via /api/evidence.
    """
    out = []
    for a in reversed(load_alerts(include_fp=_wants_include_fp())):
        if get_user(a) != username:
            continue
        out.append(_alert_to_feed_item(a, include_evidence=False))
    return jsonify(out)


# ── False-positive management ────────────────────────────────────────────────
@app.route("/api/false-positives")
def list_false_positives():
    """Return all FP records, each enriched with the original alert payload."""
    # Always read the raw alert list (include_fp=True) so we can look up the
    # underlying alert even if it's been FP-filtered.
    raw = load_alerts(include_fp=True)
    by_id = {a.get("event_id"): a for a in raw if a.get("event_id")}
    out = []
    for eid, rec in _fp_dict.items():
        a = by_id.get(eid)
        out.append({**rec, "alert": _alert_to_feed_item(a) if a else None})
    out.sort(key=lambda r: r.get("marked_at", ""), reverse=True)
    return jsonify(out)


@app.route("/api/false-positive", methods=["POST"])
def mark_false_positive():
    """Mark a single alert as FP. Also auto-creates a suppression pattern
    derived from the alert's (signature_id, user, agent) fingerprint so future
    similar alerts are filtered out of the feed. The per-event record stays
    around as an audit trail (which alert prompted the pattern).
    """
    body = request.get_json(silent=True) or {}
    eid = (body.get("event_id") or "").strip()
    reason = (body.get("reason") or "").strip()
    if not eid:
        return jsonify({"ok": False, "error": "event_id required"}), 400
    rec = {
        "event_id":  eid,
        "reason":    reason,
        "marked_at": datetime.now(timezone.utc).isoformat(),
    }
    with _fp_lock:
        _fp_dict[eid] = rec
        save_fps()

    # Auto-suppress similar alerts: derive a pattern from the underlying alert.
    raw = _read_all_alerts_for_lookup()
    alert = next((a for a in raw if a.get("event_id") == eid), None)
    pat, pat_new = (None, False)
    if alert:
        candidate = _pattern_from_alert(alert, reason)
        pat, pat_new = _add_pattern_if_new(candidate)
    return jsonify({
        "ok":          True,
        "record":      rec,
        "pattern":     pat,       # None if alert missing or no signature_id
        "pattern_new": pat_new,   # False if pattern already existed (dedupe)
    })


@app.route("/api/false-positive/<path:event_id>", methods=["DELETE"])
def unmark_false_positive(event_id):
    """Restore an FP-marked alert AND tear down the auto-suppression pattern
    that was created when it was marked. The mark and the pattern are created
    together by mark_false_positive — symmetry says they should be torn down
    together too.
    """
    with _fp_lock:
        existed = _fp_dict.pop(event_id, None)
        if existed:
            save_fps()

    # Resolve the alert's rule description and drop any matching pattern.
    patterns_removed = 0
    if existed:
        raw = _read_all_alerts_for_lookup()
        alert = next((a for a in raw if a.get("event_id") == event_id), None)
        if alert:
            desc = (alert.get("security", {}) or {}).get("signature")
            patterns_removed = _remove_patterns_for_descriptions([desc])

    return jsonify({
        "ok":               True,
        "removed":          bool(existed),
        "patterns_removed": patterns_removed,
    })


def _event_ids_in_campaign(campaign_id: str) -> list[str]:
    """Scan the raw (unfiltered) alert list and return every event_id whose
    ueba.campaign_id equals campaign_id."""
    raw = _read_all_alerts_for_lookup()
    return [
        a["event_id"]
        for a in raw
        if a.get("event_id")
        and (a.get("ueba", {}) or {}).get("campaign_id") == campaign_id
    ]


@app.route("/api/false-positive/campaign/<path:campaign_id>", methods=["POST"])
def mark_campaign_false_positive(campaign_id):
    """Mark every alert in a campaign as FP. Also auto-creates one pattern per
    unique rule description within the campaign so the suppression follows
    similar alerts forward in time."""
    body = request.get_json(silent=True) or {}
    reason = (body.get("reason") or "").strip() \
             or f"campaign {campaign_id} marked as false positive"
    eids = _event_ids_in_campaign(campaign_id)
    if not eids:
        return jsonify({"ok": False, "error": "no alerts for campaign"}), 404
    now = datetime.now(timezone.utc).isoformat()
    with _fp_lock:
        for eid in eids:
            _fp_dict[eid] = {"event_id": eid, "reason": reason, "marked_at": now}
        save_fps()

    # Auto-suppress: one pattern per unique fingerprint in the campaign.
    raw = _read_all_alerts_for_lookup()
    by_id = {a.get("event_id"): a for a in raw}
    seen: set = set()
    patterns_new = 0
    for eid in eids:
        a = by_id.get(eid)
        if not a:
            continue
        candidate = _pattern_from_alert(a, reason)
        if not candidate:
            continue
        key = _norm_desc(candidate["rule_description"])
        if key in seen:
            continue
        seen.add(key)
        _, was_new = _add_pattern_if_new(candidate)
        if was_new:
            patterns_new += 1
    return jsonify({
        "ok":           True,
        "marked":       len(eids),
        "campaign_id":  campaign_id,
        "patterns_new": patterns_new,
    })


@app.route("/api/false-positive/campaign/<path:campaign_id>", methods=["DELETE"])
def unmark_campaign_false_positive(campaign_id):
    """Restore every alert in a campaign AND drop the auto-suppression
    patterns that were created when the campaign was marked. Mirrors the
    per-event unmark — mark and pattern are created together, so torn down
    together.
    """
    eids = _event_ids_in_campaign(campaign_id)
    with _fp_lock:
        removed = 0
        for eid in eids:
            if _fp_dict.pop(eid, None):
                removed += 1
        if removed:
            save_fps()

    # Collect descriptions from this campaign's alerts and tear down patterns.
    raw = _read_all_alerts_for_lookup()
    by_id = {a.get("event_id"): a for a in raw}
    descs = {
        (by_id.get(eid, {}).get("security") or {}).get("signature")
        for eid in eids if eid in by_id
    }
    patterns_removed = _remove_patterns_for_descriptions(descs)

    return jsonify({
        "ok":               True,
        "removed":          removed,
        "campaign_id":      campaign_id,
        "patterns_removed": patterns_removed,
    })


# ── False-positive PATTERN management ────────────────────────────────────────
# Patterns auto-suppress any future alert whose rule description matches
# (whitespace-trimmed, case-insensitive). One pattern = one rule description.
def _read_suppress_stats() -> dict:
    """Read the engine-written per-pattern hit tally ({pattern_id: count}) from
    the sibling of the patterns file. Best-effort: missing/corrupt → {}."""
    p = FP_PATTERNS_FILE.with_name("fp_suppress_stats.json")
    try:
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8") or "{}")
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


@app.route("/api/false-positive-patterns")
def list_fp_patterns():
    """Return all FP patterns with a `matched` count.

    The engine drops a suppressed alert BEFORE it is written to the alert
    file, so counting matches in the loaded alerts would (correctly) yield ~0
    once suppression is working. The real, cumulative count lives in the
    engine-written sibling file `fp_suppress_stats.json` ({pattern_id: hits}).
    We use that as the source of truth, and add any still-in-file matches
    (alerts scored before the engine picked up the pattern) so the count is
    never an under-count.
    """
    eng_counts = _read_suppress_stats()
    raw = load_alerts(include_fp=True)
    counts: dict = {}
    for a in raw:
        p = _matching_pattern(a)
        if p:
            counts[p.get("id")] = counts.get(p.get("id"), 0) + 1
    out = []
    for p in _fp_patterns:
        pid = p.get("id")
        matched = int(eng_counts.get(pid, 0)) + counts.get(pid, 0)
        out.append({**p, "matched": matched})
    out.sort(key=lambda r: r.get("marked_at", ""), reverse=True)
    return jsonify(out)


@app.route("/api/false-positive-pattern", methods=["POST"])
def mark_fp_pattern():
    """Add a new FP pattern directly. Body: {rule_description, reason}."""
    body = request.get_json(silent=True) or {}
    desc = (str(body.get("rule_description") or "")).strip()
    reason = (body.get("reason") or "").strip()
    if not desc:
        return jsonify({"ok": False, "error": "rule_description required"}), 400
    candidate = {
        "id":               "fpp-" + uuid.uuid4().hex[:10],
        "rule_description": desc,
        "reason":           reason,
        "marked_at":        datetime.now(timezone.utc).isoformat(),
    }
    rec, was_new = _add_pattern_if_new(candidate)
    return jsonify({"ok": True, "record": rec, "deduped": (not was_new)})


@app.route("/api/false-positive-pattern/<pat_id>", methods=["DELETE"])
def unmark_fp_pattern(pat_id):
    with _fp_pat_lock:
        before = len(_fp_patterns)
        _fp_patterns[:] = [p for p in _fp_patterns if p.get("id") != pat_id]
        removed = before - len(_fp_patterns)
        if removed:
            save_fp_patterns()
    return jsonify({"ok": True, "removed": bool(removed)})


# ── Engine health ────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    """Engine + dashboard health snapshot for the Overview health card."""
    alerts = load_alerts(include_fp=True)   # include FPs so we report the real engine output
    total = len(alerts)

    now = datetime.now(timezone.utc)
    one_hour_ago  = now - timedelta(hours=1)
    one_day_ago   = now - timedelta(hours=24)
    alerts_1h     = 0
    alerts_24h    = 0
    newest_iso    = None
    newest_dt     = None
    for a in alerts:
        # Reuse the memoised timestamp (_alert_ts caches the parse on the dict)
        # instead of re-parsing every ISO string here — health runs over the full
        # window and was paying a second full parse pass on every call.
        d = _alert_ts(a)
        if d is None:
            continue
        if d >= one_hour_ago: alerts_1h  += 1
        if d >= one_day_ago:  alerts_24h += 1
        if newest_dt is None or d > newest_dt:
            newest_dt  = d
            newest_iso = (a.get("ueba", {}) or {}).get("processed_at") or a.get("event_time") or ""

    try:
        file_size = ALERTS_FILE.stat().st_size if ALERTS_FILE.exists() else 0
    except Exception:
        file_size = 0

    fp_count = len(_fp_dict)
    fp_rate  = round((fp_count / total) * 100, 2) if total > 0 else 0.0

    try:
        started = datetime.fromisoformat(_SERVER_STARTED_AT)
        uptime  = int((now - started).total_seconds())
    except Exception:
        uptime = 0

    # "Engine live" = at least one alert within the last 5 minutes.
    engine_live = bool(newest_dt and (now - newest_dt).total_seconds() < 300)

    # Feed liveness — is the engine's INPUT (enriched.jsonl) still growing? This
    # is the true "is the 222→98 feed alive" signal, INDEPENDENT of whether any
    # alert fired: a quiet period legitimately produces no alerts but the feed is
    # still healthy. The stale-feed banner keys on this, not on alert recency.
    feed_mtime_iso = None
    feed_age_secs  = None
    try:
        ep = Path(str(CFG.get("enriched_file") or "/root/NEW_DRIVE/aditya_ueba/enriched.jsonl"))
        if ep.exists():
            feed_dt = datetime.fromtimestamp(ep.stat().st_mtime, timezone.utc)
            feed_mtime_iso = feed_dt.isoformat()
            feed_age_secs  = int((now - feed_dt).total_seconds())
    except Exception:
        pass
    feed_live = feed_age_secs is not None and feed_age_secs < 180

    with _agent_sync_lock:
        agent_sync_status = {
            "enabled":    bool((CFG.get("agent_sync") or {}).get("enabled")),
            "last_at":    _agent_sync_last_at,
            "last_error": _agent_sync_last_error,
        }

    return jsonify({
        "total_alerts":           total,
        "alerts_1h":              alerts_1h,
        "alerts_24h":             alerts_24h,
        "newest_alert_time":      newest_iso,
        "alerts_file_size_bytes": file_size,
        "fp_count":               fp_count,
        "fp_rate_pct":            fp_rate,
        "server_started_at":      _SERVER_STARTED_AT,
        "uptime_secs":            uptime,
        "engine_live":            engine_live,
        "feed_mtime":             feed_mtime_iso,
        "feed_age_secs":          feed_age_secs,
        "feed_live":              feed_live,
        "agent_sync":             agent_sync_status,
    })


# ── Live event stream (Server-Sent Events) ───────────────────────────────────
# /api/stream tails ueba_alerts.jsonl from "now" and pushes every new alert as
# an SSE 'alert' event. The dashboard's initial state is already loaded via
# /api/feed at boot — the stream only delivers what arrives after connection.

@app.route("/api/stream")
def stream_alerts():
    @stream_with_context
    def event_stream():
        # Send a hello frame so the EventSource transitions from 'connecting'
        # to 'open' immediately, even before the first alert arrives.
        yield "event: hello\ndata: {}\n\n"

        # Start at the current end of the file — don't replay history.
        try:
            last_pos = ALERTS_FILE.stat().st_size if ALERTS_FILE.exists() else 0
        except Exception:
            last_pos = 0
        last_heartbeat = time.time()

        while True:
            try:
                if ALERTS_FILE.exists():
                    try:
                        size = ALERTS_FILE.stat().st_size
                    except Exception:
                        size = last_pos
                    if size < last_pos:
                        # File rotated / truncated — start from the new end.
                        last_pos = 0
                    if size > last_pos:
                        try:
                            with open(ALERTS_FILE, "r", encoding="utf-8", errors="replace") as f:
                                f.seek(last_pos)
                                chunk = f.read()
                                last_pos = f.tell()
                        except Exception:
                            chunk = ""
                        for line in chunk.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                alert = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            eid = alert.get("event_id")
                            if eid and eid in _fp_dict:
                                continue   # already a known FP, don't push it
                            if _matching_pattern(alert) is not None:
                                continue   # auto-suppressed by a stored pattern
                            payload = _alert_to_feed_item(alert)
                            yield f"event: alert\ndata: {json.dumps(payload, default=str)}\n\n"

                now = time.time()
                if now - last_heartbeat > 15:
                    # SSE comment lines keep the connection alive through
                    # proxies/load balancers without delivering an event.
                    yield ": heartbeat\n\n"
                    last_heartbeat = now
                time.sleep(1.0)
            except GeneratorExit:
                return
            except Exception as e:
                # Surface and continue; the client will keep us open.
                try:
                    yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                except Exception:
                    return
                time.sleep(2.0)

    headers = {
        "Cache-Control":     "no-cache",
        "X-Accel-Buffering": "no",       # disable nginx buffering
        "Connection":        "keep-alive",
    }
    return Response(event_stream(), mimetype="text/event-stream", headers=headers)


# ── AI Security Analyst proxy ────────────────────────────────────────────────
@app.route("/api/ai-analyze", methods=["POST"])
def ai_analyze():
    """Proxy the AI Security Analyst prompt to Anthropic with a server-side key.

    Request body: { "prompt": "..." }
    Response: { "ok": bool, "text": "...", "source": "anthropic"|"fallback", "error": "..." }
    """
    ai_cfg = CFG.get("ai_analyst", {}) or {}
    body = request.get_json(silent=True) or {}
    prompt = (body.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"ok": False, "error": "missing prompt", "source": "fallback"}), 400

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()

    if not ai_cfg.get("enabled", True):
        return jsonify({"ok": False, "error": "ai_analyst disabled", "source": "fallback"})
    if not api_key:
        return jsonify({"ok": False, "error": "ANTHROPIC_API_KEY not set", "source": "fallback"})
    if requests is None:
        return jsonify({"ok": False, "error": "requests not installed", "source": "fallback"})

    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model":      ai_cfg.get("model", "claude-sonnet-4-6"),
                "max_tokens": int(ai_cfg.get("max_tokens", 1000)),
                "messages":   [{"role": "user", "content": prompt}],
            },
            timeout=int(ai_cfg.get("timeout_secs", 20)),
        )
        if r.status_code != 200:
            return jsonify({
                "ok": False,
                "error": f"upstream {r.status_code}: {r.text[:200]}",
                "source": "fallback",
            })
        data = r.json()
        text = "".join(c.get("text", "") for c in data.get("content", []) if c.get("type") == "text")
        if not text:
            return jsonify({"ok": False, "error": "empty response", "source": "fallback"})
        return jsonify({"ok": True, "text": text, "source": "anthropic"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "source": "fallback"})


# ── Live threat map (firewall geoIP) ─────────────────────────────────────────
# Tail recent FIREWALL events from the enriched feed, geolocate each external
# source IP via a local MaxMind GeoLite2 DB, and serve source→DC arcs. All
# offline — no external geo API. Degrades to empty if the DB/lib is missing.
import ipaddress

try:
    import geoip2.database as _geoip2_db  # type: ignore
except Exception:
    _geoip2_db = None

# Known on-disk locations for the GeoLite2 DBs (first existing one wins).
_GEOIP_CITY_CANDIDATES = [
    "/root/NEW_DRIVE/aditya_ueba/databases/GeoLite2-City.mmdb",
    "/data/CyberSentinel-Event-Correlation/databases/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
]
_GEOIP_ASN_CANDIDATES = [
    "/root/NEW_DRIVE/aditya_ueba/databases/GeoLite2-ASN.mmdb",
    "/data/CyberSentinel-Event-Correlation/databases/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
]

_geo_city_reader = None
_geo_asn_reader  = None
_geo_readers_tried = False
_geo_cache: dict = {}        # ip -> geo dict | None  (None = un-geolocatable, cached too)
_geo_cache_lock = __import__("threading").Lock()
_dc_loc: dict | None = None


def _first_existing(explicit: str, candidates: list) -> str | None:
    if explicit and Path(explicit).is_file():
        return explicit
    for c in candidates:
        if Path(c).is_file():
            return c
    return None


def _open_geo_readers():
    """Open the GeoLite2 City/ASN readers once (lazy). Safe if absent."""
    global _geo_city_reader, _geo_asn_reader, _geo_readers_tried
    if _geo_readers_tried:
        return
    _geo_readers_tried = True
    if _geoip2_db is None:
        print("[threatmap] geoip2 not installed — /api/geofeed will be empty")
        return
    city_path = _first_existing(str(CFG.get("geoip_city_db") or ""), _GEOIP_CITY_CANDIDATES)
    asn_path  = _first_existing(str(CFG.get("geoip_asn_db") or ""),  _GEOIP_ASN_CANDIDATES)
    if not city_path:
        print("[threatmap] no GeoLite2-City.mmdb found — /api/geofeed will be empty")
        return
    try:
        _geo_city_reader = _geoip2_db.Reader(city_path)
        print(f"[threatmap] GeoLite2-City loaded from {city_path}")
    except Exception as e:
        print(f"[threatmap] failed to open City DB {city_path}: {e}")
    if asn_path:
        try:
            _geo_asn_reader = _geoip2_db.Reader(asn_path)
        except Exception as e:
            print(f"[threatmap] failed to open ASN DB {asn_path}: {e}")


def _is_public_ip(ip: str) -> bool:
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (o.is_private or o.is_loopback or o.is_reserved
                or o.is_link_local or o.is_multicast or o.is_unspecified)


def _geo_lookup(ip: str) -> dict | None:
    """Lat/lng/country/city/asn for a public IP, cached. None if not resolvable."""
    if ip in _geo_cache:
        return _geo_cache[ip]
    result = None
    if _geo_city_reader is not None:
        try:
            c = _geo_city_reader.city(ip)
            if c.location.latitude is not None and c.location.longitude is not None:
                result = {
                    "lat": round(c.location.latitude, 4),
                    "lng": round(c.location.longitude, 4),
                    "country": c.country.iso_code or "??",
                    "country_name": c.country.name or "Unknown",
                    "city": c.city.name or "",
                }
                if _geo_asn_reader is not None:
                    try:
                        a = _geo_asn_reader.asn(ip)
                        result["asn"] = a.autonomous_system_number
                        result["org"] = a.autonomous_system_organization or ""
                    except Exception:
                        pass
        except Exception:
            result = None
    with _geo_cache_lock:
        if len(_geo_cache) > 50000:        # bound the cache
            _geo_cache.clear()
        _geo_cache[ip] = result
    return result


def _resolve_dc() -> dict:
    """The arc target: geolocate the configured DC/WAN IP once, else fall back
    to the configured DC coords."""
    global _dc_loc
    if _dc_loc is not None:
        return _dc_loc
    tm = CFG.get("threatmap") or {}
    dc_ip = str(tm.get("dc_ip") or "")
    loc = _geo_lookup(dc_ip) if dc_ip and _is_public_ip(dc_ip) else None
    if loc:
        _dc_loc = {"lat": loc["lat"], "lng": loc["lng"],
                   "country": loc.get("country", "IN"),
                   "label": tm.get("dc_label", "Datacenter")}
    else:
        _dc_loc = {"lat": float(tm.get("dc_lat", 21.1463)),
                   "lng": float(tm.get("dc_lng", 79.0849)),
                   "country": "IN", "label": tm.get("dc_label", "Datacenter")}
    return _dc_loc


def _is_firewall_event(e: dict) -> bool:
    h = e.get("host") or {}
    if h.get("type") == "firewall":
        return True
    if str((h.get("os") or {}).get("name") or "").lower() == "fortios":
        return True
    return "fortigate" in str((e.get("context") or {}).get("source") or "").lower()


# Classify a firewall event into a traffic category + arc direction, and pick the
# EXTERNAL endpoint to geolocate. Categories mirror the analyst legend:
#   incoming_threat  (red)    – external → DC, blocked/failed/attack
#   normal_incoming  (blue)   – external → DC, allowed/successful
#   outgoing         (green)  – DC → external, our server reaching out
#   external_conn    (yellow) – VPN / session connections (external → DC)
# arc_dir is "in" (external→DC) or "out" (DC→external) and drives the on-globe
# flow direction so the analyst can see which way the traffic moves.
def _classify_firewall(e: dict):
    net      = e.get("network") or {}
    direction = str(net.get("direction") or "").lower()
    outcome  = str(e.get("event_outcome") or "").lower()
    sig      = str((e.get("security") or {}).get("signature") or "").lower()
    sub_ip   = str((e.get("subject") or {}).get("ip") or "")
    obj_ip   = str((e.get("object") or {}).get("ip") or "")

    failed = ("fail" in outcome or "fail" in sig or "block" in sig or "denied" in sig
              or "deny" in sig or "attack" in sig or "drop" in sig or "invalid" in sig)
    is_vpn = "vpn" in sig

    if direction == "outgoing":
        ext = obj_ip if _is_public_ip(obj_ip) else sub_ip
        return ("outgoing", "out", ext)

    # incoming / internal / none / unknown — the external party is the source side
    ext = sub_ip if _is_public_ip(sub_ip) else obj_ip
    if is_vpn and not failed:
        return ("external_conn", "in", ext)
    if failed:
        return ("incoming_threat", "in", ext)
    return ("normal_incoming", "in", ext)


def _tail_firewall_geo(window_bytes: int, max_arcs: int) -> dict:
    """Read the tail of enriched.jsonl, keep firewall events with a public source
    IP, geolocate them, and build source→DC arcs (newest last) plus aggregates."""
    _open_geo_readers()
    dc = _resolve_dc()
    geo_ok = _geo_city_reader is not None
    path = Path(str(CFG.get("enriched_file") or "/root/NEW_DRIVE/aditya_ueba/enriched.jsonl"))
    arcs: list = []
    by_country: dict = {}
    by_sig: dict = {}
    by_category: dict = {"incoming_threat": 0, "normal_incoming": 0,
                         "outgoing": 0, "external_conn": 0}
    seen_ips: set = set()
    scanned = 0
    if geo_ok and path.is_file():
        try:
            size = path.stat().st_size
            with open(path, "rb") as f:
                f.seek(max(0, size - window_bytes))
                blob = f.read()
            lines = blob.split(b"\n")
            if size > window_bytes and lines:
                lines = lines[1:]          # drop the partial first line
            for raw in lines:
                if not raw.strip():
                    continue
                try:
                    e = json.loads(raw)
                except Exception:
                    continue
                if not _is_firewall_event(e):
                    continue
                scanned += 1
                category, arc_dir, ext_ip = _classify_firewall(e)
                if not ext_ip or not _is_public_ip(str(ext_ip)):
                    continue
                g = _geo_lookup(str(ext_ip))
                if not g:
                    continue
                sig = str((e.get("security") or {}).get("signature") or "Firewall event")
                arcs.append({
                    "srcLat": g["lat"], "srcLng": g["lng"],
                    "direction": arc_dir, "category": category,
                    "country": g["country"], "country_name": g.get("country_name", ""),
                    "city": g.get("city", ""), "ip": str(ext_ip),
                    "org": g.get("org", ""), "asn": g.get("asn"),
                    "sig": sig,
                    "outcome": str(e.get("event_outcome") or ""),
                    "time": e.get("event_time") or e.get("ingest_time"),
                })
                seen_ips.add(str(ext_ip))
                by_category[category] = by_category.get(category, 0) + 1
                cc = g["country"]
                bc = by_country.setdefault(cc, {"country": cc,
                        "country_name": g.get("country_name", ""), "count": 0})
                bc["count"] += 1
                by_sig[sig] = by_sig.get(sig, 0) + 1
        except Exception as e:
            print(f"[threatmap] tail read failed: {e}")

    if len(arcs) > max_arcs:
        arcs = arcs[-max_arcs:]            # keep newest

    top_countries = sorted(by_country.values(), key=lambda x: -x["count"])[:12]
    top_sigs = sorted(({"sig": s, "count": c} for s, c in by_sig.items()),
                      key=lambda x: -x["count"])[:8]
    return {
        "geo_ok": geo_ok,
        "dc": dc,
        "arcs": arcs,
        "stats": {
            "events": scanned,
            "mapped": len(arcs),
            "unique_ips": len(seen_ips),
            "countries": len(by_country),
            "categories": by_category,
            "top_countries": top_countries,
            "top_signatures": top_sigs,
        },
    }


@app.route("/api/geofeed")
def geofeed():
    """Live firewall-attack map feed: geolocated source→DC arcs for the globe."""
    tm = CFG.get("threatmap") or {}
    try:
        window = int(request.args.get("bytes") or tm.get("window_bytes", 12582912))
    except (TypeError, ValueError):
        window = int(tm.get("window_bytes", 12582912))
    window = max(256 * 1024, min(window, 64 * 1024 * 1024))   # clamp 256KB–64MB
    try:
        max_arcs = int(request.args.get("max") or tm.get("max_arcs", 400))
    except (TypeError, ValueError):
        max_arcs = int(tm.get("max_arcs", 400))
    max_arcs = max(10, min(max_arcs, 2000))
    return jsonify(_tail_firewall_geo(window, max_arcs))


# ── Static + index ───────────────────────────────────────────────────────────
def _serve_index():
    """Serve dashboard/dist/index.html if it exists, otherwise the legacy file."""
    dist_index = DASHBOARD_DIST / "index.html"
    if dist_index.exists():
        return send_from_directory(str(DASHBOARD_DIST), "index.html")
    return send_from_directory(str(DASHBOARD_DIR), "index.html")


@app.route("/")
def index():
    return _serve_index()


@app.route("/assets/<path:filename>")
def dist_assets(filename):
    """Vite's hashed JS/CSS bundles live under dashboard/dist/assets/."""
    return send_from_directory(str(DASHBOARD_DIST / "assets"), filename)


@app.route("/legacy")
def legacy_index():
    """Always serve the pre-Vite single-file dashboard for fallback debugging."""
    return send_from_directory(str(DASHBOARD_DIR), "index.legacy.html")


# SPA fallback — the client-side router activates the right tab based on the
# URL. The order is:
#   1. If a file with that exact path exists in dashboard/dist/ (e.g. logo
#      images copied from public/, favicon.ico, etc.), serve it directly.
#   2. Otherwise, if the first path segment is a known tab name, return
#      index.html so the client router can activate the right tab.
#   3. Otherwise, 404.
SPA_TAB_PATHS = {"overview", "feed", "users", "campaigns", "endpoints",
                 "false-positives", "threatmap", "incidents", "auth"}

@app.route("/<path:subpath>")
def spa_fallback(subpath):
    # 1. Real file in dist/ (Vite's public/ outputs land here at build time).
    candidate = DASHBOARD_DIST / subpath
    try:
        if candidate.is_file() and candidate.resolve().is_relative_to(DASHBOARD_DIST.resolve()):
            return send_from_directory(str(DASHBOARD_DIST), subpath)
    except (OSError, ValueError):
        pass
    # 2. Known SPA tab — return index.html for client-side routing.
    head = subpath.split("/", 1)[0]
    if head in SPA_TAB_PATHS:
        return _serve_index()
    # 3. Otherwise: not found.
    from flask import abort
    abort(404)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CyberSentinel UEBA Dashboard API server")
    p.add_argument("--config", default="ueba_config.yaml",
                   help="Path to ueba_config.yaml (default: ueba_config.yaml)")
    p.add_argument("--host", default=None, help="Bind host (overrides config)")
    p.add_argument("--port", type=int, default=None, help="Bind port (overrides config)")
    p.add_argument("--alerts", default=None, help="Path to ueba_alerts.jsonl (overrides config)")
    p.add_argument("--agents-registry", default=None,
                   help="Path to agents.json (overrides config)")
    p.add_argument("--fp-file", default=None,
                   help="Path to false_positives.json (overrides config)")
    p.add_argument("--fp-patterns-file", default=None,
                   help="Path to fp_patterns.json (overrides config)")
    p.add_argument("--debug", action="store_true", help="Run Flask in debug mode")
    return p.parse_args()


def _warm_archive_cache() -> None:
    """Pre-parse archived alert zips within the history window so the first wide
    ('All'/30D/90D) request doesn't block several seconds on a cold cache. Runs
    in a daemon thread; the server starts serving immediately regardless."""
    # Live file FIRST: it backs every default (24h) request and is the one the
    # first post-restart call needs. The live file can be hundreds of MB, so this
    # one-time full parse (subsequent reads are incremental/cheap) must finish
    # before the heavier 95-day archive warm, or the first request pays it.
    try:
        t = time.time()
        n = len(_read_live_alerts())
        print(f"[dashboard] live cache warmed: {n} alerts in {time.time() - t:.1f}s")
    except Exception as e:
        print(f"[dashboard] live cache warm-up failed ({e}) — loading lazily")
    # Then the archives (wide 'All'/30D/90D windows) in the background.
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(CFG.get("history_days", 95) or 95))
        t = time.time()
        n = len(_read_archived_alerts(cutoff))
        print(f"[dashboard] archive cache warmed: {n} alerts in {time.time() - t:.1f}s "
              f"from {CFG.get('archive_dir')}")
    except Exception as e:  # never let warm-up crash startup
        print(f"[dashboard] archive cache warm-up failed ({e}) — loading lazily")

    # Now that the alert caches are hot, seed the endpoint result cache for the
    # windows analysts land on first (All=0 and 24h) so the very first dashboard
    # load after a restart is instant instead of paying the cold aggregation. The
    # background result-warmer then keeps these (and any others viewed) fresh.
    for window in ((0, False), (24, False)):
        _active_windows[window] = time.time()
    try:
        t = time.time()
        for (hours, include_fp) in ((0, False), (24, False)):
            for name, builder in list(_ENDPOINT_BUILDERS.items()):
                try:
                    _build_and_store(name, builder, hours, include_fp)
                except Exception:
                    pass
        print(f"[dashboard] result cache pre-warmed (All + 24h) in {time.time() - t:.1f}s")
    except Exception as e:
        print(f"[dashboard] result cache pre-warm failed ({e}) — building lazily")


def _start_archive_warm_thread() -> None:
    import threading
    threading.Thread(target=_warm_archive_cache, name="archive-warm", daemon=True).start()


def _start_result_warm_thread() -> None:
    """Keep the endpoint result cache hot for actively-viewed windows so loads
    stay instant (the heavy aggregation runs off the request path)."""
    import threading
    threading.Thread(target=_warm_results_loop, name="result-warm", daemon=True).start()


def main() -> None:
    global CFG, ALERTS_FILE, AGENTS_REGISTRY, FP_FILE, FP_PATTERNS_FILE
    args = _parse_args()
    CFG = load_dashboard_config(args.config)

    if args.host:             CFG["host"] = args.host
    if args.port:             CFG["port"] = args.port
    if args.alerts:           CFG["alerts_file"] = args.alerts
    if args.agents_registry:  CFG["agents_registry"] = args.agents_registry
    if args.fp_file:          CFG["false_positives_file"] = args.fp_file
    if args.fp_patterns_file: CFG["fp_patterns_file"] = args.fp_patterns_file

    # Auth must be initialised before the first request is served. A bad auth
    # config raises here and stops the server on purpose: running "enforcing but
    # unable to authenticate anyone" is an outage, and running "meant to be
    # enforcing but silently open" is worse.
    auth_status = "module not installed"
    auth_cfg: dict = {}
    if AUTH_MODULE_AVAILABLE:
        raw_cfg = load_raw_config(args.config)
        auth_cfg = ueba_auth.init_auth(app, raw_cfg)
        ready, reason = ueba_auth.is_ready()
        auth_status = (
            f"enabled={auth_cfg.get('enabled')} enforce={auth_cfg.get('enforce')} "
            f"ready={ready} ({reason})"
        )
    cors_status = _configure_cors(auth_cfg)

    ALERTS_FILE       = Path(CFG["alerts_file"])
    AGENTS_REGISTRY   = Path(CFG["agents_registry"])
    FP_FILE           = Path(CFG["false_positives_file"])
    FP_PATTERNS_FILE  = Path(CFG.get("fp_patterns_file") or _DEFAULTS["fp_patterns_file"])
    load_fps()
    load_fp_patterns()

    dist_ok = (DASHBOARD_DIST / "index.html").exists()
    print("CyberSentinel UEBA Dashboard")
    print(f"  Config:           {args.config}")
    print(f"  Reading alerts:   {ALERTS_FILE}")
    print(f"  Agents registry:  {AGENTS_REGISTRY}")
    print(f"  False positives:  {FP_FILE}  ({len(_fp_dict)} loaded)")
    print(f"  FP patterns:      {FP_PATTERNS_FILE}  ({len(_fp_patterns)} loaded)")
    print(f"  Dashboard build:  {'dist/ (Vite build)' if dist_ok else 'legacy index.html'}")
    print(f"  AI analyst:       "
          f"{'enabled' if CFG['ai_analyst'].get('enabled') and os.environ.get('ANTHROPIC_API_KEY') else 'fallback only'}")
    print(f"  Auth/SSO:         {auth_status}")
    print(f"  CORS:             {cors_status}")
    print(f"  Listening on:     http://{CFG['host']}:{CFG['port']}")
    print(f"  Archive dir:      {CFG.get('archive_dir')}  "
          f"(history {CFG.get('history_days')}d, feed cap {CFG.get('max_feed_alerts')})")
    _start_agent_sync_thread()
    _start_archive_warm_thread()
    _start_result_warm_thread()
    # threaded=True: serve requests concurrently so one slow scan (e.g. a wide
    # hours=N feed query over the multi-GB enriched file) can't block every other
    # endpoint and freeze the whole dashboard.
    app.run(host=CFG["host"], port=CFG["port"], debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
