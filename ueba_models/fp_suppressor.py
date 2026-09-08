"""
ueba_models/fp_suppressor.py
─────────────────────────────
Engine-side analyst-FP suppression.

The dashboard writes `fp_patterns.json` whenever an analyst marks an alert
as a false positive. Each pattern carries a rule description and a
`marked_at` timestamp. This module reads that file inside the engine
and skips emitting any alert whose `security.signature` matches a stored
pattern (and whose `ueba.processed_at` is strictly later than the pattern
was marked — same time-guard semantics the dashboard uses).

Mtime-based lazy reload: each call to `is_fp` does one `stat()` on the
patterns file; only when the mtime changes do we re-parse the JSON. Adding
or removing a pattern in the dashboard therefore takes effect on the very
next event the engine processes — no engine restart, no polling thread.

Failure mode: if the patterns file is missing, unreadable, or malformed,
we log once and keep using the last-good in-memory pattern set, so a bad
write from the dashboard can never starve alerting.
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path

log = logging.getLogger("ueba.fp_suppressor")


def _norm(s) -> str:
    """Whitespace-trim + lowercase; matches dashboard `_norm_desc`."""
    if not isinstance(s, str):
        return ""
    return s.strip().lower()


def _parse_iso(ts) -> datetime | None:
    if not ts:
        return None
    try:
        s = ts.replace("Z", "+00:00") if isinstance(ts, str) else ts
        return datetime.fromisoformat(s)
    except (ValueError, AttributeError):
        return None


class FPPatternSuppressor:
    """
    Per-engine FP-pattern matcher with mtime-tracked reload.

    `is_fp(alert, processed_at)` returns the matching pattern dict (with
    `id` and `reason`) when the alert should be suppressed, else None.
    Thread-safe — the engine reads/writes from a single thread today, but
    this is also touched by stats output which may be on another thread.
    """

    def __init__(self, patterns_file: str):
        self._path = Path(patterns_file)
        # Per-pattern suppression tally, persisted alongside the patterns file so
        # the dashboard can show a real "Matched" count. The engine drops a
        # suppressed alert BEFORE it is written to ueba_alerts.jsonl, so the
        # dashboard can never recover the count from the alert file — it lives
        # only here.
        self._stats_path = self._path.with_name("fp_suppress_stats.json")
        self._counts: dict[str, int] = {}         # pattern id -> cumulative hits
        self._patterns: list[dict] = []           # parsed records
        self._index: dict[str, list[dict]] = {}   # normalized desc -> [pattern, ...]
        self._mtime: float = -1.0
        self._lock = threading.Lock()
        self._reload_errors = 0
        self.suppressed_count = 0
        self._load_stats()
        self._maybe_reload()
        log.info("FP suppressor initialized: file=%s, patterns=%d, counts=%d",
                 self._path, len(self._patterns), sum(self._counts.values()))

    def _maybe_reload(self) -> None:
        """Re-read patterns file if its mtime changed since the last load."""
        try:
            if not self._path.exists():
                if self._patterns:
                    log.info("FP patterns file removed — clearing %d patterns",
                             len(self._patterns))
                    with self._lock:
                        self._patterns, self._index, self._mtime = [], {}, -1.0
                return
            cur_mtime = self._path.stat().st_mtime
            if cur_mtime == self._mtime:
                return

            raw = self._path.read_text(encoding="utf-8") or "[]"
            data = json.loads(raw)
            if not isinstance(data, list):
                raise ValueError(f"expected JSON list, got {type(data).__name__}")

            patterns: list[dict] = []
            index: dict[str, list[dict]] = {}
            for p in data:
                if not isinstance(p, dict):
                    continue
                desc = _norm(p.get("rule_description"))
                if not desc:
                    continue
                marked = _parse_iso(p.get("marked_at"))
                if marked is None:
                    continue
                rec = {
                    "id":         p.get("id") or "",
                    "desc":       desc,
                    "marked_at":  marked,
                    "reason":     p.get("reason") or "",
                }
                patterns.append(rec)
                index.setdefault(desc, []).append(rec)

            with self._lock:
                old_count = len(self._patterns)
                self._patterns = patterns
                self._index = index
                self._mtime = cur_mtime
            if len(patterns) != old_count:
                log.info("FP patterns reloaded: %d → %d", old_count, len(patterns))
        except Exception as e:
            self._reload_errors += 1
            if self._reload_errors <= 3 or self._reload_errors % 100 == 0:
                log.warning(
                    "FP patterns reload failed (%s) — keeping previous %d patterns",
                    e, len(self._patterns),
                )

    def is_fp(self, alert: dict, processed_at) -> dict | None:
        """
        Return the first matching pattern (record dict) for this alert,
        or None if no pattern applies.

        `processed_at` may be a `datetime` or an ISO-8601 string (the engine
        passes `ueba.processed_at` directly from the alert).

        Match criteria:
          1. alert.security.signature (normalized) equals pattern.desc, AND
          2. processed_at > pattern.marked_at (engine-time guard, mirrors
             the dashboard's `_alert_matches_pattern` so the engine and the
             dashboard agree on what is suppressed).
        """
        self._maybe_reload()
        if not self._patterns:
            return None

        sec = alert.get("security") or {}
        desc = _norm(sec.get("signature"))
        if not desc:
            return None

        candidates = self._index.get(desc)
        if not candidates:
            return None

        if not isinstance(processed_at, datetime):
            processed_at = _parse_iso(processed_at)
            if processed_at is None:
                return None

        for pat in candidates:
            if processed_at > pat["marked_at"]:
                self.suppressed_count += 1
                pid = pat.get("id") or ""
                if pid:
                    self._counts[pid] = self._counts.get(pid, 0) + 1
                return pat
        return None

    def refresh(self) -> None:
        """Force an mtime check now (used by periodic stats logging so the
        reported pattern count is fresh even when no alerts have fired)."""
        self._maybe_reload()

    def _load_stats(self) -> None:
        """Load the persisted per-pattern hit tally so counts survive engine
        restarts. Best-effort: a missing/corrupt file just starts from zero."""
        try:
            if self._stats_path.exists():
                data = json.loads(self._stats_path.read_text(encoding="utf-8") or "{}")
                if isinstance(data, dict):
                    self._counts = {str(k): int(v) for k, v in data.items()
                                    if isinstance(v, (int, float))}
        except Exception as e:
            log.warning("FP suppress-stats load failed (%s) — starting counts at 0", e)
            self._counts = {}

    def write_stats(self) -> None:
        """Atomically persist per-pattern hit counts to the sibling stats file
        (`fp_suppress_stats.json`) for the dashboard to read. Pruned to the
        current pattern set so removed patterns don't leave stale rows."""
        try:
            with self._lock:
                current = {p.get("id") for p in self._patterns if p.get("id")}
                snapshot = {pid: c for pid, c in self._counts.items() if pid in current}
                # Drop counts for patterns that no longer exist.
                self._counts = dict(snapshot)
            tmp = self._stats_path.with_suffix(self._stats_path.suffix + ".tmp")
            tmp.write_text(json.dumps(snapshot), encoding="utf-8")
            tmp.replace(self._stats_path)
        except Exception as e:
            log.warning("FP suppress-stats write failed (%s)", e)

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)
