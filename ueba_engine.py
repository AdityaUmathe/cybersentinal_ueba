#!/usr/bin/env python3
"""
ueba_engine.py
──────────────
CyberSentinel UEBA Engine — Main Streaming Entry Point

Tails enriched.jsonl in real-time (same pattern as your existing pipeline).
For each log, runs it through all 3 layers:
  L1: Isolation Forest     → event_anomaly_score
  L2: Autoencoder          → user_deviation_score
  L3: HDBSCAN              → campaign_id (background thread)
  RAG: FAISS retrieval     → similar_past_events

Normal logs are SILENTLY DISCARDED.
Only anomalous logs get a `ueba` block appended and written to ueba_alerts.jsonl.

Usage:
  # Start the UEBA engine (streaming mode)
  python3 ueba_engine.py --config ueba_config.yaml

  # Override input/output paths
  python3 ueba_engine.py \
      --input  enriched.jsonl \
      --output ueba_alerts.jsonl \
      --config ueba_config.yaml
"""

import argparse
import json
import logging
import logging.handlers
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import yaml

from ueba_preprocessor import FeatureExtractor, UserProfileStore
from ueba_models.isolation_forest import IsolationForestScorer
from ueba_models.autoencoder import AutoencoderScorer
from ueba_models.clusterer import CampaignDetector, RAGRetriever
from ueba_models.fp_suppressor import FPPatternSuppressor

# ── Logging ───────────────────────────────────────────────────────────────────

def setup_logging(config: dict):
    log_cfg = config["logging"]
    os.makedirs("logs", exist_ok=True)

    formatter = logging.Formatter(
        log_cfg["format"],
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    level = getattr(logging, log_cfg["level"].upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Clear any handlers added by basicConfig or other modules
    root.handlers.clear()

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    # Rotating file
    fh = logging.handlers.RotatingFileHandler(
        config["paths"]["log_file"],
        maxBytes=log_cfg["max_bytes"],
        backupCount=log_cfg["backup_count"],
    )
    fh.setFormatter(formatter)
    root.addHandler(fh)


log = logging.getLogger("ueba.engine")


# ── Config ────────────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── State Persistence ─────────────────────────────────────────────────────────

class StreamState:
    """
    Persists the file read position so the engine resumes from
    where it left off after a crash or restart.
    Same concept as file_tailer.py in your existing pipeline.
    """

    def __init__(self, state_path: str):
        self.path = Path(state_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.position = self._load()

    def _load(self) -> int:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
                pos = data.get("position", 0)
                log.info("Resuming from file position: %d", pos)
                return pos
            except Exception:
                pass
        # No state file — return -1 sentinel so engine seeks to END
        # of enriched.jsonl on first open (live mode, skip backlog)
        return -1

    def save(self, position: int):
        self.position = position
        self.path.write_text(json.dumps({"position": position}))


# ── Score Fusion ──────────────────────────────────────────────────────────────

def fuse_scores(if_result: dict, ae_result: dict, config: dict) -> dict:
    """
    Combine Isolation Forest and Autoencoder scores into a final verdict.

    Returns dict with:
        combined_score  — 0-1 weighted average
        risk_verdict    — 'suspicious' | 'anomalous' | 'highly_anomalous'
        confidence      — 'low' | 'medium' | 'high'
        is_alert        — bool (True if above alert_threshold)
    """
    fusion_cfg = config["score_fusion"]

    # Weighted combination
    w_if = fusion_cfg["isolation_forest_weight"]
    w_ae = fusion_cfg["autoencoder_weight"]

    combined = (
        w_if * if_result["anomaly_score"] +
        w_ae * ae_result["deviation_score"]
    )
    combined = float(np.clip(combined, 0.0, 1.0))

    threshold = fusion_cfg["alert_threshold"]
    is_alert  = combined >= threshold

    # Determine verdict and confidence
    verdict    = "normal"
    confidence = "low"
    for tier in reversed(fusion_cfg["verdicts"]):
        if combined >= tier["min"]:
            verdict    = tier["label"]
            confidence = tier["confidence"]
            break

    return {
        "combined_score": round(combined, 4),
        "risk_verdict":   verdict,
        "confidence":     confidence,
        "is_alert":       is_alert,
    }


# ── Anomaly Reason Builder ────────────────────────────────────────────────────

def build_anomaly_reasons(log_entry: dict, if_result: dict,
                          ae_result: dict) -> list[str]:
    """
    Build a human-readable list of why this log was flagged.
    Checks enrichment flags + model scores to explain the alert.
    """
    reasons = []

    def get(path: str, default=None):
        keys = path.split(".")
        val  = log_entry
        for k in keys:
            if not isinstance(val, dict):
                return default
            val = val.get(k)
            if val is None:
                return default
        return val

    # Enrichment-based reasons
    if get("enrich.anomalies.is_brute_force"):
        reasons.append("brute_force_detected")
    if get("enrich.anomalies.is_impossible_travel"):
        reasons.append("impossible_travel")
    if get("enrich.anomalies.is_tor"):
        reasons.append("tor_exit_node")
    if get("enrich.anomalies.is_malicious_ip"):
        reasons.append("malicious_ip_reputation")
    if get("enrich.anomalies.is_port_scan"):
        reasons.append("port_scan_detected")
    if get("enrich.anomalies.is_lateral_movement"):
        reasons.append("lateral_movement")
    if get("enrich.anomalies.is_data_exfiltration"):
        reasons.append("data_exfiltration")
    if get("enrich.anomalies.is_after_hours"):
        reasons.append("after_hours_activity")
    if get("enrich.anomalies.is_high_frequency"):
        reasons.append("high_frequency_events")
    if get("enrich.geo.cross_continent"):
        reasons.append("cross_continent_access")
    if get("enrich.geo.cross_border"):
        reasons.append("cross_border_access")

    # Model-based reasons
    if if_result["verdict"] in ("anomalous", "highly_anomalous"):
        reasons.append(f"isolation_forest_{if_result['verdict']}")
    if ae_result["is_anomalous"]:
        reasons.append("behavioral_baseline_deviation")

    # Catch-all if no specific reasons found
    if not reasons:
        reasons.append("statistical_anomaly")

    return reasons


# ── UEBA Block Builder ────────────────────────────────────────────────────────

def build_ueba_block(
    if_result: dict,
    ae_result: dict,
    fusion: dict,
    campaign_id: str | None,
    similar_events: list[dict],
    anomaly_reasons: list[str],
    config: dict,
) -> dict:
    """
    Assemble the `ueba` block that gets appended to the original log.
    """
    include_raw = config["output"]["include_raw_scores"]

    ueba = {
        "processed_at":        datetime.now(timezone.utc).isoformat(),
        "risk_verdict":        fusion["risk_verdict"],
        "confidence":          fusion["confidence"],
        "combined_score":      fusion["combined_score"],
        "is_alert":            fusion["is_alert"],
        "anomaly_reasons":     anomaly_reasons,
        "campaign_id":         campaign_id,
        "similar_past_events": similar_events,
    }

    if include_raw:
        ueba["raw_scores"] = {
            "isolation_forest": {
                "anomaly_score": if_result["anomaly_score"],
                "raw_score":     if_result["raw_score"],
                "verdict":       if_result["verdict"],
            },
            "autoencoder": {
                "deviation_score":      ae_result["deviation_score"],
                "reconstruction_error": ae_result["reconstruction_error"],
                "threshold":            ae_result["threshold"],
                "is_anomalous":         ae_result["is_anomalous"],
                "model_used":           ae_result["model_used"],
                "model_type": (
                    "personal"
                    if ae_result["model_used"] not in ("global", "unknown", "")
                    else "global"
                ),
            },
        }

    return ueba


# ── Evidence Block Builder ────────────────────────────────────────────────────

def build_evidence_block(
    log_entry: dict,
    if_result: dict,
    ae_result: dict,
    fusion: dict,
    anomaly_reasons: list[str],
    profile: dict | None,
    alerts_today: int | None,
) -> dict:
    """
    Build a human-readable evidence block for SOC analysts.
    Contains 4 sections:
      1. signature   — exact rule/signature that triggered
      2. raw_event   — key fields from the raw event (process, privileges, logon type etc.)
      3. baseline    — user's normal behaviour vs what happened now
      4. history     — first seen, total events seen, alerts today
    """
    def get(path: str, default=None):
        keys = path.split(".")
        val = log_entry
        for k in keys:
            if not isinstance(val, dict):
                return default
            val = val.get(k)
            if val is None:
                return default
        return val

    # ── 1. Signature ──────────────────────────────────────────────────────────
    sig = get("security.signature") or get("context.message") or "Unknown"
    sig_id = get("security.signature_id") or "N/A"
    severity = get("security.severity")
    mitre = get("context.raw_event.rule.mitre") or {}

    signature_evidence = {
        "rule_id":        sig_id,
        "description":    sig,
        "severity_level": severity,
        "mitre_tactics":  mitre.get("tactic", []),
        "mitre_techniques": mitre.get("technique", []),
        "mitre_ids":      mitre.get("id", []),
        "tags":           get("security.tags") or [],
    }

    # ── 2. Raw event fields ───────────────────────────────────────────────────
    win = get("context.raw_event.data.win") or {}
    win_sys = win.get("system", {})
    win_data = win.get("eventdata", {})
    raw = get("context.raw_event.data") or {}

    # Privileges — clean up whitespace
    privs_raw = win_data.get("privilegeList", "")
    privileges = [p.strip() for p in privs_raw.split() if p.strip()] if privs_raw else []

    # Logon type mapping
    logon_type_map = {
        "2": "Interactive", "3": "Network", "4": "Batch",
        "5": "Service",     "7": "Unlock",  "8": "NetworkCleartext",
        "9": "NewCredentials", "10": "RemoteInteractive (RDP)",
        "11": "CachedInteractive", "12": "CachedRemoteInteractive",
    }
    logon_type_raw = str(win_data.get("logonType", ""))
    logon_type = logon_type_map.get(logon_type_raw, logon_type_raw) if logon_type_raw else None

    raw_event_evidence = {
        "event_category":   get("event_category"),
        "event_action":     get("event_action"),
        "event_outcome":    get("event_outcome"),
        "source_ip":        get("subject.ip") or raw.get("srcip"),
        "dest_ip":          get("object.ip") or raw.get("dstip"),
        "host":             get("host.name"),
        "host_ip":          get("host.ip"),
        "process_name":     win_data.get("processName") or raw.get("app"),
        "logon_type":       logon_type,
        "logon_process":    win_data.get("logonProcessName", "").strip() or None,
        "privileges":       privileges if privileges else None,
        "event_id_windows": win_sys.get("eventID"),
        "failures_5m":      get("enrich.behavioral.recent_failures_5m"),
        "user_events_5m":   get("enrich.counters.user_5m"),
        "host_events_5m":   get("enrich.counters.host_5m"),
        "unique_dests_1h":  get("enrich.behavioral.unique_destinations_1h"),
        "src_country":      get("enrich.geo.src_country"),
        "src_asn":          get("enrich.network_intel.src_provider"),
        "is_tor":           get("enrich.network_intel.tor_detected"),
        "threat_detected":  get("enrich.network_intel.threat_detected"),
    }
    # Remove None values to keep JSON clean
    raw_event_evidence = {k: v for k, v in raw_event_evidence.items() if v is not None and v != "" and v != []}

    # ── 3. Baseline comparison ────────────────────────────────────────────────
    current_hour = get("enrich.temporal.hour_of_day")
    current_risk = get("enrich.risk_score")
    current_ev_1h = get("enrich.counters.user_1h") or 0
    is_business_hours = get("enrich.temporal.is_business_hours")
    is_weekend = get("enrich.temporal.is_weekend")
    day_of_week = get("enrich.temporal.day_of_week")

    if profile:
        avg_hour = round(profile.get("avg_hour", 12), 1)
        avg_risk = round(profile.get("avg_risk", 0), 1)
        avg_ev_1h = round(profile.get("avg_events_1h", 0), 1)

        # Human readable hour
        def fmt_hour(h):
            if h is None: return "unknown"
            h = int(h)
            suffix = "AM" if h < 12 else "PM"
            return f"{h % 12 or 12}:00 {suffix}"

        baseline_evidence = {
            "typical_hour":         fmt_hour(avg_hour),
            "current_hour":         fmt_hour(current_hour),
            "hour_deviation":       f"{abs((current_hour or 0) - avg_hour):.0f}h from baseline",
            "typical_risk_score":   avg_risk,
            "current_risk_score":   current_risk,
            "risk_deviation":       f"+{round((current_risk or 0) - avg_risk, 1)}" if (current_risk or 0) > avg_risk else str(round((current_risk or 0) - avg_risk, 1)),
            "typical_events_1h":    avg_ev_1h,
            "current_events_1h":    current_ev_1h,
            "events_multiplier":    f"{round(current_ev_1h / max(avg_ev_1h, 1), 1)}x normal rate" if avg_ev_1h > 0 else "no baseline",
            "is_business_hours":    is_business_hours,
            "is_weekend":           is_weekend,
            "day_of_week":          day_of_week,
            "seen_countries":       profile.get("seen_countries", []),
            "autoencoder_error":    round(ae_result["reconstruction_error"], 4),
            "autoencoder_threshold": round(ae_result["threshold"], 4),
            "error_vs_threshold":   f"{round(ae_result['reconstruction_error'] / max(ae_result['threshold'], 0.0001), 1)}x above threshold",
            "model_used":           ae_result["model_used"],
            "if_raw_score":         round(if_result["raw_score"], 4),
        }
    else:
        baseline_evidence = {
            "note":                 "No baseline available — new or unseen user",
            "current_hour":         current_hour,
            "current_risk_score":   current_risk,
            "current_events_1h":    current_ev_1h,
            "is_business_hours":    is_business_hours,
            "day_of_week":          day_of_week,
            "autoencoder_error":    round(ae_result["reconstruction_error"], 4),
            "autoencoder_threshold": round(ae_result["threshold"], 4),
            "error_vs_threshold":   f"{round(ae_result['reconstruction_error'] / max(ae_result['threshold'], 0.0001), 1)}x above threshold",
            "model_used":           ae_result["model_used"],
            "if_raw_score":         round(if_result["raw_score"], 4),
        }

    # ── 4. Historical context ─────────────────────────────────────────────────
    history_evidence = {
        "first_seen":        profile.get("first_seen") if profile else None,
        "last_seen":         profile.get("last_seen") if profile else None,
        "total_events_seen": profile.get("total_events") if profile else 0,
        "alerts_today":      alerts_today,
        "anomaly_reasons":   anomaly_reasons,
        "combined_score":    fusion["combined_score"],
        "verdict":           fusion["risk_verdict"],
        "confidence":        fusion["confidence"],
    }
    history_evidence = {k: v for k, v in history_evidence.items() if v is not None}

    return {
        "signature":  signature_evidence,
        "raw_event":  raw_event_evidence,
        "baseline":   baseline_evidence,
        "history":    history_evidence,
    }


# ── Main Engine ───────────────────────────────────────────────────────────────

class UEBAEngine:

    def __init__(self, config: dict, input_path: str, output_path: str):
        self.config      = config
        self.input_path  = input_path
        self.output_path = output_path
        self.running     = False

        # Alert-file coordination between this engine's write loop and the
        # clusterer thread's campaign-ID patcher (which atomically os.replace()s
        # the alerts file). The lock makes the patcher's read+replace mutually
        # exclusive with alert writes, so an alert is never appended to an inode
        # the patcher is about to unlink (a silent lost-write). The flag tells
        # the writer to reopen the new inode before its next write.
        self._reopen_flag = threading.Event()
        self._alert_write_lock = threading.Lock()

        # Stats
        self.stats = {
            "total_processed": 0,
            "total_alerts":    0,
            "total_errors":    0,
            "start_time":      time.time(),
        }

        # Per-user alert count today (for evidence historical context).
        # Cleared at local-wall-clock midnight by _maybe_reset_alerts_today.
        # Only attributed users get counted — alerts with user None/"unknown"
        # are excluded so the bucket doesn't blow up from unattributed events.
        self._user_alerts_today: dict[str, int] = {}
        self._alerts_today_date = None  # date the counter currently covers

        log.info("Initializing UEBA engine...")
        self._load_components()

        # State persistence
        self.state = StreamState(config["paths"]["state_file"])

        # Streaming config
        self.poll_ms    = config["streaming"]["poll_interval_ms"]
        self.save_every = config["streaming"]["state_save_interval"]
        # Isolation Forest inference is the hot path and sklearn carries a large
        # fixed cost per score_samples() call, so we score N events per call
        # instead of one. The read chunk must be big enough to actually yield
        # N events: enriched lines average ~5.4 KB, so 64 KB held only ~12.
        self.if_batch_size    = config["streaming"].get("if_batch_size", 128)
        self.read_chunk_bytes = config["streaming"].get("read_chunk_bytes", 1048576)

        # Output file
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    def _load_components(self):
        """Load all ML models and supporting components from disk."""
        cfg   = self.config
        paths = cfg["paths"]

        # Load scaler (needed by all models)
        log.info("Loading StandardScaler...")
        scaler = joblib.load(paths["scaler"])

        # Layer 1: Isolation Forest
        log.info("Loading Isolation Forest...")
        self.if_scorer = IsolationForestScorer(
            paths["isolation_forest"], paths["scaler"], cfg
        )

        # Layer 2: Autoencoder
        log.info("Loading Autoencoder models...")
        self.ae_scorer = AutoencoderScorer(
            paths["autoencoder_dir"],
            scaler,
            str(Path(paths["models_dir"]) / "thresholds.json"),
            cfg,
        )

        # Layer 3: HDBSCAN campaign detector (background thread)
        self.campaign_detector = CampaignDetector(cfg)

        # RAG: FAISS retriever
        log.info("Loading FAISS index...")
        self.rag_retriever = RAGRetriever(
            paths["faiss_index"],
            paths["faiss_metadata"],
            scaler,
            cfg,
        )

        # Feature extractor
        log.info("Loading feature extractor and profile store...")
        self.profile_store = UserProfileStore(paths["profile_db"])
        self.extractor     = FeatureExtractor(cfg, self.profile_store)

        # Analyst-FP suppressor — reads dashboard-written patterns and
        # drops matching alerts before emission. Lazy mtime reload, so
        # marks/unmarks in the dashboard take effect on the next event.
        self.fp_suppressor = FPPatternSuppressor(paths["fp_patterns_file"])

        log.info("All components loaded successfully")

    def _maybe_reset_alerts_today(self) -> None:
        """
        Clear the per-user "alerts today" counter when the local date rolls
        over. Without this, the counter accumulates for the full lifetime of
        the engine process — which is days, not hours — and the field is
        misleading. Called once per anomalous event.
        """
        today = datetime.now().date()
        if self._alerts_today_date != today:
            if self._alerts_today_date is not None:
                log.info(
                    "Day rolled over (%s → %s); clearing alerts_today counter",
                    self._alerts_today_date, today,
                )
            self._user_alerts_today.clear()
            self._alerts_today_date = today

    def _process_log(self, log_entry: dict) -> dict | None:
        """
        Process one enriched log through the full UEBA pipeline.
        Returns the enriched log with `ueba` block if anomalous, else None.
        """
        # Extract feature vector
        try:
            feature_vec = self.extractor.extract(log_entry)
            metadata    = self.extractor.extract_metadata(log_entry)
        except Exception as e:
            log.debug("Feature extraction failed: %s", e)
            return None

        # Layer 1: Isolation Forest
        if_result = self.if_scorer.score(feature_vec)

        return self._process_scored(log_entry, feature_vec, metadata, if_result)

    def _process_scored(self, log_entry: dict, feature_vec, metadata: dict,
                        if_result: dict) -> dict | None:
        """
        Everything after Layer 1: autoencoder, fusion, and — for alerts only —
        the enrichment tail. Split out of _process_log so a whole batch of
        events can share ONE vectorised Isolation Forest call (_process_batch).
        """
        # Layer 2: Autoencoder (user behavioral)
        user = metadata.get("user", "unknown")
        # Identity resolution — normalize aliases to canonical username
        _id_cfg = self.config.get("identity_resolution", {})
        if _id_cfg.get("enabled") and user:
            user = _id_cfg.get("mappings", {}).get(user, user)
            metadata["user"] = user  # propagate resolved identity
        ae_result = self.ae_scorer.score(feature_vec, user)

        # Fuse scores
        fusion = fuse_scores(if_result, ae_result, self.config)

        # Not anomalous — discard silently
        if not fusion["is_alert"]:
            return None

        # ── Anomalous event ───────────────────────────────────────────────────

        # Update user profile (only for anomalous events to track patterns)
        try:
            self.profile_store.update(log_entry, feature_vec)
        except Exception:
            pass

        # Layer 3: Get campaign ID from last HDBSCAN run
        event_id    = metadata.get("event_id", str(time.time()))
        campaign_id = self.campaign_detector.get_campaign_id(event_id)

        # Add to HDBSCAN buffer for next clustering round
        self.campaign_detector.add_anomaly(event_id, feature_vec, metadata)

        # RAG: retrieve similar past anomalies
        similar_events = self.rag_retriever.retrieve(feature_vec)

        # Add this anomaly to FAISS for future retrievals
        self.rag_retriever.add_to_index(feature_vec, {
            **metadata,
            "risk_verdict": fusion["risk_verdict"],
        })

        # Build anomaly reason list
        anomaly_reasons = build_anomaly_reasons(log_entry, if_result, ae_result)

        # Build ueba block
        ueba_block = build_ueba_block(
            if_result, ae_result, fusion,
            campaign_id, similar_events, anomaly_reasons,
            self.config,
        )

        # Track per-user alert count today for evidence. Skip unattributed
        # events (user None / "unknown") so they don't all pile into one bucket
        # and inflate the count by orders of magnitude.
        self._maybe_reset_alerts_today()
        alerts_today_for_user: int | None = None
        if user and user != "unknown":
            self._user_alerts_today[user] = self._user_alerts_today.get(user, 0) + 1
            alerts_today_for_user = self._user_alerts_today[user]

        # Fetch user profile for evidence baseline comparison
        try:
            profile = self.profile_store.get_user_profile(user)
        except Exception:
            profile = None

        # Build evidence block for SOC analysts
        evidence_block = build_evidence_block(
            log_entry, if_result, ae_result, fusion,
            anomaly_reasons, profile,
            alerts_today=alerts_today_for_user,
        )

        # Append ueba block + evidence to original log
        output_log = dict(log_entry)
        output_log["ueba"] = ueba_block
        output_log["evidence"] = evidence_block

        return output_log

    def _process_batch(self, log_entries: list) -> list:
        """
        Batch equivalent of _process_log.

        Isolation Forest inference dominated the per-event budget: sklearn's
        score_samples() has a large fixed per-call cost, so scoring one row at a
        time spent ~96% of the budget inside that single call. Scoring N rows in
        one call amortises the fixed cost across the batch.

        Returns a list of (result_or_None, errored) aligned with log_entries so
        the caller's stats accounting stays identical to the single-event path.
        """
        out = [(None, False)] * len(log_entries)

        # Phase 1 — feature extraction. A failure here is not an error, it is an
        # unusable event; _process_log has always returned None for those.
        feats, metas, idx = [], [], []
        for i, entry in enumerate(log_entries):
            try:
                fv = self.extractor.extract(entry)
                md = self.extractor.extract_metadata(entry)
            except Exception as e:
                log.debug("Feature extraction failed: %s", e)
                continue
            feats.append(fv)
            metas.append(md)
            idx.append(i)

        if not idx:
            return out

        # Phase 2 — ONE vectorised Isolation Forest call for the whole batch.
        try:
            if_results = self.if_scorer.score_batch(np.vstack(feats))
        except Exception as e:
            # A batch-level failure must never drop good events; fall back to
            # the per-row path for this batch only.
            log.warning("score_batch failed (%s) — falling back to per-row", e)
            if_results = [self.if_scorer.score(f) for f in feats]

        # Phase 3 — per-event tail (autoencoder, fusion, enrichment).
        for k, i in enumerate(idx):
            try:
                out[i] = (self._process_scored(
                    log_entries[i], feats[k], metas[k], if_results[k]), False)
            except Exception as e:
                log.debug("Processing error: %s", e)
                out[i] = (None, True)

        return out

    def run(self):
        """
        Main streaming loop. Tails enriched.jsonl and processes each line.
        Writes anomalous logs to ueba_alerts.jsonl.
        """
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT,  self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

        self.running = True

        # Register callback so clusterer patches campaign IDs immediately after clustering
        self.campaign_detector.on_cluster_complete = self._patch_campaign_ids

        # Start HDBSCAN background thread
        self.campaign_detector.start()

        log.info("=" * 60)
        log.info("UEBA ENGINE STARTED")
        log.info("  Input  : %s", self.input_path)
        log.info("  Output : %s", self.output_path)
        log.info("  Alert threshold : %.2f", self.config["score_fusion"]["alert_threshold"])
        log.info("=" * 60)

        # Wait for input file to appear
        while self.running and not Path(self.input_path).exists():
            log.info("Waiting for %s to appear...", self.input_path)
            time.sleep(2)

        last_stat_log = time.time()
        events_since_save = 0

        # Open output file as a plain handle (not a with-block) so we can reopen
        # it after _patch_campaign_ids does its atomic swap. The reopen now
        # happens at write time under _alert_write_lock (see the alert-write block).
        out_file = open(self.output_path, "a", encoding="utf-8")
        try:
            with open(self.input_path, "r", encoding="utf-8",
                      errors="replace") as in_file:

                # Seek to last known position (resume support)
                # -1 sentinel = no state file = seek to END (live mode only)
                if self.state.position == -1:
                    in_file.seek(0, 2)  # seek to end of file
                    live_start = in_file.tell()
                    self.state.save(live_start)
                    log.info("No state file found — starting from END of input "
                             "(live mode). Position: %d", live_start)
                else:
                    in_file.seek(self.state.position)
                partial_line = ""

                while self.running:
                    chunk = in_file.read(self.read_chunk_bytes)

                    if not chunk:
                        # No new data — sleep and poll
                        time.sleep(self.poll_ms / 1000.0)
                        continue

                    # Process chunk into complete lines
                    lines = (partial_line + chunk).split("\n")
                    partial_line = lines[-1]  # may be incomplete

                    # Parse the whole chunk up front, then score it in batches
                    # so the Isolation Forest runs vectorised (_process_batch).
                    parsed = []
                    for line in lines[:-1]:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            parsed.append(json.loads(line))
                        except json.JSONDecodeError:
                            self.stats["total_errors"] += 1

                    results = []
                    for _start in range(0, len(parsed), self.if_batch_size):
                        results.extend(self._process_batch(
                            parsed[_start:_start + self.if_batch_size]))

                    for result, _errored in results:
                        if _errored:
                            self.stats["total_errors"] += 1

                        self.stats["total_processed"] += 1
                        events_since_save += 1

                        # Write anomalous log to output
                        if result is not None:
                            # Suppress noise events (high-volume low-value firewall
                            # policy events). They are still scored and added to
                            # FAISS/profiles — just not written to alerts output.
                            _meta = result.get("_metadata_cache", {})
                            _is_noise = _meta.get("is_noise", False)
                            # Fallback: check signature_id directly
                            if not _is_noise:
                                from ueba_preprocessor import is_noise as _is_noise_fn
                                _is_noise = _is_noise_fn(result)

                            # Analyst-FP suppression: if the rule description
                            # matches a stored FP pattern (created when an
                            # analyst marked a similar alert as FP), drop the
                            # alert here. Tracked separately from noise so
                            # operators can tell "rule said no" from "analyst
                            # said no".
                            _fp_pat = None
                            if not _is_noise:
                                _fp_pat = self.fp_suppressor.is_fp(
                                    result,
                                    (result.get("ueba") or {}).get("processed_at"),
                                )

                            if _is_noise:
                                self.stats.setdefault("total_suppressed", 0)
                                self.stats["total_suppressed"] += 1
                            elif _fp_pat is not None:
                                self.stats.setdefault("total_fp_suppressed", 0)
                                self.stats["total_fp_suppressed"] += 1
                            else:
                                self.stats["total_alerts"] += 1
                                line_out = json.dumps(result, ensure_ascii=False)
                                # Reopen (if the patcher swapped the file) and write
                                # under the lock, so an alert is never written to an
                                # inode the patcher is about to unlink (lost-write race).
                                with self._alert_write_lock:
                                    if self._reopen_flag.is_set():
                                        try:
                                            out_file.close()
                                        except Exception:
                                            pass
                                        out_file = open(self.output_path, "a",
                                                        encoding="utf-8")
                                        self._reopen_flag.clear()
                                    out_file.write(line_out + "\n")
                                    out_file.flush()

                                # Get actual username for log display
                                _ae_model = result["ueba"].get("raw_scores", {}) \
                                                          .get("autoencoder", {}) \
                                                          .get("model_used", "")
                                _raw_data = result.get("context", {}).get("raw_event", {}).get("data", {})
                                _user = (
                                    result.get("subject", {}).get("name")
                                    or result.get("object", {}).get("name")
                                    or _raw_data.get("dstuser")
                                    or _raw_data.get("srcuser")
                                    or _raw_data.get("devname")        # Fortigate device name
                                    or _raw_data.get("win", {}).get("eventdata", {}).get("subjectUserName")
                                    or _raw_data.get("win", {}).get("eventdata", {}).get("targetUserName")
                                    or (  # only use model_used if it's a real username
                                        _ae_model
                                        if _ae_model not in ("global", "unknown", "", None)
                                        else None
                                    )
                                    or result.get("subject", {}).get("ip")
                                    or result.get("host", {}).get("name", "unknown")
                                )
                                log.info(
                                    "ALERT | user=%-20s verdict=%-18s score=%.3f | reasons=%s | rule=%s | %s",
                                    str(_user)[:20],
                                    result["ueba"]["risk_verdict"],
                                    result["ueba"]["combined_score"],
                                    result["ueba"]["anomaly_reasons"][:2],
                                    result.get("evidence", {}).get("signature", {}).get("rule_id", "N/A"),
                                    result.get("evidence", {}).get("signature", {}).get("description", "")[:60],
                                )

                    # Save state periodically
                    if events_since_save >= self.save_every:
                        self.state.save(in_file.tell())
                        events_since_save = 0

                    # Log stats every 60 seconds
                    now = time.time()
                    if now - last_stat_log >= 60:
                        self._log_stats()
                        last_stat_log = now

                # Loop exited (running=False on shutdown): persist the final read
                # offset. Without this, an unclean stop (weekly retrain, crash, or
                # manual restart) resumes from the last periodic save and
                # reprocesses up to save_every events → duplicate alerts. (The
                # daily rotate clears state separately, so it is unaffected.)
                try:
                    self.state.save(in_file.tell())
                    log.info("Final read offset persisted at shutdown: %d",
                             in_file.tell())
                except Exception as e:
                    log.warning("Could not persist final read offset: %s", e)

        except Exception:
            raise
        finally:
            # Always close the output file on exit, even if reopened mid-run
            try:
                out_file.close()
            except Exception:
                pass

        # Final steps before exit
        self._log_stats()
        log.info("Stopping campaign detector and running final clustering...")
        self.campaign_detector.stop()   # triggers final _run_clustering() → callback
        self.profile_store.close()

        log.info("UEBA engine stopped.")

    def _patch_campaign_ids(self, campaign_map: dict):
        """
        Called immediately by the clusterer thread after each HDBSCAN run.
        Patches campaign_id into ueba_alerts.jsonl in-place using atomic
        temp-file swap. Only rewrites lines that changed (null → assigned).
        Fast and safe — the main write loop holds an open append handle but
        we swap the file atomically so no data is lost.
        """
        if not campaign_map:
            return
        if not Path(self.output_path).exists():
            return
        # Hold the alert-write lock across the whole read→replace so the engine's
        # write loop cannot append to the file we are about to unlink (which would
        # silently lose those alerts). Alert writes block briefly once per
        # clustering interval; none are lost.
        self._alert_write_lock.acquire()
        try:
            tmp_path = self.output_path + ".tmp"
            changed = 0
            with open(self.output_path, "r", encoding="utf-8") as fin,                  open(tmp_path, "w", encoding="utf-8") as fout:
                for line in fin:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    d = json.loads(stripped)
                    eid = d.get("event_id", "")
                    cid = campaign_map.get(eid)
                    if cid and d.get("ueba") and d["ueba"].get("campaign_id") is None:
                        d["ueba"]["campaign_id"] = cid
                        changed += 1
                        fout.write(json.dumps(d, ensure_ascii=False) + "\n")
                    else:
                        fout.write(line if line.endswith("\n") else line + "\n")
            if changed > 0:
                os.replace(tmp_path, self.output_path)
                n_camps = len(set(v for v in campaign_map.values() if v))
                log.info("Campaign IDs patched: %d alerts → %d campaigns",
                         changed, n_camps)
                # ── FIX: signal the main loop to reopen its output file handle.
                # os.replace() above atomically replaced self.output_path with
                # a new inode. The main loop's out_file fd now points to the
                # orphaned old inode — writes succeed but go to a ghost file.
                # Setting this flag tells the main loop to reopen on next iteration.
                if hasattr(self, "_reopen_flag"):
                    self._reopen_flag.set()
            else:
                os.unlink(tmp_path)
        except Exception as e:
            log.error("Failed to patch campaign IDs: %s", e)
        finally:
            self._alert_write_lock.release()


    def _log_stats(self):
        elapsed = time.time() - self.stats["start_time"]
        rate    = self.stats["total_processed"] / max(elapsed, 1)
        alert_rate = (
            self.stats["total_alerts"] / max(self.stats["total_processed"], 1) * 100
        )
        suppressed = self.stats.get("total_suppressed", 0)
        # Refresh FP patterns from disk before reporting count, so operators
        # see the current pattern set rather than whatever was loaded the last
        # time an alert was scored (which may be far behind during quiet hours).
        self.fp_suppressor.refresh()
        # Persist per-pattern hit counts so the dashboard's "Matched" column
        # reflects real suppressions (the suppressed alerts never reach the
        # alert file, so this sibling stats file is the only source of truth).
        self.fp_suppressor.write_stats()
        fp_suppressed = self.stats.get("total_fp_suppressed", 0)
        log.info(
            "Stats | processed: %d | alerts: %d (%.2f%%) | "
            "suppressed_noise: %d | suppressed_fp: %d (%d patterns) | "
            "errors: %d | rate: %.0f/sec | ae_cache: %d",
            self.stats["total_processed"],
            self.stats["total_alerts"],
            alert_rate,
            suppressed,
            fp_suppressed,
            self.fp_suppressor.pattern_count,
            self.stats["total_errors"],
            rate,
            self.ae_scorer.cache_size,
        )

    def _handle_shutdown(self, signum, frame):
        log.info("Shutdown signal received — stopping gracefully...")
        self.running = False
        # stop() and close() are now called in run() after the main loop exits
        pass


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel UEBA Engine — real-time behavioral anomaly detection",
    )
    parser.add_argument("--config", default="ueba_config.yaml")
    parser.add_argument("--input",  default=None,
                        help="Override input path from config")
    parser.add_argument("--output", default=None,
                        help="Override output path from config")
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(config)

    for d in ["logs", ".state", "profiles"]:
        os.makedirs(d, exist_ok=True)

    input_path  = args.input  or config["paths"]["enriched_input"]
    output_path = args.output or config["paths"]["ueba_output"]

    engine = UEBAEngine(config, input_path, output_path)
    engine.run()


if __name__ == "__main__":
    main()
