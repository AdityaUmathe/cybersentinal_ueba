# CyberSentinel UEBA — How It Works

A short guide to the User & Entity Behaviour Analytics engine.
*Host: box 98 (`164.52.194.98`) · Base: `/root/NEW_DRIVE/aditya_ueba`*

---

## 1. What it does in one line

It reads every enriched security event from the SIEM, scores how *unusual* it is for that particular user, and writes out only the tiny fraction that looks genuinely anomalous.

**Not a rules engine.** Rules ask *"did something forbidden happen?"* UEBA asks *"is this normal **for this person**?"* A 3 a.m. login is fine for the night-shift admin and alarming for the accounts clerk — same event, different verdict.

Roughly **0.2% of events become alerts**.

---

## 2. The pipeline

```
SIEM (box 222)                  box 98
enriched events  ──ssh tunnel──►  enriched.jsonl
                                       │
                                       ▼
                              ┌─── ueba_engine.py ───┐
                              │  1. extract features │
                              │  2. Isolation Forest │
                              │  3. Autoencoder      │
                              │  4. fuse scores      │
                              └──────────┬───────────┘
                                         │  score >= 0.75 ?
                        no ◄─────────────┴─────────────► yes
                     (discard)                            │
                                                          ▼
                                             enrich: campaign, RAG,
                                             reasons, evidence
                                                          │
                                                          ▼
                                                ueba_alerts.jsonl
                                                          │
                                                          ▼
                                              dashboard (port 3026)
```

---

## 3. Step by step

### Step 1 — Get the events
`ueba-bridge.service` syncs enriched events from the SIEM box (222) to box 98 over an SSH tunnel, appending to **`enriched.jsonl`**. Average event ≈ 5.7 KB.

### Step 2 — Turn an event into numbers
`ueba_preprocessor.py` converts each event into a **35-number feature vector** — hour of day, is-weekend, bytes moved, port, failure counts, geo, how far it deviates from that user's norm, and so on.

It also decides **who** the event belongs to, in order of preference:
> real username → `ip:<source>` → `host:<name>` → `unknown`

### Step 3 — Score it twice (two independent opinions)

| Model | What it's good at | How it works |
|---|---|---|
| **Isolation Forest** | Globally weird events | 200 random trees; things easy to "isolate" are rare. Trained on everyone. |
| **Autoencoder** | Personally weird events | A 35→24→12→24→35 neural net that learns to rebuild *your* normal behaviour. If it rebuilds an event badly, that event is unlike you. |

Two models catch different things — one flags the globally rare, the other the personally out-of-character.

### Step 4 — Fuse and decide

```
score = 0.5 × IsolationForest  +  0.5 × Autoencoder
```

| Score | Verdict | Confidence |
|---|---|---|
| < 0.75 | *(discarded — never written)* | — |
| 0.75 – 0.85 | `suspicious` | low |
| 0.85 – 0.93 | `anomalous` | medium |
| 0.93 – 1.00 | `highly_anomalous` | high |

**This is the key design fact:** below 0.75 the engine returns nothing at all. It is a discrete *alert producer*, not a dashboard that scores everything.

### Step 5 — Add context (alerts only)

Only for the 0.2% that survive:

- **Campaign ID** — HDBSCAN clusters related anomalies every 15 min, so 50 alerts from one attack share one campaign.
- **Similar past events** — a FAISS vector search returns the 5 most similar past anomalies. *"We've seen this before, here's what it was."*
- **Reasons** — plain English: `after_hours_activity`, `impossible_travel`, `behavioral_baseline_deviation`.
- **Evidence** — the analyst's proof pack: `signature`, `raw_event`, `baseline` (their normal vs. this), `history`.

### Step 6 — Filter noise
Two suppression layers before writing:
- **Noise suppression** — known-boring signature IDs, zero-risk network chatter, IPv6 multicast.
- **Analyst FP suppression** — when an analyst marks something a false positive in the dashboard, the pattern is saved and matching alerts are dropped automatically. Takes effect on the next event, no restart.

### Step 7 — Serve it
`ueba_dashboard_server.py` (Flask, port **3026**) reads `ueba_alerts.jsonl` and serves ~25 endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /api/feed` | Alert table (evidence stripped for speed) |
| `GET /api/stream` | **Live SSE stream** — pushes each new alert as it lands |
| `GET /api/evidence/<event_id>` | Full evidence for one alert, on demand |
| `GET /api/users` | Top 20 riskiest users |

---

## 4. Learning: baselines and retraining

- **User profiles** (`profiles/user_profiles.db`, SQLite) hold each entity's rolling **30-day** baseline — typical hours, volumes, hosts. Updated live.
- **Weekly retrain** — Sundays 03:30, rebuilds both models from the rolling training corpus. Old models are kept as timestamped backups for rollback.
- **Daily rotation** — 00:05, archives yesterday's alerts to a zip and restarts the engine (~35s gap).

---

## 5. The moving parts

| Component | What it is |
|---|---|
| `ueba_engine.py` | The main loop. Tails enriched.jsonl, scores, writes alerts. |
| `ueba_preprocessor.py` | Feature extraction + identity resolution + profile store |
| `ueba_models/isolation_forest.py` | Layer 1 scorer |
| `ueba_models/autoencoder.py` | Layer 2 scorer (PyTorch, CPU) |
| `ueba_models/clusterer.py` | HDBSCAN campaigns + FAISS RAG retrieval |
| `ueba_models/fp_suppressor.py` | Analyst false-positive patterns |
| `ueba_dashboard_server.py` | Flask API + dashboard |
| `ueba_config.yaml` | All thresholds and tuning in one place |

**Services:** `ueba-engine` · `ueba-dashboard` · `ueba-bridge` (+ `ueba-engine-watchdog`)

---

## 6. Numbers that matter

*Measured 2026-08-24; throughput re-measured 2026-08-27 after the batching fix.*

| Metric | Value |
|---|---|
| Sustained throughput | **208 events/sec** (was 70 before the 2026-08-27 batching fix) |
| Alert rate | ~0.2% of events |
| Peak alert volume | **1,034 alerts/min** |
| End-to-end latency | ~3 minutes |
| Full alert size | 11.3 KB |
| Slim alert size | 534 bytes |
| Alert threshold | 0.75 |

---

## 7. Two things to know before extending it

**The engine is no longer the bottleneck — the bridge is.**
Until 2026-08-27 the engine sustained ~70 events/sec because the Isolation Forest was scored **one row at a time**, costing 96% of the hot path. It now batches (`if_batch_size: 128`, `read_chunk_bytes: 1048576` under `streaming:`) and sustains **208 events/sec**, verified bit-identical to the old output.

The constraint moved upstream. `ueba-bridge` suffers rotation races (`tail: cannot open ...`), tunnel timeouts, and a `.gz` backfill pointer that went stale for three days. Fix that before quoting any client-facing ingestion rate.

Also worth knowing: the engine still uses **one** of the host's 60 cores. Entity sharding is the next lever if 208/sec ever stops being enough.

**The dashboard has no authentication.**
No login, no session, no user table. `CORS(app)` is open and it binds `0.0.0.0:3026`. Anyone who can reach the port sees everything. This must be fixed before any external exposure.
