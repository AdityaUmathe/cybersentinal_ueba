#!/bin/bash
# ueba_weekly_retrain.sh — weekly model retraining for the UEBA pipeline.
#
# Runs from cron every Sunday at 03:30 IST. Each run:
#   1. Pulls new enriched_*.jsonl.gz chunks from 23 (since last successful
#      pull, OR last 7 days on the very first run).
#   2. Bundles them into one dated snapshot in training_zips/ — named so
#      retrain.py picks it up as a "new" training file.
#   3. Stops the engine.
#   4. Runs retrain.py (which backs up models, prepares features, retrains
#      Isolation Forest + global AE + per-user AEs + FAISS).
#   5. Restarts the engine.
#   6. Prunes weekly snapshots older than SNAPSHOT_RETENTION_DAYS.
#
# Engine downtime per run: 30–90 min (depends on features.h5 size).
# If retrain.py crashes, the engine is restarted with the previous models
# (retrain.py's own backup-then-rebuild flow ensures models/ is never half-empty).
#
# Manual invocation is safe — running mid-week pulls any new chunks since
# the last run and rebuilds normally. State tracked in .state/last_train_pull.

set -euo pipefail

BASE=/root/NEW_DRIVE/aditya_ueba
TRAINING_DIR=$BASE/training_zips
STATE_DIR=$BASE/.state
LAST_PULL_STATE=$STATE_DIR/last_train_pull
LOG=$BASE/logs/weekly_retrain.log
VENV_PY=/data/aditya_ueba/venv/bin/python3

# 23 SSH config (reuses the bridge's reverse-tunnel key)
SSH_OPTS="-p 2222 -i /root/.ssh/id_ueba -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=3"
SOC_HOST="vgipl@localhost"
SOC_ENRICHED_DIR="/home/vgipl/CyberSentinel-Event-Correlation-Kafka/data/enriched"

SNAPSHOT_RETENTION_DAYS=${SNAPSHOT_RETENTION_DAYS:-90}
# Rolling window for combined_training.jsonl — retrain.py only ever APPENDS to
# it, so without trimming it grows unbounded (~70 GB/month). Keep this aligned
# with profile_store.baseline_window_days (30) so the AE/IF baseline and the
# behavioural baseline cover the same period.
TRAINING_RETENTION_DAYS=${TRAINING_RETENTION_DAYS:-30}
COMBINED=/data/ueba_training/combined_training.jsonl

mkdir -p "$TRAINING_DIR" "$STATE_DIR" "$(dirname "$LOG")"
exec >> "$LOG" 2>&1

echo "==================================================================="
echo "$(date '+%Y-%m-%d %H:%M:%S')  Weekly retrain start"

# ── 1. Discover new chunks on 23 ────────────────────────────────────────
# Filenames are enriched_YYYY-MM-DD_HH-MM-SS.jsonl.gz, so lexicographic
# comparison == chronological. State file holds the last-pulled basename.
LAST_PULLED=$(cat "$LAST_PULL_STATE" 2>/dev/null || echo "")
if [ -n "$LAST_PULLED" ]; then
  echo "  Last pulled: $LAST_PULLED"
  REMOTE_FILES=$(ssh $SSH_OPTS $SOC_HOST \
    "ls $SOC_ENRICHED_DIR/enriched_*.jsonl.gz 2>/dev/null | sort" \
    | awk -F/ -v last="$LAST_PULLED" '$NF > last { print $NF }')
else
  echo "  First run: pulling last 7 days of .gz from 23"
  REMOTE_FILES=$(ssh $SSH_OPTS $SOC_HOST \
    "find $SOC_ENRICHED_DIR -maxdepth 1 -name 'enriched_*.jsonl.gz' -mtime -7 -printf '%f\n' | sort")
fi

if [ -z "$REMOTE_FILES" ]; then
  echo "  No new .gz on 23 — skipping retrain (engine left running)"
  exit 0
fi

CHUNK_COUNT=$(echo "$REMOTE_FILES" | wc -l)
NEWEST=$(echo "$REMOTE_FILES" | tail -1)
echo "  Found $CHUNK_COUNT new chunk(s); newest: $NEWEST"

# ── 2. Bundle into a single weekly snapshot ──────────────────────────────
WEEK_TS=$(date +%Y-%m-%d)
SNAPSHOT="enriched-weekly-${WEEK_TS}.json.gz"
SNAPSHOT_PATH="$TRAINING_DIR/$SNAPSHOT"

if [ -e "$SNAPSHOT_PATH" ]; then
  TS_SUFFIX=$(date +%H%M%S)
  SNAPSHOT="enriched-weekly-${WEEK_TS}_${TS_SUFFIX}.json.gz"
  SNAPSHOT_PATH="$TRAINING_DIR/$SNAPSHOT"
  echo "  Today's snapshot exists; using ${SNAPSHOT}"
fi

echo "  Building $SNAPSHOT (zcat $CHUNK_COUNT remote chunks → gzip)..."
REMOTE_PATHS=$(echo "$REMOTE_FILES" | awk -v dir="$SOC_ENRICHED_DIR" '{print dir"/"$0}' | tr '\n' ' ')
if ! ssh $SSH_OPTS $SOC_HOST "zcat $REMOTE_PATHS" | gzip > "$SNAPSHOT_PATH"; then
  echo "  ERROR: snapshot build failed — aborting (engine left running)"
  rm -f "$SNAPSHOT_PATH"
  exit 1
fi
echo "  Snapshot built: $(numfmt --to=iec "$(stat -c %s "$SNAPSHOT_PATH")")"

# State updated only after a successful snapshot, so a failed pull is replayed.
echo "$NEWEST" > "$LAST_PULL_STATE"

# ── 3. Stop engine ───────────────────────────────────────────────────────
# The engine runs under systemd (ueba-engine.service). Stop it THROUGH systemd so
# a clean stop does NOT trip Restart=always (which would respawn a unit-managed
# engine racing this script's restart on the same .state byte offset). Falls back
# to legacy pgrep-kill only where the unit isn't installed.
ENGINE_UNIT=ueba-engine
if systemctl cat "${ENGINE_UNIT}.service" >/dev/null 2>&1; then
  USE_SYSTEMD=1
else
  USE_SYSTEMD=0
fi

if [ "$USE_SYSTEMD" = 1 ]; then
  echo "  stopping engine via 'systemctl stop ${ENGINE_UNIT}'"
  systemctl stop "${ENGINE_UNIT}" || echo "  WARNING: systemctl stop returned non-zero"
else
  ENGINE_PID=$(pgrep -f "python3 ueba_engine\.py" | head -1 || true)
  if [ -n "$ENGINE_PID" ]; then
    echo "  Stopping engine PID=$ENGINE_PID"
    kill "$ENGINE_PID" 2>/dev/null || true
    for i in $(seq 1 30); do
      sleep 1
      kill -0 "$ENGINE_PID" 2>/dev/null || { echo "  engine exited after ${i}s"; break; }
    done
    if kill -0 "$ENGINE_PID" 2>/dev/null; then
      echo "  engine didn't exit in 30s — SIGKILL"
      kill -9 "$ENGINE_PID" || true
      sleep 1
    fi
  else
    echo "  No engine running"
  fi
fi

# ── 4. Run retrain.py ────────────────────────────────────────────────────
echo "  Running retrain.py..."
cd "$BASE"
RETRAIN_OK=1
if ! "$VENV_PY" retrain.py; then
  echo "  retrain.py FAILED — restarting engine with previous models"
  RETRAIN_OK=0
fi

# ── 5. Restart engine ────────────────────────────────────────────────────
cd "$BASE"
if [ "$USE_SYSTEMD" = 1 ]; then
  echo "  starting engine via 'systemctl start ${ENGINE_UNIT}'"
  systemctl start "${ENGINE_UNIT}"
  NEW_PID=$(systemctl show -p MainPID --value "${ENGINE_UNIT}" 2>/dev/null || echo "?")
  echo "  Engine restart launched (systemd MainPID: $NEW_PID, takes ~35s to be fully ready)"
else
  setsid "$VENV_PY" ueba_engine.py >> engine.log 2>&1 < /dev/null &
  NEW_PID=$!
  echo "  Engine restart launched (new PID: $NEW_PID, takes ~35s to be fully ready)"
fi

# ── 5.5 Prune combined_training.jsonl to a rolling window ────────────────────
# retrain.py APPENDS each week's new events to combined_training.jsonl and never
# trims it, so it grows unbounded. Keep only events newer than
# TRAINING_RETENTION_DAYS so features.h5 stays a rolling baseline and disk stays
# bounded. Runs AFTER the engine restart (zero added downtime). Fully defensive:
# streams to a temp file, refuses to produce an empty result, verifies the last
# line is complete JSON, and only THEN swaps — any failure leaves the original
# combined_training.jsonl untouched.
#
# NOT gated on RETRAIN_OK: combined_training.jsonl is an INPUT, and retrain.py
# appends this week's events to it BEFORE the validation gate runs. Gating the
# prune on a successful retrain meant a gate FAIL (2026-07-19) appended a week
# and never trimmed it — the file regrew 215G→260G. Whether the candidate model
# promoted has no bearing on which events belong in the rolling window.
if [ -f "$COMBINED" ]; then
  CUTOFF=$(date -d "${TRAINING_RETENTION_DAYS} days ago" +%Y-%m-%d)
  TMP="${COMBINED}.pruned.$$"
  echo "  Pruning combined_training.jsonl to events >= ${CUTOFF} (${TRAINING_RETENTION_DAYS}d window)..."
  if "$VENV_PY" - "$COMBINED" "$TMP" "$CUTOFF" <<'PYPRUNE'
import sys
src, dst, cutoff = sys.argv[1], sys.argv[2], sys.argv[3]
KEY = b'"event_time":"'; KLEN = len(KEY); cut = cutoff.encode()
read = kept = 0
with open(src, "rb") as fi, open(dst, "wb") as fo:
    for line in fi:
        read += 1
        i = line.find(KEY)
        if i == -1:                       # no parseable ts → keep defensively
            kept += 1; fo.write(line); continue
        if line[i + KLEN:i + KLEN + 10] >= cut:   # ISO8601 sorts lexically
            kept += 1; fo.write(line)
print(f"  PRUNE read={read} kept={kept} dropped={read - kept}")
sys.exit(0 if kept > 0 else 3)            # never leave an empty training file
PYPRUNE
  then
    if tail -1 "$TMP" | "$VENV_PY" -c "import sys,json; json.loads(sys.stdin.read())" >/dev/null 2>&1; then
      mv "$TMP" "$COMBINED"
      echo "  combined_training.jsonl pruned → $(numfmt --to=iec "$(stat -c %s "$COMBINED")")"
    else
      echo "  WARNING: pruned temp failed JSON check — keeping original, removing temp"
      rm -f "$TMP"
    fi
  else
    echo "  WARNING: prune produced empty/failed output — keeping original, removing temp"
    rm -f "$TMP"
  fi
fi

# ── 6. Prune snapshots older than N days ─────────────────────────────────
DELETED=$(find "$TRAINING_DIR" -maxdepth 1 -name 'enriched-weekly-*.json.gz' \
            -mtime "+${SNAPSHOT_RETENTION_DAYS}" -print -delete 2>/dev/null || true)
if [ -n "$DELETED" ]; then
  DCOUNT=$(echo "$DELETED" | wc -l)
  echo "  Pruned $DCOUNT old weekly snapshot(s) >${SNAPSHOT_RETENTION_DAYS}d"
fi

if [ "$RETRAIN_OK" = "1" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S')  Weekly retrain done"
else
  echo "$(date '+%Y-%m-%d %H:%M:%S')  Weekly retrain FAILED — engine restored with old models"
  exit 1
fi
