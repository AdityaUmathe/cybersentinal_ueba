#!/bin/bash
# ueba_sync_bridge.sh — Sync enriched logs from 222 to 98
# Handles rotated gzipped chunks + live active file.
# Format on 222: .../data/enriched/enriched_YYYY-MM-DD_HH-MM-SS.jsonl[.gz]
#
# ── 2026-08-29 reliability rewrite ────────────────────────────────────────
# The previous version fell 3 days behind and stayed there. Root causes,
# all fixed here:
#
#   1. `ssh` inside the `while read` gz loop inherited the loop's stdin and
#      swallowed the rest of the here-string, so exactly ONE chunk was
#      processed per outer cycle no matter how deep the backlog. This is why
#      the state pointer crawled ~13 min of events forward every ~20 min of
#      wall clock — it was losing ground continuously. Fixed with `ssh -n`
#      (see rssh(), which every remote call now goes through).
#
#   2. `ssh "zcat FILE"` decompressed on 222 and shipped PLAINTEXT over the
#      reverse tunnel — ~900 MB per chunk instead of ~90 MB. That saturated
#      the single SSH transport backing 127.0.0.1:2222, which starved every
#      other channel on it (new connections died at banner exchange). We now
#      `cat` the compressed bytes and gunzip locally.
#
#   3. No timeout on any ssh. A half-open tunnel left the bridge blocked in
#      banner exchange forever — ConnectTimeout only covers TCP connect, and
#      ServerAlive* only applies post-auth. Every remote call is now wrapped
#      in `timeout`.
#
#   4. Backlog gz chunks and the live tail both appended to enriched.jsonl
#      concurrently, so the engine saw 3-day-old events interleaved with live
#      ones. The engine does NOT dedup by event_id, so overlap also produced
#      duplicate alerts. Drain and tail are now mutually exclusive: we only
#      tail once the backlog is drained.
#
#   5. The state pointer advanced even when the transfer died mid-stream,
#      silently dropping a chunk and leaving a torn line behind. Chunks now
#      land in a temp file, are integrity-checked with `gzip -t`, and only
#      then get appended and committed to state (atomically).
#
#   6. Nothing bounded disk. Draining a multi-day backlog at ~900 MB/chunk
#      would have filled /data before the 00:05 rotation could flush. We now
#      apply backpressure on both unprocessed bytes and free disk.

set -euo pipefail

# ── Config
SOC_HOST="vgipl@localhost"
SOC_PORT="2222"
SOC_ENRICHED_DIR="/home/vgipl/CyberSentinel-Event-Correlation-Kafka/data/enriched"
BASE="/root/NEW_DRIVE/aditya_ueba"
LOCAL_ENRICHED="$BASE/enriched.jsonl"
STATE_FILE="$BASE/.state/sync_bridge.state"
UEBA_STATE="$BASE/.state/ueba.state"
TMPDIR_CHUNK="$BASE/.state/chunks"
LOG="$BASE/logs/sync_bridge.log"

# ── Tunables (override via systemd Environment= or the shell)
SSH_CMD_TIMEOUT=${SSH_CMD_TIMEOUT:-1800}       # hard cap on a single remote call (s)
SSH_LIST_TIMEOUT=${SSH_LIST_TIMEOUT:-60}       # hard cap on a cheap `ls` call (s)
BACKPRESSURE_GB=${BACKPRESSURE_GB:-8}          # pause pulling above this unprocessed backlog
DISK_MIN_FREE_GB=${DISK_MIN_FREE_GB:-60}       # pause pulling below this free space on /data
STALL_SECS=${STALL_SECS:-300}                  # restart the tail if it delivers nothing for this long
ROTATE_POLL_SECS=${ROTATE_POLL_SECS:-30}       # how often to check for an active-file rotation
LOG_MAX_BYTES=${LOG_MAX_BYTES:-52428800}       # self-rotate this log at 50 MB

GB=$((1024*1024*1024))

mkdir -p "$(dirname "$STATE_FILE")" "$(dirname "$LOG")" "$TMPDIR_CHUNK"

SSH_OPTS=(-p "${SOC_PORT}" -i /root/.ssh/id_ueba
          -o StrictHostKeyChecking=no
          -o ConnectTimeout=10
          -o ServerAliveInterval=30
          -o ServerAliveCountMax=3
          -o BatchMode=yes)

log() {
    # Self-rotate so this file can't grow without bound (it reached 1.7 MB
    # over five weeks with no rotation configured anywhere).
    if [ -f "$LOG" ] && [ "$(stat -c %s "$LOG" 2>/dev/null || echo 0)" -gt "$LOG_MAX_BYTES" ]; then
        mv -f "$LOG" "${LOG}.1" 2>/dev/null || true
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S')  $*" >> "$LOG"
}

# Every remote call goes through here. `-n` is load-bearing: without it ssh
# steals stdin from whatever loop encloses the call (bug #1 above). `timeout`
# is load-bearing too: a half-open tunnel otherwise blocks forever (bug #3).
rssh() {
    local t="$1"; shift
    timeout "$t" ssh -n "${SSH_OPTS[@]}" "$SOC_HOST" "$@"
}

get_last_processed() { [ -f "$STATE_FILE" ] && cat "$STATE_FILE" || echo ""; }

# Atomic — a crash mid-write must never leave a truncated pointer, which
# would silently re-pull or skip chunks on restart.
set_last_processed() {
    printf '%s\n' "$1" > "${STATE_FILE}.tmp" && mv -f "${STATE_FILE}.tmp" "$STATE_FILE"
}

unprocessed_bytes() {
    local size pos
    size=$(stat -c %s "$LOCAL_ENRICHED" 2>/dev/null || echo 0)
    pos=$(sed -nE 's/.*"position"[: ]*([0-9-]+).*/\1/p' "$UEBA_STATE" 2>/dev/null || echo 0)
    [ -n "$pos" ] || pos=0
    [ "$pos" -ge 0 ] 2>/dev/null || pos=0
    if [ "$size" -gt "$pos" ]; then echo $(( size - pos )); else echo 0; fi
}

free_bytes() { df -B1 --output=avail "$BASE" 2>/dev/null | tail -1 | tr -d ' ' || echo 0; }

# Hold off pulling more data when the engine is already behind or the disk is
# tight. Without this, draining a multi-day backlog (~900 MB/chunk
# uncompressed) fills /data long before the 00:05 rotation can flush it.
await_capacity() {
    local waited=0 unproc free
    while true; do
        unproc=$(unprocessed_bytes)
        free=$(free_bytes)
        if [ "$unproc" -lt $(( BACKPRESSURE_GB * GB )) ] && \
           [ "$free"   -gt $(( DISK_MIN_FREE_GB * GB )) ]; then
            [ "$waited" -gt 0 ] && log "  backpressure cleared after ${waited}s (unproc=$(numfmt --to=iec "$unproc") free=$(numfmt --to=iec "$free"))"
            return 0
        fi
        if [ $(( waited % 300 )) = 0 ]; then
            log "  BACKPRESSURE: unproc=$(numfmt --to=iec "$unproc") (limit ${BACKPRESSURE_GB}G) free=$(numfmt --to=iec "$free") (floor ${DISK_MIN_FREE_GB}G) — engine still draining, holding off"
        fi
        sleep 30
        waited=$(( waited + 30 ))
    done
}

# Pull one .gz chunk: compressed over the wire, verified, then appended.
# Returns non-zero without touching state if anything goes wrong, so the
# chunk is simply retried on the next cycle.
fetch_chunk() {
    local gz_path="$1" fname="$2"
    local tmp="$TMPDIR_CHUNK/${fname}.part"
    rm -f "$tmp"

    # `cat` not `zcat` — ship the compressed bytes (bug #2). ~10x less data.
    if ! rssh "$SSH_CMD_TIMEOUT" "cat '${gz_path}'" > "$tmp" 2>/dev/null; then
        log "  ERROR: transfer failed for ${fname} — will retry next cycle"
        rm -f "$tmp"; return 1
    fi
    if [ ! -s "$tmp" ]; then
        log "  ERROR: ${fname} arrived empty — will retry next cycle"
        rm -f "$tmp"; return 1
    fi
    # Integrity gate: a truncated transfer must never reach enriched.jsonl.
    if ! gzip -t "$tmp" 2>/dev/null; then
        log "  ERROR: ${fname} failed gzip integrity check ($(numfmt --to=iec "$(stat -c %s "$tmp")")) — will retry next cycle"
        rm -f "$tmp"; return 1
    fi

    # Local decompress+append. No network in the middle, so a partial append
    # can only happen on a hard crash; roll back to the pre-append size if
    # the pipe reports failure.
    local before after
    before=$(stat -c %s "$LOCAL_ENRICHED" 2>/dev/null || echo 0)
    if ! gunzip -c "$tmp" >> "$LOCAL_ENRICHED"; then
        log "  ERROR: append failed for ${fname} — rolling back to ${before}"
        truncate -s "$before" "$LOCAL_ENRICHED" 2>/dev/null || true
        rm -f "$tmp"; return 1
    fi
    after=$(stat -c %s "$LOCAL_ENRICHED" 2>/dev/null || echo 0)
    rm -f "$tmp"

    # Only now is it safe to advance the pointer (bug #5).
    set_last_processed "$fname"
    log "  Appended ${fname} (+$(numfmt --to=iec $(( after - before ))))"
    return 0
}

TAIL_PID=""
STATS_PID=""
cleanup() {
    log "Shutting down sync bridge..."
    [ -n "$TAIL_PID" ]  && kill "$TAIL_PID"  2>/dev/null || true
    [ -n "$STATS_PID" ] && kill "$STATS_PID" 2>/dev/null || true
    rm -f "$TMPDIR_CHUNK"/*.part 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

log "=== UEBA Sync Bridge Started (backlog-first mode) ==="
log "  SOURCE DIR : ${SOC_HOST}:${SOC_ENRICHED_DIR}"
log "  LOCAL FILE : ${LOCAL_ENRICHED}"
log "  TUNABLES   : backpressure=${BACKPRESSURE_GB}G disk_floor=${DISK_MIN_FREE_GB}G ssh_timeout=${SSH_CMD_TIMEOUT}s stall=${STALL_SECS}s"

# Leftover .part files from a previous kill are never valid input.
rm -f "$TMPDIR_CHUNK"/*.part 2>/dev/null || true

# ── STATS loop
stats_loop() {
    while true; do
        sleep 60
        sz=$(stat -c %s "$LOCAL_ENRICHED" 2>/dev/null || echo 0)
        log "Stats | enriched.jsonl: $(numfmt --to=iec --suffix=B "$sz" 2>/dev/null || echo "${sz}B") | unprocessed: $(numfmt --to=iec "$(unprocessed_bytes)") | free: $(numfmt --to=iec "$(free_bytes)") | state: $(get_last_processed)"
    done
}
stats_loop &
STATS_PID=$!
log "Stats PID: ${STATS_PID}"

# ── Main loop
while true; do
    if ! REMOTE_FILES=$(rssh "$SSH_LIST_TIMEOUT" "ls ${SOC_ENRICHED_DIR}/enriched_*.jsonl* 2>/dev/null | sort"); then
        log "WARNING: could not list ${SOC_ENRICHED_DIR} (tunnel down?) — retrying in 30s"
        sleep 30; continue
    fi
    if [ -z "$REMOTE_FILES" ]; then
        log "WARNING: No enriched files found on 222 — retrying in 30s"
        sleep 30; continue
    fi

    GZ_FILES=$(echo "$REMOTE_FILES" | grep '\.gz$' || true)
    ACTIVE_FILE=$(echo "$REMOTE_FILES" | grep -v '\.gz$' | tail -1 || true)
    LAST_PROCESSED=$(get_last_processed)

    # ── Phase 1: drain the ENTIRE gz backlog before tailing anything.
    # Reading the list into an array first means no subshell and no stdin
    # contention; combined with `ssh -n` this loop now actually iterates.
    PENDING=()
    while IFS= read -r gz_file; do
        [ -z "$gz_file" ] && continue
        fname=$(basename "$gz_file")
        if [ -z "$LAST_PROCESSED" ] || [[ "$fname" > "$LAST_PROCESSED" ]]; then
            PENDING+=("$gz_file")
        fi
    done <<< "$GZ_FILES"

    if [ "${#PENDING[@]}" -gt 0 ]; then
        log "Backlog: ${#PENDING[@]} chunk(s) pending (from $(basename "${PENDING[0]}"))"
        # Stop tailing while we drain — mixing 3-day-old backlog with live
        # events puts the engine's input badly out of order (bug #4).
        if [ -n "$TAIL_PID" ]; then
            log "  pausing live tail while backlog drains"
            kill "$TAIL_PID" 2>/dev/null || true
            wait "$TAIL_PID" 2>/dev/null || true
            TAIL_PID=""
        fi
        drained=0
        for gz_file in "${PENDING[@]}"; do
            await_capacity
            fname=$(basename "$gz_file")
            log "Processing chunk $(( drained + 1 ))/${#PENDING[@]}: ${fname}"
            if fetch_chunk "$gz_file" "$fname"; then
                drained=$(( drained + 1 ))
            else
                log "  aborting this drain pass after ${drained} chunk(s); will re-list and resume"
                break
            fi
        done
        log "Backlog pass complete: ${drained}/${#PENDING[@]} chunk(s) appended"
        # Re-list before deciding to tail — more chunks may have rotated in.
        continue
    fi

    # ── Phase 2: backlog is empty → tail the active file for low latency.
    if [ -z "$ACTIVE_FILE" ]; then
        log "No active file — waiting 30s"
        sleep 30; continue
    fi

    ACTIVE_FNAME=$(basename "$ACTIVE_FILE")
    log "PULL: tailing active file ${ACTIVE_FNAME}..."
    [ -n "$TAIL_PID" ] && { kill "$TAIL_PID" 2>/dev/null || true; wait "$TAIL_PID" 2>/dev/null || true; }

    # -n 0: stream from EOF only; otherwise tail re-emits the last 10 lines
    # of the file on every bridge restart, which the engine then re-processes.
    timeout "$SSH_CMD_TIMEOUT" ssh -n "${SSH_OPTS[@]}" "$SOC_HOST" \
        "tail -n 0 -f ${ACTIVE_FILE}" >> "$LOCAL_ENRICHED" &
    TAIL_PID=$!
    log "  Tail PID: ${TAIL_PID}"

    LAST_SIZE=$(stat -c %s "$LOCAL_ENRICHED" 2>/dev/null || echo 0)
    STALLED_FOR=0
    while kill -0 "$TAIL_PID" 2>/dev/null; do
        sleep "$ROTATE_POLL_SECS"

        # Stall detector: a tail whose remote file was rotated out from under
        # it stays alive forever delivering nothing. Previously that wedged
        # the bridge silently until someone noticed. Now we break and re-list.
        NOW_SIZE=$(stat -c %s "$LOCAL_ENRICHED" 2>/dev/null || echo 0)
        if [ "$NOW_SIZE" = "$LAST_SIZE" ]; then
            STALLED_FOR=$(( STALLED_FOR + ROTATE_POLL_SECS ))
            if [ "$STALLED_FOR" -ge "$STALL_SECS" ]; then
                log "  STALL: no new bytes for ${STALLED_FOR}s — restarting tail"
                kill "$TAIL_PID" 2>/dev/null || true; TAIL_PID=""
                break
            fi
        else
            STALLED_FOR=0
            LAST_SIZE="$NOW_SIZE"
        fi

        # Rotation check. A FAILED ssh must not be read as "no rotation" —
        # that was how a dead tunnel used to leave the bridge tailing a file
        # that no longer existed.
        if ! NEW_ACTIVE=$(rssh "$SSH_LIST_TIMEOUT" "ls ${SOC_ENRICHED_DIR}/enriched_*.jsonl 2>/dev/null | sort | tail -1"); then
            log "  WARNING: rotation check failed (tunnel down?) — restarting tail"
            kill "$TAIL_PID" 2>/dev/null || true; TAIL_PID=""
            break
        fi
        if [ -n "$NEW_ACTIVE" ] && [ "$(basename "$NEW_ACTIVE")" != "$ACTIVE_FNAME" ]; then
            log "File rotated → $(basename "$NEW_ACTIVE") — restarting tail"
            kill "$TAIL_PID" 2>/dev/null || true; TAIL_PID=""
            break
        fi
    done
done
