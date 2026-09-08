#!/bin/bash
# Phase 2 of the clean retrain re-run: train models on the freshly-rebuilt
# features.h5, with backup + restore-on-failure so the engine always comes back
# on valid models. Engine is down only for the training step (prepare already
# ran with the engine up). Self-contained: completes the engine restart even if
# the launching SSH session drops.
set -u
cd /data/aditya_ueba
TS=$(date +%Y%m%d-%H%M%S)
LOG=logs/phase2_retrain.log
exec >> "$LOG" 2>&1
echo "==================================================================="
echo "PHASE 2 START $(date '+%Y-%m-%d %H:%M:%S')"

# 1. Stop engine (kill the python directly; SIGKILL fallback)
echo "engine pids: $(pgrep -f 'ueba_engine\.py' | tr '\n' ' ')"
for p in $(pgrep -f 'ueba_engine\.py'); do echo "  kill $p"; kill "$p" 2>/dev/null; done
for i in $(seq 1 30); do sleep 1; pgrep -f 'ueba_engine\.py' >/dev/null || { echo "  engine down after ${i}s"; break; }; done
for p in $(pgrep -f 'ueba_engine\.py'); do echo "  SIGKILL $p"; kill -9 "$p" 2>/dev/null; done
sleep 2

# 2. Backup current (working) models, keep 3 newest backups
echo "backup → models_backup_$TS"
cp -a models "models_backup_$TS"
ls -dt models_backup_* 2>/dev/null | tail -n +4 | xargs -r rm -rf
echo "backups kept: $(ls -d models_backup_* 2>/dev/null | tr '\n' ' ')"

# 3. Clear models so trainer starts fresh (drops stale per-user AEs)
rm -f models/*.pkl
rm -rf models/autoencoders
mkdir -p models/autoencoders
echo "cleared models/"

# 4. Train
echo "===== TRAINING START $(date '+%H:%M:%S') ====="
if ./venv/bin/python3 ueba_trainer.py --config ueba_config.yaml; then
  TRAIN_OK=1; echo "===== TRAINING OK $(date '+%H:%M:%S') ====="
else
  TRAIN_OK=0; echo "===== TRAINING FAILED — restoring backup ====="
  rm -rf models; cp -a "models_backup_$TS" models
fi

# 5. Restart engine (mirrors the weekly wrapper's relaunch)
echo "restarting engine..."
setsid ./venv/bin/python3 ueba_engine.py >> engine.log 2>&1 < /dev/null &
sleep 10
echo "engine procs: $(pgrep -af 'ueba_engine\.py' | head -1)"

if [ "$TRAIN_OK" = "1" ]; then
  echo "PHASE 2 DONE — models retrained $(date '+%Y-%m-%d %H:%M:%S')"
else
  echo "PHASE 2 FAILED — engine restored on OLD models $(date '+%Y-%m-%d %H:%M:%S')"
fi
