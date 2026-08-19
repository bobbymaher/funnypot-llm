#!/bin/sh
# LoRA fine-tune Qwen2.5-Coder-0.5B on the self-distilled corpus (train/data), via mlx-lm on Apple
# Silicon. Produces train/adapter/. Tunables are env vars with sane defaults.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
PY="${PY:-python}"
MODEL="${MODEL:-Qwen/Qwen2.5-Coder-0.5B-Instruct}"
DATA="${DATA:-$DIR/data}"
ADAPTER="${ADAPTER:-$DIR/adapter}"

exec "$PY" -m mlx_lm lora \
    --model "$MODEL" \
    --train \
    --data "$DATA" \
    --iters "${ITERS:-300}" \
    --batch-size "${BATCH:-4}" \
    --num-layers "${LAYERS:-16}" \
    --max-seq-length "${SEQ:-1024}" \
    --adapter-path "$ADAPTER" \
    --steps-per-report "${STEPS_REPORT:-20}" \
    --steps-per-eval "${STEPS_EVAL:-100}"
