#!/bin/sh
# LoRA fine-tune Qwen2.5-Coder-0.5B on the self-distilled corpus (train/data), via mlx-lm on Apple
# Silicon. Produces train/adapter/. Tunables are env vars with sane defaults.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
PY="${PY:-python}"
MODEL="${MODEL:-Qwen/Qwen2.5-Coder-0.5B-Instruct}"

exec "$PY" -m mlx_lm lora \
    --model "$MODEL" \
    --train \
    --data "$DIR/data" \
    --iters "${ITERS:-300}" \
    --batch-size "${BATCH:-4}" \
    --num-layers "${LAYERS:-16}" \
    --max-seq-length "${SEQ:-1024}" \
    --adapter-path "$DIR/adapter" \
    --steps-per-report 20 \
    --steps-per-eval 100
