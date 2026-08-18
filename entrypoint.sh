#!/bin/sh
# Launch llama.cpp's server with the baked model. The server binary has moved paths across image
# versions, so probe the known locations rather than assuming one. Every tunable is an env var so
# the compose file can override without editing this script.
set -e

BIN=""
for c in llama-server /llama-server /app/llama-server; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then
        BIN="$c"
        break
    fi
done
if [ -z "$BIN" ]; then
    echo "funnypot-llm: llama-server binary not found in image" >&2
    exit 1
fi

exec "$BIN" \
    --model "$MODEL_PATH" \
    --host 0.0.0.0 \
    --port "${PORT:-8080}" \
    --ctx-size "${CTX_SIZE:-2048}" \
    --parallel "${PARALLEL:-2}" \
    --threads "${THREADS:-2}" \
    --cont-batching \
    --no-webui
