#!/bin/sh
# Launch llama.cpp's server with the baked model. The server binary has moved paths across image
# versions, so probe the known locations rather than assuming one. Every tunable is an env var so
# the compose file can override without editing this script.
set -e

BIN=""
# Absolute paths first: a bare name is only accepted once command -v resolves it to a real path,
# so we never hand exec a cwd-relative name that PATH lookup then fails to find.
for c in /app/llama-server /llama-server /usr/local/bin/llama-server; do
    if [ -x "$c" ]; then
        BIN="$c"
        break
    fi
done
if [ -z "$BIN" ]; then
    BIN="$(command -v llama-server 2>/dev/null || true)"
fi
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
