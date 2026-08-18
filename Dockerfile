# funnypot-llm — a tiny CPU-only LLM sidecar that generates fake HTML for the honeypot's
# otherwise-404 paths. Wraps llama.cpp's HTTP server around a small quantised GGUF model.
#
# The model is baked in at build time so the running container needs no network. Pin the base
# image and the model hash for a reproducible, tamper-evident build:
#   docker build --build-arg MODEL_SHA256=<hash> -t funnypot-llm .
# With no MODEL_SHA256 the build still works and prints the computed hash to copy back here.

ARG LLAMA_IMAGE=ghcr.io/ggml-org/llama.cpp:server
FROM ${LLAMA_IMAGE}

# Qwen2.5-Coder-0.5B-Instruct, Q4_K_M (~400 MB). Small, code-biased, and in testing it emits bare
# HTML without the refusals/"here is the code:" preambles the general 0.5B models tend to add.
ARG MODEL_URL=https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF/resolve/main/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf
# Leave empty to skip verification (the build prints the real hash); set it to pin the model.
ARG MODEL_SHA256=

ENV MODEL_PATH=/models/model.gguf \
    PORT=8080 \
    CTX_SIZE=2048 \
    PARALLEL=2 \
    THREADS=2

USER root
RUN mkdir -p /models \
    && ( command -v curl >/dev/null 2>&1 \
         && curl -fSL "$MODEL_URL" -o "$MODEL_PATH" \
         || wget -O "$MODEL_PATH" "$MODEL_URL" ) \
    && if [ -n "$MODEL_SHA256" ]; then \
           echo "$MODEL_SHA256  $MODEL_PATH" | sha256sum -c - ; \
       else \
           echo "WARN: MODEL_SHA256 unset — pin this value for reproducible builds:" ; \
           sha256sum "$MODEL_PATH" ; \
       fi

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
