# funnypot-llm

A tiny, CPU-only LLM sidecar for [funnypot](https://github.com/bobbymaher/funnypot). It generates a
plausible fake HTML page for requests the honeypot has no template for — the paths that would
otherwise return a bare 404 — so a scanner walking an unknown app keeps getting believable pages
instead of a wall of 404s.

It is a thin wrapper: [llama.cpp](https://github.com/ggml-org/llama.cpp)'s HTTP server plus one small
quantised model, baked into an image that needs no network at runtime.

## What it is (and is not)

- **Is:** an internal HTTP service exposing llama.cpp's `/completion` and `/health`, pinned to a
  small model, tuned for short single-shot generations on a CPU-only box.
- **Is not:** anything funnypot-specific. It holds no honeypot logic, no prompt building, no output
  sanitising, no gating. All of that lives in funnypot's `src/App/Llm/*`. This repo could be swapped
  for any OpenAI-ish `/completion` endpoint without touching funnypot.

Keeping the two apart matters for the deception: funnypot itself never links a heavy ML runtime, and
the model process is reachable only from funnypot over the internal Docker network — never from the
internet.

## The model

Default: **Qwen2.5-Coder-0.5B-Instruct**, `Q4_K_M` GGUF (~400 MB). Chosen because at 0.5B it still
emits bare HTML on request, where the general-purpose 0.5B models tend to refuse or wrap the answer
in `here is the code:` prose. funnypot pins the output shape with a GBNF grammar regardless, but a
model that cooperates needs fewer retries.

Swap it at build time with `--build-arg MODEL_URL=... --build-arg MODEL_SHA256=...`.

## Build & run standalone

```bash
docker compose up --build
curl -s localhost:8080/health
curl -s localhost:8080/completion \
  -d '{"prompt":"<|im_start|>user\nhi<|im_end|>\n<|im_start|>assistant\n","n_predict":16}'
```

The first build downloads the model. Pin it for reproducible, tamper-evident builds — run once with
no hash, copy the printed `sha256sum`, then build with `--build-arg MODEL_SHA256=<hash>` (or set
`MODEL_SHA256` in your environment for compose).

## HTTP contract

funnypot's `LlmClient` POSTs JSON to `/completion` and reads back `content`:

**Request** (funnypot sends; extra fields are llama.cpp defaults funnypot pins):

| field            | value                                             |
| ---------------- | ------------------------------------------------- |
| `prompt`         | ChatML prompt built by funnypot                   |
| `grammar`        | GBNF that forces `<!doctype html>`-first HTML      |
| `n_predict`      | token cap (default 320)                            |
| `temperature`    | 0.4                                               |
| `top_p`          | 0.9                                               |
| `repeat_penalty` | 1.1                                               |
| `cache_prompt`   | `true` (reuse the shared system+exemplar prefix)  |
| `stop`           | `["<|im_end|>", "</html>"]`                        |
| `seed`           | 42 (repeatable generations)                        |

**Response:** llama.cpp JSON; funnypot uses `.content` (the generated text) and ignores the rest.

**Health:** `GET /health` → `200` once the model is loaded. Compose gates readiness on it.

funnypot treats every non-200, timeout, or malformed body as "no fake" and falls through to its plain
404 — the sidecar being slow, down, or absent only ever costs a fake, never breaks the honeypot.

## Runtime tunables (env)

| var         | default | meaning                                   |
| ----------- | ------- | ----------------------------------------- |
| `PORT`      | 8080    | listen port                               |
| `CTX_SIZE`  | 2048    | context window                            |
| `PARALLEL`  | 2       | concurrent decode slots                   |
| `THREADS`   | 2       | CPU threads (match the instance's vCPUs)  |

## Wiring into the funnypot stack

The sidecar stays internal — no published port. Add to funnypot's `demo/docker-compose.yml`:

```yaml
services:
  funnypot:
    environment:
      FUNNYPOT_LLM: "1"
      # FUNNYPOT_LLM_URL defaults to http://funnypot-llm:8080/completion

  funnypot-llm:
    image: funnypot-llm:latest        # or build: { context: ../../funnypot-llm }
    restart: unless-stopped
    # no ports: reachable only from funnypot on the internal network
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:8080/health || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 12
      start_period: 60s
```

funnypot does **not** hard-depend on the sidecar (the breaker and timeout handle its absence), so it
is safe to leave the service out entirely — funnypot just serves plain 404s for unknown paths.

### Capping concurrency

Unknown-path 404s can arrive in bursts (a scanner walking an app hits tens per second). funnypot caps
how many generations run at once with `FUNNYPOT_LLM_MAX_CONCURRENT` (default 4); every request over
the cap falls straight through to the plain 404 — never queued, never blocking. The probe gate sheds
the random-URL scans *before* the cap, so the cap is only ever spent on genuinely plausible paths.

Set the app cap at or below the sidecar's decode slots so the server never has to queue internally:

| knob                          | where     | default | note                                  |
| ----------------------------- | --------- | ------- | ------------------------------------- |
| `FUNNYPOT_LLM_MAX_CONCURRENT` | funnypot  | 4       | hard ceiling on simultaneous requests |
| `PARALLEL`                    | sidecar   | 2       | llama.cpp decode slots                |
| `THREADS`                     | sidecar   | 2       | CPU threads (≈ the instance's vCPUs)  |

On a small CPU box, keeping both caps at 2 is a good starting point: at most two pages generate at
once, everything else during a burst is an instant 404, and the results cache means each unknown path
is only ever generated once anyway.

## Sizing

The 0.5B Q4 model runs on a small always-on instance (~1–2 vCPU, ~1 GB free RAM). Generations are a
few hundred ms to low seconds on CPU; funnypot caches every result by normalised path, so a given
unknown URL is generated once and served from SQLite forever after.
