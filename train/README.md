# Training experiment — self-distilled LoRA for bare-prompt HTML

An experiment: can we fine-tune the 0.5B model so it emits a clean fake page from a **bare** request
prompt, dropping the GBNF grammar + one-shot exemplar the prompt-only setup needs? Less scaffolding =
shorter prompts, lower latency, fewer refusals.

See `../../funnypot/docs/LLM-TRAINING-BRAINSTORM.md` and `LLM-TRAINING-STRATEGY.md` for the full
reasoning. Short version: this is the "throwaway LoRA to learn the mechanics" phase — **not** a
production model. It deliberately trains on clean, self-distilled data (never raw nuclei inversions,
which carry canonical matcher strings a scanner fingerprints on).

## The data (`data/`)

`train.jsonl` (200) / `valid.jsonl` (20) / `test.jsonl` (20), mlx-lm's native chat format, one line:

```json
{"messages": [
  {"role": "system", "content": "You are a web server. Output only the raw HTML..."},
  {"role": "user", "content": "GET /acme-crm/login.php"},
  {"role": "assistant", "content": "<!doctype html>...</html>"}
]}
```

(Chat format matters: baking the ChatML `<|im_start|>` markers into a raw `prompt`/`completion` string
double-formats them and the model learns to emit end-of-turn immediately — empty output. Let the
tokenizer apply the template.)

**How it was built** (`generate-corpus.php`): for ~220 plausible unknown paths, the *current* model was
asked (full production prompt + grammar) for a clean page, sanitized, and paired with a **bare** input
(one-line system instruction + `METHOD /path`, no exemplar, no grammar). Training on this teaches the
model to produce, from a bare prompt, what it currently needs the scaffolding for — self-distillation.
No nuclei matcher strings are involved.

Regenerate/extend it: `php generate-corpus.php <N>` (needs a running funnypot-llm sidecar at
`127.0.0.1:18080`), then re-split into `data/`.

**Corpus validation** (220 pairs): 100% valid HTML (`<!doctype`/`<html`, `<` first byte), 142–501
chars (median 271 — real pages, not stubs), 220 distinct `<title>`s, and **zero** fingerprint-poison
substrings (`nuclei`, `CVE-`, `matcher`, `interactsh`, `{{BaseURL}}`, …). Clean and safe to train on.

## Result (first run — it works)

300 iters LoRA (16 layers, 2.9M params, ~2 min on an M1 Max), train loss 1.12→0.11, val ~0.22.
A/B on the 20 held-out prompts, both with the **bare** prompt (no grammar, no exemplar):

| model              | servable HTML | fenced/preamble | avg len |
| ------------------ | ------------- | --------------- | ------- |
| base 0.5B          | 3/20 (15%)    | 17/20           | 340     |
| **base + adapter** | **20/20**     | **0/20**        | 250     |

The base model, given a bare request, wraps its answer in a ```` ```html ```` fence — not directly
servable. The adapter makes it emit clean bare HTML every time:

```
base:   ```html\n<!DOCTYPE html>\n<html lang="en">\n<head>...   (fenced, verbose)
tuned:  <!doctype html><html><head><title>Status - Admin Users</title>...  (clean, servable)
```

So a fine-tuned model could let the sidecar **drop the GBNF grammar + one-shot exemplar** (shorter
prompt → faster) and still emit clean HTML. Caveats before trusting it in production: val plateaued
(~0.22 — mild overfit at 300 iters; try fewer iters or more/again-more-varied data), and this is
self-distilled from the current model, so it inherits its style — the real quality unlock is
**distillation from a big model** (per `LLM-TRAINING-BRAINSTORM.md`). Keep the sanitizer regardless.

## Run it (Apple Silicon)

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install mlx-lm
./lora.sh                       # LoRA fine-tune -> train/adapter/
python eval.py                  # A/B: base vs base+adapter on the held-out test set
```

Tunables via env: `ITERS` (300), `BATCH` (4), `LAYERS` (16), `SEQ` (1024), `MODEL`.

## What "better" means

`eval.py` scores base-model vs base+adapter on the 20 held-out prompts, both with the **bare** prompt:

- **HTML rate** — output starts with `<` and contains `<html`/`<!doctype` (no `Sure!`/prose/fences).
- **refusal rate** — output contains a refusal phrase.
- **length** — plausible page size, not a stub.

The hypothesis: the base model on a bare prompt sometimes refuses or adds preamble; the adapter makes
it reliably emit clean HTML. If confirmed, a fused GGUF adapter lets the sidecar drop the grammar.

## Ship it (if it wins)

```bash
python -m mlx_lm.fuse --model Qwen/Qwen2.5-Coder-0.5B-Instruct --adapter-path adapter --save-path fused
# then llama.cpp convert_hf_to_gguf.py fused/ + quantize to Q4_K_M -> bake into the sidecar image
```

Keep the sanitizer regardless — a fine-tuned model can still hallucinate.
