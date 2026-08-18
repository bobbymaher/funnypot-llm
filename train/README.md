# Training experiment — self-distilled LoRA for bare-prompt HTML

An experiment: can we fine-tune the 0.5B model so it emits a clean fake page from a **bare** request
prompt, dropping the GBNF grammar + one-shot exemplar the prompt-only setup needs? Less scaffolding =
shorter prompts, lower latency, fewer refusals.

See `../../funnypot/docs/LLM-TRAINING-BRAINSTORM.md` and `LLM-TRAINING-STRATEGY.md` for the full
reasoning. Short version: this is the "throwaway LoRA to learn the mechanics" phase — **not** a
production model. It deliberately trains on clean, self-distilled data (never raw nuclei inversions,
which carry canonical matcher strings a scanner fingerprints on).

## The data (`data/`)

`train.jsonl` (200) / `valid.jsonl` (20) / `test.jsonl` (20), each line:

```json
{"prompt": "<|im_start|>system\nYou are a web server...\n<|im_start|>user\nGET /acme-crm/login.php<|im_end|>\n<|im_start|>assistant\n",
 "completion": "<!doctype html>...</html><|im_end|>"}
```

**How it was built** (`generate-corpus.php`): for ~220 plausible unknown paths, the *current* model was
asked (full production prompt + grammar) for a clean page, sanitized, and paired with a **minimal**
prompt (one-line system instruction + bare `METHOD /path`, no exemplar, no grammar). Training on this
teaches the model to produce, from a bare prompt, what it currently needs the scaffolding for —
self-distillation. No nuclei matcher strings are involved.

Regenerate/extend it: `php generate-corpus.php <N>` (needs a running funnypot-llm sidecar at
`127.0.0.1:18080`), then re-split into `data/`.

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
