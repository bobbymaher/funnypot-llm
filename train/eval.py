#!/usr/bin/env python
"""A/B the base model vs base+LoRA-adapter on the held-out test prompts, both with the BARE prompt.

Measures whether the adapter makes the model reliably emit clean HTML from a bare request (no grammar,
no exemplar), which is the whole point of the fine-tune. Prints per-model aggregate scores + a sample.
"""
import json
import os
import re
import sys

from mlx_lm import load, generate

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.environ.get("MODEL", "Qwen/Qwen2.5-Coder-0.5B-Instruct")
ADAPTER = os.environ.get("ADAPTER", os.path.join(HERE, "adapter"))
MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "400"))

REFUSAL = re.compile(r"\b(i can'?t|i cannot|i'?m sorry|as an ai|here'?s|here is|sure[,!]|```)", re.I)


def score(text: str) -> dict:
    t = text.strip()
    low = t.lower()
    return {
        "html": t[:1].startswith("<") and ("<html" in low or "<!doctype" in low),
        "refusal": bool(REFUSAL.search(t[:80])),
        "len": len(t),
    }


def run(prompts, adapter=None):
    model, tok = load(MODEL, adapter_path=adapter)
    rows = []
    for p in prompts:
        try:
            out = generate(model, tok, prompt=p, max_tokens=MAX_TOKENS, verbose=False)
        except TypeError:
            # older mlx-lm signature
            out = generate(model, tok, p, max_tokens=MAX_TOKENS)
        rows.append((out, score(out)))
    return rows


def summarize(name, rows):
    n = len(rows)
    html = sum(1 for _, s in rows if s["html"])
    refusal = sum(1 for _, s in rows if s["refusal"])
    avglen = sum(s["len"] for _, s in rows) // max(1, n)
    print(f"\n== {name} ==  n={n}")
    print(f"  HTML-valid : {html}/{n} ({100*html//n}%)")
    print(f"  refusals   : {refusal}/{n}")
    print(f"  avg length : {avglen} chars")
    return html, refusal


def main():
    test = [json.loads(l)["prompt"] for l in open(os.path.join(HERE, "data", "test.jsonl")) if l.strip()]
    print(f"model={MODEL}\nadapter={ADAPTER}\ntest prompts={len(test)}")

    base = run(test, adapter=None)
    tuned = run(test, adapter=ADAPTER) if os.path.isdir(ADAPTER) else None

    bh, _ = summarize("BASE (bare prompt, no adapter)", base)
    if tuned is not None:
        th, _ = summarize("BASE + LoRA adapter (bare prompt)", tuned)
        print(f"\nHTML-valid delta: base {bh} -> tuned {th}  ({'+' if th>=bh else ''}{th-bh})")
    else:
        print(f"\n(no adapter at {ADAPTER} — run ./lora.sh first)")

    # show one example (first test path)
    print("\n--- sample: BASE ---\n" + base[0][0][:280])
    if tuned is not None:
        print("\n--- sample: TUNED ---\n" + tuned[0][0][:280])


if __name__ == "__main__":
    sys.exit(main())
