#!/usr/bin/env python
"""A/B the base model vs base+LoRA-adapter on the held-out test prompts.

Both models get the same bare request (system + `METHOD /path`) via the tokenizer's chat template —
exactly how mlx-lm trained. Measures whether the adapter makes the model reliably emit clean HTML
from a bare prompt (no grammar, no exemplar), which is the whole point of the fine-tune.
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

REFUSAL = re.compile(r"(i can'?t|i cannot|i'?m sorry|as an ai|here'?s|here is|sure[,!]|``)", re.I)


def score(text: str) -> dict:
    t = text.strip()
    low = t.lower()
    return {
        "html": t[:1] == "<" and ("<html" in low or "<!doctype" in low),
        "refusal": bool(REFUSAL.search(t[:80])),
        "len": len(t),
    }


def run(rows, adapter=None):
    model, tok = load(MODEL, adapter_path=adapter)
    out = []
    for r in rows:
        prompt = tok.apply_chat_template(r["messages"][:-1], add_generation_prompt=True, tokenize=False)
        text = generate(model, tok, prompt=prompt, max_tokens=MAX_TOKENS, verbose=False) or ""
        out.append((text, score(text)))
    return out


def summarize(name, rows):
    n = len(rows)
    html = sum(1 for _, s in rows if s["html"])
    refusal = sum(1 for _, s in rows if s["refusal"])
    avglen = sum(s["len"] for _, s in rows) // max(1, n)
    print(f"\n== {name} ==  n={n}")
    print(f"  HTML-valid (< first, has <html/doctype) : {html}/{n} ({100*html//n}%)")
    print(f"  fenced/preamble/refusal                 : {refusal}/{n}")
    print(f"  avg length                              : {avglen} chars")
    return html


def main():
    rows = [json.loads(l) for l in open(os.path.join(HERE, "data", "test.jsonl")) if l.strip()]
    print(f"model={MODEL}\nadapter={ADAPTER}\ntest prompts={len(rows)}")

    base = run(rows, adapter=None)
    tuned = run(rows, adapter=ADAPTER) if os.path.isdir(ADAPTER) else None

    bh = summarize("BASE (bare prompt, no adapter)", base)
    if tuned is not None:
        th = summarize("BASE + LoRA adapter (bare prompt)", tuned)
        print(f"\nHTML-valid: base {bh}/{len(rows)} -> tuned {th}/{len(rows)}  ({'+' if th >= bh else ''}{th - bh})")
    else:
        print(f"\n(no adapter at {ADAPTER} — run ./lora.sh first)")

    print("\n--- sample BASE ---\n" + (base[0][0][:240] or "(empty)"))
    if tuned is not None:
        print("\n--- sample TUNED ---\n" + (tuned[0][0][:240] or "(empty)"))


if __name__ == "__main__":
    sys.exit(main())
