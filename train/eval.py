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

# Same canonical scanner/nuclei + self-revealing-honeypot signatures the corpus builder gates on
# (build-galah-corpus.py) — a fine-tune could in principle hallucinate one even if none were in its
# training data, so this stays a runtime check, not just a build-time one. Target is ~0 hits.
FINGERPRINT = re.compile(
    r"(nuclei|cve-|matcher|interactsh|\{\{baseurl\}\}|projectdiscovery|x-nuclei|nikto|sqlmap|"
    r"acunetix|openvas|burpcollaborator|oastify|w3af|qualys|honeypot|galah\b|opencanary|conpot|"
    r"dionaea)",
    re.I,
)

# Rough "does this look like bait, not a bare status page" read — a proxy for the qualitative
# juiciness check, not a scored pass/fail on its own.
JUICY = re.compile(r"(<table|<tr|<td|<ul|<li|token|admin|dashboard|record|account|config|database|api.?key)", re.I)


def score(text: str) -> dict:
    t = text.strip()
    low = t.lower()
    return {
        "html": t[:1] == "<" and ("<html" in low or "<!doctype" in low),
        "refusal": bool(REFUSAL.search(t[:80])),
        "fingerprint": bool(FINGERPRINT.search(t)),
        "juicy": bool(JUICY.search(t)),
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
    fingerprint = sum(1 for _, s in rows if s["fingerprint"])
    juicy = sum(1 for _, s in rows if s["juicy"])
    avglen = sum(s["len"] for _, s in rows) // max(1, n)
    print(f"\n== {name} ==  n={n}")
    print(f"  HTML-valid (< first, has <html/doctype) : {html}/{n} ({100*html//n}%)")
    print(f"  fenced/preamble/refusal                 : {refusal}/{n}")
    print(f"  fingerprint-signature hit (target 0)    : {fingerprint}/{n}")
    print(f"  looks juicy (table/admin/record marker) : {juicy}/{n}")
    print(f"  avg length                              : {avglen} chars")
    return html


# Galah's 62 real attacker paths skew heavily toward raw exploit payloads (Log4j JNDI strings, RCE
# command injection) where a terse error/ack page is the realistic response, not bait content — so
# test.jsonl alone under-samples the "plausible unknown admin/API path" case the exemplar in
# LlmPromptBuilder targets and funnypot serves most often in practice. This fixed smoke set (not
# drawn from Galah, not used for training or scoring) is a quick manual sanity check that the
# adapter still produces juicy bait on THAT shape of path, not just terse acks on exploit payloads.
SMOKE_PATHS = [
    ("GET", "/acme-portal/admin/users"),
    ("POST", "/wp-login.php"),
    ("GET", "/vendor-portal/admin/config"),
    ("GET", "/hr-portal/reports/quarterly"),
]


def smoke_check(adapter):
    system = json.loads(open(os.path.join(HERE, "data", "train.jsonl")).readline())["messages"][0]["content"]
    model, tok = load(MODEL, adapter_path=adapter)
    print(f"\n== admin-path smoke check (adapter={adapter}) ==")
    for method, path in SMOKE_PATHS:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": f"Method: {method}\nPath: {path}"}]
        prompt = tok.apply_chat_template(messages, add_generation_prompt=True, tokenize=False)
        text = generate(model, tok, prompt=prompt, max_tokens=300, verbose=False) or ""
        s = score(text)
        print(f"  {method} {path}: html={s['html']} juicy={s['juicy']} fingerprint={s['fingerprint']} len={s['len']}")
        print(f"    {text[:200]}")


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

    n_samples = int(os.environ.get("SAMPLES", "3"))
    for i in range(min(n_samples, len(rows))):
        path = rows[i]["messages"][1]["content"].replace("\n", " | ")
        print(f"\n--- sample[{i}] {path} ---")
        print("BASE : " + (base[i][0][:220] or "(empty)"))
        if tuned is not None:
            print("TUNED: " + (tuned[i][0][:220] or "(empty)"))

    if tuned is not None and os.environ.get("SMOKE", "1") != "0":
        smoke_check(ADAPTER)


if __name__ == "__main__":
    sys.exit(main())
