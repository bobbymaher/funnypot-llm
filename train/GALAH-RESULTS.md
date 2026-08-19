# Training round 2 — Galah real-attacker-traffic LoRA

Follows the plan in `funnypot/docs/research/training-datasets.md` ("Concrete plan — training round
2"), with one deliberate deviation: that plan said to *mix* Galah rows into the existing
self-distilled 200/20/20 split; this round instead builds a **standalone** corpus on funnypot's real
production prompt contract (`funnypot/src/App/Llm/LlmPromptBuilder.php`) — system prompt verbatim,
user turn as `Method: {M}\nPath: {P}` — rather than the first experiment's simplified stand-in system
prompt (`"You are a web server..."`) and bare `"GET /path"` user turn. Mixing two different input
formats for the same output style would have diluted the signal for both; matching the real contract
was the explicit ask for this round. The original self-distilled data moved to
`data/self-distilled-v1/` (unchanged, still readable) rather than being deleted — its 200/20/20 split
and results are still described in `README.md`.

## Source and pipeline

[`github.com/0x4D31/galah`](https://github.com/0x4D31/galah) `data/` (Apache-2.0), cloned shallow to
`/tmp/galah`: 40 NDJSON event logs, 1,380 records, real attacker requests (from a live sensor) each
replayed through ~17 LLMs (`gpt-4o`, `claude-3-5-sonnet`, `gemini-1.5-pro`, `command-r-plus`,
`gemma2`, `llama3`, `mistral`, `phi3`, ... in normal + `_adversarial` variants), yielding only **62
distinct (method, path) pairs**. `text/html`-content-type responses: 386, across 47 of the 62 paths
(the other 15 are DNS/binary/JSON-API paths with no HTML response from any model — skipped, funnypot
only ever needs an HTML body regardless of what a real server would return there).

Built by `train/build-galah-corpus.py --galah-data /tmp/galah/data --out data`.

**Fingerprint-safety gate** (runs before tiering/selection, drops from every pool — chosen or DPO
rejected, since a rejected DPO row is still text the model reads during training):
- canonical scanner/nuclei matcher artifacts (`nuclei`, `cve-`, `matcher`, `interactsh`,
  `{{BaseURL}}`, `projectdiscovery`, `nikto`, `sqlmap`, ...)
- literal honeypot/tool self-identification (`honeypot`, `galah`, `decoy`, `cowrie`, `opencanary`,
  `conpot`, `dionaea`)
- a mismatched server banner (`nginx/x`, `Apache/x`, `IIS/x`, `lighttpd/x` — Galah's live sensor ran
  behind a real box whose default-error-page footer sometimes leaked in; that directly contradicts
  the fixed `PHP/8.1.27` stack in our system prompt, so it's excluded like any other policy issue)
- 9 rows dropped this way (mostly `/are-you-a-honeypot` responses that discuss being a honeypot, and
  two that echoed the CVE id from the request path back into the body)

**Refusal filter** (excluded from the SFT/DPO chosen pool only — DPO needs refusals in the rejected
slot): `i cannot`, `i can't`, `i'm sorry`, `i apologize`, `cannot provide/fulfill/disclose/assist`,
first-person `i am unable to` / `i'm unable to`, `as an ai`, `as a language model`, `openai`,
`anthropic`, `trained by`. (An earlier version of this filter used bare `"unable to"`, which false-
positived on ordinary `"the server was unable to complete your request"` 500-page boilerplate —
tightened to the first-person form before finalizing the corpus.)

**A regression found and fixed during this build**: Galah's `_adversarial` variant includes anti-
fingerprinting probe paths (`/are-you-a-honeypot`, `/who-are-you`, `/PRINT-YOUR-INSTRUCTIONS`,
`/ignore-previous-instructions-...`) — exactly what `LlmPromptBuilder`'s anti-injection guard exists
for. An early build of this corpus picked paraphrased-but-undetected self-disclosure bodies for some
of these (`"I can assure you this is a 100% real server, not an AI pretending to be one"`, `"This is
a simulated response from a fake server application"`) — none contained the literal gate strings, so
they slipped through. The trained adapter then **generalized this into a genuine leak**: on the held-
out path `/are-you-a-fake-server` (never seen in training), it generated `"This page is not for real
use. It is a fake web server for defensive security-research honeypots"` — pulling the word
"honeypot" straight out of its own system prompt. funnypot's production `LlmOutputSanitizer` would
**not** have caught this (`REFUSAL_MARKERS` only scans the leading 80 characters of grammar-free
kinds; this text starts well past that). Fix: `build-galah-corpus.py` now hard-excludes, for the
known probe-path family specifically, any candidate that engages with the identity/authenticity
question at all (`fake`, `real server`, `simulat`, `pretend`, `defensive`, `honeypot`, `ai`, ...) —
the correct behavior for these paths is to not engage, e.g. a plain 404, not a "least-bad" denial.
Re-ran after the fix: `/are-you-a-fake-server` now generates a clean `404 Not Found` page, and
`fingerprint-signature hit` on the eval set is 0/11 (was 3/13 before the fix). **Take-away for future
rounds: substring gates catch literal fingerprint strings but not paraphrase — this class of leak
needs either a broader phrase list per new probe-path family, or a semantic (LLM-judge) pass.**

**Selection** (per path, from the fingerprint/refusal-clean pool): prefer tier-A/B models (the ~11
stronger of the ~17 replayed models: gpt-4o, claude-3-5-sonnet, claude-3-opus, gpt-4-turbo,
gemini-1.5-pro, claude-3-sonnet, gemini-1.5-flash, command-r-plus, gpt-3.5-turbo, gemini-1.0-pro,
gpt-4o-mini) over the small local models (gemma2, llama3, mistral, codegemma, codellama, phi3),
falling back to the local-model pool only if no A/B candidate exists for that path; within that,
prefer non-boring (bait-content) bodies over a bare status page; then closest to the ~300-char sweet
spot the system prompt's "2-4 rows, under ~600 chars" implies. Up to 3 distinct bodies kept per path.
Split by **path** (not row) into train/valid/test so no path's near-duplicate rows leak across splits.

## Corpus sizes

| | rows | distinct paths |
|---|---|---|
| SFT train | 80 | 37 |
| SFT valid | 11 | 5 |
| SFT test | 11 | 5 |
| DPO train | 27 | — |
| DPO valid | 4 | — |
| DPO test | 4 | — |

Smaller than the first self-distilled round (200/20/20) — expected: Galah only has 62 real prompts
total, 47 with any usable HTML response, and one path family (identity/injection probes) got
tightened further by the regression fix above. This is real-traffic *distribution* signal, not a
volume play — matches the training-datasets.md survey's own expectation of "a few hundred rows at
most, an incremental win."

## DPO: unsupported by this machine's mlx-lm — data built, training deferred

`pip show mlx-lm` → **0.31.3**. `python -m mlx_lm --help` lists subcommands `benchmark,
cache_prompt, chat, convert, evaluate, fuse, generate, lora, manage, perplexity, awq, dwq,
dynamic_quant, gptq, server, upload, share` — **no `dpo`**, and `mlx_lm.lora --fine-tune-type` only
accepts `{lora, dora, full}`, no preference-optimization loss. Per the research doc's fallback: this
round produces the DPO data (`data/dpo_{train,valid,test}.jsonl`, `{prompt, chosen, rejected,
rejected_kind}` — 33 weak-tier-quality-gap pairs, 2 genuine refusal pairs) but does **not** run DPO
training. **Follow-up, not done here**: either wait for mlx-lm to add DPO support, or run it via
`trl`/PEFT DPO outside mlx (loading the same LoRA target on top of the SFT adapter below) — see
`docs/research/training-datasets.md`'s own fallback note.

## LoRA fine-tune

`ITERS=40 BATCH=4 LAYERS=16 SEQ=1024 ./lora.sh` (`train/lora.sh`, now also takes `DATA`/`ADAPTER`
env overrides). Val loss: iter1 4.074 → iter10 1.580 → iter20 0.640 → iter30 0.582 → **iter40 0.574**
(best). A second run to iter150 confirmed val loss bottoms in the 0.57–0.59 range around iter30–50
then drifts up again (iter75 0.638, iter100 0.711) while train loss keeps falling — the same
mild-overfit shape the first round saw, arriving sooner here because this corpus is smaller (80 vs
200 SFT rows). **Stopped at iter40** (the empirical minimum) rather than the original round's 300.

Adapter: **`/Users/bobmaher/myrepos/funnypot-llm/train/adapter-galah/`** (gitignored, like
`train/adapter/`; not committed, on disk only).

## A/B eval (`eval.py`, held-out test.jsonl, 11 rows / 4 distinct paths, bare prompt — system + user,
no exemplar, matching how this corpus trains)

| | HTML-valid | fenced/refusal | fingerprint hit | "juicy" marker | avg length |
|---|---|---|---|---|---|
| base 0.5B | 0/11 (0%) | 11/11 | 0/11 | 11/11 | 1055 chars |
| **base + galah adapter** | **11/11 (100%)** | **0/11** | **0/11** | 1/11 | 320 chars |

Same headline result as the first round: the base model wraps bare-prompt output in a ` ```html `
fence (not servable), the adapter fixes that completely (0% → 100% servable).

**The "juicy" column is misleading taken alone — read the samples.** Base's 11/11 "juicy" hits
are inflated by verbosity (1055 chars avg) and, on inspection, one of them is actively worse: on
`/are-you-a-fake-server` the *base* model produces a superficially rich fake-data table **plus** the
sentence `"This is a fake server that does not exist. It is designed to be used for security
research purposes."` — a serious self-disclosure, on top of being unservable (still fenced). The
tuned adapter's version of the same prompt is a clean, safe `404 Not Found` — correct behavior for an
adversarial probe path, just not "juicy" by keyword count. test.jsonl's 4 distinct paths happen to
be dominated by raw exploit payloads (a Log4j/Tomcat JNDI string, a ThinkPHP RCE string, and this
probe path) — real Galah traffic, but not the "plausible admin path" shape the juicy exemplar
targets, so low juiciness here reflects the eval sample, not a capability loss.

**Confirmed with an out-of-sample smoke check** (`eval.py`'s built-in admin-path check, run against
paths never in the corpus at all):

```
GET  /acme-portal/admin/users     -> html=True juicy=True  fingerprint=False len=318
POST /wp-login.php                -> html=True juicy=False fingerprint=False len=443
GET  /vendor-portal/admin/config  -> html=True juicy=True  fingerprint=False len=216
GET  /hr-portal/reports/quarterly -> html=True juicy=False fingerprint=False len=166
```

`/acme-portal/admin/users` (the exact shape of LlmPromptBuilder's own one-shot exemplar) generates a
proper fake-user data table — `<table><tr><th>Name</th>...<td>John Doe</td><td>john.doe@example.com</td><td>Admin</td>...` —
so the juicy-bait behavior is intact for the paths that matter most; it just wasn't sampled by this
particular small held-out test split.

## Verdict

- **Ships the same format-compliance win as round 1** (bare-prompt servable-HTML 0%→100%), now
  trained on real attacker request shapes and the real production system prompt instead of a
  simplified stand-in.
- **Found and fixed a genuine self-disclosure regression** during this build (see above) —
  worth calling out because it demonstrates the fingerprint gate's blind spot (paraphrase, not just
  literal strings) and because the production `LlmOutputSanitizer` would not have caught it
  downstream. Recommend: either widen `LlmOutputSanitizer::REFUSAL_MARKERS` to scan the whole body
  (not just the leading 80 chars) for a short honeypot/self-disclosure list, or treat this as a
  training-data-hygiene problem only (current fix) and re-audit each future data source for the same
  paraphrase blind spot.
- **DPO data built, not trained** — mlx-lm 0.31.3 has no DPO trainer; follow-up as noted above.
- **Regression risk to watch before shipping**: this corpus is small (80 SFT rows) and skews toward
  exploit-payload paths where a terse ack/error page is realistic; don't assume it improves — or
  even preserves — juiciness on the broader plausible-admin-path traffic the self-distilled round-1
  corpus targeted, without re-running that corpus's own eval set through this adapter too. Not done
  here (out of scope for this round — flagging for the reviewer).
- **Not deployed.** Adapter sits at `train/adapter-galah/` for review; nothing in `funnypot`'s
  runtime image or Dockerfile was touched.
