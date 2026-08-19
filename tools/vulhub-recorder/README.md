# vulhub-recorder

Records **ground-truth** (real HTTP request → real HTTP response) pairs from dockerised
[Vulhub](https://github.com/vulhub/vulhub) targets, for funnypot's 0.5B honeypot model. This is
the only route to *real* responses in the training data, as opposed to the self-distilled
(`train/generate-corpus.php`) and Galah-replayed (`train/build-galah-corpus.py`) corpora, which
both inherit a model's own hallucinated headers/versions.

Design doc: `../../../funnypot/docs/research/dataset-indexes-and-vulhub.md` (target selection,
proxy tooling decision, output format spec, safety/isolation/licensing rules). Read that first —
this README covers how to actually run the tool it specifies.

## What it does

1. Starts one Vulhub target (`docker compose up -d`) on an isolated Docker network.
2. Fires a request corpus at it through [`mitmdump`](https://mitmproxy.org) as a recording proxy.
3. `record_addon.py` (a mitmdump addon) writes every captured exchange to two JSONL files:
   - **`ground-truth.jsonl`** — the rich eval-oracle record: full method/path/query/headers/body
     on both sides, with header order+casing preserved and volatile fields (`Date`, `ETag`,
     `Set-Cookie` session ids, long tokens) templated to placeholders.
   - **`messages.jsonl`** — the LoRA-ready slice, one line per capture that survives the
     fingerprint-safety gate, in mlx-lm's *native chat format* (`{"messages": [...]}`) — **not**
     ChatML text. Matches funnypot's real prompt contract
     (`funnypot/src/App/Llm/LlmPromptBuilder.php::forHtml()`) exactly: same system instruction
     (stack substituted from the captured `Server` header), same `Method: X\nPath: Y` user-turn
     shape. Baking `<|im_start|>`/`<|im_end|>` tokens into this file would double-format the
     prompt at train time and the model would learn to emit an immediate end-of-turn — empty
     output. Let `mlx_lm.lora`'s tokenizer apply the chat template; this file supplies content, not
     control tokens.
4. Tears the container down (`docker compose down -v`).

## Prerequisites

- **Docker** + Docker Compose v2 (`docker compose`, not the standalone `docker-compose`).
- **A local [`vulhub/vulhub`](https://github.com/vulhub/vulhub) checkout** (MIT). This tool does
  not clone it for you — it's a large, actively-updated monorepo; cloning it is a deliberate step,
  not a side effect of running a driver. Point `--vulhub-dir` / `$VULHUB_DIR` at it.
- **`mitmdump`** (`brew install mitmproxy`, or `pip install -r requirements.txt` into a venv).
  `record_addon.py` itself never imports `mitmproxy` — only the real `mitmdump` process does, at
  load time — so nothing else in this tool needs the package installed.
- **Python 3.9+**, stdlib only, for `driver.py` / `recorder_core.py` / `selftest.py`.
- Optional, for the wider request-corpus drivers (each is skipped with a log line, not a hard
  failure, if missing — see "Request corpus sources" below): `feroxbuster`, `nuclei`.

## Files

| File | Purpose |
| --- | --- |
| `targets.json` | The 16-target shortlist (+2 optional extras) — vulhub dir, image, host port, banner/CVE-trigger paths, license flag, per-target notes. Verified against `vulhub/vulhub@master` 2026-08-19; re-verify before a real run. |
| `fingerprint_filter.py` | The canonical scanner/matcher signature list + `contains_fingerprint_signature()`. Mirrors `train/build-galah-corpus.py`'s list — keep both in sync if either grows. |
| `recorder_core.py` | Pure transform logic (no mitmproxy import): builds both output records from plain request/response fields, applies volatile-field templating and the fingerprint gate. Independently unit-testable. |
| `record_addon.py` | The mitmdump addon (`mitmdump -s record_addon.py`). Duck-types the mitmproxy `Flow` object — extracts fields, hands them to `recorder_core`, appends JSONL. |
| `driver.py` | Orchestrates one target: compose up → health check → replay → compose down. `--dry-run` prints the exact plan without touching docker/network. |
| `selftest.py` | Feeds canned fake flows through the addon logic and asserts both output shapes. No docker, no mitmproxy, no network. |

## Run the self-test (no docker, ~instant)

```bash
python3 selftest.py
```

Asserts: ground-truth fields carry through correctly; `Date`/`Set-Cookie`/long-token volatile
fields get templated; header order is preserved; `messages.jsonl` is native chat format with no
baked ChatML tokens and the exact `Method: X\nPath: Y` user-turn shape; a response that echoes a
scanner signature (e.g. `nuclei`, `jndi:ldap`) is still recorded in `ground-truth.jsonl` (flagged
`fingerprint_poisoned: true`) but hard-dropped from `messages.jsonl`; an `internal_only` target's
license flag survives onto the ground-truth row; an empty body never produces a `messages.jsonl`
row. Exits non-zero (with a per-check `[ok]`/`[FAIL]` list) if anything regresses.

## Preview a run without touching docker

```bash
python3 driver.py --list
python3 driver.py --target tomcat-cve-2020-1938 --dry-run
python3 driver.py --target weblogic-cve-2020-14882 --dry-run --fire-cve-trigger
```

Prints the compose directory, license flag, proxy URL, every request the plan would fire (banner
path always; the documented CVE-trigger path only with `--fire-cve-trigger`), and which external
corpus drivers apply and whether their tool is installed — all without starting a container.

## Run one target for real

```bash
export VULHUB_DIR=/path/to/vulhub-checkout
python3 driver.py --target tomcat-cve-2020-1938 --out-dir ./out/tomcat-cve-2020-1938
```

This: `docker compose up -d` in `$VULHUB_DIR/tomcat/CVE-2020-1938`, polls `http://127.0.0.1:8080/`
directly until it answers (some targets — GitLab especially — take minutes), starts
`mitmdump -s record_addon.py -p 8080`, fires the manifest's banner request through it (plus the
CVE trigger with `--fire-cve-trigger`, plus any installed external drivers), stops the proxy, and
tears the container down. Output lands in `./out/tomcat-cve-2020-1938/{ground-truth,messages}.jsonl`.

Run several targets by repeating with a different `--target`/`--out-dir` — **one target up at a
time** (per the design doc's isolation section: most Vulhub compose files claim fixed host ports,
so two targets can't run concurrently anyway).

### Isolation

Put every target's Docker network on `internal: true` (no egress) before running this for real —
`targets.json`'s top-level `network_mode` field documents the expectation, but it's each target's
own `docker-compose.yml` (from your vulhub checkout) that has to actually declare it; this tool
does not patch that file for you. A genuinely-triggered RCE still can't beacon out if the network
has no route external.

## Request corpus sources

| driver id | what it needs | source |
| --- | --- | --- |
| `banner` | nothing — always runs | the manifest's own documented safe GET (from each target's vulhub `README.md`) |
| `cve_trigger_optional` | `--fire-cve-trigger` flag | the manifest's documented PoC path — real scanner-probe shape, still no destructive payload for most targets (see per-target `notes` for the handful that need more than one request, or a header/cookie instead of a path) |
| `seclists_raft_medium` | `feroxbuster` installed + `$SECLISTS_DIR` pointing at a [SecLists](https://github.com/danielmiessler/SecLists) checkout (MIT) | `Discovery/Web-Content/raft-medium-words.txt` — the unknown-path 404 corpus, the highest-value driver per the design doc (it's exactly funnypot's own use case) |
| `nuclei_cve_tag` | `nuclei` installed | its own bundled [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT), filtered to this target's CVE tag |
| `csic_2010_replay` | `$CSIC_2010_PATH` pointing at a request-list file | [CSIC 2010](https://github.com/msudol/Web-Application-Attack-Datasets) (research use) — turns the request-only academic set into pairs against a *different* real stack than it was collected on |

`driver.py`'s built-in replayer (`replay_line_corpus`) treats `csic_2010_replay` as a flat list of
one path per line — that's a simplification of CSIC's actual raw-HTTP-request-line format (method,
headers, body per record), good enough to prove the plumbing but not a full parser; see "Gaps"
below. funnypot's own production hit logs are the design doc's *highest-priority* corpus (item 5,
section 3.3) and aren't wired into any driver id yet — export them as one-path-per-line and point
`csic_2010_replay`'s `$CSIC_2010_PATH` at that file, or add a dedicated driver id, before a real run.

## Fingerprint safety

`fingerprint_filter.py` holds the canonical drop-list (`nuclei`, `cve-`, `matcher`, `interactsh`,
`{{baseurl}}`, `jndi:ldap`, `honeypot`, `galah`, …). A real vulnerable app can echo the attacker's
own probe back in an error page — the literal scanner payload — and training on that would teach
the model to output scanner tells, which defeats the whole point.

The gate runs in `recorder_core.build_messages_record()`: any response body containing a
signature is **hard-dropped from `messages.jsonl`**, never entering the training corpus. It is
**still written to `ground-truth.jsonl`**, flagged `"fingerprint_poisoned": true` — the oracle
file is meant to reflect reality faithfully (including the bad captures), so filtering happens
only at the training-data boundary, not at the record boundary.

## License / redistribution constraints

Vulhub's own compose/build files are MIT. What actually governs a captured response body is the
software running *inside* the container:

- **`oss`** targets (httpd, php, nginx, ThinkPHP, Struts2, Spring, Drupal, Tomcat, Solr,
  phpMyAdmin, the Log4Shell host app, Jenkins): default/error pages are low-creativity functional
  text. Internal training is low-risk. Still don't republish vendor-branded static assets (logos,
  CSS) verbatim if the corpus is ever shared externally.
- **`internal_only`** targets — **WebLogic, Confluence, GitLab** — bake a proprietary/repackaged
  binary (Oracle, Atlassian, GitLab EE) into vulhub's own published Docker Hub image. Captures
  from these are **internal-training-only. Never redistribute the corpus, and never publish an
  example body from these three targets, even in a blog post.**

`targets.json` carries this per-target as `"license_flag": "oss" | "internal_only"` (see
`license_flag_meanings` at the top of the file), and `record_addon.py` copies it onto every
`ground-truth.jsonl` row as `license_flag` — so a later corpus-assembly step can filter on it
mechanically instead of relying on someone remembering which three targets are which. `messages.
jsonl` rows do **not** carry the flag (they're already meant to be internal training input only);
if you ever build a redistributable subset, do it from `ground-truth.jsonl` and exclude
`license_flag == "internal_only"` rows there first.

## Feeding the output into `train/lora.sh`

`messages.jsonl` is already `mlx_lm.lora`'s native chat format — the same shape
`train/data/{train,valid,test}.jsonl` use (see `../../train/README.md`). To use it:

1. Run one or more targets, collecting `out/<target>/messages.jsonl` files.
2. Concatenate, then **dedup and review** before merging — this tool does not dedup across runs or
   across targets (the design doc calls for dedup by `(path-class, status, normalized-body-hash)`;
   not implemented here, see "Gaps"). At minimum, run the same fingerprint-signature and basic
   sanity checks `train/build-galah-corpus.py` already applies to its own corpus.
3. Split into `train.jsonl` / `valid.jsonl` / `test.jsonl` (e.g. 80/10/10), drop them into
   `train/data/` (or a new subdirectory alongside `train/data/self-distilled-v1/`, following that
   existing convention), and run `./train/lora.sh` with `DATA` pointed at the new directory.

`ground-truth.jsonl` isn't LoRA input — it's the eval oracle (`train/eval.py`-style response-diff
against the real captured response) and the future header-realism-lint source the design doc
describes (section on eval, item 6). Keep it around per-target even after building `messages.jsonl`.

## Gaps — what's stubbed vs. what actually runs

Built and verified on this box (no Vulhub, no docker, per this task's instructions):

- `selftest.py`: **passes**, 20/20 checks, against canned fake flows.
- `record_addon.py` under **real `mitmdump`** (verified live here): loads with no import/syntax
  errors, and a real proxied request/response through a plain local HTTP server produced correctly
  shaped `ground-truth.jsonl` and `messages.jsonl` rows — confirms the addon itself works end to
  end against `mitmdump`, independent of the `selftest.py` fakes.
- `driver.py --list` / `--dry-run`: **verified** against every target in the manifest — correct
  compose dir, ports, banner/trigger requests, external-driver gating.

Not run, and not runnable here by design (no docker, no Vulhub checkout, no heavy capture):

- A real `docker compose up` against any Vulhub target — `driver.py`'s compose/health-check/
  teardown code path is untested against a live container.
- The external corpus drivers (`feroxbuster`, `nuclei`) — wired up and tool-presence-gated, but
  never actually invoked.
- `csic_2010_replay` / funnypot-hit-log replay — the line-based replayer is a simplification (see
  "Request corpus sources" above), not a full CSIC request-line parser.
- Cross-run **dedup** — the design doc calls for it before training; not implemented, called out
  above as a required step before merging into `train/data/`.
- Content-type-aware system prompts — `recorder_core.py` always builds the **HTML** system prompt
  (`LlmPromptBuilder::forHtml()`), matching `train/build-galah-corpus.py`'s existing precedent.
  `LlmPromptBuilder` also has `forJson`/`forCss`/`forJs`/`forXml`/`forPlaintext` builders for
  non-HTML captures (e.g. Solr's JSON admin responses); this tool doesn't pick a builder by
  response `Content-Type`, so a captured JSON/XML response still gets labeled with the HTML system
  prompt in `messages.jsonl`. Fine for a first pass (most Vulhub banner/error pages are HTML), a
  real gap before training on Solr/JSON-heavy targets specifically.
- `jenkins-cve-2024-23897`'s CVE trigger (CLI-over-HTTP, needs JVM proxy flags), `gitlab-
  cve-2021-22205`'s (multi-request ExifTool PoC), and `tomcat-cve-2020-1938`'s Ghostcat (AJP
  protocol, not HTTP — out of scope for an HTTP proxy by construction) are documented in
  `targets.json`'s per-target `notes` but not wired into any automated trigger.
