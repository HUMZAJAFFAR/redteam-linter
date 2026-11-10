# RedTeam Linter

**Offensive-oriented static analysis for Python — dangerous-sink detection, secret harvesting, and a dark web console, with redaction enforced on the way out.**

RedTeam Linter parses Python source with `ast`, flags calls to dangerous sinks (`eval`, `exec`, `compile`, `os.system`, `subprocess.call`, `pickle.loads`, …) plus hard-coded credentials, and reports them through a severity-ranked terminal report, a JSON artifact, or an interactive browser console.

Every finding is redacted **before** it is printed or serialized: raw secrets and raw matched source lines never reach your terminal, your JSON file, or your browser devtools. The underlying finding keeps the original bytes in memory so taint analysis can still reason about them.

![RedTeam Linter console](docs/screenshot.png)

---

## Table of contents

- [Why it exists](#why-it-exists)
- [Features](#features)
- [Architecture](#architecture)
- [Install](#install)
- [Quick start](#quick-start)
  - [Web console](#web-console)
  - [Python API](#python-api)
- [Rule configuration (`sinks.yaml`)](#rule-configuration-sinksyaml)
- [Output & redaction model](#output--redaction-model)
- [HTTP API](#http-api)
- [Test target & expected results](#test-target--expected-results)
- [Project layout](#project-layout)
- [Design constraints](#design-constraints)
- [Limitations](#limitations)

---

## Why it exists

Most Python linters check style; most SAST tools are heavy, noisy, or SaaS. RedTeam Linter is a small, dependency-light tool you can read end to end in an afternoon, aimed at the offensive/audit workflow:

1. Drop in a target codebase (or a single file you found during an engagement).
2. Get the risky call sites ranked, with the exact line and the argument expression that flows into the sink.
3. Review the same results in a UI without a build step, then export a JSON report that is safe to attach to a writeup.

The project intentionally separates **harvesting**, **analysis**, **reporting**, and **presentation**, so any layer can be replaced without touching the others.

## Features

**Detection**

- AST-based sink matching — no regex guessing on source text, so comments, strings and docstrings cannot produce false positives.
- Import-alias resolution: `from os import system as sh` and `import subprocess as sp` are still resolved to `os.system` / `subprocess.call`.
- Context-aware `shell=True` handling: `subprocess.call(["ls", "-l"])` is clean, `subprocess.call(cmd, shell=True)` is `HIGH`.
- Severity per category (`CRITICAL` for dynamic execution/deserialization, `HIGH` for secret hits and shell exec, `MEDIUM` for weaker credential patterns).
- Secret patterns: AWS access key IDs, GitHub tokens, Slack tokens, PEM private keys, JWTs, bearer tokens, and generic `password`/`api_key`/`secret`-style assignments.
- Placeholder filtering, so `password = "changeme"`, `api_key = "<your-key>"` and `secret = "example"` do not become findings.
- Syntax-error input produces a single `INFO` parse finding instead of crashing the scan.
- Non-Python files are skipped and reported as skipped, not silently dropped.

**Reporting**

- Rich terminal report: severity-coloured table, per-severity summary panel, one row per finding.
- Deterministic JSON report (`summary` + `findings`) identical between CLI and web export.
- Strict output-side redaction (`AKIA…` → `AKIA***REDACTED***`).

**Web console** (vanilla HTML/CSS/JS, no build step)

- Paste-code and drag-and-drop-file tabs, up to 25 files / 2 MB total.
- Stat cards (total / critical / high / medium / low), severity filter chips with counts, free-text filter, sticky findings table.
- Detail drawer per finding: description, location, masked evidence, **`arguments_passed`** (the taint bridge), and the redacted raw finding JSON.
- Rule inspector driven by `GET /api/rules`, showing the active rule source (`sinks.yaml` vs. built-in fallback).
- Copy JSON, one-click redacted report download, skeleton loading state, toasts, live health pill.
- Keyboard: <kbd>Ctrl</kbd>/<kbd>⌘</kbd>+<kbd>Enter</kbd> scan, <kbd>/</kbd> filter, <kbd>Esc</kbd> close drawer.
- All rendering uses `textContent` — a malicious snippet cannot inject markup into the page.

## Architecture

```
samples/*.py ─┐
              ├─► webapp/engine.py ──► findings[] ──► reporter.ReportGenerator ──► terminal / JSON / browser
uploads ──────┘        (AST)                                (redaction boundary)
                            ▲
                     sinks.yaml (config_loader)
```

| Layer | File | Responsibility |
| --- | --- | --- |
| Rules | `sinks.yaml`, `config_loader.py` | Declarative sink table, validated and loaded with a built-in fallback. |
| Analysis | `webapp/engine.py` | Parses source, resolves imports, walks `ast.Call` nodes, matches sinks (incl. `shell=True`), harvests secrets, computes the taint heuristic. |
| Reporting | `reporter.py` | Single enforcement point for redaction, severity ordering, terminal and JSON rendering. |
| Presentation | `webapp/server.py`, `webapp/static/*` | FastAPI routes + the single-page console. |

## Install

Requires **Python 3.9+**.

```bash
git clone https://github.com/HUMZAJAFFAR/redteam-linter.git
cd redteam-linter

python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

`rich` and `PyYAML` are needed for the report/rules; `fastapi` + `uvicorn` are only needed for the web console.

## Quick start

### Web console

```bash
.venv/bin/python -m uvicorn webapp.server:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000
```

Then either paste code, drag in `.py` files, or click **Load sample** for the embedded demo target. A known-vulnerable fixture is also served for testing:

```bash
curl -s http://127.0.0.1:8000/samples/vulnerable_target.py -o target.py
```

Equivalent one-liner without uvicorn:

```bash
.venv/bin/python webapp/server.py
```

### Python API

```python
from webapp.engine import scan_files
from reporter import ReportGenerator
from config_loader import load_sink_config

rules = load_sink_config("sinks.yaml")
source = open("samples/vulnerable_target.py", encoding="utf-8").read()

findings, scanned, skipped = scan_files(
    [{"path": "samples/vulnerable_target.py", "content": source}], rules
)

generator = ReportGenerator(findings, files_scanned=len(scanned))
generator.print_report()                    # redacted terminal table
generator.export_to_json("redteam-report.json")   # redacted JSON artifact
```

A finding looks like this (after redaction):

```json
{
  "file_path": "samples/vulnerable_target.py",
  "line_number": 32,
  "severity": "CRITICAL",
  "category": "RCE",
  "sink": "eval",
  "matched_snippet": "retu***REDACTED***",
  "secret_value": "",
  "arguments_passed": ["expression"],
  "description": "Remote code execution sink: attacker-controlled input here means code execution.",
  "user_input_reachable": true
}
```

## Rule configuration (`sinks.yaml`)

Rules live in `sinks.yaml` and are loaded by `config_loader.load_sink_config()`. If the file is missing or invalid, the loader returns the built-in baseline table and the UI reports the source as `built-in fallback` — a broken config degrades, it never crashes a scan.

```yaml
sinks:
  - name: "subprocess.call"       # required: callable exactly as written in source
    category: "RCE"               # free-form taint family
    requires_shell_true: true     # only dangerous when shell=True is passed
    description: "Safe with a list and shell=False; flagged when shell=True."
```

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | str | yes | Fully-qualified callable (`os.system`) or bare name (`eval`). Aliases are resolved by the analyzer, not duplicated here. |
| `category` | str | no | Taint family shown in the report (`RCE`, `DESERIALIZATION`, `SECRET`, …). |
| `requires_shell_true` | bool | no | When `true`, the call is only flagged if `shell=True` is present. |
| `severity`, `cwe`, `remediation`, `description` | any | no | Carried through untouched for reporting/annotation. |

Add a rule by copying a block, then validate the file:

```bash
python -c "import yaml; yaml.safe_load(open('sinks.yaml'))"
```

## Output & redaction model

Redaction is **output-side only**, and it is enforced in exactly one place: `reporter.ReportGenerator`.

- Raw matched lines and secret values are scrubbed at any nesting depth before display or serialization.
- Only the first four characters of a sensitive value survive (`AKIA***REDACTED***`, `DB_P***REDACTED***`), which is enough to recognise a key and useless to an attacker.
- `arguments_passed` is **deliberately not redacted**: it is the bridge for taint tracing and carries structural data (`"'ping -c 1 ' + host"`), not credential material. It is truncated to 160 characters.
- The web server builds its payload through the same generator, so the browser can only ever receive redacted findings — nothing sensitive is available in devtools, a saved page, or the exported report.

## HTTP API

`webapp/server.py` exposes a small JSON API; `GET /` serves the console.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness probe: engine id, rule count, rule source. |
| `GET` | `/api/rules` | Active sink rules for the in-UI rule inspector. |
| `POST` | `/api/scan` | Scan submitted sources, return the redacted findings payload. |
| `POST` | `/api/report` | Scan and return the redacted JSON report as a download. |
| `GET` | `/samples/<file>.py` | Known-vulnerable fixtures used for testing. |

```bash
curl -s -X POST http://127.0.0.1:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d "{\"files\":[{\"path\":\"target.py\",\"content\":$(python -c 'import json;print(json.dumps(open("samples/vulnerable_target.py").read()))')}]}" \
  | python -m json.tool | head -40
```

Payload shape:

```json
{
  "files": [{ "path": "target.py", "content": "import os\nos.system(cmd)\n" }]
}
```

Response: `{"summary": {...severity_breakdown...}, "findings": [...], "meta": {...}}` where `meta` carries `engine`, `rules_loaded`, `rule_source`, `duration_ms`, `files_scanned`, `files_skipped`, `redacted`.

Limits and validation: 25 files, 2 MB total, `.py` extension enforced, duplicate names suffixed, empty files rejected with `422`, oversized payloads with `413`.

## Test target & expected results

[`samples/vulnerable_target.py`](samples/vulnerable_target.py) is a self-documented fixture. It contains 7 sink call sites and 4 credentials, plus safe counterparts that must produce nothing. Result: **11 findings — 4 CRITICAL, 4 HIGH, 3 MEDIUM**.

| Severity | Line | Sink | Category |
| --- | --- | --- | --- |
| CRITICAL | 32 | `eval` (tainted) | RCE |
| CRITICAL | 38 | `exec` (tainted) | RCE |
| CRITICAL | 44 | `compile` (tainted) | RCE |
| CRITICAL | 61 | `pickle.loads` | DESERIALIZATION |
| HIGH | 22 | `aws-access-key` | SECRET |
| HIGH | 23 | `github-token` | SECRET |
| HIGH | 50 | `os.system` | RCE |
| HIGH | 55 | `subprocess.call` (`shell=True`) | RCE |
| MEDIUM | 24 | `jwt` | SECRET |
| MEDIUM | 25 | `generic-credential` | SECRET |
| MEDIUM | 66 | `os.system` | RCE |

The safe counterparts at the bottom of the same file (list-form `subprocess.run` with `shell=False`, parameterised SQL) produce no findings — that is the false-positive check.

## Project layout

```
redteam-linter/
├── config_loader.py          # sinks.yaml loading + built-in fallback table
├── reporter.py               # redaction boundary, Rich terminal report, JSON export
├── sinks.yaml                # declarative sink rules (7 baseline entries)
├── requirements.txt
├── samples/
│   └── vulnerable_target.py  # documented test fixture (expect 11 findings)
├── webapp/
│   ├── engine.py             # AST sink matching, secret harvesting, taint heuristic
│   ├── server.py             # FastAPI routes + redacted payload boundary
│   └── static/
│       ├── index.html
│       ├── styles.css
│       └── app.js
└── docs/
    └── screenshot.png
```

## Design constraints

- **Never render raw secrets.** Not in the terminal, not in JSON, not in the browser. The only copy of a secret is the in-process finding.
- **Redaction is output-side.** Harvesting and analysis keep original bytes so future data-flow work is not crippled by masking.
- **`arguments_passed` stays structurally intact.** It is the taint-analysis bridge; keep it clean and JSON-serializable.
- **Config over code.** New sink patterns go in `sinks.yaml`, validated and falling back safely.
- **Python 3.9+, type hints, docstrings, modular.** Each layer importable and replaceable on its own.
- **The console has no build step.** Plain HTML/CSS/JS served by FastAPI, so it runs anywhere Python runs.

## Limitations

- **Heuristic taint, not proof.** `user_input_reachable` marks findings whose argument expression mentions request/argv/input-style identifiers. It is a triage signal, not a data-flow proof; cross-function flows are only visible through `arguments_passed`.
- **Single-file, single-pass AST analysis.** No interprocedural analysis, no whole-project call graph, no CTF-style reachability.
- **Secret detection is pattern-based.** Encoded, split, or generated secrets are missed; the generic-credential rule is intentionally conservative to keep noise low.
- **No authentication on the web console.** It is a local review tool: bind it to `127.0.0.1`. Files submitted to it are scanned in memory and never written to disk.
