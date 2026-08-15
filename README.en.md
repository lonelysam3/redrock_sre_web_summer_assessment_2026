# Code Audit Platform

[中文文档](README.md) | **English**

A source-code security audit platform: upload a project → static scan → AI deep analysis → **sandbox-based dynamic attack verification** → AI auto-fix, all visualized in a web UI.

Supports **Python / PHP / C / C++**, covering SQL injection, command execution, SSRF, insecure deserialization, XXE, SSTI, XSS (including template XSS), path traversal, ZIP Slip, open redirect, hardcoded credentials and more. Built on a version-aware rule engine, a project-wide interprocedural taint analysis engine, and an AI verification system that can **actually attack the target application inside a sandbox** using MCP tools.

## Features

- **Project upload**: upload source archives (zip/tar.gz), auto-extract and scan by language
- **Static scan engine**: project-wide interprocedural taint analysis (cross-file/cross-function data flow) + data-flow enrichment + AST pattern analysis + call-graph supplement + template XSS analysis + ZIP Slip detection
- **AI deep analysis**: every vulnerability gets root cause, attack methods and fix recommendations (the AI explores the source with MCP tools)
- **AI payload verification**: the AI builds attack vectors; for web-exploitable vulns the platform **launches the target app in a local sandbox** and the AI sends real HTTP attack requests, comparing responses to judge whether the vulnerability is real
- **AI auto-fix**: the AI generates fixes and applies them directly to the source (automatic `.bak` backup before editing), either auto-triggered per scan or manually per finding
- **Version-aware rule engine**: PHP/Python/C/C++ rules activate and re-weight by target version
- **Web UI**: projects → project detail → scan results, three-level pages; severity/verdict sorting and filtering, data-flow display, dark/light themes (HarmonyOS Sans font, glassmorphism/aurora effects)

## Workflow

### 1. Overall Flow

```
User uploads source archive (zip/tar.gz)
        │
        ▼
┌──────────────────┐     ┌───────────────────────────────────┐
│ Project created   │     │ New scan (optional checkboxes)     │
│ extracted/        │ ──► │ ☑ AI analysis  ☑ Payload verify    │
│ language/version  │     │ ☑ Auto fix                        │
└──────────────────┘     └──────────────┬────────────────────┘
                                        │ async background thread
                                        ▼
                        ┌───────────────────────────────┐
                        │ Static scan pipeline           │
                        │ see "Engine Pipeline" below    │
                        └──────────────┬────────────────┘
                                       │ findings stored (CWE/severity/data flow)
                                       ▼
                        ┌───────────────────────────────┐
                        │ AI deep analysis (per vuln)    │
                        │ MCP tool exploration → cause/  │
                        │ attack/fix                     │
                        └──────────────┬────────────────┘
                                       ▼
                        ┌───────────────────────────────┐
                        │ Payload verification (optional)│
                        │ sandbox real attack →          │
                        │ confirmed/potential/false_positive│
                        └──────────────┬────────────────┘
                                       ▼
                        ┌───────────────────────────────┐
                        │ AI fix (optional/manual)       │
                        │ apply_code_fix + .bak backup   │
                        └──────────────┬────────────────┘
                                       ▼
                             Scan results: browse/filter/sort
```

### 2. Engine Pipeline

```
Source files (Python AST / PHP·C·C++ tree-sitter parsing)
  │
  ▼
┌─────────────────────────────────────┐
│ Stage 1: Taint Tracking (ground truth)│
│ • Single project-wide taint graph,    │
│   cross-file / cross-function         │
│ • Scope namespacing (module,function) │
│ • Return propagation + call-site      │
│   linking (arg→param, callee #ret→    │
│   caller variable)                    │
│ • Module attribute links (import db;  │
│   db.c)                               │
│ • Local type inference (cursor/conn)  │
│ • Sanitizer recognition (int/escape)  │
│ • Per-source BFS + spread visited-set │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ Stage 2: Data-Flow Enrichment         │
│ • Protection level (none/partial/     │
│   strong/bypassable)                  │
│ • Exploit difficulty (easy~unlikely)  │
│ • Data transformation history         │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ Stage 3: AST Patterns (filter+add)    │
│ • Parameterized queries → downgrade   │
│   SQL false positives                │
│ • Allowlist detection → downgrade     │
│ • Supplements: deserialization chains/│
│   hardcoded credentials/debug mode/   │
│   dangerous combos                    │
│ 3b. ZIP Slip detection (CWE-22 var.)  │
│ 3c. Template XSS (|safe / autoescape  │
│     off / <script> + view→template    │
│     variable linking)                 │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ Stage 4: Call-Graph Supplement        │
│ (cross-file call chains)             │
└──────────────┬──────────────────────┘
               │
               ▼
   dedup → CWE annotation → persist
```

**Architecture principles**: Stage 1 is ground truth; Stages 2/3/4 never scan independently (preventing re-introduction of filtered false positives by looser heuristics); enrichment in Stage 2, filtering in Stage 3, supplementation in Stage 4.

### 3. AI Deep Analysis

Each vulnerability (or "analyze all") invokes the AI, which explores the source autonomously with MCP tools and returns a JSON verdict:

| MCP tool | Purpose |
|---|---|
| `search_dangerous_calls` | find dangerous function calls in a file |
| `search_user_inputs` | locate user-input entry points |
| `trace_variable_flow` | trace a variable's propagation path |
| `read_file_region` | read a line range of a file |
| `search_project` | cross-file regex search |
| `list_project_files` | list project files |

Output: root cause, attack methods, fix recommendations, and an initial verdict (confirmed / potential / false_positive).

### 4. Payload Verification (Sandbox Dynamic Attack)

Static analysis can only *guess* whether e.g. a SQL injection is exploitable. The platform ships a **sandbox executor** so the AI can attack for real:

1. **Platform pre-start**: for web-attackable vuln types (SQLi/XSS/SSRF/SSTI/path traversal/open redirect/…), the target project is copied to a temp directory and launched as a subprocess (127.0.0.1, random port; missing dependencies are auto-installed on demand and cached) before verification begins
2. **AI attacks**: the model sends a baseline request via the MCP tool `send_http_request`, then fires attack payloads and compares status codes/errors/content; `run_target_app` / `stop_target_app` control the app lifecycle
3. **Verdict & evidence**: outputs `verdict` (confirmed/potential/false_positive), `confidence`, `exploit_payload`, `payload_effect` and the full evidence chain (baseline vs attack response comparison)

**Live example** (SQL injection in the demo store app):

| Request | Response | Conclusion |
|---|---|---|
| `/?q=xyz` (baseline) | 200 "No products found" | — |
| `/?q='` | **500** SQL syntax error | injection point confirmed |
| `/?q=' OR '1'='1` | 200, all 21 products returned (incl. hidden ones) | filter bypassed |
| `/?q=' UNION SELECT sql FROM sqlite_master--` | full schema leaked | schema readable |
| `/?q=' UNION SELECT email\|\|':'\|password FROM user--` | user credentials leaked | **data exfiltrated** |

Final verdict `confirmed @ 1.0` with a complete evidence chain.

> Note: the platform targets **vulnerability detection in normal code**; the sandbox exists to prove exploitability (real attack requests, verified by response). Scanned code runs in a temp copy, listens only on a localhost random port, has timeout protection, and is cleaned up on exit.

### 5. AI Fix (separated from verification)

- Fixing is a separate flow: the verification stage **does not expose** `apply_code_fix` (even if the model asks for it, the executor refuses) — "clicking analyze" can never modify code
- Triggers: check "Auto fix" when scanning, or click "Fix" for a single finding on the results page
- Mechanism: `apply_code_fix(file_path, start_line, end_line, new_code)` replaces a line range, creating a `.bak` backup first

### 6. Results Browsing

- Severity sorting (critical → high → medium → low; fixed in both the backend `SEVERITY_RANK` and the frontend)
- AI verdict badges: ✅ confirmed / ⚠️ potential / ❌ false positive / unanalyzed
- Finding detail: data-flow path, sink code, CWE id, full AI analysis, before/after fix diff

## Supported Vulnerability Types

| Type | CWE | Python | PHP | C/C++ |
|---|---|---|---|---|
| Command execution / code injection | CWE-78/94 | ✅ | ✅ | ✅ |
| SQL injection | CWE-89 | ✅ | ✅ | ✅ |
| Insecure deserialization | CWE-502 | ✅ | ✅ | — |
| SSRF | CWE-918 | ✅ | ✅ | — |
| XXE | CWE-611 | ✅ | — | — |
| Path traversal / arbitrary file read | CWE-22 | ✅ | ✅ | ✅ |
| ZIP Slip | CWE-22 | ✅ | — | — |
| Open redirect | CWE-601 | ✅ | ✅ | — |
| SSTI (server-side template injection) | CWE-94 | ✅ | — | — |
| XSS (incl. template XSS) | CWE-79 | ✅ | ✅ | — |
| File upload | CWE-434 | — | ✅ | — |
| Hardcoded credentials | CWE-798 | ✅ | — | — |
| Debug mode enabled | CWE-215 | ✅ | — | — |

## Engine Capabilities

- **Project-wide interprocedural taint analysis**: cross-file/cross-function taint graph, return-value propagation, call-site arg→param linking, module attribute links, scope namespacing to isolate same-named variables
- **Local type inference**: `conn = sqlite3.connect()` → `cur = conn.cursor()` → `cur.execute()` cursor-type propagation hits the most common real-world SQLi patterns
- **Full source coverage**: `request.args.get('x')`, `request.args['x']`, `request.data`, `request.get_json()`, Django `request.GET['x']`, `sys.argv`, `os.environ`, `parse_qs`, Flask-RESTX `api.payload`, etc.
- **Sink suffix fallback**: `cursor.execute` / `conn.execute` / `db.session.execute` / `Model.objects.raw`; plus new sinks like os.exec*/spawn*, xmltodict, flask.Response, file operations
- **Dict/attribute taint propagation**: `x = data.get('k')`, `x = d['k']`, `obj.attr` propagate from tainted objects
- **Type-aware sanitizers**: `int()` sanitizes everything, `html.escape` only XSS, `shlex.quote` only command injection
- **Template XSS analysis**: scans `.html/.j2` for `|safe` (skipping literals), autoescape off, `<script>` interpolations; view→template variable linking reduces false positives
- **Dependency dir exclusion**: venv / site-packages / node_modules / dist skipped automatically
- **CWE annotation**: every finding carries a CWE id, directly comparable against external benchmarks

## Benchmark (RealVuln Benchmark v2.0.0)

Full evaluation of the static engine against the [RealVuln Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark) (66 real Python repos, 1,903 human-labeled vulnerabilities, 279 FP traps):

| Metric | This platform | Semgrep | SonarQube | Snyk* |
|---|---:|---:|---:|---:|
| TP | 253 | 134 | 274 | 121 |
| FP | **136** | 905 | 1587 | 280 |
| Precision | **0.650** | 0.129 | 0.147 | 0.302 |
| Recall | **13.3%** | 7.0% | 14.4% | 17.7% |
| F2 Score | **15.8** | 7.7 | 14.5 | 19.3 |

\* Snyk's official data covers only 25/66 repos.

- **F2 is 2× Semgrep and beats SonarQube**, with 5× Semgrep's precision and an order of magnitude lower false-positive rate
- Per-family recall: command injection **78%**, open redirect **47%**, SSRF **46%**, XXE **45%**, XSS 26% (template analyzer lifted it from 5%), SQL injection 23%, path traversal 23%
- Methodology, per-family data and reproduction steps: [docs/评测报告.md](docs/评测报告.md) (中文) / [docs/evaluation-report.md](docs/evaluation-report.md) (English)

## Getting Started

```bash
# Clone and install dependencies
git clone https://github.com/lonelysam3/redrock_sre_web_summer_assessment_2026.git
cd redrock_sre_web_summer_assessment_2026
pip install -r requirements.txt

# Run
cd backend
python app.py
# visit http://localhost:5000
```

### Docker

```bash
docker compose up -d
# visit http://localhost:5000
```

### AI Configuration

Configure the AI API in `backend/.env` (or via the "AI Settings" web page, which also tests connectivity):

```env
DEEPSEEK_API_KEY=***
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
```

The AI settings page ships presets for common providers: DeepSeek (`deepseek-v4-flash`), OpenAI (`gpt-4.1`), local Ollama (`qwen2.5`), plus any custom OpenAI-compatible endpoint.

## Tech Stack

| Layer | Technology |
|------|------|
| Web framework | Flask + Jinja2 |
| Database | SQLite + SQLAlchemy ORM |
| AST/CST parsing | Python AST + tree-sitter (PHP/C/C++) |
| Taint tracking | project-wide taint graph + BFS path search + sanitizer recognition + local type inference + dict/attribute/return propagation |
| Rule engine | version-aware rule scheduling (min/max_version + severity_overrides) |
| Template analysis | template XSS detection + view→template variable linking |
| AI integration | OpenAI-compatible API (DeepSeek/GPT/custom) + MCP tool protocol (JSON/XML call parsing, retries, hardened JSON repair) |
| Sandbox verification | subprocess sandbox (temp copy + random port + on-demand dependency install + HTTP attack verification) |
| Frontend | Vanilla JS + CSS variable theming + HarmonyOS Sans + glassmorphism/aurora effects |

## Directory Layout

```
backend/
├── app.py                    # Flask entry (routes, scan orchestration)
├── models.py                 # data models (vuln/project/scan + severity ranking)
├── engine/                   # static analysis engine (multi-stage pipeline)
│   ├── pipeline.py           # pipeline orchestration (dedup, CWE, dir exclusion)
│   ├── python_scanner.py     # Python scanner (AST + project-wide taint tracking)
│   ├── php_scanner.py        # PHP scanner (tree-sitter + session taint tracking)
│   ├── c_scanner.py          # C/C++ scanner
│   ├── taint_tracker.py      # taint graph (cross-file/cross-function BFS)
│   ├── sinks_py.py           # Python sink table + CWE mapping
│   ├── sources_py.py         # Python source table
│   ├── ast_analyzer.py       # AST patterns (parameterized queries/creds/debug/ZIP Slip)
│   ├── template_analyzer.py  # template XSS (|safe + view→template linking)
│   ├── sandbox.py            # sandbox executor (dynamic attack infrastructure)
│   ├── mcp_tools.py          # MCP tool set (source exploration/fix/sandbox attack)
│   ├── ai_verifier.py        # AI verification flow wrapper
│   └── payload_builder.py    # payload construction
├── ai/                       # AI client and prompts
├── ai_chat_core/             # OpenAI-compatible chat core (model routing)
├── api/                      # REST API (projects/scans/vulns/settings)
├── static/                   # frontend assets (CSS, HarmonyOS Sans font)
├── templates/                # Jinja2 pages
├── docs/                     # evaluation reports etc.
└── test_audit_logic.py       # audit logic regression tests (14 cases)
```
