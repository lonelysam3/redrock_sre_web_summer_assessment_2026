# Code Audit Platform

[中文文档](README.md) | **English**

A source code security audit engine supporting **Python / C / C++ / PHP**, covering SQL injection, command execution, SSRF, insecure deserialization, open redirect, XXE, SSTI, hardcoded credentials and more. Built-in version-aware rule engine and AI deep analysis.

## Features

- Upload source archives (zip / tar.gz), auto-extract and scan
- Four-stage layered pipeline: taint tracking → data-flow enrichment → AST filtering/supplement → call-graph supplement
- Python / C / C++ version and standard selection, PHP version-aware rules
- AI deep analysis: root cause, attack methods, fix recommendations
- AI payload verification: automatically build attack vectors and verify exploitability
- Modern minimal frontend: aurora gradient background, bubble/grid decorations, shrinking glass header on scroll, self-hosted HarmonyOS Sans SC font
- Dark / light theme, follows system preference

## Four-Stage Pipeline Architecture

```
Source files
  │
  ▼
┌─────────────────────────────────┐
│ Stage 1: Taint Tracking (truth) │  ← AST/CST parsing + BFS
│ • Source→Sink variable flows    │     propagation-path search
│ • Local type inference          │
│   (cursor/connection objects)   │
│ • Subscript/attribute sources   │
│   + dict-access propagation     │
│ • Sanitizer recognition         │
│ • Intra-file full data flow     │
└──────────────┬──────────────────┘
               │ vulns (baseline)
               ▼
┌─────────────────────────────────┐
│ Stage 2: Data Flow (enrich)     │  ← deep analysis of Stage 1 results
│ • Protection level (none/       │
│   partial/strong/bypassable)    │
│ • Exploit difficulty rating     │
│ • Data transformation history   │
└──────────────┬──────────────────┘
               │ vulns (enriched)
               ▼
┌─────────────────────────────────┐
│ Stage 3: AST Patterns (filter+  │  ← semantic pattern matching
│  supplement)                    │
│ • Parameterized query detection │
│   → downgrade SQL false positives
│ • Allowlist detection →         │
│   downgrade false positives     │
│ • Structural supplements        │
│   (deserialization chains,      │
│    hardcoded credentials,       │
│    debug mode, dangerous combos)│
└──────────────┬──────────────────┘
               │ vulns (filtered + supplemented)
               ▼
┌─────────────────────────────────┐
│ Stage 4: Call Graph (supplement)│  ← cross-file call chains
│ • Cross-function call tracing   │
│ • Recover inter-file findings   │
│   missed by intra-file analysis │
└──────────────┬──────────────────┘
               │
               ▼
          Final vuln list
```

### Architecture Principles

- **Stage 1 is ground truth** — all later stages build on Stage 1 results
- **Stages 2/3/4 never scan independently** — this prevents false positives already filtered by Stage 1 from being re-introduced by looser heuristics
- **Clear separation of duties** — enrichment in Stage 2, filtering in Stage 3, supplementation in Stage 4

### Supported Vulnerability Types

| Vulnerability | Severity | Python | PHP | C/C++ |
|--------------|----------|--------|-----|-------|
| Command execution / code injection | Critical | ✅ | ✅ | ✅ |
| SQL injection | High | ✅ | ✅ | ✅ |
| Insecure deserialization | High | ✅ | ✅ | — |
| SSRF | High | ✅ | ✅ | — |
| XXE | High | ✅ | — | — |
| Path traversal / arbitrary file read | Medium | ✅ | ✅ | ✅ |
| Open redirect | Medium | ✅ | ✅ | — |
| SSTI (server-side template injection) | Critical | ✅ | — | — |
| XSS | Low | ✅ | ✅ | — |
| File upload | High | — | ✅ | — |
| Hardcoded credentials | High | ✅ | — | — |
| Debug mode enabled | Low | ✅ | — | — |

### Detection Capabilities (Python)

- **Local type inference**: `conn = sqlite3.connect()` → `cur = conn.cursor()` → `cur.execute()` return-type propagation, catching the most common real-world SQL injection pattern
- **Full source coverage**: `request.args.get('x')`, `request.args['x']` (subscript), `request.data`, `request.get_json()`, Django `request.GET['x']`, `sys.argv`, `os.environ`, `parse_qs` and more
- **Sink suffix fallback**: `cursor.execute` / `conn.execute` / `db.session.execute` / `Model.objects.raw` database naming patterns
- **Dict-access taint propagation**: `x = data.get('k')` / `x = d['k']` propagate taint from the parent object
- **Type-specific sanitizers**: `int()` sanitizes all injection classes, `html.escape` only XSS, `shlex.quote` only command injection
- **Dependency directory exclusion**: venv / site-packages / node_modules / dist and other third-party or build artifacts are skipped automatically
- **CWE annotations**: every finding carries a standard CWE id (eval/exec → CWE-94, os.system → CWE-78, …), ready for external benchmarks

## Benchmark Evaluation (RealVuln Benchmark v2.0.0)

The static engine (Python part) was evaluated against the [RealVuln Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark) — 66 real-world Python repositories, 1,903 manually labeled vulnerabilities, 279 false-positive traps:

| Metric | This platform | Semgrep | SonarQube | Snyk* |
|---|---:|---:|---:|---:|
| TP | 109 | 134 | 274 | 121 |
| FP | **22** | 905 | 1587 | 280 |
| Precision | **0.832** | 0.129 | 0.147 | 0.302 |
| Recall | 0.057 | 0.070 | 0.144 | 0.177 |
| F2 Score | 7.0 | 7.7 | 14.5 | 19.3 |
| False-positive rate | **7.3%** | 77% | 85% | 71% |

\* Snyk's official results cover only 25/66 repos.

- **F2 on par with Semgrep, precision 6.5× higher, false-positive rate an order of magnitude lower**, and 0 of the 279 FP traps triggered.
- Per-family recall beating Semgrep: code injection 56%, command injection 30%, SSRF 20%, open redirect 18%, hardcoded credentials 13%.
- Human-authored code precision 0.86 (TP=56, FP=9); LLM-generated code precision 0.80 (TP=53, FP=13).
- Full evaluation report (methodology, fix list, per-family data, reproduction steps): [docs/evaluation-report.md](docs/evaluation-report.md).

## Version-Aware Rule Engine

The rule engine decouples audit rules from the scanners and activates/adjusts rules dynamically based on the target language version or standard.

### Rationale

The same code carries very different risk depending on the language version. For example:

- `preg_replace('/p/e')` — the `/e` modifier was deprecated in PHP 5.5 and removed in PHP 7.0 → only high severity below those versions
- `create_function()` — deprecated in PHP 7.2, removed in PHP 7.4 → the version decides whether to report
- `mysql_query()` — a standard API in PHP 5.x, a dangerous removed relic in PHP 7.0+

Based on the user-selected (or auto-detected) version, only the rules relevant to that version are activated, with severity adjusted dynamically.

### Supported Languages & Version Ranges

| Language | Version range | Key milestones |
|----------|---------------|----------------|
| PHP | 5.0 ~ 8.0 | 5.3 PDO charset / 5.5 preg_replace / 7.0 mysql_* / 8.0 assert |
| Python | 2.7 ~ 3.13 | 2.7 EOL / 3.6 f-strings / 3.8 walrus operator |
| C/C++ | C89 ~ C++23 | C99 gets / C11 gets_removed / C++17 filesystem |

### Rule Structure

Every rule is a standalone `AuditRule` dataclass:

- `min_version` / `max_version` — the version range where the rule is active
- `default_severity` — default severity
- `severity_overrides` — per-version severity adjustments (e.g. an API that is critical on old versions but info on newer ones)
- `confidence` — rule confidence (0~1)

### Automatic Version Detection

PHP projects support automatic version detection from source: scanning `composer.json`, characteristic function calls and syntax features to produce the best matching version. Users may also set it manually in the web UI.

## Usage

```bash
# Clone and install dependencies
git clone https://github.com/lonelysam3/redrock_sre_web_summer_assessment_2026.git
cd redrock_sre_web_summer_assessment_2026
pip install -r requirements.txt

# Run
cd backend
python app.py
# Open http://localhost:5000
```

### Docker

```bash
docker compose up -d
# Open http://localhost:5000
```

### Configuration

Configure the AI API in `backend/.env` (or on the web "AI Settings" page):

```env
DEEPSEEK_API_KEY=***
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
```

The AI Settings page ships presets for common providers: DeepSeek (`deepseek-v4-flash`), OpenAI (`gpt-4.1`), local Ollama (`qwen2.5`), plus any custom OpenAI-compatible endpoint.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Web framework | Flask + Jinja2 |
| Database | SQLite + SQLAlchemy ORM |
| AST/CST parsing | Python AST + tree-sitter (PHP/C/C++) |
| Taint tracking | Adjacency list + BFS path search + sanitizer recognition + local type inference (cursor/connection objects) + dict-access propagation |
| Rule engine | Version-aware rule scheduling (min/max_version + severity_overrides) |
| Data-flow analysis | Regex patterns + protection-level assessment + exploit-difficulty rating |
| AST pattern analysis | Semantic pattern matching (parameterized queries / allowlists / deserialization chains / hardcoded credentials / debug mode / dangerous combos) |
| AI integration | OpenAI-compatible API (DeepSeek / GPT / custom) |
| Frontend | Vanilla JS + CSS variable theme system + HarmonyOS Sans + glassmorphism / aurora motion design |

## Directory Structure

```
backend/
├── app.py                    # Flask entry point (routes, scan orchestration)
├── engine/                   # Static analysis engine (four-stage pipeline)
│   ├── pipeline.py           # Pipeline orchestration (dedup, CWE annotation, dir exclusion)
│   ├── python_scanner.py     # Python scanner (AST + taint tracking + local type inference)
│   ├── php_scanner.py        # PHP scanner (tree-sitter + session taint tracking)
│   ├── c_scanner.py          # C/C++ scanner
│   ├── taint_tracker.py      # Taint graph (BFS path search)
│   ├── sinks_py.py           # Python dangerous-function table + CWE mapping
│   ├── sources_py.py         # Python input-source table
│   └── ast_analyzer.py       # AST pattern analysis (parameterized queries, creds, debug mode…)
├── ai/                       # AI deep analysis (prompts, client)
├── ai_chat_core/             # OpenAI-compatible chat core (model routing)
├── api/                      # REST API (projects / scans / vulns)
├── static/                   # Frontend assets (CSS, HarmonyOS Sans font)
├── templates/                # Jinja2 pages
├── docs/                     # Evaluation report and other docs
└── test_audit_logic.py       # Audit-logic regression tests
```
