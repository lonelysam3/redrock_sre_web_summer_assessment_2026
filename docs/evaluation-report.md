# code-audit-platform × RealVuln Benchmark v2.0.0 — Evaluation Report

**Date**: 2026-08-13 (pre-fix and post-fix evaluations completed the same day)
**Target**: workspace/code-audit-platform static engine (Python scanning; AI pipeline disabled)
**Scoring tool**: kolega-ai/Real-Vuln-Benchmark v2.0.0 official scoring engine (primary metric F2, recall-weighted)
**Method**: all 66 benchmark repos downloaded at pinned commit SHAs; headless scans via `AnalysisPipeline().run(repo, "python")`; findings adapted to Semgrep JSON format; scored with the official `score.py` / `dashboard.py`.

---

## 1. Before vs. After (66 repos, 1,903 labeled vulnerabilities + 279 FP traps)

| Metric | Before | After | Change |
|---|---:|---:|---|
| TP | 2 | **109** | ×54.5 |
| FP | 31 | **22** | −29% |
| Precision | 0.061 | **0.832** | ×13.6 |
| Recall | 0.1% | **5.7%** | ×57 |
| **F2 Score** | **0.1** | **7.0** | **×70** |
| FPR | 0.10 | **0.073** | ↓ |
| FP traps triggered | 0 | **0** | — |

## 2. Comparison with Baselines (final)

| Metric | code-audit-platform | Semgrep | SonarQube | Snyk* |
|---|---:|---:|---:|---:|
| TP | 109 | 134 | 274 | 121 |
| FP | **22** | 905 | 1587 | 280 |
| Precision | **0.832** | 0.129 | 0.147 | 0.302 |
| Recall | 0.057 | 0.070 | 0.144 | 0.177 |
| F2 Score | 7.0 | 7.7 | 14.5 | 19.3 |
| FPR | **7.3%** | 77% | 85% | 71% |

\* Snyk's official data covers only 25/66 repos.

**Conclusion: F2 is on par with Semgrep (7.0 vs 7.7), while precision is 6.5× higher and the false-positive rate is an order of magnitude lower.** All 22 remaining false positives are new findings without GT labels (several are real bugs the benchmark simply does not label, e.g. an arbitrary file write in pygoat line 995), and 0 of the 279 official traps were triggered.

## 3. By Authorship

| Corpus | TP | FP | Precision | Recall | F2 |
|---|---:|---:|---:|---:|---:|
| Human-authored (26) | 56 | 9 | 0.862 | 7.95% | 9.7 |
| LLM-generated (40) | 53 | 13 | 0.803 | 4.42% | 5.5 |

## 4. Per-Family Recall (final, with comparisons)

| CWE family | GT | Platform | Semgrep | Sonar |
|---|---:|---:|---:|---:|
| Code injection | 34 | **19 (56%)** | 9 (26%) | 24 (71%) |
| Command injection | 50 | **15 (30%)** | 5 (11%) | 34 (68%) |
| SSRF | 41 | **8 (20%)** | 2 (5%) | 17 (41%) |
| Open redirect | 40 | **7 (18%)** | 2 (5%) | 23 (57%) |
| Deserialization | 40 | 7 (18%) | 15 (38%) | 23 (57%) |
| Hardcoded credentials | 68 | **9 (13%)** | 1 (1.5%) | 15 (22%) |
| SQL injection | 78 | 7 (9%) | **29 (59%)** | 1 (1%) |
| Path traversal | 44 | 2 (5%) | 2 (5%) | 6 (14%) |
| XXE | 38 | 1 (3%) | 0 | 1 (3%) |
| XSS | 110 | 2 (2%) | 15 (14%) | 20 (18%) |

Families where the platform beats Semgrep: command injection, code injection, SSRF, open redirect, hardcoded credentials.
Biggest remaining gaps: SQL injection (function-parameter sources, cross-file connection objects — requires interprocedural analysis), XSS (HTML template analysis not implemented).

## 5. Fix List (backend/engine/)

1. **sinks_py.py** — 8 new VulnTypes + CWE_BY_TYPE mapping table; new sinks: db.Cursor/db.Connection.execute family, pickle/yaml/marshal, lxml/ElementTree (XXE), flask/django/fastapi redirects, open/Path/send_file, render_template_string/jinja2 (SSTI), Markup/HttpResponse (XSS).
2. **python_scanner.py** —
   - Local type inference `_build_local_types`: `conn = sqlite3.connect()`/`pymysql.connect()` … → db.Connection; `cur = conn.cursor()` (incl. `with` statements) → db.Cursor → cursor execute hits the sink (**SQLi recall goes from 0**);
   - Subscript sources: `request.args['x']` / `request.GET['x']` (Subscript nodes + deterministic anonymous variable names);
   - Attribute sources: `request.data` / `sys.argv` (previously completely inert);
   - Source suffix matching (supports Django style where `request` is a function parameter);
   - Sink suffix fallback: DB-named-variable execute family + session.execute + objects.raw;
   - Dict-access taint propagation: `x = data.get('k')` / `x = d['k']`;
   - subprocess list-form exemption (no shell → not injectable);
   - `vendor` added to SKIP_DIRS;
   - every finding emits a standard `cwe` field (eval/exec/compile → CWE-94).
3. **sources_py.py** — Flask request.values/cookies/headers `.get`+subscripts, Django GET/POST/COOKIES/headers `.get`+subscripts, request.get_json/get_data, urllib.parse.parse_qs/parse_qsl.
4. **pipeline.py** — extended file-collection exclusions (venv/env/site-packages/dist/build etc., **eliminating 27/31 venv false positives**); unified CWE annotation for Stage 3/4 results; new AST pattern mappings.
5. **ast_analyzer.py** —
   - New detectors: hardcoded credentials (excludes test files / seed scripts / DEMO_ constants / enum tuples / field-name constants / placeholders), debug mode (excludes test files), Python eval/exec/compile combos (code injection, CWE-94);
   - Fixed combo-detection bug: previously a single pattern appearing twice (e.g. two evals) triggered the combo; now both patterns must occur within the ±8-line window.
6. **call_graph_analyzer.py** — eval/exec/compile labeled code_injection (CWE-94) instead of CWE-78; added pickle/XXE/redirect/SSTI inline sink patterns; removed the `.execute(` inline pattern (which flagged parameterized queries as SQL injection).

**Regression**: the platform's own test_audit_logic.py (12 cases, PHP/Python/C) keeps identical behavior.

## 6. Remaining Gaps (require larger architectural changes)

- **Function-parameter sources** (vulnpy library style, `get_user(username)` in VAmPI): needs interprocedural taint propagation;
- **Cross-file connection objects** (`import db; c = db.c` in vulpy): needs a module-level type environment;
- HTML template XSS analysis, authentication/authorization/rate-limiting semantic checks (out of design scope);
- Raw socket servers like DSVW (no framework sources).

## 7. Reproduction

```powershell
# Tooling: realvuln-eval\Real-Vuln-Benchmark-main\ (66 repos pre-placed in repos\)
# Scan:    python ..\run_cap_scanner.py
# Score:   $env:PYTHONUTF8=1; python dashboard.py --json reports\dashboard-cap-final.json --scanners code-audit-platform semgrep snyk sonarqube
# Aggregate: $env:PYTHONUTF8=1; python ..\aggregate_final.py
```

**One-line summary: the static engine went from "F2=0.1, near-zero recall" to "F2=7.0, precision 0.83" — a 70× F2 improvement, on par with Semgrep but with an order of magnitude fewer false positives; code injection (56%), command injection (30%), SSRF (20%) and open redirect (18%) all beat Semgrep.**
