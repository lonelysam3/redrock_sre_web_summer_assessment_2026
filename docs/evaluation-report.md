# code-audit-platform × RealVuln Benchmark v2.0.0 — Evaluation Report (current)

**Date**: 2026-08-16 (updated to the current engine state after commit f7832ac "view-to-template variable linking")
**Target**: workspace/code-audit-platform static engine (Python scanning; AI pipeline disabled)
**Scoring tool**: kolega-ai/Real-Vuln-Benchmark v2.0.0 official scoring engine (primary metric F2, recall-weighted)
**Method**: all 66 benchmark repos downloaded at pinned commit SHAs; headless scans via `AnalysisPipeline().run(repo, "python")`; findings adapted to Semgrep JSON format; scored with the official `score.py` / `dashboard.py` (PYTHONUTF8=1).
**Matching**: file + CWE (acceptable_cwes) + line tolerance (GT range ±10 lines).

---

## 1. Progression (same benchmark, same scoring)

| Milestone | TP | FP | Precision | Recall | F2 Score | Notes |
|---|---:|---:|---:|---:|---:|---|
| Before fixes (2026-08-13) | 2 | 31 | 0.061 | 0.1% | 0.1 | initial engine |
| First round of fixes (2026-08-13) | 109 | **22** | **0.832** | 5.7% | 7.0 | sink/source system + local type inference + venv exclusion |
| v3 interprocedural engine (94888b0) | 238 | 82 | 0.744 | 12.5% | 15.0 | project-wide taint graph, return propagation, call-site linking |
| Deeper detection (aff7251) | **257** | 142 | 0.644 | **13.5%** | **16.0** | template XSS + ZIP Slip + new sinks |
| **Current (f7832ac, kept)** | 253 | 136 | 0.650 | 13.3% | 15.8 | view→template linking trims template XSS false positives |

The current version trades 4 TP for 6 FP fewer than aff7251 (F2 16.0→15.8 essentially unchanged, precision up) — the optimal precision/recall balance point (see §5 for the XSS experiment matrix).

## 2. Comparison with Baselines (current)

| Metric | code-audit-platform | Semgrep | SonarQube | Snyk* |
|---|---:|---:|---:|---:|
| TP | 253 | 134 | 274 | 121 |
| FP | **136** | 905 | 1587 | 280 |
| Precision | **0.650** | 0.129 | 0.147 | 0.302 |
| Recall | **13.3%** | 7.0% | 14.4% | 17.7% |
| F2 Score | **15.8** | 7.7 | 14.5 | 19.3 |
| FPR | **33%** | 77% | 85% | 71% |

\* Snyk's official data covers only 25/66 repos.

**Conclusion: F2 is 2× Semgrep and beats SonarQube (15.8 vs 14.5); precision is 5× Semgrep and 4.4× SonarQube.** TP exceeds Semgrep (253 vs 134) and Snyk (253 vs 121). Of the 136 FPs, 7 hit official traps (5 path traversal, 2 IDOR) and the other 129 are new findings without GT labels (several are real bugs, e.g. an arbitrary file write in pygoat line 995). Zero traps hit in any core injection family (SQLi/XSS/SSRF/XXE/command injection/code injection).

## 3. Per-Family Recall (current, with baselines)

| CWE family | GT | Platform TP | Platform recall | Semgrep | SonarQube | Platform wins |
|---|---:|---:|---:|---:|---:|---|
| Code injection | 34 | 29 | **85%** | 26% | 71% | ✅ beats both |
| Command injection | 50 | 39 | **78%** | 11% | 68% | ✅ beats both |
| Open redirect | 40 | 19 | 47% | 5% | **57%** | beats Semgrep |
| SSRF | 41 | 19 | 46% | 5% | 41% | ✅ beats both |
| XXE | 38 | 17 | **45%** | 0% | 3% | ✅ beats both |
| XSS | 110 | 29 | **26%** | 14% | 18% | ✅ beats both |
| Deserialization | 40 | 10 | 25% | **38%** | **57%** | — |
| SQL injection | 78 | 18 | 23% | **59%** | 1% | beats SonarQube |
| Path traversal | 44 | 10 | 23% | 5% | 14% | ✅ beats both |
| Hardcoded credentials | 68 | 9 | 13% | 1.5% | 22% | beats Semgrep |
| Other (weak patterns/sessions…) | 877 | 54 | 6% | — | — | — |
| Sensitive data exposure | 155 | 0 | 0% | — | — | not implemented |
| Security misconfiguration | 112 | 0 | 0% | — | — | not implemented |
| Missing auth/authz | 83 | 0 | 0% | — | — | not implemented |
| IDOR / broken access control | 83 | 0 | 0% | — | — | not implemented |
| Denial of service | 44 | 0 | 0% | — | — | not implemented |

(Semgrep/SonarQube baselines are from the 2026-08-13 official dashboard on the same benchmark; GT unchanged, still valid.)

The platform beats Semgrep in **8 of 10 core injection families** and leads SonarQube in 7 families (code injection, command injection, SSRF, XXE, XSS, SQL injection, path traversal). Remaining gaps: SQL injection (the 59% gap is parameterized-query variants and ORM semantics), deserialization (needs gadget-chain modeling). Semantic categories (sensitive data/auth/IDOR/DoS) are outside the static-taint framework's design scope.

## 4. By Authorship / By Severity (current)

**By authorship**

| Corpus | Repos | TP | FP | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| Human-authored | 26 | 111 | 73 | 0.603 | 15.8% |
| LLM-generated | 40 | 142 | 63 | 0.693 | 11.8% |

**By severity (GT labels)**

| Severity | TP | FN | Recall |
|---|---:|---:|---:|
| critical | 104 | 51 | **67.1%** |
| high | 88 | 664 | 11.7% |
| medium | 61 | 849 | 6.7% |
| low | 0 | 86 | 0% |

Recall improves with severity (critical 67%), matching the "high-severity first" product positioning.

## 5. XSS Precision Tuning Experiment (2026-08-15, decision record)

The template XSS analyzer (aff7251) lifted XSS recall from 5% to 30% but introduced many template false positives. Three modes were measured with view→template variable linking:

| Mode | TP | FP | Precision | F2 | XSS TP |
|---|---:|---:|---:|---:|---:|
| Unlinked (aff7251) | 257 | 142 | 0.644 | **16.0** | 33 |
| **Lenient-linked (f7832ac, kept)** | 253 | 136 | 0.650 | 15.8 | 29 |
| Strict (local experiment) | 236 | 82 | **0.742** | 14.9 | 12 |

Strict mode reaches 0.742 precision but kills template XSS in vulnerable repos almost entirely (Django CBV / context-variable passing can't be linked), TP −21. Lenient linking is the balance point (FP −6, F2 essentially unchanged), so f7832ac was kept. Distinguishing "real risk vs safe usage" in template XSS is fundamentally a data-flow problem; the remaining FPs would need context-processor / template-include analysis with diminishing returns.

## 6. Fix List (relative to the 7.0-era report)

**Engine core (backend/engine/):**

1. **v3 project-wide interprocedural taint analysis (94888b0)** — single project-level taint graph (cross-file/cross-function); scope namespacing (module,function) prefixes; return-value propagation (#ret nodes → call sites); call-site linking (arg→param, self.m()/Class.m()/module.f()/from x import f); module attribute links (`import db; c = db.c`); per-source BFS in analyze() with an independent spread visited-set; Flask-RESTX api.payload/parse_args sources.
2. **Deeper detection (aff7251)** — template XSS analyzer (Stage 3c: `|safe` excluding literals, autoescape off, `<script>` interpolations); ZIP Slip detector (CWE-22 variant); new sinks: os.exec*/spawn*/pty.spawn/posix_spawn, xmltodict.parse, flask.Response/django JsonResponse, os.rename/remove/unlink/makedirs, shutil.move/copy/copyfile/copytree.
3. **View→template variable linking (f7832ac)** — render_template/render kwargs + Django ctx dicts feed the set of view variables; only those variables trigger `|safe` warnings in templates; sanitizers cut the chain; unlinked templates fall back to lenient mode.
4. **Parameter taint + attribute propagation (1bfa6b1)** — function parameters are untrusted sources (except self/cls); attribute reads propagate (obj.attr ← obj); dangerous-combo window relaxed (PHP same-class block OR ±8 lines; Python same-function OR ±8 lines).

**Regression**: test_audit_logic.py — 14/14 pass (incl. T11 cross-file return, T12 scope-isolation SSTI).

## 7. Remaining Gaps

- **SQL injection (23%)**: parameterized-query variants, ORM chained-call forms (string concatenation beyond `.filter(name=...)`), cross-file ORM config
- **Deserialization (25%)**: gadget-chain modeling, all forms of `yaml.load`
- **Semantic categories (0%)**: sensitive data exposure (155 GT), security misconfiguration (112), auth/authz (83), IDOR/access control (83), DoS (44) — outside the static-taint framework's scope
- **"Other" family (6.2%)**: a grab bag of 877 GT entries (weak patterns, session management) — lowest ROI
- Dependency-directory exclusion eliminated nearly all venv FPs; remaining FPs are mostly unlabeled new findings

## 8. Reproduction

```powershell
# Tooling: realvuln-eval\Real-Vuln-Benchmark-main\ (66 repos pre-placed in repos\)
# Scan:    cd realvuln-eval; $env:PYTHONUTF8=1; python run_cap_scanner.py
#          (results -> Real-Vuln-Benchmark-main\scan-results\<repo>\code-audit-platform\results.json)
# Score:   $env:PYTHONUTF8=1; python dashboard.py --json reports\dashboard-cap-linked.json --scanners code-audit-platform
# Verify:  TP/FP/F2 in this report come from dashboard-cap-linked.json's aggregates.code-audit-platform.micro
```

**One-line summary: the static engine evolved from "F2=0.1, near-zero recall" to "F2=15.8, recall 13.3%, precision 0.650" — F2 is 2× Semgrep and beats SonarQube, with more TPs than Semgrep and Snyk; code injection (85%), command injection (78%), XXE (45%) and XSS (26%) lead 8 families over Semgrep.**
