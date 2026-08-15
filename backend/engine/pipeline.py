"""
四级分析流水线编排器
===================
统一编排 Source-Sink 污点分析 → 数据流分析 → AST 模式分析 → 调用图分析的流水线。

==== 架构原则 ====

Stage 1 (污点追踪) 是地面真相（ground truth）—— 基于 AST/CST 的变量传播分析。
Stage 2 (数据流) 富化 Stage 1 结果，添加防护等级和利用难度。
Stage 3 (AST 模式) 用安全模式降级 Stage 1 误报 + 补充结构性问题。
Stage 4 (调用图) 补充 Stage 1 漏掉的跨函数跨文件漏洞。

Stage 2/3/4 不独立扫描——这杜绝了"Stage 1 已过滤的误报被 Stage 2 的粗正则
或 Stage 3 的模式匹配重新引入"的问题。

==== 流水线流程 ====

   源文件
     │
     ▼
   ┌─────────────────────────┐
   │ Stage 1: 污点追踪        │  ← TaintTracker + Scanner
   │ • Source→Sink 路径检测   │     (地面真相)
   │ • BFS 变量传播分析       │
   │ • 消毒函数过滤           │
   └──────────┬──────────────┘
              │ vulns (基准)
              ▼
   ┌─────────────────────────┐
   │ Stage 2: 数据流分析      │  ← DataFlowAnalyzer
   │ • 防护等级检测（富化）    │
   │ • 利用难度评定           │
   └──────────┬──────────────┘
              │ vulns (富化)
              ▼
   ┌─────────────────────────┐
   │ Stage 3: AST 模式分析    │  ← ASTAnalyzer
   │ • 参数化查询识别（降级）  │
   │ • 白名单检测（降级）     │
   │ • 补充结构性问题         │
   └──────────┬──────────────┘
              │ vulns (过滤 + 补充)
              ▼
   ┌─────────────────────────┐
   │ Stage 4: 调用图分析      │  ← CallGraphAnalyzer
   │ • 跨函数调用链           │
   │ • 跨文件补充漏报         │
   └──────────┬──────────────┘
              │
              ▼
         最终漏洞列表

==== 使用方式 ====

    pipeline = AnalysisPipeline()
    results = pipeline.run(project_path, language)
    # results 包含所有四级分析的信息
"""
from pathlib import Path
from dataclasses import dataclass, field
import re

from engine.python_scanner import PythonScanner
from engine.c_scanner import CScanner
from engine.php_scanner import PHPScanner
from engine.data_flow_analyzer import DataFlowAnalyzer, DataFlowFinding, ProtectionLevel
from engine.ast_analyzer import ASTAnalyzer, ASTFinding
from engine.call_graph_analyzer import CallGraphAnalyzer


@dataclass
class PipelineResult:
    """
    流水线执行结果
    ==============
    包含三级分析的所有输出。
    """
    # Stage 1: 污点追踪结果（原始漏洞列表）
    vulns_stage1: list[dict] = field(default_factory=list)
    stage1_count: int = 0

    # Stage 2: 数据流分析结果
    data_flow_findings: list[DataFlowFinding] = field(default_factory=list)
    stage2_exploitable: int = 0          # 可利用数量
    stage2_protected: int = 0            # 有防护数量

    # Stage 3: AST 分析结果
    ast_findings: list[ASTFinding] = field(default_factory=list)
    stage3_safe_patterns: int = 0        # 发现的安全模式数量
    stage3_dangerous_patterns: int = 0   # 发现的危险模式数量

    # Stage 4: 调用图分析结果
    call_graph_vulns: list[dict] = field(default_factory=list)
    stage4_count: int = 0

    # 最终输出：四级分析后的漏洞列表（去重+过滤+降级后）
    final_vulns: list[dict] = field(default_factory=list)
    final_count: int = 0

    # PHP 版本解析结果
    resolved_php_version: str = ""
    php_version_auto_detected: bool = False

    # 统计
    total_files: int = 0
    errors: list[str] = field(default_factory=list)


class AnalysisPipeline:
    """
    四级分析流水线
    ==============
    Stage 1 (污点追踪) 是核心地面真相。
    Stage 2 (数据流) 富化 Stage 1 结果，添加防护等级和利用难度。
    Stage 3 (AST 模式) 过滤 Stage 1 误报 + 补充结构性问题。
    Stage 4 (调用图) 补充跨函数跨文件的漏报。

    架构原则：Stage 2→3→4 不独立扫描，而是围绕 Stage 1 做
    富化 → 过滤 → 补充，杜绝 Stage 1 已过滤的误报被后续阶段重新引入。
    """

    def __init__(self):
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.ast_analyzer = ASTAnalyzer()
        self.call_graph_analyzer = CallGraphAnalyzer()

    def run(self, project_path: str, language: str, php_version: str | None = None) -> PipelineResult:
        """
        四级分层分析流水线。

        架构：Stage 1 是地面真相，Stage 2 富化，Stage 3 过滤+补充，Stage 4 补充。
        Stage 2/3 不再独立扫描——这杜绝了"Stage 1 已过滤的误报被正则/模式重新引入"的问题。

        Stage 1: 污点追踪 — AST 级变量传播分析（核心）
        Stage 2: 数据流   — 对 Stage 1 结果做防护等级和利用难度评定
        Stage 3: AST 模式 — 安全模式降级 Stage 1 误报 + 补充结构性问题
        Stage 4: 调用图   — 跨函数跨文件调用链补充漏报

        参数:
            php_version: PHP 版本号字符串（如 "5.0", "7.4"），仅 PHP 项目生效。
                         为空时默认 UNKNOWN（所有规则生效）。
        """
        result = PipelineResult()

        # ---- 收集源文件 ----
        source_code_map = self._collect_source_files(project_path, language)
        result.total_files = len(source_code_map)

        # ---- 解析 PHP 版本（用户选择优先，否则自动检测） ----
        if language == "php":
            from engine.rule_engine import resolve_php_version
            resolved, auto = resolve_php_version(php_version, source_code_map)
            result.resolved_php_version = resolved
            result.php_version_auto_detected = auto
            self.ast_analyzer.set_php_version(resolved)
            print(f"[PIPELINE] PHP 版本: {resolved} {'(自动检测)' if auto else '(用户指定)'}")

        # ================================================================
        # Stage 1: 污点追踪 — 地面真相
        # ================================================================
        print(f"[PIPELINE] Stage 1 (污点追踪): {language} — {len(source_code_map)} 个文件")
        stage1_vulns = self._run_stage1(project_path, language, source_code_map)
        result.vulns_stage1 = stage1_vulns
        result.stage1_count = len(stage1_vulns)
        print(f"[PIPELINE] Stage 1 完成: {len(stage1_vulns)} 个漏洞")

        # Stage 1 结果作为后续所有阶段的基准
        all_vulns: list[dict] = list(stage1_vulns)

        # ================================================================
        # Stage 2: 数据流 — 富化（不独立产出新漏洞）
        # ================================================================
        print(f"[PIPELINE] Stage 2 (数据流): 富化 Stage 1 结果...")
        if stage1_vulns:
            data_flow_findings = self.data_flow_analyzer.analyze(stage1_vulns, source_code_map)
            result.data_flow_findings = data_flow_findings
            result.stage2_exploitable = sum(1 for f in data_flow_findings if f.is_exploitable)
            result.stage2_protected = sum(1 for f in data_flow_findings if not f.is_exploitable)
            all_vulns = self._merge_stage2_results(stage1_vulns, data_flow_findings)
            result.stage2_count = result.stage2_exploitable
        else:
            result.stage2_count = 0
        print(f"[PIPELINE] Stage 2 完成: {result.stage2_exploitable} 可利用, "
              f"{result.stage2_protected} 有防护")

        # ================================================================
        # Stage 3: AST 模式 — 过滤 + 补充
        # ================================================================
        print(f"[PIPELINE] Stage 3 (AST 模式): 过滤误报 + 补充结构性问题...")
        ast_findings = self.ast_analyzer.analyze(source_code_map)
        result.ast_findings = ast_findings
        result.stage3_safe_patterns = sum(1 for f in ast_findings if f.is_safe)
        result.stage3_dangerous_patterns = sum(1 for f in ast_findings if not f.is_safe)

        # 3a: 用安全模式降级 Stage 1 误报（参数化查询 / 白名单等）
        all_vulns = self._apply_ast_filters(all_vulns, ast_findings)

        # 3b: 补充 Stage 1 漏掉的结构性问题（不重复）
        existing_keys = {(v["file_path"], v.get("line_number", 0), v["vuln_type"])
                         for v in all_vulns}
        supplementary_vulns = self._ast_findings_to_vulns(ast_findings, language)
        stage3_added = 0
        for v in supplementary_vulns:
            key = (v["file_path"], v["line_number"], v["vuln_type"])
            if key not in existing_keys:
                all_vulns.append(v)
                stage3_added += 1
        result.stage3_count = stage3_added
        print(f"[PIPELINE] Stage 3 完成: {result.stage3_safe_patterns} 安全模式, "
              f"{stage3_added} 个补充漏洞")

        # ================================================================
        # Stage 4: 调用图 — 补充
        # ================================================================
        print(f"[PIPELINE] Stage 4 (调用图): 跨函数跨文件分析...")
        stage4_vulns = self.call_graph_analyzer.analyze(source_code_map, language)
        for v in stage4_vulns:
            v["language"] = language
        result.call_graph_vulns = stage4_vulns

        # 补充不重复的跨文件漏报
        existing_keys = {(v.get("file_path"), v.get("line_number", 0), v.get("vuln_type"))
                         for v in all_vulns}
        stage4_added = 0
        for v in stage4_vulns:
            key = (v.get("file_path"), v.get("line_number", 0), v.get("vuln_type"))
            if key not in existing_keys:
                all_vulns.append(v)
                stage4_added += 1
        result.stage4_count = stage4_added
        print(f"[PIPELINE] Stage 4 完成: {stage4_added} 个跨函数漏洞")

        # ================================================================
        # 最终：去重 + 过滤（仅对非 Stage 1 的结果做 source 检查）
        # ================================================================
        final_vulns = self._deduplicate(all_vulns)
        final_vulns = self._filter_no_source(final_vulns, source_code_map)

        # 统一为所有结果补充 CWE 标注（Stage 1 已由扫描器输出，这里补 Stage 3/4）
        from engine.sinks_py import CWE_BY_TYPE
        for v in final_vulns:
            if not v.get("cwe"):
                v["cwe"] = CWE_BY_TYPE.get(v.get("vuln_type", ""), "")

        result.final_vulns = final_vulns
        result.final_count = len(final_vulns)
        print(f"[PIPELINE] 输出: {len(final_vulns)} 个漏洞 "
              f"(S1={result.stage1_count} +S3={stage3_added} +S4={stage4_added})")

        return result

    def _ast_findings_to_vulns(self, findings: list, language: str) -> list[dict]:
        """
        将 AST 发现的危险模式转化为漏洞字典。
        只转化真正的危险模式（is_safe=False）；
        BLACKLIST_FILTER（黑名单过滤）只是弱防护提示，不是漏洞本身，跳过。
        """
        from engine.ast_analyzer import ASTPattern

        # 危险模式 → 漏洞类型映射
        PATTERN_TO_VULN = {
            ASTPattern.DANGEROUS_COMBO: "command_execution",
            ASTPattern.EXTRACT_OVERRIDE: "command_execution",
            ASTPattern.HARDCODED_CREDENTIALS: "hardcoded_credentials",
            ASTPattern.DEBUG_MODE: "debug_mode",
        }
        # 模式 → 默认严重程度（不再一刀切 medium）
        PATTERN_SEVERITY = {
            ASTPattern.EXTRACT_OVERRIDE: "high",
            ASTPattern.STRING_CONCAT_SQL: "high",
            ASTPattern.DANGEROUS_COMBO: "medium",
            ASTPattern.HARDCODED_CREDENTIALS: "high",
            ASTPattern.DEBUG_MODE: "low",
        }

        vulns = []
        for f in findings:
            if f.is_safe:
                continue
            # 黑名单过滤是"弱防护提示"，不是漏洞，不上报
            if f.pattern == ASTPattern.BLACKLIST_FILTER:
                continue
            vuln_type = PATTERN_TO_VULN.get(f.pattern, "command_execution")
            # 取相关漏洞类型中第一个
            if f.related_vuln_types:
                vuln_type = f.related_vuln_types[0]
            # 模式名 → 可读标签
            pattern_labels = {
                "dangerous_combo": "危险函数组合",
                "blacklist_filter": "不安全的防护措施",
                "extract_override": "变量覆盖风险",
                "string_concat_sql": "SQL 字符串拼接",
                "magic_method_chain": "魔术方法链风险",
                "hardcoded_credentials": "硬编码凭据",
                "debug_mode": "调试模式开启",
            }
            data_flow_label = pattern_labels.get(
                f.pattern.value, f"AST模式({f.pattern.value})"
            )
            severity = PATTERN_SEVERITY.get(f.pattern, "medium")

            vulns.append({
                "file_path": f.file_path,
                "line_number": f.line_number,
                "sink_line": f.line_number,
                "vuln_type": vuln_type,
                "severity": severity,
                "language": language,
                "source_code": f.evidence,
                "sink_code": f.description,
                "data_flow": f"AST分析 — {data_flow_label}",
                "pipeline_stage": "ast",
                "confidence": f.confidence,
                "description": f.description,
            })
        return vulns

    def _run_stage1(self, project_path: str, language: str,
                    source_code_map: dict[str, str]) -> list[dict]:
        """执行 Stage 1 污点追踪扫描"""
        all_vulns = []

        # 根据语言选择扫描器
        if language == "python":
            scanner = PythonScanner()
            all_vulns = scanner.scan_project(source_code_map)  # 项目级跨函数/跨文件分析
        elif language in ("c", "cpp"):
            try:
                scanner = CScanner()
                all_vulns = scanner.scan_directory(project_path)
            except RuntimeError as e:
                print(f"[PIPELINE] C/C++ 扫描器初始化失败: {e}")
        elif language == "php":
            try:
                scanner = PHPScanner()
                all_vulns = scanner.scan_directory(project_path)
            except RuntimeError as e:
                print(f"[PIPELINE] PHP 扫描器初始化失败: {e}")

        # 去重
        seen = set()
        deduped = []
        for v in all_vulns:
            key = (v.get("file_path", ""), v.get("line_number", 0), v.get("vuln_type", ""))
            if key not in seen:
                seen.add(key)
                deduped.append({**v, "pipeline_stage": "taint"})

        return deduped

    def _merge_stage2_results(self, vulns: list[dict],
                              findings: list[DataFlowFinding]) -> list[dict]:
        """将 Stage 2 的数据流分析结果合并到漏洞字典中"""
        enriched = []
        for i, v in enumerate(vulns):
            enriched_v = dict(v)
            if i < len(findings):
                f = findings[i]
                enriched_v["protection_level"] = f.protection_level.value
                enriched_v["is_exploitable"] = f.is_exploitable
                enriched_v["exploit_difficulty"] = f.exploit_difficulty
                enriched_v["data_flow_notes"] = f.notes
                if f.is_exploitable:
                    enriched_v["pipeline_stage"] = "data_flow"
            enriched.append(enriched_v)
        return enriched

    def _apply_ast_filters(self, vulns: list[dict],
                           ast_findings: list) -> list[dict]:
        """
        使用 AST 安全模式（参数化查询、白名单等）降级 Stage 1 的误报。

        策略：
          - 如果漏洞所在行 ±3 行内存在安全模式覆盖此漏洞类型 → 降级为 info
          - 不直接删除，保留为低严重度供人工确认
        """
        safe_findings = [f for f in ast_findings if f.is_safe]
        if not safe_findings:
            return vulns

        # 预建查找表：(file, line) → pattern
        safe_at: dict[tuple[str, int], object] = {}
        for f in safe_findings:
            key = (f.file_path, f.line_number)
            if key not in safe_at:
                safe_at[key] = []
            safe_at[key].append(f.pattern)

        filtered = []
        for v in vulns:
            file = v.get("file_path", "")
            line = v.get("line_number", 0)
            vuln_type = v.get("vuln_type", "")

            # 搜索 ±3 行内是否有安全模式覆盖
            is_safe = False
            for offset in range(-3, 4):
                patterns_at_line = safe_at.get((file, line + offset), [])
                if any(self._safe_pattern_covers(p, vuln_type)
                       for p in patterns_at_line):
                    is_safe = True
                    break

            if is_safe:
                v_safe = dict(v)
                v_safe["severity"] = "info"
                v_safe["data_flow"] = (
                    f"[AST安全模式检测] {v.get('data_flow', '')}"
                )
                filtered.append(v_safe)
            else:
                filtered.append(v)

        return filtered

    @staticmethod
    def _safe_pattern_covers(pattern, vuln_type: str) -> bool:
        """判断 AST 安全模式是否覆盖此漏洞类型"""
        from engine.ast_analyzer import ASTPattern
        coverage = {
            ASTPattern.PARAMETERIZED_QUERY: {"sql_injection"},
            ASTPattern.ALLOWLIST_CHECK: {
                "command_execution", "path_traversal", "sql_injection",
            },
        }
        return vuln_type in coverage.get(pattern, set())

    def _deduplicate(self, vulns: list[dict]) -> list[dict]:
        """去重"""
        seen = set()
        deduped = []
        for v in vulns:
            key = (v.get("file_path", ""), v.get("line_number", 0), v.get("vuln_type", ""),
                   v.get("sink_line", 0))
            if key not in seen:
                seen.add(key)
                deduped.append(v)
        return deduped

    def _filter_no_source(self, vulns: list[dict],
                          source_code_map: dict[str, str]) -> list[dict]:
        """
        安全网过滤：只对 Stage 3/4 的补充结果做 source 存在性检查。

        Stage 1 (taint) 的结果已通过 AST 级污点追踪验证，跳过此过滤。
        Stage 2 (data_flow) 的结果是从 Stage 1 富化而来，同样跳过。
        Stage 3 (ast) 的结构性问题不依赖用户输入，跳过。
        只有 Stage 3/4 补充的非结构性问题才需要确认文件中确实有用户输入入口。
        """
        # 需要用户输入的漏洞类型
        INPUT_DEPENDENT_TYPES = {
            "sql_injection", "command_execution", "ssrf",
            "path_traversal", "arbitrary_file_read", "xss",
            "file_upload", "deserialization",
        }
        # 不需要 source 的类型 + 阶段
        SKIP_FILTER_STAGES = {"taint", "data_flow", "ast"}  # 已通过污点追踪或结构性问题
        SKIP_FILTER_TYPES = {
            "wide_byte_injection", "deprecated_api",
        }

        # PHP 用户输入模式
        PHP_SOURCE_PATTERNS = [
            r'\$_GET\b', r'\$_POST\b', r'\$_REQUEST\b',
            r'\$_COOKIE\b', r'\$_SERVER\b', r'\$_FILES\b',
            r'\$_SESSION\b', r'\$_ENV\b',
            r"getenv\s*\(", r"php://input",
            r"file_get_contents\s*\(\s*['\"]php://",
            r"getallheaders\s*\(", r"\$argv\b",
        ]
        # Python 用户输入模式
        PY_SOURCE_PATTERNS = [
            r'request\.(?:args|form|json|data|values)\.get\b',
            r'input\s*\(', r'sys\.argv\b',
        ]

        filtered = []
        for v in vulns:
            vuln_type = v.get("vuln_type", "")
            language = v.get("language", "")
            file_path = v.get("file_path", "")

            # 不需要 source 的类型直接保留
            if vuln_type in SKIP_FILTER_TYPES:
                filtered.append(v)
                continue

            # AST 阶段：结构性问题，不依赖用户输入
            if v.get("pipeline_stage") in SKIP_FILTER_STAGES:
                filtered.append(v)
                continue

            # 需要 source 且非 AST 阶段：检查文件中有没有用户输入
            if vuln_type in INPUT_DEPENDENT_TYPES:
                file_code = source_code_map.get(file_path, "")
                if not file_code:
                    # 文件找不到，保守保留
                    filtered.append(v)
                    continue

                patterns = PHP_SOURCE_PATTERNS if language == "php" else PY_SOURCE_PATTERNS
                has_source = any(re.search(p, file_code) for p in patterns)
                if not has_source:
                    # 没有用户输入 → 误报，跳过
                    continue

            filtered.append(v)

        return filtered

    def _collect_source_files(self, project_path: str, language: str) -> dict[str, str]:
        """
        收集项目中所有源码文件内容。

        返回:
            {file_path: source_code} 映射
        """
        extensions = {
            "python": {".py"},
            "c": {".c", ".h"},
            "cpp": {".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".c++", ".h++"},
            "php": {".php", ".php3", ".php4", ".php5", ".phtml", ".pht", ".inc"},
        }

        exts = extensions.get(language, set())
        source_map = {}
        # 排除目录：依赖/虚拟环境/构建产物等，避免扫描第三方代码产生误报
        EXCLUDED_DIRS = {
            "__pycache__", ".git", "vendor", "node_modules", ".venv",
            "venv", "env", "site-packages", "dist", "build",
            ".tox", ".mypy_cache", ".pytest_cache", ".eggs",
        }

        try:
            for file_path in Path(project_path).rglob("*"):
                if file_path.is_file() and file_path.suffix.lower() in exts:
                    # 跳过常见排除目录
                    parts = set(file_path.parts)
                    if parts & EXCLUDED_DIRS:
                        continue
                    try:
                        source_map[str(file_path)] = file_path.read_text(
                            encoding="utf-8", errors="ignore"
                        )
                    except Exception:
                        pass
        except Exception as e:
            print(f"[PIPELINE] 收集源文件出错: {e}")

        return source_map
