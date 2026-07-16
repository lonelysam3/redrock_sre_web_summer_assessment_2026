"""
三级分析流水线编排器
===================
统一编排 Source-Sink 污点分析 → 数据流分析 → AST 分析 的三级流水线。

==== 流水线流程 ====

   源文件
     │
     ▼
   ┌─────────────────────────┐
   │ Stage 1: 污点追踪        │  ← TaintTracker + Scanner
   │ • Source→Sink 路径检测   │
   │ • BFS 变量传播分析       │
   │ • 消毒函数过滤           │
   └──────────┬──────────────┘
              │ vulns_stage1
              ▼
   ┌─────────────────────────┐
   │ Stage 2: 数据流分析      │  ← DataFlowAnalyzer
   │ • 防护等级检测           │
   │ • 数据变换追踪           │
   │ • 利用难度评定           │
   └──────────┬──────────────┘
              │ vulns_stage2 (enriched)
              ▼
   ┌─────────────────────────┐
   │ Stage 3: AST 模式分析    │  ← ASTAnalyzer
   │ • 参数化查询识别         │
   │ • 白名单验证检测         │
   │ • 危险组合模式           │
   │ • 降级误报漏洞           │
   └──────────┬──────────────┘
              │ vulns_stage3 (filtered + enriched)
              ▼
         最终漏洞列表

==== 使用方式 ====

    pipeline = AnalysisPipeline()
    results = pipeline.run(project_path, language)
    # results 包含所有三级分析的信息
"""
from pathlib import Path
from dataclasses import dataclass, field

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

    # 统计
    total_files: int = 0
    errors: list[str] = field(default_factory=list)


class AnalysisPipeline:
    """
    四级分析流水线
    ==============
    四个阶段独立扫描，结果合并去重。
    """

    def __init__(self):
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.ast_analyzer = ASTAnalyzer()
        self.call_graph_analyzer = CallGraphAnalyzer()

    def run(self, project_path: str, language: str) -> PipelineResult:
        """
        四级独立分析流水线。
        四个阶段完全独立扫描，互不知晓对方结果，最后一次性合并去重。

        Stage 1: 污点追踪 — AST 级变量传播分析
        Stage 2: 数据流 — 正则模式检测 Source + Sink 同块
        Stage 3: AST 模式 — 危险函数组合 / 反序列化 / 变量覆盖
        Stage 4: 调用图 — 跨函数跨文件调用链分析
        """
        result = PipelineResult()

        # ---- 收集源文件 ----
        source_code_map = self._collect_source_files(project_path, language)
        result.total_files = len(source_code_map)

        all_vulns: list[dict] = []

        # ================================================================
        # Stage 1: 污点追踪
        # ================================================================
        print(f"[PIPELINE] Stage 1 (污点追踪): {language} — {len(source_code_map)} 个文件")
        stage1_vulns = self._run_stage1(project_path, language, source_code_map)
        result.vulns_stage1 = stage1_vulns
        result.stage1_count = len(stage1_vulns)
        print(f"[PIPELINE] Stage 1 完成: {len(stage1_vulns)} 个漏洞")
        all_vulns.extend(stage1_vulns)

        # ================================================================
        # Stage 2: 数据流（独立扫描）
        # ================================================================
        print(f"[PIPELINE] Stage 2 (数据流): 独立扫描中...")
        stage2_vulns = self.data_flow_analyzer.analyze_independent(source_code_map, language)
        result.stage2_count = len(stage2_vulns)
        print(f"[PIPELINE] Stage 2 完成: {len(stage2_vulns)} 个漏洞")
        all_vulns.extend(stage2_vulns)

        # ================================================================
        # Stage 3: AST 模式（独立扫描）
        # ================================================================
        print(f"[PIPELINE] Stage 3 (AST 模式): 独立扫描中...")
        ast_findings = self.ast_analyzer.analyze(source_code_map)
        result.ast_findings = ast_findings
        result.stage3_safe_patterns = sum(1 for f in ast_findings if f.is_safe)
        result.stage3_dangerous_patterns = sum(1 for f in ast_findings if not f.is_safe)
        stage3_vulns = self._ast_findings_to_vulns(ast_findings, language)
        result.stage3_count = len(stage3_vulns)
        print(f"[PIPELINE] Stage 3 完成: {len(stage3_vulns)} 个漏洞")
        all_vulns.extend(stage3_vulns)

        # ================================================================
        # Stage 4: 调用图（独立扫描）
        # ================================================================
        print(f"[PIPELINE] Stage 4 (调用图): 独立扫描中...")
        stage4_vulns = self.call_graph_analyzer.analyze(source_code_map, language)
        for v in stage4_vulns:
            v["language"] = language
        result.call_graph_vulns = stage4_vulns
        result.stage4_count = len(stage4_vulns)
        print(f"[PIPELINE] Stage 4 完成: {len(stage4_vulns)} 个漏洞")
        all_vulns.extend(stage4_vulns)

        # ================================================================
        # 合并去重（唯一一次，四个阶段均不知晓彼此结果）
        # ================================================================
        final_vulns = self._deduplicate(all_vulns)

        result.final_vulns = final_vulns
        result.final_count = len(final_vulns)
        print(f"[PIPELINE] 合并去重完成: 总共 {len(final_vulns)} 个漏洞"
              f" (S1={result.stage1_count} S2={result.stage2_count}"
              f" S3={result.stage3_count} S4={result.stage4_count})")

        return result

    def _ast_findings_to_vulns(self, findings: list, language: str) -> list[dict]:
        """
        将 AST 发现的危险模式转化为漏洞字典。
        只转化危险模式（is_safe=False），安全模式只用于降级/过滤。
        """
        from engine.ast_analyzer import ASTPattern

        # 危险模式 → 漏洞类型映射
        PATTERN_TO_VULN = {
            ASTPattern.BLACKLIST_FILTER: "sql_injection",
            ASTPattern.DANGEROUS_COMBO: "command_execution",
            ASTPattern.EXTRACT_OVERRIDE: "command_execution",
        }

        vulns = []
        for f in findings:
            if f.is_safe:
                continue
            vuln_type = PATTERN_TO_VULN.get(f.pattern, "command_execution")
            # 取相关漏洞类型中第一个
            if f.related_vuln_types:
                vuln_type = f.related_vuln_types[0]
            vulns.append({
                "file_path": f.file_path,
                "line_number": f.line_number,
                "sink_line": f.line_number,
                "vuln_type": vuln_type,
                "severity": "medium",
                "language": language,
                "source_code": "",
                "sink_code": f.evidence,
                "data_flow": "",
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
            all_vulns = scanner.scan_directory(project_path)
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

        try:
            for file_path in Path(project_path).rglob("*"):
                if file_path.is_file() and file_path.suffix.lower() in exts:
                    # 跳过常见排除目录
                    parts = set(file_path.parts)
                    if parts & {"__pycache__", ".git", "vendor", "node_modules", ".venv"}:
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
