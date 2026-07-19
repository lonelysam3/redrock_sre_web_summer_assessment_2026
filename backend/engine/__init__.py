"""
扫描引擎统一入口（v2 — 三级流水线）
=================================
根据语言类型分发给对应的扫描器，并执行三级分析流水线。

流水线: Source-Sink污点分析 → 数据流分析 → AST模式分析

支持语言: Python / C / C++ / PHP

用法:
    from engine import scan_project, scan_with_pipeline

    # 简单扫描（向后兼容）
    vulns = scan_project("/path/to/project", "python")

    # 完整三级流水线分析（推荐）
    result = scan_with_pipeline("/path/to/project", "php")
"""
from engine.python_scanner import PythonScanner
from engine.c_scanner import CScanner
from engine.php_scanner import PHPScanner
from engine.pipeline import AnalysisPipeline, PipelineResult
from engine.payload_builder import PayloadBuilder
from engine.ai_verifier import AIVerifier, VerificationReport


def scan_project(project_path: str, language: str) -> list[dict]:
    """
    简单扫描（向后兼容 v1 API）。
    只执行 Stage 1 污点追踪分析。

    参数:
        project_path: 项目源码的磁盘路径
        language:     编程语言 (python/c/cpp/php)

    返回:
        list[dict]: 漏洞列表
    """
    result = scan_with_pipeline(project_path, language)
    return result.final_vulns


def scan_with_pipeline(project_path: str, language: str, php_version: str | None = None) -> PipelineResult:
    """
    使用四级流水线扫描项目。

    流水线: Stage 1 污点追踪 → Stage 2 数据流 → Stage 3 AST → Stage 4 调用图

    PHP 项目若未指定 php_version，会自动检测源码所需的 PHP 最低版本。

    参数:
        project_path: 项目源码的磁盘路径
        language:     编程语言 (python/c/cpp/php)
        php_version:  PHP 版本，None 时自动检测

    返回:
        PipelineResult: 包含四级分析全部结果 + resolved_php_version
    """
    pipeline = AnalysisPipeline()
    return pipeline.run(project_path, language, php_version=php_version)


def scan_with_verification(
    project_path: str, language: str, ai_client=None, php_version: str | None = None
) -> tuple[list[dict], list[VerificationReport]]:
    """
    完整扫描 + AI 自动验证。

    流程:
      1. 四级流水线扫描
      2. AI Payload 构建
      3. AI Payload 验证
      4. 自动标记 confirmed / potential

    参数:
        project_path: 项目源码目录
        language:     编程语言
        ai_client:    AI 客户端（可选，用于 Payload 构建和验证）
        php_version:  PHP 版本（仅 php 项目生效）

    返回:
        (final_vulns, verification_reports): 最终漏洞列表和验证报告
    """
    # ---- 1. 四级流水线 ----
    pipeline = AnalysisPipeline()
    result = pipeline.run(project_path, language, php_version=php_version)
    vulns = result.final_vulns

    if not vulns:
        return [], []

    # ---- 2. 收集源文件 ----
    source_code_map = pipeline._collect_source_files(project_path, language)

    # ---- 3. AI Payload 构建 ----
    if ai_client and ai_client.is_configured():
        payload_builder = PayloadBuilder(ai_client)
        payload_sets = payload_builder.build_payloads(vulns, source_code_map)

        # ---- 4. AI 验证 ----
        verifier = AIVerifier(ai_client)
        reports = verifier.verify(vulns, payload_sets, source_code_map)

        # ---- 5. 应用验证结果 ----
        vulns = verifier.apply_verification(vulns, reports)

        return vulns, reports

    return vulns, []


def scan_single_file(source_code: str, file_path: str, language: str) -> list[dict]:
    """
    扫描单个文件（测试/调试用）。

    参数:
        source_code: 源代码内容
        file_path:   文件路径
        language:    编程语言

    返回:
        list[dict]: 漏洞列表
    """
    if language == "python":
        scanner = PythonScanner()
        return scanner.scan_source(source_code, file_path)
    elif language in ("c", "cpp"):
        scanner = CScanner()
        return scanner.scan_source(source_code, file_path)
    elif language == "php":
        scanner = PHPScanner()
        return scanner.scan_source(source_code, file_path)
    return []
