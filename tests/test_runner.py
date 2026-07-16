"""
测试脚本 —— 验证扫描引擎是否正常工作
==================================
运行此脚本可以：
  1. 测试 Python 扫描器是否能检测所有预期漏洞类型
  2. 测试 C/C++ 扫描器（如果 tree-sitter 已安装）
  3. 输出每种漏洞类型的发现数量统计

用法:
    python tests/test_runner.py
"""
import sys
import json
from pathlib import Path

# 将 backend 目录加入 Python 路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from engine import scan_project, scan_single_file


def test_python():
    """
    测试 Python 扫描器
    ==================
    使用 test_python_vulns.py 作为测试用例，
    验证能否检测 SQL 注入、命令执行、SSRF 三种漏洞。
    """
    print("=" * 50)
    print("Testing Python Scanner（测试 Python 扫描器）")
    print("=" * 50)

    # 读取测试文件
    test_file = Path(__file__).parent / "test_python_vulns.py"
    source = test_file.read_text(encoding="utf-8")

    # 执行扫描
    results = scan_single_file(source, str(test_file), "python")

    print(f"\nFound {len(results)} vulnerabilities（发现 {len(results)} 个漏洞）:\n")

    # 逐个打印漏洞详情
    for r in results:
        severity = r["severity"]
        # 按严重程度选择图标
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
        print(f"  {icon} [{severity.upper()}] {r['vuln_type']}")
        print(f"     File（文件）: {r['file_path']}:{r['line_number']}")
        print(f"     Source（源）: {r['source_func']}")
        print(f"     Sink（汇）: {r['sink_func']}")
        print(f"     Flow（数据流）: {r['data_flow']}")
        print()

    # 验证是否检测到所有预期漏洞类型
    expected_types = {"sql_injection", "command_execution", "ssrf"}  # 预期类型
    found_types = {r["vuln_type"] for r in results}                   # 实际发现类型

    if expected_types.issubset(found_types):
        print("✅ Python scanner detects all expected vulnerability types!")
        print("   （Python 扫描器成功检测到所有预期漏洞类型！）")
    else:
        missing = expected_types - found_types
        print(f"❌ Missing（缺失）: {missing}")

    return results


def test_c():
    """
    测试 C/C++ 扫描器
    ================
    使用 test_c_vulns.c 作为测试用例。
    如果 tree-sitter 未安装，跳过测试。
    """
    print("\n" + "=" * 50)
    print("Testing C/C++ Scanner（测试 C/C++ 扫描器）")
    print("=" * 50)

    test_file = Path(__file__).parent / "test_c_vulns.c"
    source = test_file.read_text(encoding="utf-8")

    try:
        results = scan_single_file(source, str(test_file), "c")
        print(f"\nFound {len(results)} vulnerabilities（发现 {len(results)} 个漏洞）:\n")
        for r in results:
            severity = r["severity"]
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
            print(f"  {icon} [{severity.upper()}] {r['vuln_type']}")
            print(f"     File（文件）: {r['file_path']}:{r['line_number']}")
            print(f"     Source（源）: {r['source_func']}")
            print(f"     Sink（汇）: {r['sink_func']}")
            print(f"     Flow（数据流）: {r['data_flow']}")
            print()
    except RuntimeError as e:
        # tree-sitter 未安装
        print(f"⚠️  C scanner skipped（C 扫描器跳过）: {e}")

    return []


if __name__ == "__main__":
    # 运行 Python 测试
    py_results = test_python()

    # 运行 C/C++ 测试
    test_c()

    # ---- 汇总统计 ----
    print(f"\n{'=' * 50}")
    print(f"✅ Total Python vulns found（Python 漏洞总计）: {len(py_results)}")
    print(f"   SQL Injection（SQL 注入）: {sum(1 for r in py_results if r['vuln_type'] == 'sql_injection')}")
    print(f"   Command Exec（命令执行）:  {sum(1 for r in py_results if r['vuln_type'] == 'command_execution')}")
    print(f"   SSRF（服务端请求伪造）:    {sum(1 for r in py_results if r['vuln_type'] == 'ssrf')}")
