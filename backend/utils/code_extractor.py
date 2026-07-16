"""
代码提取工具模块（v2 — 带路径安全校验）
=====================================
提供从源文件中按行号提取代码片段、语言检测等功能。

v2 新增：路径安全校验，防止任意文件读取。
"""
from pathlib import Path


def extract_source_context(file_path: str, source_line: int,
                           sink_line: int, context_lines: int = 10,
                           project_root: str = "") -> str:
    """
    提取 Source 和 Sink 附近的上下文代码。

    安全校验:
      - 如果提供了 project_root，检查文件路径是否在项目目录内
      - 防止通过数据库中的路径读取任意系统文件

    参数:
        file_path:      源文件路径
        source_line:    Source 点所在行号（1-based）
        sink_line:      Sink 点所在行号（1-based）
        context_lines:  在 Source/Sink 前后各显示多少行（默认 10 行）
        project_root:   项目根目录（用于路径安全校验）

    返回:
        str: 带行号的上下文代码字符串
             读取失败或路径不安全返回空字符串
    """
    # ---- 路径安全校验 ----
    if project_root:
        from utils.path_security import validate_file_in_project, PathSecurityError
        try:
            file_path = validate_file_in_project(file_path, project_root)
        except PathSecurityError:
            return ""  # 路径不安全，静默返回

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return ""  # 文件不可读

    all_relevant = sorted(set([source_line, sink_line]))
    start = max(0, min(all_relevant) - context_lines)
    end = min(len(lines), max(all_relevant) + context_lines)

    result = []
    for i in range(start, end):
        line_num = i + 1
        marker = ""
        if line_num == source_line:
            marker = "  ← SOURCE（用户输入入口）"
        elif line_num == sink_line:
            marker = "  ← SINK（危险函数调用）"
        result.append(f"{line_num:4d} | {lines[i].rstrip()}{marker}")

    return "\n".join(result)


def extract_vuln_snippet(file_path: str, line_range: tuple[int, int]) -> str:
    """
    提取指定行范围的代码片段（含前后 3 行缓冲）。

    参数:
        file_path:  源文件路径
        line_range: (start_line, end_line) 元组，1-based

    返回:
        str: 代码片段字符串
    """
    start, end = line_range
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return ""
    snippet = "".join(lines[max(0, start-3):end+3])
    return snippet.strip()


def detect_language(file_path: str) -> str:
    """
    根据文件扩展名判断编程语言。

    返回: "python" / "c" / "cpp" / "php" / "unknown"
    """
    ext = Path(file_path).suffix.lower()
    if ext == ".py":
        return "python"
    if ext in {".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".h++", ".c++"}:
        return "cpp"
    if ext in {".c", ".h"}:
        return "c"
    if ext in {".php", ".php3", ".php4", ".php5", ".phtml", ".pht", ".inc"}:
        return "php"
    return "unknown"


def detect_project_language(project_path: str) -> str:
    """
    检测项目目录的主要编程语言。
    遍历文件统计各语言数量，返回占比最高的。
    """
    from collections import Counter
    counter = Counter()
    for root, dirs, files in Path(project_path).walk():
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            lang = detect_language(f)
            if lang != "unknown":
                counter[lang] += 1
    return counter.most_common(1)[0][0] if counter else "unknown"
