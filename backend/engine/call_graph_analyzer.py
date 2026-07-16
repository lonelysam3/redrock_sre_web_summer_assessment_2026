"""
调用图分析器（第四阶段 — Call Graph）
==================================
通过构建函数调用图，发现跨函数、跨文件的 Source→Sink 路径。

==== 三个阶段各自独立，互补漏报 ====

Stage 1 (污点追踪):    AST 级单文件变量传播
Stage 2 (数据流):      防护检测 + 利用难度评定
Stage 3 (AST 模式):    正则模式匹配危险函数组合
Stage 4 (调用图):      跨函数/跨文件调用链分析 ← 本模块

==== 原理 ====

   function getUserInput() {   ← Source 函数（接收用户输入）
       return $_GET['name'];
   }

   function buildQuery($name) {  ← Pass-through
       return "SELECT * FROM users WHERE name='" . $name . "'";
   }

   function run() {              ← Sink 函数（执行危险操作）
       $sql = buildQuery(getUserInput());
       mysqli_query($db, $sql);  ← 最终 Sink
   }

调用图分析发现: getUserInput → buildQuery → run → mysqli_query
"""

from __future__ import annotations
import re
from collections import defaultdict, deque
from pathlib import Path
from dataclasses import dataclass, field


# ======================================================================
# 数据结构
# ======================================================================

@dataclass
class FunctionNode:
    """调用图中的一个函数节点"""
    name: str
    file_path: str
    line_number: int                       # 函数定义行号
    is_source: bool = False                # 是否接收用户输入
    is_sink: bool = False                  # 是否包含危险操作
    source_labels: list[str] = field(default_factory=list)   # 匹配到的 Source 类型
    sink_labels: list[str] = field(default_factory=list)     # 匹配到的 Sink 类型
    vuln_type: str = ""                    # 如果是 sink，对应哪种漏洞类型
    calls: set[str] = field(default_factory=set)  # 调用了哪些函数


@dataclass
class CallPath:
    """一条 Source→Sink 调用路径"""
    path: list[str]                        # 函数名列表 [source, ..., sink]
    files: list[str]                       # 每个函数所在文件
    lines: list[int]                       # 每个函数的行号
    vuln_type: str                         # 漏洞类型
    severity: str = "medium"
    description: str = ""


# ======================================================================
# 语言特定的函数提取规则
# ======================================================================

# Python: def func_name(params):
PY_DEF_PATTERN = re.compile(
    r'^\s*def\s+(\w+)\s*\(', re.MULTILINE
)
PY_CALL_PATTERN = re.compile(
    r'(?<!def\s)(?<!\.)\b(\w+)\s*\(', re.MULTILINE
)

# PHP: function func_name(params)
PHP_DEF_PATTERN = re.compile(
    r'(?:function\s+(\w+)\s*\(|(\$\w+)\s*=\s*function\s*\()', re.MULTILINE
)
PHP_CALL_PATTERN = re.compile(
    r'(?<!function\s)(?<!->)(?<!::)\b(\w+)\s*\(', re.MULTILINE
)

# C/C++: type func_name(params)
C_DEF_PATTERN = re.compile(
    r'^\s*(?:static\s+)?(?:inline\s+)?(?:virtual\s+)?(?:[\w*&<>:]+\s+)+\*?(\w+)\s*\([^)]*\)\s*(?:const\s*)?\{',
    re.MULTILINE
)
C_CALL_PATTERN = re.compile(
    r'(?<!\.)(?<!->)(?<!\w\.)(?<!\w->)\b(\w{2,})\s*\(', re.MULTILINE
)

# ======================================================================
# Source / Sink 特征码（用于标注函数角色）
# ======================================================================

# 函数名包含这些关键词 → 可能是 Source
SOURCE_KEYWORDS = {
    "python": [
        "request", "get_input", "read_input", "get_param", "get_arg",
        "get_query", "get_body", "get_json", "get_form", "get_cookie",
        "parse_input", "recv", "receive", "user_input", "argv",
    ],
    "php": [
        "request", "getinput", "readinput", "getparam", "getarg",
        "getquery", "getbody", "getjson", "getform", "getcookie",
        "parseinput", "recv", "receive", "userinput", "upload",
    ],
    "c": [
        "recv", "receive", "read_input", "get_input", "fgets",
        "scanf", "get_param", "parse_request", "get_query",
        "read_request", "getenv", "argv", "argc",
    ],
    "cpp": [
        "recv", "receive", "read_input", "get_input", "fgets",
        "scanf", "get_param", "parse_request", "get_query",
        "read_request", "getenv", "argv", "argc",
    ],
}

# 函数名包含这些关键词 → 可能是 Sink
SINK_KEYWORDS = {
    "python": [
        ("execute", "command_execution"),
        ("eval", "command_execution"),
        ("system", "command_execution"),
        ("subprocess", "command_execution"),
        ("popen", "command_execution"),
        ("exec_cmd", "command_execution"),
        ("run_cmd", "command_execution"),
        ("sql", "sql_injection"),
        ("query", "sql_injection"),
        ("exec_sql", "sql_injection"),
        ("db_query", "sql_injection"),
        ("fetch_url", "ssrf"),
        ("request_url", "ssrf"),
        ("read_file", "arbitrary_file_read"),
        ("open_file", "path_traversal"),
        ("write_file", "path_traversal"),
    ],
    "php": [
        ("execute", "command_execution"),
        ("eval", "command_execution"),
        ("shell", "command_execution"),
        ("system", "command_execution"),
        ("exec_cmd", "command_execution"),
        ("sql", "sql_injection"),
        ("query", "sql_injection"),
        ("exec_sql", "sql_injection"),
        ("db_query", "sql_injection"),
        ("fetch_url", "ssrf"),
        ("request_url", "ssrf"),
        ("read_file", "arbitrary_file_read"),
        ("open_file", "path_traversal"),
        ("include", "path_traversal"),
        ("require", "path_traversal"),
        ("unserialize", "deserialization"),
        ("deserialize", "deserialization"),
        ("upload", "file_upload"),
        ("move_upload", "file_upload"),
        ("echo_output", "xss"),
        ("render_output", "xss"),
    ],
    "c": [
        ("exec", "command_execution"),
        ("system", "command_execution"),
        ("popen", "command_execution"),
        ("spawn", "command_execution"),
        ("sql", "sql_injection"),
        ("query", "sql_injection"),
        ("connect", "ssrf"),
        ("fopen", "path_traversal"),
        ("open", "path_traversal"),
        ("read", "arbitrary_file_read"),
    ],
    "cpp": [
        ("exec", "command_execution"),
        ("system", "command_execution"),
        ("popen", "command_execution"),
        ("spawn", "command_execution"),
        ("sql", "sql_injection"),
        ("query", "sql_injection"),
        ("connect", "ssrf"),
        ("fopen", "path_traversal"),
        ("open", "path_traversal"),
        ("read", "arbitrary_file_read"),
    ],
}

# 当函数体内出现以下模式时，标记为 Source 或 Sink（更精确的检测）
INLINE_SOURCE_PATTERNS = {
    "php": [
        (r'\$_GET\b', "HTTP GET"),
        (r'\$_POST\b', "HTTP POST"),
        (r'\$_REQUEST\b', "HTTP Request"),
        (r'\$_COOKIE\b', "Cookie"),
        (r'\$_SERVER\b', "Server var"),
        (r'\$_FILES\b', "File upload"),
        (r'php://input', "Raw input"),
        (r'getenv\s*\(', "Environment"),
    ],
    "python": [
        (r'request\.(?:args|form|json|data|cookies|headers)', "Web request"),
        (r'sys\.argv', "CLI args"),
        (r'os\.environ', "Environment"),
        (r'input\s*\(', "stdin"),
    ],
    "c": [
        (r'(?:fgets|scanf|gets)\s*\(', "Input function"),
        (r'getenv\s*\(', "Environment"),
        (r'argv\b', "CLI args"),
    ],
    "cpp": [
        (r'(?:fgets|scanf|gets|std::cin)\s*\(', "Input function"),
        (r'getenv\s*\(', "Environment"),
        (r'argv\b', "CLI args"),
    ],
}

INLINE_SINK_PATTERNS = {
    "php": [
        (r'(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(', "Command execution", "command_execution"),
        (r'eval\s*\(', "Code execution", "command_execution"),
        (r'(?:mysqli_query|mysql_query|pg_query|sqlite_query|->query)\s*\(', "SQL query", "sql_injection"),
        (r'(?:include|require)(?:_once)?\s*\(?\s*\$', "Dynamic include", "path_traversal"),
        (r'unserialize\s*\(', "Deserialization", "deserialization"),
        (r'(?:curl_exec|file_get_contents)\s*\(', "SSRF/file read", "ssrf"),
        (r'move_uploaded_file\s*\(', "File upload", "file_upload"),
        (r'(?:echo|print|printf)\s+(?!.*htmlspecialchars)', "Direct output", "xss"),
    ],
    "python": [
        (r'os\.system\s*\(', "Command execution", "command_execution"),
        (r'subprocess\.(?:call|run|Popen)\s*\(', "Subprocess", "command_execution"),
        (r'eval\s*\(', "Eval", "command_execution"),
        (r'exec\s*\(', "Exec", "command_execution"),
        (r'\.execute\s*\(', "SQL execute", "sql_injection"),
        (r'(?:open|builtins\.open)\s*\(', "File open", "path_traversal"),
        (r'requests\.(?:get|post|put|delete)\s*\(', "HTTP request", "ssrf"),
    ],
    "c": [
        (r'(?:system|popen|exec[lv]p?)\s*\(', "Command execution", "command_execution"),
        (r'(?:mysql_query|sqlite3_exec)\s*\(', "SQL query", "sql_injection"),
        (r'fopen\s*\(', "File open", "path_traversal"),
    ],
    "cpp": [
        (r'(?:system|popen|exec[lv]p?)\s*\(', "Command execution", "command_execution"),
        (r'(?:mysql_query|sqlite3_exec)\s*\(', "SQL query", "sql_injection"),
        (r'fopen\s*\(', "File open", "path_traversal"),
    ],
}

# 严重程度映射
SEVERITY_MAP = {
    "command_execution": "critical",
    "sql_injection": "high",
    "deserialization": "high",
    "file_upload": "high",
    "ssrf": "high",
    "path_traversal": "medium",
    "arbitrary_file_read": "medium",
    "xss": "low",
}


# ======================================================================
# 调用图分析器
# ======================================================================

class CallGraphAnalyzer:
    """
    调用图分析器
    ============
    1. 从源码中提取函数定义
    2. 在函数体内找到对其他函数的调用
    3. 构建有向图
    4. 标注 Source/Sink 函数
    5. BFS 查找 Source → Sink 路径
    """

    def __init__(self):
        pass

    def analyze(self, source_code_map: dict[str, str], language: str) -> list[dict]:
        """
        执行调用图分析。

        参数:
            source_code_map: {file_path: source_code}
            language:        python / c / cpp / php

        返回:
            list[dict]: 漏洞列表
        """
        # ---- 1. 提取所有函数 ----
        functions: dict[str, FunctionNode] = {}
        self._extract_functions(source_code_map, language, functions)

        if not functions:
            return []

        # ---- 2. 分析每个函数体的调用关系 ----
        self._resolve_calls(source_code_map, language, functions)

        # ---- 3. 标注 Source 和 Sink ----
        sources = []
        sinks = []
        for name, func in functions.items():
            if func.is_source:
                sources.append(name)
            if func.is_sink:
                sinks.append(name)

        if not sources or not sinks:
            return []

        # ---- 4. BFS 查找 Source → Sink 路径 ----
        paths = self._find_paths(functions, sources, sinks)

        # ---- 5. 转化为漏洞报告 ----
        return self._paths_to_vulns(paths, functions)

    # ----------------------------------------------------------------
    # 函数提取
    # ----------------------------------------------------------------

    def _extract_functions(self, source_code_map: dict[str, str], language: str,
                           functions: dict[str, FunctionNode]):
        """从源文件中提取函数定义"""
        def_pattern = self._get_def_pattern(language)

        for file_path, source in source_code_map.items():
            for match in def_pattern.finditer(source):
                name = match.group(1) or match.group(2)
                if not name:
                    continue
                line_num = source[:match.start()].count("\n") + 1

                if name not in functions:
                    functions[name] = FunctionNode(
                        name=name, file_path=file_path, line_number=line_num
                    )
                self._classify_function(name, source, file_path, language, functions)

    def _classify_function(self, name: str, source: str, file_path: str,
                           language: str, functions: dict[str, FunctionNode]):
        """标注函数角色：Source / Sink / Pass-through"""
        func = functions[name]
        name_lower = name.lower()

        # 按函数名关键词判断
        for kw, vuln_type in SINK_KEYWORDS.get(language, []):
            if kw in name_lower:
                func.is_sink = True
                func.vuln_type = vuln_type
                func.sink_labels.append(f"name:{kw}")
                break

        for kw in SOURCE_KEYWORDS.get(language, []):
            if kw in name_lower:
                func.is_source = True
                func.source_labels.append(f"name:{kw}")
                break

        # 函数体内检测 Source/Sink 模式（更精确）
        for pattern, label in INLINE_SOURCE_PATTERNS.get(language, []):
            if re.search(pattern, source, re.IGNORECASE):
                func.is_source = True
                func.source_labels.append(label)

        for pattern, label, vuln_type in INLINE_SINK_PATTERNS.get(language, []):
            if re.search(pattern, source, re.IGNORECASE):
                func.is_sink = True
                func.sink_labels.append(label)
                if not func.vuln_type:
                    func.vuln_type = vuln_type

    # ----------------------------------------------------------------
    # 调用关系解析
    # ----------------------------------------------------------------

    def _resolve_calls(self, source_code_map: dict[str, str], language: str,
                       functions: dict[str, FunctionNode]):
        """分析每个函数调用了哪些其他函数"""
        call_pattern = self._get_call_pattern(language)

        for file_path, source in source_code_map.items():
            lines = source.split("\n")

            # 逐个函数查找其调用
            for name, func in functions.items():
                if func.file_path != file_path:
                    continue

                # 提取函数体
                body = self._extract_function_body(source, name, language)
                if not body:
                    continue

                # 找函数体内的调用
                for call_match in call_pattern.finditer(body):
                    called = call_match.group(1)
                    if called and called in functions and called != name:
                        func.calls.add(called)

    def _extract_function_body(self, source: str, name: str, language: str) -> str:
        """提取单个函数的函数体"""
        if language == "python":
            pattern = re.compile(
                rf'^\s*def\s+{re.escape(name)}\s*\([^)]*\)\s*(?:->.*?)?\s*:(.*?)(?:^\S|\Z)',
                re.MULTILINE | re.DOTALL
            )
            match = pattern.search(source)
            return match.group(1) if match else ""
        else:
            # PHP / C / C++: find function signature then grab everything up to matching }
            sig_pattern = re.compile(
                rf'\b{re.escape(name)}\s*\([^)]*\)\s*\{{',
                re.DOTALL
            )
            sm = sig_pattern.search(source)
            if not sm:
                return ""
            # From the opening {, find the matching closing }
            pos = sm.end()
            depth = 1
            while pos < len(source) and depth > 0:
                if source[pos] == '{':
                    depth += 1
                elif source[pos] == '}':
                    depth -= 1
                pos += 1
            return source[sm.end():pos-1]

    # ----------------------------------------------------------------
    # 路径搜索
    # ----------------------------------------------------------------

    def _find_paths(self, functions: dict[str, FunctionNode],
                    sources: list[str], sinks: list[str]) -> list[CallPath]:
        """
        查找 Source → Sink 调用路径。
        逻辑：某函数 f 调用了 source，且 f（直接或间接）也调用了 sink。
        即数据从 source 流入 f，再从 f 流出到 sink。
        """
        sink_set = set(sinks)
        paths: list[CallPath] = []

        # BFS：从 source 出发，沿"谁调用了 source"方向走 caller 链
        for source_name in sources:
            queue = deque()
            # 初始：找到所有直接调用 source 的函数
            for name, func in functions.items():
                if source_name in func.calls:
                    # 该函数调用了 source，检查它是否也（直接/间接）调用 sink
                    chain = [source_name, name]
                    visited_sinks = self._find_reachable_sinks(
                        functions, name, sink_set, {source_name, name}, max_depth=4
                    )
                    for sink_name, sink_path in visited_sinks:
                        full_path = chain + sink_path
                        sink_func = functions.get(sink_name)
                        if sink_func:
                            paths.append(CallPath(
                                path=full_path,
                                files=[functions.get(n, FunctionNode(n, "", 0)).file_path for n in full_path],
                                lines=[functions.get(n, FunctionNode(n, "", 0)).line_number for n in full_path],
                                vuln_type=sink_func.vuln_type or "command_execution",
                                severity=SEVERITY_MAP.get(sink_func.vuln_type or "", "medium"),
                                description=(
                                    f"跨函数调用链: {' → '.join(full_path)}。"
                                    f"Source '{source_name}' 的数据流经调用链到达 Sink '{sink_name}'"
                                ),
                            ))

        return paths

    def _find_reachable_sinks(self, functions: dict[str, FunctionNode],
                               start: str, sink_set: set[str],
                               visited: set[str], max_depth: int) -> list[tuple[str, list[str]]]:
        """
        从 start 函数出发，沿它所调用的函数链，找到可达的 sink 函数。
        返回: [(sink_name, [intermediate_funcs...]), ...]
        """
        results = []
        queue = deque([(start, [])])

        while queue:
            current, path = queue.popleft()
            if len(path) >= max_depth:
                continue

            func = functions.get(current)
            if not func:
                continue

            for called in func.calls:
                if called in visited:
                    continue
                visited.add(called)
                new_path = path + [called]

                if called in sink_set:
                    results.append((called, new_path))
                else:
                    queue.append((called, new_path))

        return results

    # ----------------------------------------------------------------
    # 输出转换
    # ----------------------------------------------------------------

    def _paths_to_vulns(self, paths: list[CallPath],
                        functions: dict[str, FunctionNode]) -> list[dict]:
        """将调用路径转化为漏洞报告"""
        vulns = []
        seen = set()

        for p in paths:
            # 去重
            key = (p.vuln_type, p.files[-1], p.lines[-1])
            if key in seen:
                continue
            seen.add(key)

            sink_func = functions.get(p.path[-1], FunctionNode("?", "", 0))
            source_func = functions.get(p.path[0], FunctionNode("?", "", 0))

            vulns.append({
                "file_path": p.files[-1],
                "line_number": p.lines[-1],
                "sink_line": p.lines[-1],
                "vuln_type": p.vuln_type,
                "severity": p.severity,
                "language": "unknown",  # 由 pipeline 补充
                "source_code": f"Function: {p.path[0]} (Source: {', '.join(source_func.source_labels)})",
                "sink_code": f"Function: {p.path[-1]} (Sink: {', '.join(sink_func.sink_labels)})",
                "data_flow": " → ".join(p.path),
                "pipeline_stage": "call_graph",
                "description": p.description,
            })

        return vulns

    # ----------------------------------------------------------------
    # 语言选择
    # ----------------------------------------------------------------

    def _get_def_pattern(self, language: str):
        if language == "python":
            return PY_DEF_PATTERN
        elif language == "php":
            return PHP_DEF_PATTERN
        else:
            return C_DEF_PATTERN

    def _get_call_pattern(self, language: str):
        if language == "python":
            return PY_CALL_PATTERN
        elif language == "php":
            return PHP_CALL_PATTERN
        else:
            return C_CALL_PATTERN
