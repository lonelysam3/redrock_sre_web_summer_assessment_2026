"""
MCP Tool 模块 — 代码审计工具集
=============================
暴露给 AI 的可调用工具，让 AI 在分析漏洞时自主搜索源码中的危险函数和用户输入。

工具设计遵循 MCP 思想：每个工具有 name / description / parameters schema，
AI 在分析过程中通过 JSON 格式请求工具调用，系统执行后将结果反馈给 AI 继续分析。

工具列表:
  1. search_dangerous_calls  — 在文件中搜索所有危险函数调用
  2. search_user_inputs      — 在文件中搜索所有用户输入入口
  3. read_file_region        — 读取文件指定行范围的代码
  4. search_project          — 在整个项目中搜索正则模式
  5. trace_variable_flow     — 追踪变量在文件中的传播路径
  6. list_project_files      — 列出项目中所有源码文件
"""
from __future__ import annotations
import re
import json
from pathlib import Path
from dataclasses import dataclass, field


# ========================================================================
# 工具定义
# ========================================================================

@dataclass
class MCPTool:
    """MCP 工具定义"""
    name: str
    description: str
    parameters: dict  # JSON Schema 格式的参数定义


# 工具注册表
MCP_TOOLS: list[MCPTool] = [
    MCPTool(
        name="search_dangerous_calls",
        description=(
            "在指定文件中搜索所有危险函数调用（SQL查询、命令执行、文件包含、反序列化等）。"
            "返回函数名、行号、完整调用代码。用于定位 Sink 点。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "要搜索的文件路径"},
            },
            "required": ["file_path"],
        },
    ),
    MCPTool(
        name="search_user_inputs",
        description=(
            "在指定文件中搜索所有用户/外部输入入口（$_GET、$_POST、$_REQUEST、"
            "php://input、$_COOKIE、$_SERVER、$_FILES、$_SESSION 等）。"
            "返回变量名、行号、完整代码。用于定位 Source 点。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "要搜索的文件路径"},
            },
            "required": ["file_path"],
        },
    ),
    MCPTool(
        name="read_file_region",
        description=(
            "读取文件指定行范围的代码。用于获取 Source 或 Sink 周围的完整上下文。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "文件路径"},
                "start_line": {"type": "integer", "description": "起始行号（1-based）"},
                "end_line": {"type": "integer", "description": "结束行号（1-based）"},
            },
            "required": ["file_path", "start_line", "end_line"],
        },
    ),
    MCPTool(
        name="search_project",
        description=(
            "在整个项目中按正则模式搜索代码。用于查找特定变量、函数调用、"
            "配置项等跨文件信息。返回所有匹配的文件路径、行号和代码行。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "正则表达式搜索模式"},
                "file_pattern": {"type": "string", "description": "可选，限制文件类型（如 *.php）", "default": "*"},
            },
            "required": ["pattern"],
        },
    ),
    MCPTool(
        name="trace_variable_flow",
        description=(
            "追踪指定变量在文件中的赋值和使用链路。从变量定义/赋值处开始，"
            "沿代码追踪它的所有使用位置（包括拼接、函数参数传递等）。"
            "返回赋值链列表，展示变量如何从 Source 传播到 Sink。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "文件路径"},
                "variable_name": {"type": "string", "description": "要追踪的变量名（如 $username）"},
            },
            "required": ["file_path", "variable_name"],
        },
    ),
    MCPTool(
        name="list_project_files",
        description="列出项目中所有源码文件路径，按语言分类。",
        parameters={
            "type": "object",
            "properties": {
                "project_path": {"type": "string", "description": "项目根目录"},
            },
            "required": ["project_path"],
        },
    ),
    MCPTool(
        name="apply_code_fix",
        description=(
            "直接修改源码文件，应用修复。传入文件路径、起始行、结束行和替换代码，"
            "工具会用新代码替换指定行范围的内容。自动创建 .bak 备份文件。"
            "用于在验证漏洞后自动修复代码。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "要修改的文件路径"},
                "start_line": {"type": "integer", "description": "替换起始行号（1-based）"},
                "end_line": {"type": "integer", "description": "替换结束行号（1-based，含）"},
                "new_code": {"type": "string", "description": "替换用的新代码（可多行）"},
            },
            "required": ["file_path", "start_line", "end_line", "new_code"],
        },
    ),
    # ---- 沙箱动态验证工具 ----
    MCPTool(
        name="run_target_app",
        description=(
            "在本地沙箱中启动被扫描的目标应用（Flask 项目），返回监听端口。"
            "用于动态验证 Web 类漏洞（SQL 注入/SSRF/XSS 等）：启动后用 "
            "send_http_request 发送攻击 Payload，根据真实响应判定漏洞。"
            "验证结束请调用 stop_target_app。"
        ),
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    MCPTool(
        name="send_http_request",
        description=(
            "向沙箱中运行的目标应用发送 HTTP 请求，返回状态码和响应内容摘要。"
            "method: GET/POST；path: 请求路径（可含查询串）；"
            "params: 查询参数对象（如 {\"q\": \"payload\"}）；"
            "data: POST 表单体字符串（如 key=value&key2=value2）。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "HTTP 方法，默认 GET"},
                "path": {"type": "string", "description": "请求路径，如 / 或 /product/1"},
                "params": {"type": "object", "description": "查询参数对象"},
                "data": {"type": "string", "description": "POST 表单体（key=value&...）"},
                "files": {"type": "object", "description": "multipart 文件上传，如 {表单字段名: {'filename': 'a.pkl', 'content': '...'}}"},
            },
            "required": ["path"],
        },
    ),
    MCPTool(
        name="stop_target_app",
        description="停止并清理沙箱中运行的目标应用。",
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
]


# ========================================================================
# 工具执行引擎
# ========================================================================

# PHP 危险函数模式
PHP_DANGEROUS_PATTERNS = {
    "SQL查询": [
        r"(?:mysqli_query|mysql_query|pg_query|sqlite_query|odbc_exec)\s*\(",
        r"->query\s*\(",
        r"->exec\s*\(",
        r"->prepare\s*\(",
        r"->execute\s*\(",
    ],
    "命令执行": [
        r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(",
        r"\beval\s*\(",
        r"\bassert\s*\(",
        r"\bcreate_function\s*\(",
        r"\bpreg_replace\s*\(.*/e",
    ],
    "文件包含": [
        r"\b(?:include|require)(?:_once)?\s*\(?\s*\$",
    ],
    "SSRF": [
        r"\b(?:curl_exec|file_get_contents|readfile|fopen|fsockopen)\s*\(",
    ],
    "反序列化": [
        r"\bunserialize\s*\(",
    ],
    "文件上传": [
        r"\bmove_uploaded_file\s*\(",
        r"\bcopy\s*\(\s*\$_(?:FILES|GET|POST)",
    ],
    "动态函数调用": [
        r"\bcall_user_func\s*\(",
        r"\bforward_static_call\s*\(",
    ],
}

# PHP Source 点模式
PHP_SOURCE_PATTERNS = {
    "GET参数": r'\$_GET\b',
    "POST参数": r'\$_POST\b',
    "REQUEST参数": r'\$_REQUEST\b',
    "COOKIE": r'\$_COOKIE\b',
    "SERVER变量": r'\$_SERVER\b',
    "FILES上传": r'\$_FILES\b',
    "SESSION": r'\$_SESSION\b',
    "环境变量": r'\$_ENV\b',
    "HTTP原始输入": r'php://input',
    "请求头": r'\bgetallheaders\s*\(',
    "命令行参数": r'\$argv\b',
}


class MCPToolExecutor:
    """MCP 工具执行器"""

    def __init__(self, project_path: str,
                 source_code_map: dict[str, str] | None = None,
                 allow_fix: bool = False,
                 sandbox=None):
        self.project_path = project_path
        self._allow_fix = allow_fix  # 只有修复流程才允许 apply_code_fix
        self._sandbox = sandbox      # 沙箱执行器（验证流程传入）
        self._source_map = source_code_map or {}
        if not self._source_map:
            self._build_source_map()

    def _build_source_map(self):
        """构建项目文件 → 源码映射"""
        php_exts = {".php", ".php3", ".php4", ".php5", ".phtml", ".pht", ".inc"}
        py_exts = {".py"}
        c_exts = {".c", ".h", ".cpp", ".hpp"}
        skip_dirs = {"__pycache__", ".git", "vendor", "node_modules", ".venv", "venv"}

        for fp in Path(self.project_path).rglob("*"):
            if fp.is_file() and fp.suffix.lower() in (php_exts | py_exts | c_exts):
                if set(fp.parts) & skip_dirs:
                    continue
                try:
                    self._source_map[str(fp)] = fp.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    pass

    def _read_file(self, file_path: str) -> tuple[list[str], str]:
        """读取文件，返回 (行列表, 源码)。

        支持相对路径（相对项目根解析）与绝对路径；
        匹配不到时按文件名/路径后缀在源码索引中回退查找。
        """
        source = self._source_map.get(file_path, "")
        if not source:
            # 相对路径 → 拼项目根
            fp = Path(file_path)
            if not fp.is_absolute() and self.project_path:
                candidate = Path(self.project_path) / fp
                if str(candidate) in self._source_map:
                    file_path = str(candidate)
                    source = self._source_map[file_path]
            if not source and fp.exists():
                try:
                    source = fp.read_text(encoding="utf-8", errors="ignore")
                    file_path = str(fp)
                except Exception:
                    pass
            if not source:
                # 回退：按规范化路径后缀在索引里找
                norm = str(fp).replace("\\", "/").lower()
                for key, val in self._source_map.items():
                    if key.replace("\\", "/").lower().endswith(norm):
                        source = val
                        file_path = key
                        break
        lines = source.split("\n")
        return lines, source

    # ================================================================
    # 工具实现
    # ================================================================

    def search_dangerous_calls(self, file_path: str) -> str:
        """搜索文件中的危险函数调用"""
        lines, source = self._read_file(file_path)
        if not source:
            return json.dumps({"error": f"文件不存在或无法读取: {file_path}"}, ensure_ascii=False)

        findings = []
        for i, line in enumerate(lines, 1):
            for category, patterns in PHP_DANGEROUS_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        findings.append({
                            "line": i,
                            "category": category,
                            "code": line.strip(),
                        })
                        break  # 每行每个类别只报一次

        return json.dumps({
            "file": file_path,
            "total": len(findings),
            "dangerous_calls": findings,
        }, ensure_ascii=False, indent=2)

    def search_user_inputs(self, file_path: str) -> str:
        """搜索文件中的用户输入入口"""
        lines, source = self._read_file(file_path)
        if not source:
            return json.dumps({"error": f"文件不存在或无法读取: {file_path}"}, ensure_ascii=False)

        findings = []
        for i, line in enumerate(lines, 1):
            for source_name, pattern in PHP_SOURCE_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "line": i,
                        "source_type": source_name,
                        "code": line.strip(),
                    })
                    break

        return json.dumps({
            "file": file_path,
            "total": len(findings),
            "user_inputs": findings,
        }, ensure_ascii=False, indent=2)

    def read_file_region(self, file_path: str, start_line: int, end_line: int) -> str:
        """读取文件指定行范围"""
        lines, source = self._read_file(file_path)
        if not source:
            return json.dumps({"error": f"文件不存在: {file_path}"}, ensure_ascii=False)

        start = max(0, start_line - 1)
        end = min(len(lines), end_line)
        region = []
        for i in range(start, end):
            region.append(f"{i + 1:4d} | {lines[i].rstrip()}")
        return "\n".join(region) if region else "(空)"

    def search_project(self, pattern: str, file_pattern: str = "*") -> str:
        """在项目中搜索正则模式"""
        findings = []
        for fp, source in self._source_map.items():
            # 文件名过滤
            if file_pattern != "*":
                from fnmatch import fnmatch
                if not fnmatch(Path(fp).name, file_pattern):
                    continue

            lines = source.split("\n")
            for i, line in enumerate(lines, 1):
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "file": fp,
                            "line": i,
                            "code": line.strip()[:200],  # 截断长行
                        })
                except re.error:
                    return json.dumps({"error": f"无效的正则表达式: {pattern}"}, ensure_ascii=False)

        return json.dumps({
            "pattern": pattern,
            "total_matches": len(findings),
            "results": findings[:50],  # 最多 50 条
        }, ensure_ascii=False, indent=2)

    def trace_variable_flow(self, file_path: str, variable_name: str) -> str:
        """追踪变量在文件中的传播路径"""
        lines, source = self._read_file(file_path)
        if not source:
            return json.dumps({"error": f"文件不存在: {file_path}"}, ensure_ascii=False)

        var_escaped = re.escape(variable_name)
        # 用 (?<!\w) 和 (?!\w) 代替 \b，兼容 $ 前缀的变量名
        usage_pattern = re.compile(rf'(?<!\w){var_escaped}(?!\w)')

        steps = []
        for i, line in enumerate(lines, 1):
            if usage_pattern.search(line):
                is_assign = bool(re.search(
                    rf'{var_escaped}\s*=(?!=)', line
                ))
                steps.append({
                    "line": i,
                    "type": "赋值" if is_assign else "引用",
                    "code": line.strip(),
                })

        return json.dumps({
            "variable": variable_name,
            "file": file_path,
            "total_refs": len(steps),
            "flow": steps,
        }, ensure_ascii=False, indent=2)

    def list_project_files(self, project_path: str = "") -> str:
        """列出项目文件"""
        by_ext = {}
        for fp in self._source_map:
            ext = Path(fp).suffix.lower()
            if ext not in by_ext:
                by_ext[ext] = []
            by_ext[ext].append(fp)

        return json.dumps({
            "project_path": project_path or self.project_path,
            "total_files": len(self._source_map),
            "by_extension": {k: len(v) for k, v in by_ext.items()},
            "files": {k: v for k, v in by_ext.items()},
        }, ensure_ascii=False, indent=2)

    def apply_code_fix(self, file_path: str, start_line: int,
                        end_line: int, new_code: str) -> str:
        """
        直接修改源码文件，用 new_code 替换 [start_line, end_line] 范围。
        自动创建 .bak 备份。

        参数:
            file_path:  文件路径（绝对或相对 project_path）
            start_line: 起始行（1-based，含）
            end_line:   结束行（1-based，含）
            new_code:   替换用的新代码

        返回:
            JSON 字符串，包含修改结果
        """
        import shutil

        # 解析路径
        fp = Path(file_path)
        if not fp.is_absolute():
            fp = Path(self.project_path) / file_path

        if not fp.exists():
            return json.dumps({
                "success": False,
                "error": f"文件不存在: {fp}"
            }, ensure_ascii=False)

        try:
            # 读取原文件
            with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            total = len(lines)
            s = max(0, start_line - 1)
            e = min(total, end_line)

            if s >= total:
                return json.dumps({
                    "success": False,
                    "error": f"起始行 {start_line} 超出文件总行数 {total}"
                }, ensure_ascii=False)

            # 创建备份
            bak = str(fp) + '.bak'
            shutil.copy2(fp, bak)

            # 确保 new_code 以换行结尾
            fixed_code = new_code
            if not fixed_code.endswith('\n'):
                fixed_code += '\n'

            # 执行替换
            new_lines = (
                lines[:s]
                + fixed_code.splitlines(keepends=True)
                + lines[e:]
            )

            with open(fp, 'w', encoding='utf-8', errors='ignore') as f:
                f.writelines(new_lines)

            # 更新内存缓存
            self._source_map[str(fp)] = ''.join(new_lines)

            return json.dumps({
                "success": True,
                "file": str(fp),
                "backup": bak,
                "old_lines": f"{start_line}-{end_line}（共 {e - s} 行）",
                "new_lines_count": len(fixed_code.splitlines()),
                "old_code_preview": ''.join(lines[s:e]).rstrip()[:300],
                "new_code_preview": fixed_code.rstrip()[:300],
            }, ensure_ascii=False, indent=2)

        except Exception as ex:
            return json.dumps({
                "success": False,
                "error": f"修改失败: {ex}"
            }, ensure_ascii=False)

    # ================================================================
    # 工具调度
    # ================================================================

    def execute(self, tool_name: str, arguments: dict) -> str:
        """根据工具名和参数执行对应工具，返回结果字符串"""
        # 双重保险：验证流程不允许修改源文件，即使模型执意调用也拒绝
        if tool_name == "apply_code_fix" and not self._allow_fix:
            return json.dumps({
                "success": False,
                "error": "当前流程（验证）不允许修改源文件。修复请走修复流程。"
            }, ensure_ascii=False)

        tool_map = {
            "search_dangerous_calls": lambda: self.search_dangerous_calls(
                arguments.get("file_path", "")
            ),
            "search_user_inputs": lambda: self.search_user_inputs(
                arguments.get("file_path", "")
            ),
            "read_file_region": lambda: self.read_file_region(
                arguments.get("file_path", ""),
                int(arguments.get("start_line", 1)),
                int(arguments.get("end_line", 10)),
            ),
            "search_project": lambda: self.search_project(
                arguments.get("pattern", ""),
                arguments.get("file_pattern", "*"),
            ),
            "trace_variable_flow": lambda: self.trace_variable_flow(
                arguments.get("file_path", ""),
                arguments.get("variable_name", ""),
            ),
            "list_project_files": lambda: self.list_project_files(
                arguments.get("project_path", self.project_path),
            ),
            "apply_code_fix": lambda: self.apply_code_fix(
                arguments.get("file_path", ""),
                int(arguments.get("start_line", 1)),
                int(arguments.get("end_line", 1)),
                arguments.get("new_code", ""),
            ),
            "run_target_app": lambda: self._run_target_app(),
            "send_http_request": lambda: self._send_http_request(arguments),
            "stop_target_app": lambda: self._stop_target_app(),
        }

        handler = tool_map.get(tool_name)
        if handler is None:
            return json.dumps({"error": f"未知工具: {tool_name}"}, ensure_ascii=False)

        try:
            return handler()
        except Exception as e:
            return json.dumps({"error": f"工具执行失败: {str(e)}"}, ensure_ascii=False)

    # ---- 沙箱工具实现 ----

    def _run_target_app(self) -> str:
        if self._sandbox is None:
            return json.dumps({
                "success": False,
                "error": "沙箱不可用（目标应用不是可启动的 Flask 项目）",
            }, ensure_ascii=False)
        return json.dumps(self._sandbox.start(), ensure_ascii=False)

    def _send_http_request(self, arguments: dict) -> str:
        if self._sandbox is None:
            return json.dumps({
                "success": False,
                "error": "沙箱不可用，请先 run_target_app",
            }, ensure_ascii=False)
        params = arguments.get("params")
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except Exception:
                params = None
        files = arguments.get("files")
        if isinstance(files, str):
            try:
                files = json.loads(files)
            except Exception:
                files = None
        resp = self._sandbox.request(
            method=arguments.get("method", "GET"),
            path=arguments.get("path", "/"),
            params=params if isinstance(params, dict) else None,
            data=arguments.get("data"),
            files=files if isinstance(files, dict) else None,
        )
        # 响应摘要限制体积，避免 token 爆炸
        if isinstance(resp.get("body"), str):
            resp["body"] = resp["body"][:2000]
        if isinstance(resp.get("headers"), dict):
            resp["headers"] = dict(list(resp["headers"].items())[:10])
        return json.dumps(resp, ensure_ascii=False)

    def _stop_target_app(self) -> str:
        if self._sandbox is None:
            return json.dumps({"success": True}, ensure_ascii=False)
        return json.dumps(self._sandbox.stop(), ensure_ascii=False)


# ========================================================================
# Prompt 生成
# ========================================================================

def build_tool_system_prompt(include_fix_tool: bool = False,
                            include_sandbox: bool = False) -> str:
    """生成描述可用工具的 System Prompt 片段。

    include_fix_tool=False（默认）：不暴露 apply_code_fix —— 验证流程专用，
    保证"payload 验证"与"AI 修复"分离。
    include_sandbox=True：暴露沙箱动态验证工具（run_target_app 等）。
    """
    tools = [t for t in MCP_TOOLS
             if (include_fix_tool or t.name != "apply_code_fix")
             and (include_sandbox or not t.name.startswith(
                 ("run_target_app", "send_http_request", "stop_target_app")))]

    tool_list = "\n".join(
        f"- **{t.name}**: {t.description}"
        for t in tools
    )

    fix_hint = ("- 确认漏洞后，用 apply_code_fix 直接修改源文件应用修复\n"
                if include_fix_tool
                else "- 只做验证与分析，不要尝试修改任何源文件\n")

    return """## 可用工具

你可以调用以下工具来搜索和分析项目代码：

{tool_list}

### 工具调用方式

需要调用工具时，输出一个 JSON 代码块。支持以下任意格式：

**推荐格式（简洁）：**
```json
[{{"name": "search_user_inputs", "arguments": {{"file_path": "register.php"}}}}]
```

**也支持：**
```json
{{"tool_calls": [{{"name": "search_dangerous_calls", "arguments": {{"file_path": "register.php"}}}}]}}
```

**或函数调用风格：**
```
search_dangerous_calls(file_path="register.php")
```

系统会执行工具并返回结果。收到结果后继续或输出最终 JSON。

### 提示
- 优先 search_user_inputs + search_dangerous_calls 定位 Source/Sink
- 用 read_file_region 读取关键代码上下文
- 用 search_project(pattern="exec|system") 跨文件搜索危险函数
- 工具返回的 file_path 可用于后续 read_file_region
{fix_hint}- 分析完成后输出最终 JSON，不要再用 ```json 包裹""".format(
        tool_list=tool_list, fix_hint=fix_hint)


def parse_tool_calls(response: str) -> list[dict]:
    """从 AI 回复中解析工具调用请求"""
    calls = []

    # 策略 0：Claude 风格 XML 工具调用（v4 模型偶尔用）
    # <tool_calls><invoke name="x"><parameter name="k">v</parameter></invoke>...</tool_calls>
    for m in re.finditer(
            r'<(?:(?:\w+:)?invoke)\s+name="([^"]+)"[^>]*>([\s\S]*?)</(?:\w+:)?invoke>',
            response):
        name = m.group(1)
        body = m.group(2)
        args: dict = {}
        for pm in re.finditer(
                r'<(?:(?:\w+:)?parameter)\s+name="([^"]+)"[^>]*>([\s\S]*?)</(?:\w+:)?parameter>',
                body):
            raw = pm.group(2).strip()
            val: object = raw
            try:
                val = json.loads(raw)
            except Exception:
                pass  # 纯文本参数，保留字符串
            args[pm.group(1)] = val
        calls.append(dict(name=name, arguments=args))
    if calls:
        return calls

    # 策略 1： ```json ... ``` 中的 tool_calls
    for m in re.finditer(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response):
        try:
            data = json.loads(m.group(1))
            if "tool_calls" in data:
                for tc in data["tool_calls"]:
                    calls.append(dict(name=tc.get("name", ""), arguments=tc.get("arguments", {})))
        except (json.JSONDecodeError, TypeError):
            pass
    if calls:
        return calls

    # 策略 1b：```json [...] 数组格式（系统 prompt 推荐的格式）
    # 用括号计数提取完整 JSON 数组，处理参数中含嵌套 {} 的情况
    for m in re.finditer(r'```(?:json)?\s*\[', response):
        start = m.end() - 1  # 指向 '['
        depth = 0
        end = start
        for i in range(start, len(response)):
            if response[i] == '[':
                depth += 1
            elif response[i] == ']':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end > start:
            try:
                data = json.loads(response[start:end])
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "name" in item:
                            calls.append(dict(name=item.get("name", ""),
                                             arguments=item.get("arguments", {})))
            except (json.JSONDecodeError, TypeError):
                pass
    if calls:
        return calls

    # 策略 1c：裸 JSON 数组 [{"name":...,"arguments":{...}}]（无 ``` 包裹）
    # 括号计数提取
    stripped = response.strip()
    if stripped.startswith('['):
        depth = 0
        end = 0
        for i, ch in enumerate(stripped):
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end > 0:
            try:
                data = json.loads(stripped[:end])
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "name" in item:
                            calls.append(dict(name=item.get("name", ""),
                                             arguments=item.get("arguments", {})))
            except (json.JSONDecodeError, TypeError):
                pass
    if calls:
        return calls

    # 策略 2：裸 JSON 对象含 tool_calls（无 ``` 包裹）
    for m in re.finditer(r'\{\s*"tool_calls"\s*:\s*\[([\s\S]*?)\]\s*\}', response):
        try:
            data = json.loads(m.group(0))
            for tc in data.get("tool_calls", []):
                calls.append(dict(name=tc.get("name", ""), arguments=tc.get("arguments", {})))
        except (json.JSONDecodeError, TypeError):
            pass
    if calls:
        return calls

    # 策略 3：单个裸 JSON 对象含 name + arguments（支持空参数 {}）
    for m in re.finditer(r'\{\s*"name"\s*:\s*"(\w+)"\s*,\s*"arguments"\s*:', response):
        # 括号计数提取 arguments 对象（支持嵌套与空对象）
        start = m.end()
        while start < len(response) and response[start] != '{':
            start += 1
        if start >= len(response):
            continue
        depth = 0
        end = start
        for i in range(start, len(response)):
            if response[i] == '{':
                depth += 1
            elif response[i] == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        try:
            args = json.loads(response[start:end])
            if isinstance(args, dict):
                calls.append(dict(name=m.group(1), arguments=args))
        except (json.JSONDecodeError, TypeError):
            pass
    if calls:
        return calls

    # 策略 4：tool_name(file_path="...") 函数调用风格
    for m in re.finditer(r'(search_\w+|read_file_\w+|trace_\w+|list_\w+|apply_\w+)\s*\(\s*([^)]*)\s*\)', response):
        name = m.group(1)
        args_str = m.group(2)
        args = {}
        for am in re.finditer(r'''(\w+)\s*=\s*["']([^"']+)["']''', args_str):
            args[am.group(1)] = am.group(2)
        if args:
            calls.append(dict(name=name, arguments=args))

    return calls
