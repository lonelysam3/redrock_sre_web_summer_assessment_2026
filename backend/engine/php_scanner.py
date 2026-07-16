"""
PHP 代码扫描器
=============
基于 tree-sitter 的 PHP 静态安全分析扫描器。

==== 特点 ====

1. 使用 tree-sitter-php 解析 PHP 源码
2. 识别超全局变量（$_GET, $_POST, $_SERVER 等）作为 Source 点
3. 识别危险函数调用（system, eval, mysqli_query 等）作为 Sink 点
4. 识别赋值关系（变量传播），构建污点图
5. 针对 PHP 特有的 XSS / 文件包含 / 反序列化 进行专项检测

==== 依赖 ====

    pip install tree-sitter tree-sitter-php
"""
import os
from pathlib import Path

from engine.taint_tracker import TaintTracker
from engine.sources_php import PHP_SOURCES
from engine.sinks_php import PHP_SINKS, VulnType

try:
    import tree_sitter_php
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


# 严重程度映射表（与 Python 版保持一致，新增 PHP 特有类型）
SEVERITY_MAP = {
    "command_execution": "critical",     # 命令执行：最高风险
    "sql_injection": "high",             # SQL 注入
    "ssrf": "high",                      # SSRF
    "deserialization": "high",           # 反序列化：PHP 高危漏洞
    "file_upload": "high",               # 文件上传：可能 Getshell
    "path_traversal": "medium",          # 路径穿越
    "arbitrary_file_read": "medium",     # 任意文件读取
    "xss": "low",                        # XSS：存在 CSP 等多重缓解
}


class PHPScanner:
    """
    PHP 静态代码扫描器
    ==================
    逐文件扫描 PHP 源码，通过 tree-sitter CST 分析找出潜在安全漏洞。

    支持的漏洞类型：
      - SQL 注入（字符串拼接 → mysqli_query / PDO::query）
      - 命令执行（$_GET → system / eval / shell_exec）
      - SSRF（用户可控 URL → curl_exec / file_get_contents）
      - 路径穿越 / LFI（$_GET → include / require / file_get_contents）
      - 任意文件读取
      - XSS（echo $_GET['name']）
      - 文件上传
      - 反序列化
    """

    # PHP 文件扩展名
    PHP_EXTENSIONS = {".php", ".php3", ".php4", ".php5", ".phtml", ".pht", ".phps", ".inc"}

    # 扫描时跳过的目录
    SKIP_DIRS = {
        "__pycache__", ".git", ".venv", "venv", "build",
        "node_modules", "vendor", "cache", "storage", "tmp",
    }

    def __init__(self):
        if not TREE_SITTER_AVAILABLE:
            raise RuntimeError(
                "tree-sitter 未安装，请运行: "
                "pip install tree-sitter tree-sitter-php"
            )
        # 初始化 PHP parser（tree-sitter-php 0.23+ 使用 language_php()）
        self.php_lang = Language(tree_sitter_php.language_php())
        self.parser = Parser(self.php_lang)

        # ---- 建立 Source 索引 ---- 
        # key: 如 "$_GET", "php://input", "getenv()"
        self.source_set: set[str] = {s.source_name for s in PHP_SOURCES}
        self.source_info: dict[str, PHPSource] = {s.source_name: s for s in PHP_SOURCES}

        # ---- 建立 Sink 索引 ----
        # key: 函数名 → [(vuln_type, dangerous_param_index), ...]
        self.sink_info: dict[str, list[tuple[str, int | None]]] = {}
        for s in PHP_SINKS:
            fn = s.func_name
            if fn not in self.sink_info:
                self.sink_info[fn] = []
            self.sink_info[fn].append((s.vuln_type, s.dangerous_param_index))

    def scan_directory(self, dir_path: str) -> list[dict]:
        """扫描整个目录下的所有 PHP 文件"""
        all_vulns = []
        for file_path in self._collect_php_files(dir_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                vulns = self.scan_source(source, file_path)
                all_vulns.extend(vulns)
            except Exception as e:
                print(f"[WARN] 扫描 {file_path} 出错: {e}")
        return all_vulns

    def scan_source(self, source_code: str, file_path: str = "<unknown>") -> list[dict]:
        """扫描单个 PHP 文件的源代码"""
        source_bytes = source_code.encode("utf-8")
        self._source_bytes = source_bytes  # 缓存供辅助方法使用
        tree = self.parser.parse(source_bytes)
        root = tree.root_node

        tracker = TaintTracker(file_path=file_path)
        self._walk(root, tracker, source_bytes)
        raw_results = tracker.analyze()
        return self._format_results(raw_results, file_path)

    def _walk(self, root, tracker: TaintTracker, source_bytes: bytes):
        """一次性遍历 CST，收集 Source / Sink / 赋值关系"""
        for node in self._traverse(root):
            self._detect_source(node, tracker, source_bytes)
            self._detect_sink(node, tracker, source_bytes)
            self._detect_assignment(node, tracker, source_bytes)
            self._detect_xss_direct_echo(node, tracker, source_bytes)

    def _traverse(self, node):
        """迭代遍历所有 CST 节点"""
        stack = [node]
        while stack:
            n = stack.pop()
            yield n
            for child in reversed(n.children):
                if child.type not in ("comment", "text_interpolation"):
                    stack.append(child)

    # ===================================================================
    # Source 点检测
    # ===================================================================

    def _detect_source(self, node, tracker: TaintTracker, source_bytes: bytes):
        """检测 PHP Source 点（超全局变量 + 输入流）"""
        text = self._text(node, source_bytes)

        # 模式 1：超全局数组访问 $_GET['name']
        if node.type == "subscript_expression":
            var_text = self._text_of_first_child(node, source_bytes)
            if var_text in self.source_set:
                assigned_to = self._get_assigned_var(node)
                tracker.mark_source(
                    assigned_to,
                    source_func=var_text,
                    code=text,
                    line=node.start_point[0] + 1,
                )

        # 模式 2：函数调用作为 source（如 getenv(), file_get_contents()）
        elif node.type == "function_call_expression":
            func_name = self._func_name(node, source_bytes)
            if func_name and func_name in self.source_set:
                assigned_to = self._get_assigned_var(node)
                tracker.mark_source(
                    assigned_to,
                    source_func=func_name,
                    code=text,
                    line=node.start_point[0] + 1,
                )

    # ===================================================================
    # Sink 点检测
    # ===================================================================

    def _detect_sink(self, node, tracker: TaintTracker, source_bytes: bytes):
        """检测 PHP Sink 点（危险函数调用）"""
        if node.type != "function_call_expression":
            return

        func_name = self._func_name(node, source_bytes)
        if not func_name or func_name not in self.sink_info:
            return

        text = self._text(node, source_bytes)
        for vuln_type, arg_idx in self.sink_info[func_name]:
            arg_vars = self._extract_arg_vars(node, arg_idx, source_bytes)
            for var in arg_vars:
                tracker.mark_sink(
                    var,
                    sink_func=func_name,
                    vuln_type=vuln_type,
                    code=text,
                    line=node.start_point[0] + 1,
                )

    # ===================================================================
    # XSS 直接输出检测
    # ===================================================================

    def _detect_xss_direct_echo(self, node, tracker: TaintTracker, source_bytes: bytes):
        """
        专门检测 XSS 模式：echo $_GET['x'] 或 print $user_input。

        特征：echo/print 语句的参数直接引用已被污染的变量。
        """
        if node.type != "echo_statement" and node.type != "print_statement":
            return

        text = self._text(node, source_bytes)
        # 提取 echo/print 参数中的变量名
        vars_in_echo = self._extract_variable_names(node, source_bytes)

        # 检查这些变量是否已被标记为 source
        for var in vars_in_echo:
            if var in tracker.graph.nodes and tracker.graph.nodes[var].is_source:
                tracker.mark_sink(
                    var,
                    sink_func="echo/print",
                    vuln_type=VulnType.XSS.value,
                    code=text,
                    line=node.start_point[0] + 1,
                )

    # ===================================================================
    # 赋值检测
    # ===================================================================

    def _detect_assignment(self, node, tracker: TaintTracker, source_bytes: bytes):
        """检测 PHP 赋值关系"""
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right:
                left_vars = self._extract_variable_names(left, source_bytes)
                right_vars = self._extract_variable_names(right, source_bytes)
                text = self._text(node, source_bytes)
                for lv in left_vars:
                    for rv in right_vars:
                        tracker.mark_assign(
                            lv, rv, reason="assign",
                            code=text, line=node.start_point[0] + 1,
                        )

        # 字符串拼接：$sql = "SELECT ..." . $input
        elif node.type == "binary_expression":
            if node.child_by_field_name("operator"):
                op_text = self._text(node.child_by_field_name("operator"), source_bytes)
                if op_text == ".":
                    _ = op_text  # 暂存以备后用

    # ===================================================================
    # 辅助方法
    # ===================================================================

    def _text(self, node, source_bytes: bytes) -> str:
        """获取节点源码文本"""
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _text_of_first_child(self, node, source_bytes: bytes) -> str:
        """获取第一个子节点的文本"""
        if node.children:
            return self._text(node.children[0], source_bytes)
        return ""

    def _func_name(self, call_node, source_bytes: bytes) -> str | None:
        """从 function_call_expression 中提取函数名"""
        func = call_node.child_by_field_name("function")
        if func is None:
            return None
        return self._text(func, source_bytes)

    def _get_assigned_var(self, node) -> str:
        """
        获取当前节点被赋值给的变量名。
        向上查找父节点链，找到最近的赋值语句左侧变量。
        """
        current = node
        for _ in range(5):
            parent = current.parent
            if parent is None:
                break
            if parent.type == "assignment_expression":
                left = parent.child_by_field_name("left")
                if left and left.type == "variable_name":
                    # variable_name 结构: [$: '$', name: 'id']
                    # 直接用 _text 取完整文本如 "$id"
                    var_name = self._text(left, self._source_bytes)
                    if var_name:
                        return var_name
                break
            current = parent
        return f"__php_var_{node.start_point[0] + 1}"

    def _extract_variable_names(self, node, source_bytes: bytes) -> list[str]:
        """从表达式节点中提取所有变量名"""
        if node.type == "variable_name":
            text = self._text(node, source_bytes)
            return [text] if text else []
        if node.type == "name":
            return [self._text(node, source_bytes)]
        if node.type in ("string", "integer", "float", "boolean", "null"):
            return []

        result = []
        for child in node.children:
            result.extend(self._extract_variable_names(child, source_bytes))
        return result

    def _extract_arg_vars(self, call_node, arg_idx, source_bytes: bytes) -> list[str]:
        """从函数调用中提取指定参数的变量名"""
        args = call_node.child_by_field_name("arguments")
        if args is None:
            return []
        arg_nodes = [c for c in args.children
                     if c.type not in ("(", ")", ",")]
        if arg_idx is None:
            arg_idx = 0
        if arg_idx < len(arg_nodes):
            return self._extract_variable_names(arg_nodes[arg_idx], source_bytes)
        return []

    def _collect_php_files(self, dir_path: str) -> list[str]:
        """递归收集目录下所有 PHP 文件"""
        files = []
        for root, dirs, filenames in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for f in filenames:
                ext = Path(f).suffix.lower()
                if ext in self.PHP_EXTENSIONS:
                    files.append(os.path.join(root, f))
        return files

    def _format_results(self, raw: list[dict], file_path: str) -> list[dict]:
        """格式化输出统一漏洞报告"""
        results = []
        for r in raw:
            vt = r.get("vuln_type", "")
            severity = SEVERITY_MAP.get(vt, "medium")
            results.append({
                "file_path": file_path,
                "line_number": r.get("sink_line", r.get("source_line", 0)),
                "vuln_type": vt,
                "severity": severity,
                "language": "php",
                "source_code": r.get("source_code", ""),
                "sink_code": r.get("sink_code", ""),
                "data_flow": r.get("data_flow", ""),
                "source_func": r.get("source_func", ""),
                "sink_func": r.get("sink_func", ""),
                "source_line": r.get("source_line", 0),
                "sink_line": r.get("sink_line", 0),
            })
        return results
