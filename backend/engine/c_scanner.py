"""
C/C++ 代码扫描器 v2（tree-sitter 0.26 兼容）
==========================================
基于 tree-sitter 的 C/C++ 静态安全分析扫描器。

==== 扫描流程 ====

   源码文件
      │
      ▼
   tree-sitter 解析 ──── 生成具体语法树（CST）
      │
      ├──→ 遍历 CST ──→ 找 Source 点（用户输入入口）
      │                 找 Sink 点（危险函数调用）
      │                 找赋值关系（变量传播）
      │
      ▼
   污点追踪器（TaintTracker）──→ 构建变量传播图
      │
      ▼
   Source→Sink 路径分析 ──→ 输出漏洞报告

==== 与 Python 扫描器的区别 ====

1. 使用 tree-sitter 而非 Python AST：
   - C/C++ 没有内置的 AST 解析器
   - tree-sitter 是增量解析引擎，支持 C 和 C++

2. 节点类型不同：
   - Python: ast.Call, ast.Assign, ast.Name...
   - C/C++:  call_expression, declaration, init_declarator, assignment_expression...

3. 变量提取更复杂：
   - 需要处理指针声明（int *p）
   - 需要处理多维数组（char buf[256]）
   - 需要处理类型转换等

4. 需要区分 .c 和 .cpp 文件（使用不同的 parser）
"""
import os
from pathlib import Path

from engine.taint_tracker import TaintTracker
from engine.sources_c import C_SOURCES
from engine.sinks_c import C_SINKS, VulnType

# ---- tree-sitter 导入（带优雅降级） ----
try:
    import tree_sitter_c     # C 语言语法
    import tree_sitter_cpp   # C++ 语言语法
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    # tree-sitter 未安装时，扫描器初始化会抛出 RuntimeError


# ---- 漏洞严重程度映射 ----
SEVERITY_MAP = {
    VulnType.COMMAND_EXECUTION: "critical",    # 命令执行：最高风险
    VulnType.PATH_TRAVERSAL: "high",           # 路径穿越：可访问任意文件
    VulnType.ARBITRARY_FILE_READ: "medium",    # 任意文件读取：中等风险
}


class CScanner:
    """
    C/C++ 静态代码扫描器
    ====================
    逐文件扫描 C/C++ 源码，通过 tree-sitter CST 分析找出潜在安全漏洞。

    依赖:
        pip install tree-sitter tree-sitter-c tree-sitter-cpp
    """

    # C 语言文件扩展名
    C_EXTENSIONS = {".c", ".h"}
    # C++ 文件扩展名
    CPP_EXTENSIONS = {".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".h++", ".c++"}

    # 扫描时跳过的目录
    SKIP_DIRS = {
        "__pycache__", ".git", ".venv", "venv", "build",
        "node_modules", "third_party", "vendor", "extern", "external",
    }

    def __init__(self):
        """
        初始化 C/C++ 扫描器。

        创建两个 parser：
          - C parser:   处理 .c / .h 文件
          - C++ parser: 处理 .cpp / .hpp 等文件

        预建 Source/Sink 索引表。
        """
        if not TREE_SITTER_AVAILABLE:
            raise RuntimeError(
                "tree-sitter 未安装，请运行: pip install tree-sitter tree-sitter-c tree-sitter-cpp"
            )

        # 创建 C 语言 parser
        self.c_lang = Language(tree_sitter_c.language())
        self.c_parser = Parser(self.c_lang)

        # 创建 C++ 语言 parser
        self.cpp_lang = Language(tree_sitter_cpp.language())
        self.cpp_parser = Parser(self.cpp_lang)

        # ---- 建立 Source 索引表 ----
        # key: 函数名 (如 "getenv", "scanf")
        # value: {tainted_params: [...]}
        self.source_info: dict[str, dict] = {}
        for s in C_SOURCES:
            self.source_info[s.func] = {"tainted_params": s.tainted_params}

        # ---- 建立 Sink 索引表 ----
        # key: 函数名 (如 "system", "fopen")
        # value: (vuln_type, dangerous_param_index)
        self.sink_info: dict[str, tuple[str, int | None]] = {}
        for s in C_SINKS:
            self.sink_info[s.func] = (s.vuln_type.value, s.dangerous_param_index)

    # ========================================================================
    # 公开接口
    # ========================================================================

    def scan_directory(self, dir_path: str) -> list[dict]:
        """
        扫描整个目录下的所有 C/C++ 文件。

        参数:
            dir_path: 项目源码目录的绝对路径

        返回:
            list[dict]: 所有发现的漏洞列表
        """
        all_vulns = []
        for file_path in self._collect_c_files(dir_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                vulns = self.scan_source(source, file_path)
                all_vulns.extend(vulns)
            except Exception as e:
                print(f"[WARN] 扫描 {file_path} 出错: {e}")
        return all_vulns

    def scan_source(self, source_code: str, file_path: str = "<unknown>") -> list[dict]:
        """
        扫描单个 C/C++ 文件的源代码。

        参数:
            source_code: 源代码字符串
            file_path:   文件路径

        返回:
            list[dict]: 该文件中发现的漏洞列表
        """
        # ---- 1. 根据文件扩展名选择 parser ----
        ext = Path(file_path).suffix.lower()
        parser = self.cpp_parser if ext in self.CPP_EXTENSIONS else self.c_parser

        # ---- 2. tree-sitter 解析 ----
        source_bytes = source_code.encode("utf-8")
        tree = parser.parse(source_bytes)
        root = tree.root_node  # 语法树的根节点

        # ---- 3. 创建追踪器 ----
        tracker = TaintTracker(file_path=file_path)

        # ---- 4. 一次性遍历收集 Source / Sink / 赋值 ----
        self._walk(root, tracker, source_bytes)

        # ---- 5. 执行分析 ----
        raw_results = tracker.analyze()

        # ---- 6. 格式化输出 ----
        return self._format_results(raw_results, source_code, file_path)

    # ========================================================================
    # 核心遍历逻辑
    # ========================================================================

    def _walk(self, root, tracker: TaintTracker, source_bytes: bytes):
        """
        一次性遍历整个 CST，同时收集 Source / Sink / 赋值关系。

        使用迭代方式（而非递归）避免深层嵌套导致的栈溢出。

        参数:
            root:         tree-sitter 根节点
            tracker:      污点追踪器
            source_bytes: 源文件的 UTF-8 字节
        """
        for node in self._traverse(root):
            self._check_source(node, tracker, source_bytes)
            self._check_sink(node, tracker, source_bytes)
            self._check_assignment(node, tracker, source_bytes)

    def _traverse(self, node):
        """
        迭代遍历 tree-sitter 的所有节点。

        使用栈（stack）模拟递归遍历，避免 Python 递归深度限制。
        遍历顺序为深度优先（后进先出 + reversed 子节点 = 先序遍历）。
        """
        stack = [node]
        while stack:
            n = stack.pop()       # 取出栈顶节点
            yield n               # 产出当前节点
            # 子节点逆序入栈，保证正序遍历
            stack.extend(reversed(n.children))

    # ========================================================================
    # Source 点检测
    # ========================================================================

    def _check_source(self, node, tracker: TaintTracker, source_bytes: bytes):
        """
        检查 CST 节点是否为 Source 点（用户输入入口）。

        检测两类 Source：
          1. 已知函数调用（如 getenv, scanf, fgets）
          2. main 函数的 argv 参数
        """
        # ---- 类型 1：函数调用 Source ----
        if node.type == "call_expression":
            fname = self._func_name(node, source_bytes)  # 获取被调用的函数名
            if fname and fname in self.source_info:
                # 匹配到已知 Source 函数
                info = self.source_info[fname]
                tainted_params = info.get("tainted_params")

                # 提取被污染参数中的变量名
                arg_vars = self._call_arg_vars(node, tainted_params, source_bytes)
                code = self._text(node, source_bytes)

                for var in arg_vars:
                    tracker.mark_source(var, source_func=fname, code=code,
                                        line=node.start_point[0] + 1)  # tree-sitter 行号从 0 开始

        # ---- 类型 2：函数定义的 argv 参数 ----
        if node.type == "function_definition":
            decl = node.child_by_field_name("declarator")  # 函数声明器
            if decl:
                params = decl.child_by_field_name("parameters")  # 参数列表
                if params:
                    # 筛选出 parameter_declaration 类型的子节点
                    param_decls = [c for c in params.children
                                   if c.type == "parameter_declaration"]
                    for pd in param_decls:
                        name = self._decl_name(pd, source_bytes)
                        # 如果参数名是 argv 或 args，视为命令行参数 Source
                        if name and name.lower() in ("argv", "args"):
                            tracker.mark_source(
                                name, source_func="function_argv",
                                code=self._text(pd, source_bytes),
                                line=pd.start_point[0] + 1)

    # ========================================================================
    # Sink 点检测
    # ========================================================================

    def _check_sink(self, node, tracker: TaintTracker, source_bytes: bytes):
        """
        检查 CST 节点是否为 Sink 点（危险函数调用）。

        匹配函数名与预定义的 Sink 列表，提取危险参数中的变量。
        """
        if node.type != "call_expression":
            return

        fname = self._func_name(node, source_bytes)
        if not fname or fname not in self.sink_info:
            return  # 不是已知的危险函数

        # 获取漏洞类型和危险参数索引
        vuln_type, arg_idx = self.sink_info[fname]
        arg_vars = self._call_arg_vars(node, arg_idx, source_bytes)
        code = self._text(node, source_bytes)

        for var in arg_vars:
            tracker.mark_sink(var, sink_func=fname, vuln_type=vuln_type,
                              code=code, line=node.start_point[0] + 1)

    # ========================================================================
    # 赋值关系检测
    # ========================================================================

    def _check_assignment(self, node, tracker: TaintTracker, source_bytes: bytes):
        """
        检查 CST 节点是否为赋值/声明语句，提取变量传播关系。

        处理三种 C/C++ 赋值形式：
          1. 声明+初始化:  int x = expr;      (declaration 节点)
          2. 初始化声明器: char *s = expr;     (init_declarator 节点)
          3. 赋值表达式:   x = expr;           (assignment_expression 节点)
        """
        # ---- 形式 1：声明并赋值 (declaration) ----
        # 如: int x = getenv("HOME");
        if node.type == "declaration":
            decl = node.child_by_field_name("declarator")  # 声明器（变量名部分）
            value = node.child_by_field_name("value")       # 初始值表达式
            if decl and value:
                name = self._decl_name(decl, source_bytes)   # 提取变量名
                vars_in_value = self._expr_vars(value, source_bytes)  # 提取值中的变量
                if name:
                    for v in vars_in_value:
                        tracker.mark_assign(name, v, reason="decl",
                                            code=self._text(node, source_bytes),
                                            line=node.start_point[0] + 1)

        # ---- 形式 2：初始化声明器 (init_declarator) ----
        # 如: char *cmd = argv[1];（多个声明器中的某一个）
        elif node.type == "init_declarator":
            name = self._decl_name(node, source_bytes)
            value = node.child_by_field_name("value")
            if name and value:
                for v in self._expr_vars(value, source_bytes):
                    tracker.mark_assign(name, v, reason="init",
                                        code=self._text(node, source_bytes),
                                        line=node.start_point[0] + 1)

        # ---- 形式 3：赋值表达式 (assignment_expression) ----
        # 如: x = y; 或 x += y;
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")    # 被赋值的变量
            right = node.child_by_field_name("right")  # 赋值来源
            if left and right:
                for lv in self._expr_vars(left, source_bytes):
                    for rv in self._expr_vars(right, source_bytes):
                        tracker.mark_assign(lv, rv, reason="assign",
                                            code=self._text(node, source_bytes),
                                            line=node.start_point[0] + 1)

    # ========================================================================
    # tree-sitter 辅助函数
    # ========================================================================

    def _text(self, node, source_bytes: bytes) -> str:
        """
        获取 CST 节点对应的源码文本。

        tree-sitter 使用字节偏移，从原始字节切片中解码出文本。

        参数:
            node:         CST 节点
            source_bytes: 完整的源文件字节

        返回:
            str: 该节点对应的源码字符串
        """
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _func_name(self, call_node, source_bytes: bytes) -> str | None:
        """
        从 call_expression 节点中提取被调用的函数名。

        tree-sitter 0.26: node.text 可能返回 bytes 或 str，
        兼容两种格式。
        """
        func = call_node.child_by_field_name("function")
        if func is None:
            return None

        # tree-sitter 0.26 兼容：检查 text 属性类型
        if func.text is not None:
            # text 可能是 bytes 或 str
            return func.text.decode("utf-8") if isinstance(func.text, bytes) else func.text

        # 回退：通过字节范围提取
        return self._text(func, source_bytes)

    def _call_arg_vars(self, call_node, arg_idx, source_bytes: bytes) -> list[str]:
        """
        从函数调用节点中提取指定参数的变量名列表。

        参数:
            call_node:     CST call_expression 节点
            arg_idx:       参数索引（None = 所有参数, int = 单个参数, list = 多个参数）
            source_bytes:  源文件字节

        返回:
            list[str]: 指定参数位置的所有变量名
        """
        # 获取 arguments 子节点
        args = call_node.child_by_field_name("arguments")
        if args is None:
            return []

        # 过滤掉括号和逗号，只保留实际参数节点
        arg_nodes = [c for c in args.children if c.type not in ("(", ")", ",")]

        if arg_idx is None:
            # None = 所有参数都可能危险（如 getenv, recv）
            result = []
            for a in arg_nodes:
                result.extend(self._expr_vars(a, source_bytes))
            return result

        if isinstance(arg_idx, list):
            # 列表 = 多个指定索引（如 [0, 1] 表示第 1 和第 2 个参数）
            result = []
            for i in arg_idx:
                if i < len(arg_nodes):
                    result.extend(self._expr_vars(arg_nodes[i], source_bytes))
            return result

        # 单个索引值
        if arg_idx < len(arg_nodes):
            return self._expr_vars(arg_nodes[arg_idx], source_bytes)

        return []  # 索引越界

    def _expr_vars(self, node, source_bytes: bytes) -> list[str]:
        """
        从 C/C++ 表达式中提取所有变量名。

        支持多种表达式类型：
          - identifier:          变量名直接返回
          - string/number/null:  常量，不产生变量
          - binary_expression:   递归提取左右操作数
          - call_expression:     递归提取函数参数（如 sprintf(buf, fmt, src)）
          - parenthesized:       递归提取括号内表达式
          - 其他:                递归遍历子节点

        参数:
            node:         CST 节点
            source_bytes: 源文件字节

        返回:
            list[str]: 表达式中的变量名列表
        """
        # ---- 标识符：直接返回变量名 ----
        if node.type == "identifier":
            return [self._text(node, source_bytes)]

        # ---- 字面量常量：不产生变量 ----
        if node.type in ("string_literal", "number_literal", "char_literal",
                         "null", "true", "false", "nullptr"):
            return []

        # ---- 二元表达式：a + b, a * b, a && b 等 ----
        if node.type == "binary_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            result = []
            if left:
                result.extend(self._expr_vars(left, source_bytes))
            if right:
                result.extend(self._expr_vars(right, source_bytes))
            return result

        # ---- 函数调用（嵌套）：如 sprintf(buf, fmt, src) ----
        if node.type == "call_expression":
            fname = self._func_name(node, source_bytes)
            # 对于字符串复制/拼接函数，最后一个参数通常是 source
            if fname in ("sprintf", "snprintf", "strcat", "strcpy", "strncat", "strncpy"):
                args = node.child_by_field_name("arguments")
                if args:
                    arg_nodes = [c for c in args.children if c.type not in ("(", ")", ",")]
                    # 字符串操作函数的最后一个参数通常是源字符串
                    if len(arg_nodes) >= 2:
                        return self._expr_vars(arg_nodes[-1], source_bytes)
            return []

        # ---- 括号表达式：(expr) ----
        if node.type in ("parenthesized_expression",):
            # 提取括号内的表达式（跳过括号本身）
            for child in node.children:
                if child.type not in ("(", ")"):
                    return self._expr_vars(child, source_bytes)
            return []

        # ---- 默认：递归遍历子节点 ----
        result = []
        for child in node.children:
            result.extend(self._expr_vars(child, source_bytes))
        return result

    def _decl_name(self, declarator, source_bytes: bytes) -> str | None:
        """
        从声明器（declarator / init_declarator）中提取变量名。

        处理多种声明器类型：
          - identifier:              int x              → "x"
          - pointer_declarator:      int *p             → "p"（递归穿透指针）
          - array_declarator:        char buf[256]      → "buf"
          - init_declarator:         int x = 5          → "x"
          - function_declarator:     void (*fp)(int)    → "fp"

        参数:
            declarator:   CST 声明器节点
            source_bytes: 源文件字节

        返回:
            str | None: 变量名，提取失败返回 None
        """
        # 简单标识符
        if declarator.type in ("identifier", "field_identifier"):
            return self._text(declarator, source_bytes)

        # 指针/数组/初始化/函数声明器：递归穿透到内部
        if declarator.type in ("pointer_declarator", "array_declarator",
                               "init_declarator", "function_declarator"):
            inner = declarator.child_by_field_name("declarator")
            if inner:
                return self._decl_name(inner, source_bytes)

        # 回退：遍历子节点找标识符
        for child in declarator.children:
            if child.type == "identifier":
                return self._text(child, source_bytes)

        return None

    def _is_main(self, func_def, source_bytes: bytes) -> bool:
        """
        判断 function_definition 节点是否定义的是 main 函数。
        用于识别命令行入口点（未在当前版本中使用，预留给未来扩展）。
        """
        decl = func_def.child_by_field_name("declarator")
        if decl is None:
            return False
        inner = decl.child_by_field_name("declarator")
        if inner and inner.type == "identifier":
            name = inner.text
            if isinstance(name, bytes):
                name = name.decode("utf-8")
            return name == "main"
        return False

    # ========================================================================
    # 文件收集 & 格式化
    # ========================================================================

    def _collect_c_files(self, dir_path: str) -> list[str]:
        """
        递归收集目录下所有 C/C++ 源文件的路径。

        同时跳过 build/ 和 cmake- 开头的构建目录。
        """
        files = []
        for root, dirs, filenames in os.walk(dir_path):
            # 跳过不需要的目录
            dirs[:] = [d for d in dirs
                       if d not in self.SKIP_DIRS
                       and not d.startswith("cmake")]
            for f in filenames:
                ext = Path(f).suffix.lower()
                if ext in self.C_EXTENSIONS or ext in self.CPP_EXTENSIONS:
                    files.append(os.path.join(root, f))
        return files

    def _format_results(self, raw: list[dict], source_code: str,
                        file_path: str) -> list[dict]:
        """
        将污点追踪器的原始输出格式化为统一的漏洞报告格式。

        参数:
            raw:         污点追踪器的原始分析结果
            source_code: 源文件内容
            file_path:   文件路径

        返回:
            list[dict]: 统一的漏洞报告列表
        """
        results = []
        for r in raw:
            vt = r.get("vuln_type", "")
            # 根据漏洞类型映射严重程度
            severity = SEVERITY_MAP.get(
                VulnType(vt) if vt in VulnType._value2member_map_ else None,
                "medium"
            )
            results.append({
                "file_path": file_path,
                "line_number": r.get("sink_line", r.get("source_line", 0)),
                "vuln_type": vt,
                "severity": severity,
                "language": "c",
                "source_code": r.get("source_code", ""),
                "sink_code": r.get("sink_code", ""),
                "data_flow": r.get("data_flow", ""),
                "source_func": r.get("source_func", ""),
                "sink_func": r.get("sink_func", ""),
                "source_line": r.get("source_line", 0),
                "sink_line": r.get("sink_line", 0),
            })
        return results
