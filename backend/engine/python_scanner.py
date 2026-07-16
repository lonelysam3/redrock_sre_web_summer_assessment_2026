"""
Python 代码扫描器（v2，支持 import 解析）
======================================
基于 Python AST（抽象语法树）的静态安全分析扫描器。

==== 扫描流程 ====

   源码文件
      │
      ▼
   ast.parse()  ──── 解析为抽象语法树
      │
      ├──→ 扫描 import 语句 ──→ 建立别名映射表（如 request → flask.request）
      │
      ├──→ 遍历 AST 节点 ──→ 找 Source 点（用户输入入口）
      │                      找 Sink 点（危险函数调用）
      │                      找赋值关系（变量传播）
      │
      ▼
   污点追踪器（TaintTracker）──→ 构建变量传播图
      │
      ▼
   Source→Sink 路径分析 ──→ 输出漏洞报告

==== 关键设计 ====

1. Import 别名解析：
   代码中 `from flask import request` 会被映射为
   `request.args.get` → `flask.request.args.get`

2. 双索引匹配：
   Source/Sink 同时用全限定名和短名索引，提高匹配率

3. 父节点引用：
   为每个 AST 节点注入 `_parent` 属性，方便上下文判断
"""
import ast
import os
from pathlib import Path

from engine.taint_tracker import TaintTracker   # 污点追踪核心
from engine.sources_py import PYTHON_SOURCES     # Python Source 点列表
from engine.sinks_py import PYTHON_SINKS, VulnType  # Python Sink 点列表和漏洞类型枚举


# ---- 漏洞严重程度映射表 ----
# VulnType 枚举值 → 严重程度字符串
SEVERITY_MAP = {
    VulnType.COMMAND_EXECUTION: "critical",    # 命令执行：最高风险，可完全控制服务器
    VulnType.SQL_INJECTION: "high",            # SQL 注入：可窃取/篡改数据库
    VulnType.SSRF: "high",                     # SSRF：可探测内网、绕过防火墙
    VulnType.PATH_TRAVERSAL: "medium",         # 路径穿越：可读取任意文件
    VulnType.ARBITRARY_FILE_READ: "medium",    # 任意文件读取：与路径穿越类似
}


class PythonScanner:
    """
    Python 静态代码扫描器
    ====================
    逐文件扫描 Python 源码，通过 AST 分析找出潜在安全漏洞。

    用法:
        scanner = PythonScanner()
        vulns = scanner.scan_directory("/path/to/project")
        # 或扫描单个文件
        vulns = scanner.scan_source(source_code, "app.py")
    """

    # 扫描时跳过的目录（第三方库、缓存、构建产物等）
    SKIP_DIRS = {
        "__pycache__", ".git", ".venv", "venv", "env",
        "node_modules", ".tox", ".mypy_cache", ".pytest_cache",
        "dist", "build", "site-packages",
    }

    def __init__(self):
        """
        初始化扫描器：预建 Source/Sink 索引表，加速匹配。
        同时按全限定名和短名建立双重索引。
        """
        # ---- Source 索引表 ----
        # key: "flask.request.args.get" 或短名 "request.args.get"
        # value: {module, func, description, tainted_params}
        self.source_map: dict[str, dict] = {}

        for src in PYTHON_SOURCES:
            full = f"{src.module}.{src.func}"  # 全限定名：flask.request.args.get
            # 短名：用模块最后一段，如 flask.request → request
            short = f"{src.module.split('.')[-1]}.{src.func}" if "." in src.module else full

            info = {
                "module": src.module,
                "func": src.func,
                "description": src.description,
                "tainted_params": src.tainted_params,
            }
            # 同时用全名和短名索引，提高匹配命中率
            self.source_map[full] = info
            if short != full:
                self.source_map[short] = info

        # ---- Sink 索引表 ----
        # key: vuln_type 字符串（如 "sql_injection"）
        # value: [sink_info, ...]
        self.sink_map: dict[str, list[dict]] = {}

        for sk in PYTHON_SINKS:
            full = f"{sk.module}.{sk.func}"
            short = f"{sk.module.split('.')[-1]}.{sk.func}" if "." in sk.module else full

            info = {
                "module": sk.module,
                "func": sk.func,
                "vuln_type": sk.vuln_type.value,
                "description": sk.description,
                "dangerous_param_index": sk.dangerous_param_index,
            }
            # 按漏洞类型分组存储
            if sk.vuln_type.value not in self.sink_map:
                self.sink_map[sk.vuln_type.value] = []
            self.sink_map[sk.vuln_type.value].append(info)

    # ========================================================================
    # 公开接口
    # ========================================================================

    def scan_directory(self, dir_path: str) -> list[dict]:
        """
        扫描整个目录下的所有 Python 文件。

        参数:
            dir_path: 项目源码目录的绝对路径

        返回:
            list[dict]: 所有发现的漏洞列表
        """
        all_vulns = []
        for file_path in self._collect_python_files(dir_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                vulns = self.scan_source(source, file_path)
                all_vulns.extend(vulns)
            except SyntaxError:
                continue  # 跳过语法错误的文件
            except Exception as e:
                print(f"[WARN] 扫描 {file_path} 出错: {e}")
        return all_vulns

    def scan_source(self, source_code: str, file_path: str = "<unknown>") -> list[dict]:
        """
        扫描单个文件的源代码。

        参数:
            source_code: 源代码字符串
            file_path:   文件路径（用于错误定位和结果展示）

        返回:
            list[dict]: 该文件中发现的漏洞列表
        """
        # ---- 1. 解析 AST ----
        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError:
            return []  # 语法错误，跳过

        # ---- 2. 建立父节点引用 ----
        # 为每个 AST 节点注入 _parent 属性，
        # 用于后续判断赋值目标（如 node 在 Assign 的 targets 中）
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                child._parent = node  # type: ignore

        # ---- 3. 解析 import 语句，建立别名表 ----
        # 映射：代码中的局部名 → 全限定模块名
        # 例如：request → flask.request
        import_aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                # import os → {"os": "os"}
                # import numpy as np → {"np": "numpy"}
                for alias in node.names:
                    name = alias.asname or alias.name
                    import_aliases[name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                # from flask import request → {"request": "flask.request"}
                module = node.module or ""
                for alias in node.names:
                    name = alias.asname or alias.name
                    import_aliases[name] = f"{module}.{alias.name}"

        # ---- 4. 创建污点追踪器 ----
        tracker = TaintTracker(file_path=file_path)

        # ---- 5. 第一阶段：收集 Source / Sink / 赋值关系 ----
        self._visit_sources(tree, tracker, source_code, import_aliases)
        self._visit_sinks(tree, tracker, source_code, import_aliases)
        self._visit_assignments(tree, tracker, source_code)

        # ---- 6. 第二阶段：执行污点分析 ----
        raw_results = tracker.analyze()

        # ---- 7. 第三阶段：格式化输出 ----
        return self._format_results(raw_results, source_code, file_path)

    # ========================================================================
    # Source 点扫描
    # ========================================================================

    def _visit_sources(self, tree: ast.AST, tracker: TaintTracker,
                       source_code: str, aliases: dict[str, str]):
        """
        遍历 AST 找出所有 Source 点（用户输入入口）。

        对每个函数调用检查是否匹配已知的 Source 函数，
        匹配成功则标记被赋值的变量为污点源。
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue  # 只关心函数调用

            # 尝试匹配：这个调用是已知的 Source 吗？
            match = self._match_source(node, aliases)
            if match is None:
                continue

            # 确定这个调用的结果赋给了哪个变量
            var_name = self._get_assigned_var(node)
            code = ast.get_source_segment(source_code, node) or ""

            # 标记为污点源
            tracker.mark_source(
                var_name,
                source_func=match,
                code=code,
                line=node.lineno,
            )

    def _match_source(self, node: ast.Call, aliases: dict[str, str]) -> str | None:
        """
        尝试把一个 AST Call 节点匹配到 Source 表。

        策略：
          1. 先用 import 别名解析完整路径，查全限定名
          2. 再用短名（最后两段）查表

        返回:
            str | None: 匹配到的完整 Source 名，或 None（不匹配）
        """
        # 策略 1：精确匹配（应用 import 别名）
        exact = self._resolve_full_call(node, aliases)
        if exact and exact in self.source_map:
            return exact

        # 策略 2：短名匹配（忽略 import 前缀）
        short_key = self._resolve_short_call(node)
        if short_key and short_key in self.source_map:
            return self.source_map[short_key].get("module", "") + "." + self.source_map[short_key]["func"]

        return None

    # ========================================================================
    # Sink 点扫描
    # ========================================================================

    def _visit_sinks(self, tree: ast.AST, tracker: TaintTracker,
                     source_code: str, aliases: dict[str, str]):
        """
        遍历 AST 找出所有 Sink 点（危险函数调用）。

        对每个函数调用检查是否匹配已知的 Sink 函数，
        匹配成功则标记传入的变量为危险出口。
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # 获取调用链最后一层的函数名（如 execute, system, get）
            func_name = self._last_func_name(node)
            if not func_name:
                continue

            # 按精确 / 短名路径匹配
            exact = self._resolve_full_call(node, aliases)
            short_key = self._resolve_short_call(node)

            # 遍历所有漏洞类型的 Sink 列表
            for vuln_type, sinks in self.sink_map.items():
                for sk in sinks:
                    s_exact = f"{sk['module']}.{sk['func']}"
                    s_short = f"{sk['module'].split('.')[-1]}.{sk['func']}"

                    # 三种匹配策略：精确匹配、短名匹配、函数名匹配
                    if exact == s_exact or short_key in (s_exact, s_short) or func_name == sk['func']:
                        self._mark_sink(node, tracker, source_code, sk, vuln_type)
                        break  # 匹配成功，跳过同类其他 Sink

    def _mark_sink(self, node: ast.Call, tracker: TaintTracker,
                   source_code: str, sk: dict, vuln_type: str):
        """
        标记一个 AST 调用节点为 Sink 点。

        提取危险参数中的变量名，逐个标记为 Sink。
        """
        arg_idx = sk.get("dangerous_param_index", 0)   # 获取危险参数索引
        arg_vars = self._extract_arg_vars(node, arg_idx)  # 提取该参数中的变量名
        code = ast.get_source_segment(source_code, node) or ""

        for var in arg_vars:
            tracker.mark_sink(
                var,
                sink_func=f"{sk['module']}.{sk['func']}",  # Sink 函数的全限定名
                vuln_type=vuln_type,
                code=code,
                line=node.lineno,
            )

    # ========================================================================
    # 赋值关系扫描
    # ========================================================================

    def _visit_assignments(self, tree: ast.AST, tracker: TaintTracker,
                           source_code: str):
        """
        遍历 AST 收集所有赋值关系（变量传播）。

        处理三种赋值形式：
          1. 普通赋值：  x = y         → mark_assign("x", "y")
          2. 增量赋值：  x += y        → mark_assign("x", "y")
          3. 注解赋值：  x: str = y    → mark_assign("x", "y")
        """
        for node in ast.walk(tree):
            # ---- 普通赋值：x = expr ----
            if isinstance(node, ast.Assign):
                targets = self._extract_target_names(node.targets)  # 赋值目标变量名
                value_vars = self._extract_names(node.value)        # 赋值来源变量名
                for target in targets:
                    for val in value_vars:
                        code = ast.get_source_segment(source_code, node) or ""
                        tracker.mark_assign(target, val, reason="assignment",
                                            code=code, line=node.lineno)

            # ---- 增量赋值：x += expr ----
            elif isinstance(node, ast.AugAssign):
                target_name = self._name_of(node.target)
                value_vars = self._extract_names(node.value)
                if target_name:
                    for val in value_vars:
                        code = ast.get_source_segment(source_code, node) or ""
                        tracker.mark_assign(target_name, val, reason="aug_assign",
                                            code=code, line=node.lineno)

            # ---- 注解赋值：x: str = expr ----
            elif isinstance(node, ast.AnnAssign) and node.value:
                target_name = self._name_of(node.target)
                value_vars = self._extract_names(node.value)
                if target_name:
                    for val in value_vars:
                        code = ast.get_source_segment(source_code, node) or ""
                        tracker.mark_assign(target_name, val,
                                            reason="ann_assign",
                                            code=code, line=node.lineno)

    # ========================================================================
    # 名称解析器（应用 import 别名）
    # ========================================================================

    def _resolve_full_call(self, node: ast.Call, aliases: dict[str, str]) -> str | None:
        """
        解析函数调用的完整路径（应用 import 别名）。

        示例:
            cursor.execute()  →  "sqlite3.Cursor.execute"
            os.system()       →  "os.system"
            request.args.get() → "flask.request.args.get"

        参数:
            node:    AST Call 节点
            aliases: import 别名映射表

        返回:
            str | None: 完整路径字符串
        """
        func = node.func
        if isinstance(func, ast.Name):
            # 简单调用：func_name()
            # 应用别名：若别名表中存在，用映射后的名；否则追加 "builtins." 前缀
            name = aliases.get(func.id, f"builtins.{func.id}")
            return name

        if isinstance(func, ast.Attribute):
            # 属性调用：obj.func_name()
            # 递归解析 obj，然后追加 .func_name
            module_path = self._resolve_attr_chain(func.value, aliases)
            return f"{module_path}.{func.attr}"

        return None

    def _resolve_short_call(self, node: ast.Call) -> str:
        """
        解析函数调用的短路径（不应用 import 别名，保留代码中的原始写法）。

        示例:
            request.args.get  →  "request.args.get"
            os.system         →  "os.system"
        """
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return f"{self._resolve_attr_chain_short(func.value)}.{func.attr}"
        return ""

    def _resolve_attr_chain(self, node: ast.expr, aliases: dict[str, str]) -> str:
        """
        递归解析属性链，应用 import 别名。

        示例:
            request.args  →  "flask.request.args"（因为 request 映射到 flask.request）
        """
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)  # 有别名用别名，无则用原名
        if isinstance(node, ast.Attribute):
            return f"{self._resolve_attr_chain(node.value, aliases)}.{node.attr}"
        if isinstance(node, ast.Call):
            # 链式调用：func().attr
            return self._resolve_attr_chain(node.func, aliases)
        return "unknown"

    def _resolve_attr_chain_short(self, node: ast.expr) -> str:
        """
        递归解析属性链（不应用别名，保留短名）。
        """
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._resolve_attr_chain_short(node.value)}.{node.attr}"
        if isinstance(node, ast.Call):
            return self._resolve_attr_chain_short(node.func)
        return "?"

    # ========================================================================
    # 变量 / 表达式辅助函数
    # ========================================================================

    def _collect_python_files(self, dir_path: str) -> list[str]:
        """
        递归收集目录下所有 .py 文件的路径列表。
        自动跳过 SKIP_DIRS 中列出的目录。
        """
        files = []
        for root, dirs, filenames in os.walk(dir_path):
            # 原地修改 dirs 列表，跳过不需要的目录
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for f in filenames:
                if f.endswith(".py"):
                    files.append(os.path.join(root, f))
        return files

    def _last_func_name(self, node: ast.Call) -> str:
        """
        获取函数调用链的最后一层函数名。

        示例:
            cursor.execute()  →  "execute"
            os.system()       →  "system"
            func()            →  "func"
        """
        func = node.func
        if isinstance(func, ast.Name):
            return func.id       # 简单调用：func()
        if isinstance(func, ast.Attribute):
            return func.attr     # 属性调用：obj.method()
        return ""

    def _get_assigned_var(self, node: ast.AST) -> str:
        """
        获取当前 AST 节点的赋值目标变量名。

        向上查找父节点，判断当前调用是否在赋值语句右侧：
          - x = func()     → 目标变量 "x"
          - x: str = func() → 目标变量 "x"
          - 独立调用 func() → 生成匿名变量名

        返回:
            str: 变量名（可能是匿名的）
        """
        parent = getattr(node, "_parent", None)
        if parent is None:
            return self._make_var_name(node)

        if isinstance(parent, ast.Assign):
            # x = func() → 提取 x
            names = self._extract_target_names(parent.targets)
            return names[0] if names else self._make_var_name(node)

        if isinstance(parent, ast.AnnAssign):
            # x: str = func() → 提取 x
            return self._name_of(parent.target) or self._make_var_name(node)

        # 无法判断赋值目标（如独立调用或作为参数传递），生成匿名变量名
        return self._make_var_name(node)

    def _make_var_name(self, node: ast.AST) -> str:
        """
        生成匿名变量名，用于无法确定变量名的表达式。

        格式: __anon_{AST类型}_{内存ID}
        保证唯一性，但可读性差（仅用于内部追踪）。
        """
        return f"__anon_{type(node).__name__}_{id(node)}"

    def _extract_target_names(self, targets: list[ast.expr]) -> list[str]:
        """
        从赋值目标列表中提取所有变量名。

        示例:
            x = ...           → ["x"]
            x, y = ...        → ["x", "y"]
            obj.attr = ...    → ["obj"]（只取对象，不取属性）
        """
        names = []
        for t in targets:
            n = self._name_of(t)
            if n:
                names.append(n)
        return names

    def _extract_names(self, node: ast.expr) -> list[str]:
        """
        递归提取表达式中出现的所有变量名。

        支持多种表达式结构：
          - Name:    x             → ["x"]
          - BinOp:   a + b         → ["a", "b"]
          - f-string: f"{x}{y}"    → ["x", "y"]
          - Call:    func(a, b)    → ["a", "b"]
          - IfExp:   x if c else y → ["x", "y"]
          - List:    [a, b]        → ["a", "b"]

        返回:
            list[str]: 变量名列表（去重由调用方处理）
        """
        if isinstance(node, ast.Name):
            # 简单变量引用
            return [node.id]

        if isinstance(node, ast.BinOp):
            # 二元运算：a + b, a * b 等
            return self._extract_names(node.left) + self._extract_names(node.right)

        if isinstance(node, ast.JoinedStr):
            # f-string: f"SELECT * FROM {table}" → 提取 table
            names = []
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    names.extend(self._extract_names(val.value))
            return names

        if isinstance(node, ast.Call):
            # 函数调用的参数
            names = []
            for arg in node.args:
                names.extend(self._extract_names(arg))
            return names

        if isinstance(node, ast.IfExp):
            # 三元表达式：a if condition else b
            return self._extract_names(node.body) + self._extract_names(node.orelse)

        if isinstance(node, ast.List) or isinstance(node, ast.Tuple):
            # 列表/元组字面量
            names = []
            for elt in node.elts:
                names.extend(self._extract_names(elt))
            return names

        # 其他类型（常量、Lambda 等）：不产生变量名
        return []

    def _extract_arg_vars(self, node: ast.Call, arg_idx: int | None) -> list[str]:
        """
        从函数调用的参数中提取变量名列表。

        参数:
            node:    AST Call 节点
            arg_idx: 参数索引（None 表示所有参数，0 表示第一个参数）

        返回:
            list[str]: 该位置参数中出现的变量名
        """
        if arg_idx is None:
            arg_idx = 0  # 默认取第一个参数
        if len(node.args) > arg_idx:
            return self._extract_names(node.args[arg_idx])
        return []

    def _name_of(self, node: ast.expr) -> str | None:
        """
        提取表达式节点的"根"变量名。

        对于链式属性访问，只返回最底层的对象名：
          - x           → "x"
          - obj.attr    → "obj"
          - a.b.c       → "a"

        返回:
            str | None: 变量名，提取失败返回 None
        """
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._name_of(node.value)  # 递归下钻
        return None

    # ========================================================================
    # 格式化输出
    # ========================================================================

    def _format_results(self, raw: list[dict], source_code: str,
                        file_path: str) -> list[dict]:
        """
        将污点追踪器的原始输出格式化为统一的漏洞报告格式。

        参数:
            raw:         污点追踪器的原始分析结果
            source_code: 源文件内容（预留，可用于后续扩展）
            file_path:   文件路径

        返回:
            list[dict]: 统一的漏洞报告列表
        """
        results = []
        for r in raw:
            vt = r.get("vuln_type", "")
            # 根据漏洞类型映射严重程度
            try:
                severity = SEVERITY_MAP[VulnType(vt)]
            except (ValueError, KeyError):
                severity = "medium"  # 未知类型默认为中等

            results.append({
                "file_path": file_path,
                "line_number": r.get("sink_line", r.get("source_line", 0)),  # 优先使用 Sink 行号
                "vuln_type": vt,
                "severity": severity,
                "language": "python",
                "source_code": r.get("source_code", ""),     # Source 点代码
                "sink_code": r.get("sink_code", ""),         # Sink 点代码
                "data_flow": r.get("data_flow", ""),         # 数据流路径
                "source_func": r.get("source_func", ""),     # Source 函数名
                "sink_func": r.get("sink_func", ""),         # Sink 函数名
                "source_line": r.get("source_line", 0),      # Source 行号
                "sink_line": r.get("sink_line", 0),          # Sink 行号
            })
        return results
