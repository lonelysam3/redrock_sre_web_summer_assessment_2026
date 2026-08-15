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
from engine.sinks_py import PYTHON_SINKS, VulnType, CWE_BY_TYPE  # Sink 点列表、漏洞类型枚举、CWE 映射


# ---- 漏洞严重程度映射表 ----
# VulnType 枚举值 → 严重程度字符串
SEVERITY_MAP = {
    VulnType.COMMAND_EXECUTION: "critical",    # 命令执行：最高风险，可完全控制服务器
    VulnType.SQL_INJECTION: "high",            # SQL 注入：可窃取/篡改数据库
    VulnType.SSRF: "high",                     # SSRF：可探测内网、绕过防火墙
    VulnType.PATH_TRAVERSAL: "medium",         # 路径穿越：可读取任意文件
    VulnType.ARBITRARY_FILE_READ: "medium",    # 任意文件读取：与路径穿越类似
    VulnType.INSCURE_DESERIALIZATION: "high",  # 反序列化：可 RCE
    VulnType.CODE_INJECTION: "critical",       # 代码注入
    VulnType.OPEN_REDIRECT: "medium",          # 开放重定向
    VulnType.XXE: "high",                      # XXE
    VulnType.XSS: "low",                       # 反射型 XSS
    VulnType.SSTI: "critical",                 # 模板注入：可 RCE
    VulnType.HARDCODED_CREDENTIALS: "high",    # 硬编码凭据
    VulnType.DEBUG_MODE: "low",                # 调试模式开启
}

# eval/exec/compile 等代码执行 sink：按 CWE-94（代码注入）标注
CODE_EXEC_SINK_MARKERS = ("eval", "exec", "compile")

# ---- 消毒函数集合 ----
# 每个函数对应它能防护的漏洞类型集合：
#   - None = 全类型消毒（类型转换等）
#   - 具体类型 = 只阻断该类漏洞（如 html.escape 只防 XSS）
PYTHON_SANITIZER_NAMES: dict[str, set | None] = {
    # 通用类型强制转换：把输入变成纯数字，对注入类漏洞普遍有效
    # str()/bytes() 不消毒任何东西，不作为消毒函数（避免误判漏报）
    "builtins.int": None, "builtins.float": None, "builtins.bool": None,
    # XSS 消毒：只阻断 XSS
    "html.escape": {"xss"},
    "cgi.escape": {"xss"},
    "markupsafe.escape": {"xss"},
    "bleach.clean": {"xss"},
    # 命令注入消毒：只阻断命令执行
    "shlex.quote": {"command_execution"},
    # 路径消毒：阻断路径穿越/任意文件读取
    "os.path.basename": {"path_traversal", "arbitrary_file_read"},
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
        "dist", "build", "site-packages", "vendor",
    }

    # 数据库连接工厂函数：返回值标记为 db.Connection
    DB_CONNECT_FUNCS = {
        "sqlite3.connect", "pymysql.connect", "MySQLdb.connect",
        "psycopg2.connect", "psycopg.connect", "mysql.connector.connect",
        "asyncpg.connect", "aiomysql.connect",
    }
    # 数据库对象基座：obj.cursor() 的 obj 解析到这些时，cursor 标记为 db.Cursor
    DB_OBJECT_BASES = {"django.db.connection", "sqlalchemy.Engine"}

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

        # 当前文件内的局部类型推断：变量名 → 类型（db.Connection / db.Cursor 等）
        self._local_types: dict[str, str] = {}

        # ---- 项目级（跨函数/跨文件）分析状态 ----
        self._prefix = ""                  # 当前作用域的变量名前缀（作用域隔离）
        self._current_file = ""            # 当前正在扫描的文件
        self._current_module = ""          # 当前文件的项目内模块路径（如 store.services.catalog）
        self._current_qualname = ""        # 当前函数限定名（模块级作用域为空）
        self._current_class = ""           # 当前函数所属类名（无则空）
        self._file_info: dict[str, dict] = {}   # file_path -> 解析信息（tree/aliases/scopes/...）
        self._func_index: dict[tuple, dict] = {}  # (module, qualname) -> FunctionInfo
        self._module_files: dict[str, str] = {}   # 模块路径 -> file_path

    # ========================================================================
    # 公开接口
    # ========================================================================

    def scan_directory(self, dir_path: str) -> list[dict]:
        """
        扫描整个目录下的所有 Python 文件（项目级跨文件分析）。

        参数:
            dir_path: 项目源码目录的绝对路径

        返回:
            list[dict]: 所有发现的漏洞列表
        """
        files = self._collect_python_files(dir_path)
        source_map = {}
        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source_map[file_path] = f.read()
            except Exception as e:
                print(f"[WARN] 读取 {file_path} 出错: {e}")
        if not source_map:
            return []
        return self.scan_project(source_map)

    def scan_project(self, source_code_map: dict[str, str]) -> list[dict]:
        """
        项目级扫描（v3）：跨函数 + 跨文件污点分析。

        与旧版逐文件扫描不同，这里：
          1. 变量按 (模块, 函数) 命名空间隔离，消除同名变量跨函数串扰；
          2. 函数参数一律视为不可信 source；
          3. return 值传播：return expr → 调用点 `x = f(...)`；
          4. 调用点实参 → 形参、被调函数返回值 → 调用点变量（跨文件也生效，
             支持 from a.b import f / import db; db.f 等形式）；
          5. 模块属性链接：import db; c = db.c → 链接到 db 模块的顶层变量。

        参数:
            source_code_map: {file_path: source_code} 映射

        返回:
            list[dict]: 所有发现的漏洞列表
        """
        self._prepare_project(source_code_map)
        tracker = TaintTracker(file_path="<project>")

        # ---- 第一轮：各作用域内收集 source/sink/赋值/return ----
        for path, info in self._file_info.items():
            source_code = info["source"]
            tree = info["tree"]
            aliases = info["aliases"]
            self._current_file = path
            self._current_module = info["module"]
            self._local_types = self._build_local_types(tree, aliases)
            for qualname, func_node, clsname, nodes in info["scopes"]:
                self._prefix = self._make_prefix(info["key"], qualname)
                self._current_qualname = qualname
                self._current_class = clsname
                self._visit_sources(nodes, tracker, source_code, aliases)
                self._visit_param_sources(func_node, tracker, source_code)
                self._visit_sinks(nodes, tracker, source_code, aliases)
                self._visit_assignments(nodes, tracker, source_code, aliases)
                self._visit_returns(nodes, tracker, source_code)

        # ---- 第二轮：调用点链接（函数索引就绪后） ----
        for path, info in self._file_info.items():
            for qualname, func_node, clsname, nodes in info["scopes"]:
                self._prefix = self._make_prefix(info["key"], qualname)
                self._current_qualname = qualname
                self._current_class = clsname
                self._current_file = path
                self._current_module = info["module"]
                self._link_calls(nodes, tracker, info)

        raw = tracker.analyze()
        return self._format_results(raw, {}, "")

    def scan_source(self, source_code: str, file_path: str = "<unknown>") -> list[dict]:
        """
        扫描单个文件的源代码（兼容旧接口，内部走项目级流程）。

        参数:
            source_code: 源代码字符串
            file_path:   文件路径（用于错误定位和结果展示）

        返回:
            list[dict]: 该文件中发现的漏洞列表
        """
        return self.scan_project({file_path: source_code})

    # ========================================================================
    # 项目预处理：解析、作用域切分、函数索引
    # ========================================================================

    def _prepare_project(self, source_code_map: dict[str, str]) -> None:
        """解析全部文件，建立作用域、别名、函数索引、模块索引。"""
        self._file_info = {}
        self._func_index = {}
        self._module_files = {}

        # ---- 项目根目录：所有文件的公共父目录 ----
        files = list(source_code_map.keys())
        root = os.path.dirname(files[0])
        for f in files[1:]:
            try:
                root = os.path.commonpath([root, os.path.dirname(f)])
            except ValueError:
                root = os.path.dirname(files[0])
                break

        # ---- 第一趟：逐文件解析，计算模块路径、作用域、别名 ----
        for file_path, source_code in source_code_map.items():
            try:
                tree = ast.parse(source_code, filename=file_path)
            except SyntaxError:
                continue
            # 父节点引用（_get_assigned_var 依赖）
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    child._parent = node  # type: ignore

            module = self._module_path_of(file_path, root)
            info = {
                "source": source_code,
                "tree": tree,
                "module": module,
                "key": module or file_path.replace("\\", "/"),
                "aliases": {},
                "alias_mod": {},
                "classes": set(),
                "scopes": [],
                "module_vars": set(),
            }
            self._build_aliases(tree, module, info)
            self._file_info[file_path] = info
            self._module_files[module] = file_path

        # ---- 第二趟：切分作用域（模块级 + 每个函数） ----
        for file_path, info in self._file_info.items():
            tree = info["tree"]
            # 类名收集（调用点解析 Class.m() 用）
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    info["classes"].add(node.name)
            scopes = [("", None, "", self._nodes_pruned(tree, include_self=False))]
            # 模块级变量索引（import db; c = db.c 跨文件链接用）
            for node in scopes[0][3]:
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = (node.targets if isinstance(node, ast.Assign)
                               else [node.target])
                    for t in targets:
                        n = self._name_of(t)
                        if n:
                            info["module_vars"].add(n)
                elif isinstance(node, (ast.For, ast.With)):
                    # for x in ...: / with ... as x: 顶层的绑定也计入模块变量
                    bind = node.target if isinstance(node, ast.For) else None
                    if isinstance(node, ast.With):
                        for item in node.items:
                            if item.optional_vars:
                                n = self._name_of(item.optional_vars)
                                if n:
                                    info["module_vars"].add(n)
                    elif bind:
                        for t in (bind.elts if isinstance(bind, (ast.Tuple, ast.List)) else [bind]):
                            n = self._name_of(t)
                            if n:
                                info["module_vars"].add(n)
            for func in self._iter_functions(tree):
                qualname, clsname = self._func_qualname(func)
                scopes.append((qualname, func, clsname,
                               self._nodes_pruned(func, include_self=True)))
            info["scopes"] = scopes

        # ---- 第三趟：全局函数索引 (module, qualname) -> info ----
        for file_path, info in self._file_info.items():
            for qualname, func_node, clsname, nodes in info["scopes"]:
                if not qualname:
                    continue
                args = func_node.args
                pos = [a.arg for a in list(args.posonlyargs) + list(args.args)]
                self._func_index[(info["module"], qualname)] = {
                    "file": file_path,
                    "key": info["key"],
                    "module": info["module"],
                    "qualname": qualname,
                    "class": clsname,
                    "node": func_node,
                    "params": pos,
                    "kwonly": {a.arg for a in args.kwonlyargs},
                    "prefix": self._make_prefix(info["key"], qualname),
                }

    def _module_path_of(self, file_path: str, root: str) -> str:
        """文件路径 → 项目内模块路径（如 store/services/catalog.py → store.services.catalog）。"""
        try:
            rel = os.path.relpath(file_path, root)
        except ValueError:
            rel = os.path.basename(file_path)
        parts = rel.replace("\\", "/").split("/")
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1][:-3] if parts[-1].endswith(".py") else parts[-1]
        return ".".join(p for p in parts if p and p not in (".", ".."))

    def _build_aliases(self, tree: ast.AST, module: str, info: dict) -> None:
        """解析 import，建立两张表：
        - aliases:    局部名 → 全限定名（source/sink 匹配用）
        - alias_mod:  局部名 → (模块, 属性名或 None)（跨文件调用解析用）
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    info["aliases"][name] = alias.name
                    info["alias_mod"][name] = (alias.name, None)
            elif isinstance(node, ast.ImportFrom):
                base = self._resolve_import_module(node, module)
                for alias in node.names:
                    name = alias.asname or alias.name
                    if alias.name == "*":
                        continue
                    info["aliases"][name] = f"{base}.{alias.name}" if base else alias.name
                    info["alias_mod"][name] = (base, alias.name)

    def _resolve_import_module(self, node: ast.ImportFrom, current_module: str) -> str:
        """相对导入解析：from . import x / from ..sub import y。"""
        level = node.level or 0
        if level == 0:
            return node.module or ""
        parts = current_module.split(".") if current_module else []
        # 每多一个点，向上退一层包
        keep = max(0, len(parts) - (level - 1))
        base_parts = parts[:keep]
        if node.module:
            base_parts = base_parts + node.module.split(".")
        return ".".join(base_parts)

    def _nodes_pruned(self, root: ast.AST, include_self: bool = False) -> list:
        """收集某个作用域内的全部节点；剪掉函数定义（嵌套函数属自己的作用域）。"""
        out: list = []

        def rec(node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node is root and include_self:
                    out.append(node)
                    for child in ast.iter_child_nodes(node):
                        rec(child)
                return
            out.append(node)
            for child in ast.iter_child_nodes(node):
                rec(child)

        if isinstance(root, ast.Module):
            for stmt in root.body:
                rec(stmt)
        else:
            rec(root)
        return out

    def _iter_functions(self, tree: ast.AST):
        """遍历所有函数定义（含类方法、嵌套函数）。"""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield node

    def _func_qualname(self, func_node: ast.AST) -> tuple[str, str]:
        """计算函数的限定名和所属类名（如 Class.method / outer.inner）。"""
        names: list[str] = []
        clsname = ""
        node = func_node
        seen = 0
        while node is not None and seen < 50:
            parent = getattr(node, "_parent", None)
            if parent is None:
                break
            if isinstance(parent, ast.ClassDef):
                names.append(parent.name)
                if not clsname:
                    clsname = parent.name
            elif isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.append(parent.name)
            node = parent
            seen += 1
        names.append(func_node.name)
        return ".".join(reversed(names)), clsname

    def _make_prefix(self, file_key: str, qualname: str) -> str:
        """作用域前缀：file_key@qualname:（模块级 qualname 为空）。"""
        return f"{file_key}@{qualname}:"

    def _v(self, name: str) -> str:
        """变量名加作用域前缀；已带前缀的名字（匿名名）保持不动。"""
        if not name:
            return name
        if self._prefix and name.startswith(self._prefix):
            return name
        if name.startswith("__anon_"):
            return name
        return f"{self._prefix}{name}"

    # ========================================================================
    # Source 点扫描
    # ========================================================================

    def _visit_sources(self, nodes: list, tracker: TaintTracker,
                       source_code: str, aliases: dict[str, str]):
        """
        在当前作用域节点中找出所有 Source 点（用户输入入口）。

        对每个函数调用（或 dict 下标访问）检查是否匹配已知的 Source 函数，
        匹配成功则标记被赋值的变量为污点源。
        """
        for node in nodes:
            # ---- dict 下标访问：request.args['name'] / request.GET['id'] ----
            if isinstance(node, ast.Subscript):
                chain = self._resolve_attr_chain(node.value, aliases)
                key = f"{chain}.__getitem__"
                if key in self.source_map or chain in self.source_map:
                    src_key = key if key in self.source_map else chain
                    var_name = self._make_var_name(node)  # 确定性匿名名（带前缀）
                    code = ast.get_source_segment(source_code, node) or ""
                    tracker.mark_source(
                        var_name,
                        source_func=src_key,
                        code=code,
                        line=node.lineno,
                        file=self._current_file,
                    )
                continue

            # ---- 属性型 source：request.data / request.headers / sys.argv ----
            if isinstance(node, ast.Attribute):
                chain = self._resolve_attr_chain(node, aliases)
                matched = None
                if chain in self.source_map:
                    matched = chain
                else:
                    # 后缀匹配：api.payload / parser.parse_args 这类实例变量写法
                    for suffix in sorted(self.source_map.keys(), key=len,
                                         reverse=True):
                        if chain.endswith(suffix):
                            matched = suffix
                            break
                if matched:
                    var_name = self._make_var_name(node)  # 确定性匿名名（带前缀）
                    code = ast.get_source_segment(source_code, node) or ""
                    tracker.mark_source(
                        var_name,
                        source_func=matched,
                        code=code,
                        line=node.lineno,
                        file=self._current_file,
                    )
                continue

            if not isinstance(node, ast.Call):
                continue  # 只关心函数调用

            # 尝试匹配：这个调用是已知的 Source 吗？
            match = self._match_source(node, aliases)
            if match is None:
                continue

            # 确定这个调用的结果赋给了哪个变量
            var_name = self._v(self._get_assigned_var(node))
            code = ast.get_source_segment(source_code, node) or ""

            # 标记为污点源
            tracker.mark_source(
                var_name,
                source_func=match,
                code=code,
                line=node.lineno,
                file=self._current_file,
            )

    def _match_source(self, node: ast.Call, aliases: dict[str, str]) -> str | None:
        """
        尝试把一个 AST Call 节点匹配到 Source 表。

        策略：
          1. 先用 import 别名解析完整路径，查全限定名
          2. 再用后缀匹配（短名）查表 —— 支持 request.GET.get('x')
             这类 request 是函数参数（非 import）的写法

        返回:
            str | None: 匹配到的完整 Source 名，或 None（不匹配）
        """
        # 策略 1：精确匹配（应用 import 别名）
        exact = self._resolve_full_call(node, aliases)
        if exact and exact in self.source_map:
            return exact

        # 策略 2：后缀匹配（忽略 import 前缀，支持函数参数形式）
        short_key = self._resolve_short_call(node)
        if short_key:
            # 按长度降序匹配，优先更长的后缀（更具体）
            for suffix in sorted(self.source_map.keys(), key=len, reverse=True):
                if short_key.endswith(suffix):
                    info = self.source_map[suffix]
                    return f"{info['module']}.{info['func']}"

        return None

    def _visit_param_sources(self, func_node, tracker: TaintTracker,
                             source_code: str):
        """
        函数参数作为不可信来源（保守假设，PySa 风格）。

        任何函数参数都可能被调用方传入用户可控数据。这是跨函数污点流的
        基础：例如 list_products(query=request.args.get('q'))，query 是
        被调函数的参数，本地没有 source，若不把参数视为不可信，此类
        sink 永远无法命中（漏报）。

        self / cls 除外：面向对象方法的自身引用，若被打上污点会导致
        所有 self.xxx 全部污染，误报爆炸。
        """
        if func_node is None:
            return
        args = func_node.args
        for arg in (list(args.posonlyargs) + list(args.args)
                    + list(args.kwonlyargs)):
            if arg.arg in ("self", "cls"):
                continue
            tracker.mark_source(
                self._v(arg.arg),
                source_func="function.parameter",
                code=arg.arg,
                line=func_node.lineno,
                file=self._current_file,
            )
        if args.vararg and args.vararg.arg not in ("self", "cls"):
            tracker.mark_source(
                self._v(args.vararg.arg), source_func="function.parameter",
                code=args.vararg.arg, line=func_node.lineno,
                file=self._current_file,
            )
        if args.kwarg and args.kwarg.arg not in ("self", "cls"):
            tracker.mark_source(
                self._v(args.kwarg.arg), source_func="function.parameter",
                code=args.kwarg.arg, line=func_node.lineno,
                file=self._current_file,
            )

    # ========================================================================
    # Sink 点扫描
    # ========================================================================

    # 数据库命名变量上的 execute 系列（后缀回退）：
    #   cursor.execute / cur.execute / conn.execute / db.execute ...
    DB_EXEC_BASES = {
        "c", "cur", "cursor", "curs", "conn", "connection",
        "db", "database", "con",
    }

    def _visit_sinks(self, nodes: list, tracker: TaintTracker,
                     source_code: str, aliases: dict[str, str]):
        """
        在当前作用域节点中找出所有 Sink 点（危险函数调用）。

        匹配策略：
          1. exact（import别名解析后全名）
          2. short_key（短名）
          3. 局部类型推断（local_types）：conn.cursor() 返回的游标变量
             经 _build_local_types 标记为 db.Cursor，cur.execute() 命中 sink
          4. 后缀回退：数据库命名变量（cursor/conn/db 等）上的 execute 系列、
             session.execute、objects.raw
        """
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue

            # 获取调用链最后一层的函数名（如 execute, system, get）
            func_name = self._last_func_name(node)
            if not func_name:
                continue

            # 按精确 / 短名路径匹配
            exact = self._resolve_full_call(node, aliases)
            short_key = self._resolve_short_call(node)

            # Django ORM raw()：User.objects.raw(tainted_sql)
            if func_name == "raw" and short_key.endswith("objects.raw"):
                sk = {"module": "django.db.models.query", "func": "raw",
                      "dangerous_param_index": 0}
                self._mark_sink(node, tracker, source_code, sk, "sql_injection")
                continue

            # 遍历所有漏洞类型的 Sink 列表
            for vuln_type, sinks in self.sink_map.items():
                for sk in sinks:
                    s_exact = f"{sk['module']}.{sk['func']}"
                    s_short = f"{sk['module'].split('.')[-1]}.{sk['func']}"

                    # 两种匹配策略：精确匹配、短名匹配
                    # 注意：不使用裸函数名匹配（func_name == sk['func']），
                    # 否则任意 .format() .execute() .get() .post() 都会误报
                    if exact == s_exact or short_key in (s_exact, s_short):
                        self._mark_sink(node, tracker, source_code, sk, vuln_type)
                        break  # 匹配成功，跳过同类其他 Sink

            # ---- 后缀回退（仅 SQL 执行，命名空间收窄防止误报） ----
            if func_name in ("execute", "executemany", "executescript"):
                base = self._sink_base_name(node)
                if base in self.DB_EXEC_BASES:
                    sk = {"module": "db", "func": func_name,
                          "dangerous_param_index": 0}
                    self._mark_sink(node, tracker, source_code, sk, "sql_injection")
                    continue
            if func_name == "execute" and short_key.endswith("session.execute"):
                sk = {"module": "sqlalchemy.session", "func": "execute",
                      "dangerous_param_index": 0}
                self._mark_sink(node, tracker, source_code, sk, "sql_injection")

    def _sink_base_name(self, node: ast.Call) -> str:
        """提取调用对象的根变量名：cursor.execute → cursor；db.session.execute → db。"""
        func = node.func
        if isinstance(func, ast.Attribute):
            return self._name_of(func.value) or ""
        return ""

    def _build_local_types(self, tree: ast.AST, aliases: dict[str, str]) -> dict[str, str]:
        """
        构建局部类型推断表：变量名 → 类型。

        两趟扫描：
          第一趟：conn = sqlite3.connect()/pymysql.connect() 等 → "db.Connection"
                  engine = sqlalchemy.create_engine()          → "sqlalchemy.Engine"
                  conn = django.db.connection（别名）            → "django.db.connection"
          第二趟：cur = conn.cursor() / with conn.cursor() as cur → "db.Cursor"

        这样 cur.execute(tainted) 就能解析为 db.Cursor.execute 命中 sink。
        """
        local: dict[str, str] = {}

        def resolve(expr):
            """解析表达式为类型名：优先局部类型，其次 import 别名。"""
            return self._resolve_attr_chain(expr, aliases, local)

        # ---- 第一趟：连接对象 ----
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                factory = resolve(node.value.func)
                if factory in self.DB_CONNECT_FUNCS or factory.endswith(".connect"):
                    for t in self._extract_target_names(node.targets):
                        local[t] = "db.Connection"
                elif factory in ("sqlalchemy.create_engine",):
                    for t in self._extract_target_names(node.targets):
                        local[t] = "sqlalchemy.Engine"
            elif isinstance(node, ast.Assign) and not isinstance(node.value, ast.Call):
                resolved = resolve(node.value)
                if resolved in self.DB_OBJECT_BASES:
                    for t in self._extract_target_names(node.targets):
                        local[t] = resolved

        # ---- 第二趟：游标对象 ----
        def cursor_base(expr) -> str:
            """obj.cursor() 的 obj 解析结果（可解析出 db 基座则返回基座类型）"""
            return resolve(expr)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func = node.value.func
                if isinstance(func, ast.Attribute) and func.attr == "cursor":
                    base = cursor_base(func.value)
                    if (base in self.DB_OBJECT_BASES or base == "db.Connection"
                            or base in self.DB_CONNECT_FUNCS or base.endswith("Connection")):
                        for t in self._extract_target_names(node.targets):
                            local[t] = "db.Cursor"
            elif isinstance(node, ast.With):
                for item in node.items:
                    if item.optional_vars and isinstance(item.context_expr, ast.Call):
                        func = item.context_expr.func
                        if isinstance(func, ast.Attribute) and func.attr == "cursor":
                            base = cursor_base(func.value)
                            if (base in self.DB_OBJECT_BASES or base == "db.Connection"
                                    or base in self.DB_CONNECT_FUNCS or base.endswith("Connection")):
                                local[self._name_of(item.optional_vars) or ""] = "db.Cursor"

        return local

    def _mark_sink(self, node: ast.Call, tracker: TaintTracker,
                   source_code: str, sk: dict, vuln_type: str):
        """
        标记一个 AST 调用节点为 Sink 点。

        提取危险参数中的变量名，逐个标记为 Sink。

        subprocess 列表形式（无 shell）不构成命令注入：
          subprocess.run(['ping', ip])   —— 参数列表形式，无 shell 解析，安全
          subprocess.run(cmd, shell=True) —— 字符串形式，可注入
        """
        # subprocess 列表形式豁免（列表/元组首参 + 无 shell=True）
        if sk.get("module", "").startswith("subprocess") and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.List, ast.Tuple)):
                # 检查是否有 shell=True
                shell_true = any(
                    isinstance(kw, ast.keyword) and kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if not shell_true:
                    return

        arg_idx = sk.get("dangerous_param_index", 0)   # 获取危险参数索引
        arg_vars = self._extract_arg_vars(node, arg_idx)  # 提取该参数中的变量名
        code = ast.get_source_segment(source_code, node) or ""

        for var in arg_vars:
            tracker.mark_sink(
                self._v(var),
                sink_func=f"{sk['module']}.{sk['func']}",  # Sink 函数的全限定名
                vuln_type=vuln_type,
                code=code,
                line=node.lineno,
                file=self._current_file,
            )

    # ========================================================================
    # 赋值关系扫描
    # ========================================================================

    def _visit_assignments(self, nodes: list, tracker: TaintTracker,
                           source_code: str, aliases: dict[str, str] | None = None):
        """
        在当前作用域节点中收集所有赋值关系（变量传播）。

        处理三种赋值形式：
          1. 普通赋值：  x = y         → mark_assign("x", "y")
          2. 增量赋值：  x += y        → mark_assign("x", "y")
          3. 注解赋值：  x: str = y    → mark_assign("x", "y")

        另做属性读取传播：obj.attr —— obj 污染则 obj.attr 也污染。
        例如 order = Order.query.get_or_404(order_id)，order 被污染后
        order.notes 也应视为污点，流向 render_template_string 即 SSTI。
        若 obj 是模块别名（import db; c = db.c），则链接到该模块的顶层变量。
        """
        info = self._file_info.get(self._current_file, {})
        # ---- 属性读取传播：obj.attr ← obj ----
        for node in nodes:
            if isinstance(node, ast.Attribute):
                base = self._name_of(node.value)
                if not base:
                    continue
                anon = self._make_var_name(node)
                code = ast.get_source_segment(source_code, node) or ""
                tracker.mark_assign(anon, self._v(base),
                                    reason="attr_read", code=code,
                                    line=node.lineno)
                # ---- 跨文件模块属性链接：import db; c = db.c ----
                entry = info.get("alias_mod", {}).get(base)
                if entry and entry[1] is None:
                    mod = entry[0]
                    tgt_path = self._module_files.get(mod)
                    if tgt_path and tgt_path != self._current_file:
                        tgt_info = self._file_info.get(tgt_path, {})
                        if node.attr in tgt_info.get("module_vars", set()):
                            tgt_name = f"{self._make_prefix(tgt_info.get('key', mod), '')}{node.attr}"
                            tracker.mark_assign(anon, tgt_name,
                                                reason="module_attr",
                                                code=code, line=node.lineno)

        for node in nodes:
            # ---- 普通赋值：x = expr ----
            if isinstance(node, ast.Assign):
                targets = self._extract_target_names(node.targets)  # 赋值目标变量名
                value_vars = self._extract_names(node.value)        # 赋值来源变量名
                for target in targets:
                    for val in value_vars:
                        code = ast.get_source_segment(source_code, node) or ""
                        tracker.mark_assign(self._v(target), self._v(val),
                                            reason="assignment",
                                            code=code, line=node.lineno)
                # dict 访问传播：x = d['k'] / x = d.get('k')
                # 若 d 已被污染，则 x 也污染（字典/对象取值传播）
                base_var = self._dict_access_base(node.value)
                if base_var:
                    for target in targets:
                        code = ast.get_source_segment(source_code, node) or ""
                        tracker.mark_assign(self._v(target), self._v(base_var),
                                            reason="dict_access",
                                            code=code, line=node.lineno)
                # 消毒函数检测：x = int(y), x = html.escape(y) 等
                self._check_sanitizer(node.value, targets, tracker, aliases or {})

            # ---- 增量赋值：x += expr ----
            elif isinstance(node, ast.AugAssign):
                target_name = self._name_of(node.target)
                value_vars = self._extract_names(node.value)
                if target_name:
                    for val in value_vars:
                        code = ast.get_source_segment(source_code, node) or ""
                        tracker.mark_assign(self._v(target_name), self._v(val),
                                            reason="aug_assign",
                                            code=code, line=node.lineno)
                    self._check_sanitizer(node.value, [target_name], tracker, aliases or {})

            # ---- 注解赋值：x: str = expr ----
            elif isinstance(node, ast.AnnAssign) and node.value:
                target_name = self._name_of(node.target)
                value_vars = self._extract_names(node.value)
                if target_name:
                    for val in value_vars:
                        code = ast.get_source_segment(source_code, node) or ""
                        tracker.mark_assign(self._v(target_name), self._v(val),
                                            reason="ann_assign",
                                            code=code, line=node.lineno)
                    self._check_sanitizer(node.value, [target_name], tracker, aliases or {})

    def _check_sanitizer(self, value_node: ast.expr, targets: list[str],
                         tracker: TaintTracker, aliases: dict[str, str]):
        """
        检查赋值的右侧表达式是否为消毒函数调用。
        如果是，则对被赋值的变量调用 tracker.sanitize() 切断污点链。

        按漏洞类型区分消毒：html.escape 只消毒 XSS，
        shlex.quote 只消毒命令执行，int() 消毒全部注入类漏洞。

        示例:
            x = int(user_input)      → 全类型消毒 "x"
            name = html.escape(raw)  → 只对 XSS 消毒 "name"
        """
        if not isinstance(value_node, ast.Call):
            return
        sanitizer_full = self._resolve_full_call(value_node, aliases)
        sanitizer_short = self._resolve_short_call(value_node)
        key = sanitizer_full if sanitizer_full in PYTHON_SANITIZER_NAMES else sanitizer_short
        if key in PYTHON_SANITIZER_NAMES:
            vuln_types = PYTHON_SANITIZER_NAMES[key]
            for target in targets:
                tracker.sanitize(self._v(target), key, vuln_types=vuln_types)

    def _dict_access_base(self, value_node: ast.expr) -> str:
        """
        提取字典/对象访问的基座变量名：
          d['k']        → d
          d.get('k')    → d
          d.get('k', 0) → d
        其它表达式返回空字符串。
        """
        if isinstance(value_node, ast.Subscript):
            return self._name_of(value_node.value) or ""
        if isinstance(value_node, ast.Call):
            func = value_node.func
            if isinstance(func, ast.Attribute) and func.attr == "get":
                return self._name_of(func.value) or ""
        return ""

    # ========================================================================
    # 返回值传播 + 调用点链接（跨函数/跨文件）
    # ========================================================================

    def _visit_returns(self, nodes: list, tracker: TaintTracker,
                       source_code: str):
        """return expr → 函数返回值节点 #ret（跨函数污点流的出口）。"""
        ret_var = f"{self._prefix}#ret"
        for node in nodes:
            if isinstance(node, ast.Return) and node.value:
                for name in self._extract_names(node.value):
                    code = ast.get_source_segment(source_code, node) or ""
                    tracker.mark_assign(ret_var, self._v(name), reason="return",
                                        code=code, line=node.lineno)

    def _resolve_project_target(self, node: ast.Call, info: dict) -> dict | None:
        """
        把调用点解析到项目内函数（跨文件）。

        支持：
          - f(...)                    本文件函数 / from x import f
          - obj.m(...)                self.m() / Class.m() / 模块别名.m()
        解析失败（外部库、实例变量等）返回 None。
        """
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
            if (info["module"], name) in self._func_index:
                return self._func_index[(info["module"], name)]
            entry = info["alias_mod"].get(name)
            if entry:
                mod, attr = entry
                if attr:
                    if (mod, attr) in self._func_index:
                        return self._func_index[(mod, attr)]
                else:
                    if (mod, name) in self._func_index:
                        return self._func_index[(mod, name)]
            return None
        if isinstance(func, ast.Attribute):
            m = func.attr
            base = func.value
            if isinstance(base, ast.Name):
                b = base.id
                if b in ("self", "cls") and self._current_class:
                    key = (info["module"], f"{self._current_class}.{m}")
                    if key in self._func_index:
                        return self._func_index[key]
                if b in info.get("classes", set()):
                    key = (info["module"], f"{b}.{m}")
                    if key in self._func_index:
                        return self._func_index[key]
                entry = info["alias_mod"].get(b)
                if entry:
                    mod, attr = entry
                    if attr:
                        key = (mod, f"{attr}.{m}")
                        if key in self._func_index:
                            return self._func_index[key]
                    else:
                        key = (mod, m)
                        if key in self._func_index:
                            return self._func_index[key]
            return None
        return None

    def _link_calls(self, nodes: list, tracker: TaintTracker, info: dict):
        """
        调用点链接：实参 → 形参、被调函数返回值 → 调用点变量。

        由于形参本身已按不可信 source 处理，这条链路主要用于：
          1. 把调用方实参的污点沿"形参 → 函数内传播"路径展示出来；
          2. 把被调函数的 return 值污点带回调用方（x = f(...) 后 x 污染）。
        """
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            target = self._resolve_project_target(node, info)
            if not target:
                continue
            callee_prefix = target["prefix"]
            params = target["params"]
            # ---- 实参 → 形参 ----
            for i, arg_node in enumerate(node.args):
                if i >= len(params):
                    break
                for name in self._extract_names(arg_node):
                    tracker.mark_assign(f"{callee_prefix}{params[i]}",
                                        self._v(name), reason="call_arg",
                                        code=ast.get_source_segment(
                                            info["source"], node) or "",
                                        line=node.lineno)
            for kw in node.keywords:
                if kw.arg and kw.arg in target["kwonly"]:
                    for name in self._extract_names(kw.value):
                        tracker.mark_assign(f"{callee_prefix}{kw.arg}",
                                            self._v(name), reason="call_kwarg",
                                            code=ast.get_source_segment(
                                                info["source"], node) or "",
                                            line=node.lineno)
            # ---- 返回值 → 调用结果 ----
            ret_node = f"{callee_prefix}#ret"
            assigned = self._get_assigned_var(node)
            if assigned:
                tracker.mark_assign(self._v(assigned), ret_node,
                                    reason="call_ret",
                                    code=ast.get_source_segment(
                                        info["source"], node) or "",
                                    line=node.lineno)

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

    def _resolve_attr_chain(self, node: ast.expr, aliases: dict[str, str],
                            local_types: dict[str, str] | None = None) -> str:
        """
        递归解析属性链，应用 import 别名和局部类型推断。

        示例:
            request.args  →  "flask.request.args"（因为 request 映射到 flask.request）
            cur           →  "db.Cursor"（cur = conn.cursor() 的局部类型）
        """
        if local_types is None:
            local_types = getattr(self, "_local_types", {})
        if isinstance(node, ast.Name):
            # 优先级：import 别名 > 局部类型 > 原名
            return aliases.get(node.id, local_types.get(node.id, node.id))
        if isinstance(node, ast.Attribute):
            return f"{self._resolve_attr_chain(node.value, aliases, local_types)}.{node.attr}"
        if isinstance(node, ast.Call):
            # 链式调用：func().attr
            return self._resolve_attr_chain(node.func, aliases, local_types)
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

        向上查找父节点链（穿过嵌套调用），判断当前调用是否在赋值语句右侧：
          - x = func()         → 目标变量 "x"
          - x = html.escape(input())  → 内层 input() 的目标也是 "x"
          - x: str = func()    → 目标变量 "x"
          - 独立调用 func()     → 生成匿名变量名

        返回:
            str: 变量名（可能是匿名的）
        """
        current = node
        for _ in range(6):  # 最多向上穿透 6 层（嵌套调用链）
            parent = getattr(current, "_parent", None)
            if parent is None:
                return self._make_var_name(node)

            if isinstance(parent, ast.Assign):
                # x = func() → 提取 x
                names = self._extract_target_names(parent.targets)
                return names[0] if names else self._make_var_name(node)

            if isinstance(parent, ast.AnnAssign):
                # x: str = func() → 提取 x
                return self._name_of(parent.target) or self._make_var_name(node)

            if isinstance(parent, ast.Call):
                # 嵌套调用：func2(func1())，继续向上找赋值目标
                current = parent
                continue

            # 遇到其它语句（如 return/参数传递），无法确定赋值目标
            return self._make_var_name(node)

        return self._make_var_name(node)

    def _make_var_name(self, node: ast.AST) -> str:
        """
        生成匿名变量名，用于无法确定变量名的表达式。

        格式: {作用域前缀}__anon_{AST类型}_{内存ID}
        保证唯一性，且与作用域绑定（跨函数不串扰）。
        """
        return f"{self._prefix}__anon_{type(node).__name__}_{id(node)}"

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

        if isinstance(node, ast.Attribute):
            # 属性访问：request.data / sys.argv
            # 返回确定性匿名名，与 _visit_sources 中属性型 source 的标记一致
            return [self._make_var_name(node)]

        if isinstance(node, ast.Subscript):
            # dict 下标访问：request.args['x']
            # 返回确定性匿名名，与 _visit_sources 中 mark_source 使用的
            # _get_assigned_var/_make_var_name 生成的名字一致
            return [self._make_var_name(node)]

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

            # CWE 标注：eval/exec/compile 等代码执行 sink 报 CWE-94，其余按类型映射
            sink_func = r.get("sink_func", "") or ""
            cwe = CWE_BY_TYPE.get(vt, "")
            if vt == "command_execution" and any(
                m in sink_func.lower() for m in CODE_EXEC_SINK_MARKERS
            ):
                cwe = "CWE-94"

            results.append({
                "file_path": r.get("file") or file_path,
                "line_number": r.get("sink_line", r.get("source_line", 0)),  # 优先使用 Sink 行号
                "vuln_type": vt,
                "severity": severity,
                "cwe": cwe,
                "language": "python",
                "source_code": r.get("source_code", ""),     # Source 点代码
                "sink_code": r.get("sink_code", ""),         # Sink 点代码
                "data_flow": r.get("data_flow", ""),         # 数据流路径
                "source_func": r.get("source_func", ""),     # Source 函数名
                "sink_func": sink_func,                       # Sink 函数名
                "source_line": r.get("source_line", 0),      # Source 行号
                "sink_line": r.get("sink_line", 0),          # Sink 行号
                "source_file": r.get("source_file", ""),     # 跨文件时的 source 文件
            })
        return results
