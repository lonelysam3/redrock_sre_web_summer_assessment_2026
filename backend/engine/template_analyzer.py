"""
模板文件 XSS 分析器（Stage 3 补充）
================================
扫描 Jinja2 / Django 模板文件（.html / .jinja2 / .j2 等），检测模板层
XSS 风险。这类问题发生在模板渲染时，纯 .py 污点追踪无法覆盖：

  1. `{{ var | safe }}`      —— 显式关闭自动转义（Jinja2/Django 均适用）
  2. `{% autoescape off %}`  —— 关闭整块转义
  3. `<script>` 块内插值 `{{ var }}` —— JS 注入（HTML 转义不防 JS 上下文）

精度收口（视图→模板变量链接）：
  从项目 .py 中收集 render_template / render(request, ...) 调用，分析
  每个上下文变量是否来自用户输入（request.* / 函数参数 / 局部传播，
  经 sanitizer 消毒的除外）。只有当模板中 |safe / autoescape off /
  <script> 涉及\"视图传入的可疑变量\"时才报告，避免把
  `{{ field.help_text|safe }}`（开发者自填文本）或已消毒变量当成漏洞。

  模板若没有任何视图链接信息（如纯静态站），保持原有宽松行为，
  保护召回。
"""
import re
import os
import ast
from dataclasses import dataclass

TEMPLATE_EXTS = {".html", ".htm", ".jinja2", ".j2", ".tmpl"}
PY_EXTS = {".py"}

SKIP_DIRS = {
    "__pycache__", ".git", "node_modules", "vendor", "venv", "env",
    "dist", "build", "site-packages", "static", "bower_components",
}

# `{% autoescape off %}` / `{% autoescape false %}`
AUTOESCAPE_OFF_RE = re.compile(r'{%\s*autoescape\s+(?:off|false)\s*%}', re.IGNORECASE)
AUTOESCAPE_END_RE = re.compile(r'{%\s*endautoescape\s*%}', re.IGNORECASE)

# `{{ expr | safe }}`
SAFE_FILTER_RE = re.compile(r'{{\s*(.*?)\s*\|\s*safe\s*}}')

# 模板变量插值
TPL_VAR_RE = re.compile(r'{{\s*([A-Za-z_][\w.]*)\s*(?:\|[^}]*)?}}')

# 疑似字面量：以引号开头
LITERAL_RE = re.compile(r'^[\'"]')

# 用户输入 source 特征（粗粒度文本匹配）
SOURCE_MARKERS = (
    "request.args", "request.form", "request.values", "request.json",
    "request.cookies", "request.headers", "request.data", "request.files",
    "request.get_json", "request.get_data", "api.payload", "parse_args",
    "sys.argv", "input(", "os.environ", "os.getenv", "request.POST",
    "request.GET", "request.COOKIES", "request.META",
)

# XSS 消毒函数：结果视为安全
XSS_SANITIZERS = {
    "escape", "html.escape", "markupsafe.escape", "cgi.escape",
    "bleach.clean", "django.utils.html.escape", "escapejs",
    "int", "float", "round", "abs",
}


@dataclass
class TemplateFinding:
    file_path: str
    line_number: int
    description: str
    evidence: str


class TemplateAnalyzer:
    """模板文件 XSS 分析器（含视图→模板变量链接）"""

    def analyze(self, project_path: str) -> list[dict]:
        view_taint = self._collect_view_taint(project_path)
        findings: list[dict] = []
        for file_path in self._collect_files(project_path, TEMPLATE_EXTS):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
            except Exception:
                continue
            tainted_vars, has_link = self._resolve_tainted_vars(file_path, view_taint)
            findings.extend(self._analyze_file(file_path, source,
                                               tainted_vars, has_link))
        return findings

    # ------------------------------------------------------------------
    # 视图→模板变量链接
    # ------------------------------------------------------------------

    def _collect_view_taint(self, project_path: str) -> dict[str, set[str]]:
        """
        收集 {模板名: 可疑上下文变量集合}。

        对每个 .py：解析函数 → 计算函数内 tainted 局部变量（参数 + 传播）；
        找到 render_template('tpl', var=expr) / render(request, 'tpl', {...})
        调用，判断每个 var 的 expr 是否 tainted。
        """
        result: dict[str, set[str]] = {}
        for py_file in self._collect_files(project_path, PY_EXTS):
            try:
                with open(py_file, "r", encoding="utf-8", errors="ignore") as f:
                    src = f.read()
                tree = ast.parse(src)
            except Exception:
                continue

            # 注入父节点引用（_enclosing_func_taint 依赖）
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    child._parent = parent  # type: ignore
            self._current_source = src

            # 每个函数：tainted 局部变量集（含参数，参数本身视为可疑输入）
            func_taint: dict[int, set[str]] = {}
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                params = {a.arg for a in node.args.args
                          if a.arg not in ("self", "cls")}
                tainted = set(params)
                for sub in ast.walk(node):
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                            and sub is not node:
                        continue  # 嵌套函数独立处理
                    if isinstance(sub, ast.Assign):
                        names = [t.id for t in sub.targets
                                 if isinstance(t, ast.Name)]
                        if self._expr_tainted(sub.value, tainted):
                            tainted.update(names)
                    elif isinstance(sub, ast.AnnAssign) and \
                            isinstance(sub.target, ast.Name):
                        if sub.value and self._expr_tainted(sub.value, tainted):
                            tainted.add(sub.target.id)
                func_taint[id(node)] = tainted

            # 收集渲染调用
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fname = self._call_name(node)
                if fname not in ("render_template", "render",
                                 "render_template_string"):
                    continue
                if not node.args:
                    continue
                tpl = node.args[0]
                tpl_name = ""
                if isinstance(tpl, ast.Constant) and isinstance(tpl.value, str):
                    tpl_name = tpl.value
                if not tpl_name:
                    continue

                # 调用所在函数的 tainted 集
                tainted = self._enclosing_func_taint(node, func_taint)
                names = result.setdefault(tpl_name, set())

                # kwargs: render_template('x', var=expr)
                for kw in node.keywords:
                    if kw.arg and self._expr_tainted(kw.value, tainted):
                        names.add(kw.arg)
                # Django render(request, 'x', {'var': expr})
                if len(node.args) >= 3 and isinstance(node.args[2], ast.Dict):
                    for k, v in zip(node.args[2].keys, node.args[2].values):
                        if isinstance(k, ast.Constant) and isinstance(k.value, str):
                            if self._expr_tainted(v, tainted):
                                names.add(k.value)
        return result

    @staticmethod
    def _enclosing_func_taint(node: ast.AST,
                              func_taint: dict[int, set[str]]) -> set[str]:
        cur = node
        while cur is not None:
            if id(cur) in func_taint:
                return func_taint[id(cur)]
            cur = getattr(cur, "_parent", None)
        return set()

    def _expr_tainted(self, expr: ast.AST | None,
                      tainted: set[str]) -> bool:
        if expr is None:
            return False
        if isinstance(expr, ast.Name):
            return expr.id in tainted
        if isinstance(expr, ast.Attribute):
            return self._expr_tainted(expr.value, tainted)
        if isinstance(expr, ast.Call):
            fname = self._call_name(expr)
            if fname in XSS_SANITIZERS:
                return False  # 已消毒
            # 文本特征：request.args.get(...) / api.payload 等 source 调用链
            seg = self._source_segment(expr)
            if seg and any(m in seg for m in SOURCE_MARKERS):
                return True
            for arg in expr.args:
                if self._expr_tainted(arg, tainted):
                    return True
            for kw in expr.keywords:
                if self._expr_tainted(kw.value, tainted):
                    return True
            return False
        if isinstance(expr, ast.Subscript):
            return self._expr_tainted(expr.value, tainted)
        if isinstance(expr, ast.BinOp):
            return self._expr_tainted(expr.left, tainted) or \
                self._expr_tainted(expr.right, tainted)
        if isinstance(expr, ast.BoolOp):
            return any(self._expr_tainted(v, tainted) for v in expr.values)
        if isinstance(expr, ast.JoinedStr):
            for val in expr.values:
                if isinstance(val, ast.FormattedValue) and \
                        self._expr_tainted(val.value, tainted):
                    return True
            return False
        if isinstance(expr, ast.IfExp):
            return self._expr_tainted(expr.body, tainted) or \
                self._expr_tainted(expr.orelse, tainted)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_tainted(e, tainted) for e in expr.elts)
        if isinstance(expr, ast.Dict):
            return any(self._expr_tainted(v, tainted) for v in expr.values)
        if isinstance(expr, ast.Lambda):
            return False
        # 兜底：源码文本含 source 特征
        seg = self._source_segment(expr)
        return bool(seg) and any(m in seg for m in SOURCE_MARKERS)

    def _source_segment(self, node: ast.AST) -> str:
        try:
            return ast.get_source_segment(
                getattr(self, "_current_source", ""), node) or ""
        except Exception:
            return ""

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        f = node.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            return f.attr
        return ""

    def _resolve_tainted_vars(self, file_path: str,
                              view_taint: dict[str, set[str]]) -> tuple[set[str], bool]:
        """模板文件 → (可疑变量集合, 是否有视图链接)。"""
        norm = file_path.replace("\\", "/")
        matched = set()
        for tpl_name, names in view_taint.items():
            tn = tpl_name.replace("\\", "/").lstrip("/")
            if norm.endswith(tn) or tn.endswith(norm.split("/")[-1]):
                matched |= names
        return matched, bool(matched)

    # ------------------------------------------------------------------
    # 模板扫描
    # ------------------------------------------------------------------

    def _collect_files(self, project_path: str, exts: set[str]) -> list[str]:
        files = []
        for root, dirs, filenames in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in exts:
                    files.append(os.path.join(root, fn))
        return files

    def _analyze_file(self, file_path: str, source: str,
                      tainted_vars: set[str], has_link: bool) -> list[dict]:
        findings = []
        lines = source.split("\n")
        in_script = False
        in_autoescape_off = False

        def var_is_tainted(var_expr: str) -> bool:
            if not has_link:
                return True  # 无视图链接信息：保持宽松（保护召回）
            m = re.match(r'[A-Za-z_]\w*', var_expr.strip())
            return bool(m) and m.group(0) in tainted_vars

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # ---- 2. autoescape off：块内有可疑变量才报 ----
            if AUTOESCAPE_OFF_RE.search(line):
                # 向后扫描到 endautoescape，检查块内是否引用可疑变量
                block_tainted = False
                j = i
                while j < len(lines):
                    if AUTOESCAPE_END_RE.search(lines[j]):
                        break
                    if AUTOESCAPE_OFF_RE.search(lines[j]) and j != i - 1:
                        break
                    for vm in TPL_VAR_RE.finditer(lines[j]):
                        if var_is_tainted(vm.group(1)):
                            block_tainted = True
                            break
                    if block_tainted:
                        break
                    j += 1
                if block_tainted:
                    findings.append(self._make(
                        file_path, i,
                        "模板关闭自动转义（autoescape off）：该块内输出视图传入的"
                        "用户可控变量时不再进行 HTML 转义，存在 XSS 风险",
                        line.strip(),
                    ))

            # ---- 1. |safe 过滤器 ----
            for m in SAFE_FILTER_RE.finditer(line):
                expr = m.group(1).strip()
                if LITERAL_RE.match(expr) or expr == "":
                    continue
                if not var_is_tainted(expr):
                    continue
                findings.append(self._make(
                    file_path, i,
                    "模板关闭自动转义（|safe）：视图传入的用户可控内容直接以 "
                    "HTML 输出，存在反射型/存储型 XSS 风险",
                    line.strip(),
                ))
                break

            # ---- 3. <script> 块内插值 ----
            if re.search(r'<script[^>]*>', stripped, re.IGNORECASE):
                in_script = True
            if in_script and "{{" in line:
                for vm in TPL_VAR_RE.finditer(line):
                    if var_is_tainted(vm.group(1)):
                        findings.append(self._make(
                            file_path, i,
                            "<script> 上下文中的模板插值：HTML 转义无法阻止 "
                            "JS 注入，存在脚本注入（XSS）风险",
                            line.strip(),
                        ))
                        break
            if "</script>" in stripped:
                in_script = False

        return findings

    @staticmethod
    def _make(file_path: str, line: int, description: str,
              evidence: str) -> dict:
        return {
            "file_path": file_path,
            "line_number": line,
            "vuln_type": "xss",
            "severity": "low",   # 与引擎 XSS 严重程度一致
            "cwe": "CWE-79",
            "language": "python",
            "description": description,
            "evidence": evidence,
            "source_code": evidence,
            "sink_code": evidence,
            "pipeline_stage": "ast",
        }
