"""
模板文件 XSS 分析器（Stage 3 补充）
================================
扫描 Jinja2 / Django 模板文件（.html / .jinja2 / .j2 等），检测模板层
XSS 风险。这类问题发生在模板渲染时，纯 .py 污点追踪无法覆盖：

  1. `{{ var | safe }}`      —— 显式关闭自动转义（Jinja2/Django 均适用）
  2. `{% autoescape off %}`  —— 关闭整块转义
  3. `<script>` 块内插值 `{{ var }}` —— JS 注入（HTML 转义不防 JS 上下文）

RealVuln 基准中 XSS GT 有 ~47 条标注在模板文件上，本模块直接以模板
行号产出发现，与 GT 对齐。

输出字段与引擎其余 Stage 一致：file_path / line_number / vuln_type /
severity / cwe / language / description / pipeline_stage。
"""
import re
import os
from dataclasses import dataclass

TEMPLATE_EXTS = {".html", ".htm", ".jinja2", ".j2", ".tmpl"}

SKIP_DIRS = {
    "__pycache__", ".git", "node_modules", "vendor", "venv", "env",
    "dist", "build", "site-packages", "static", "bower_components",
}

# `{% autoescape off %}` / `{% autoescape false %}`
AUTOESCAPE_OFF_RE = re.compile(r'{%\s*autoescape\s+(?:off|false)\s*%}', re.IGNORECASE)

# `{{ expr | safe }}` —— expr 为字面量字符串时不算（无用户输入）
SAFE_FILTER_RE = re.compile(r'{{\s*(.*?)\s*\|\s*safe\s*}}')

# 疑似字面量：以引号开头
LITERAL_RE = re.compile(r'^[\'"]')


@dataclass
class TemplateFinding:
    file_path: str
    line_number: int
    description: str
    evidence: str


class TemplateAnalyzer:
    """模板文件 XSS 分析器"""

    def analyze(self, project_path: str) -> list[dict]:
        findings: list[dict] = []
        for file_path in self._collect_templates(project_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
            except Exception:
                continue
            findings.extend(self._analyze_file(file_path, source))
        return findings

    def _collect_templates(self, project_path: str) -> list[str]:
        files = []
        for root, dirs, filenames in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in TEMPLATE_EXTS:
                    files.append(os.path.join(root, fn))
        return files

    def _analyze_file(self, file_path: str, source: str) -> list[dict]:
        findings = []
        lines = source.split("\n")
        in_script = False

        for i, line in enumerate(lines, 1):
            # ---- 1. |safe 过滤器（跳过字面量） ----
            for m in SAFE_FILTER_RE.finditer(line):
                expr = m.group(1).strip()
                if LITERAL_RE.match(expr):
                    continue  # {{ '静态字符串' | safe }} 无用户输入
                if expr == "":
                    continue
                findings.append(self._make(
                    file_path, i,
                    "模板关闭自动转义（|safe）：用户可控内容直接以 HTML 输出，"
                    "存在反射型/存储型 XSS 风险",
                    line.strip(),
                ))
                break  # 每行只报一次

            # ---- 2. autoescape off ----
            if AUTOESCAPE_OFF_RE.search(line):
                findings.append(self._make(
                    file_path, i,
                    "模板关闭自动转义（autoescape off）：该块内所有变量输出"
                    "不再进行 HTML 转义，存在 XSS 风险",
                    line.strip(),
                ))

            # ---- 3. <script> 块内插值（JS 注入） ----
            stripped = line.strip()
            if re.search(r'<script[^>]*>', stripped, re.IGNORECASE):
                in_script = True
            if in_script and "{{" in line:
                findings.append(self._make(
                    file_path, i,
                    "<script> 上下文中的模板插值：HTML 转义无法阻止 JS 注入，"
                    "存在脚本注入（XSS）风险",
                    line.strip(),
                ))
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
