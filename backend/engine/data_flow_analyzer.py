"""
数据流分析引擎（第二阶段）
=========================
在污点追踪（Source→Sink 粗筛）之后，进行更深度的数据流分析。

==== 与污点追踪的区别 ====

污点追踪（Stage 1）：
  - 只追踪"变量是否被污染"
  - BFS 从 Source 到 Sink 找路径
  - 粗筛：快速排除无关代码

数据流分析（Stage 2）：
  - 追踪"数据如何变形"（拼接、格式化、编码、截断）
  - 分析控制流（if/else/while/function call）
  - 检测安全防护是否有效（白名单、参数化、转义）
  - 区分"真漏洞"和"有防护的安全代码"

==== 分析维度 ====

1. 字符串变换追踪：
   - 拼接 → 数据完整性保留
   - 格式化（sprintf） → 攻击面可能受限
   - 编码（base64/urlencode） → 可能绕过检测
   - 截断 → 攻击面缩小

2. 控制流敏感：
   - if (in_array($x, $allowlist)) → 白名单保护
   - if (is_numeric($x)) → 类型检查保护
   - if (strlen($x) < N) → 长度限制

3. 安全函数检测：
   - mysqli_real_escape_string() → 部分缓解（不完整）
   - htmlspecialchars() → XSS 防护
   - filter_var() → 输入验证
   - prepared statements → SQL 注入防护
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import re


class ProtectionLevel(Enum):
    """
    安全防护等级
    ============
    NONE      = 完全无防护，数据原样传递到 Sink
    PARTIAL   = 部分防护（如只做了转义未做参数化）
    STRONG    = 强防护（如 prepared statement、白名单）
    BYPASSABLE = 防护存在但可绕过（如黑名单过滤）
    """
    NONE = "none"
    PARTIAL = "partial"
    STRONG = "strong"
    BYPASSABLE = "bypassable"


class DataTransform(Enum):
    """
    数据变换类型
    ============
    追踪用户数据在传播过程中经历了哪些变换，
    帮助判断攻击面。
    """
    NONE = "none"               # 无变换，原样传递
    CONCAT = "concat"            # 字符串拼接（攻击面完整保留）
    FORMAT = "format"            # 格式化（sprintf 等）
    ENCODE = "encode"            # 编码（base64, urlencode 等）
    DECODE = "decode"            # 解码（可能还原被编码的攻击载荷）
    TRUNCATE = "truncate"        # 截断
    CASE_CHANGE = "case_change"  # 大小写变换
    TYPE_CAST = "type_cast"      # 类型转换（intval, floatval）
    ESCAPE = "escape"            # 转义（addslashes, htmlspecialchars）
    FILTER = "filter"            # 过滤（strip_tags, preg_replace）


@dataclass
class DataFlowNode:
    """
    数据流图中的节点
    ================
    比污点追踪的 TaintNode 更丰富，记录数据变形历史。
    """
    var_name: str                           # 变量名
    line: int                               # 行号
    is_source: bool = False                 # 是否为输入源
    is_sink: bool = False                   # 是否为危险出口
    transforms: list[DataTransform] = field(default_factory=list)  # 数据变换历史
    protections: list[str] = field(default_factory=list)           # 经过的安全函数
    code_snippet: str = ""                  # 代码片段
    value_pattern: str = ""                 # 识别出的值模式（如 "SQL query", "URL", "file path"）


@dataclass
class DataFlowFinding:
    """
    数据流分析的发现
    ================
    """
    file_path: str
    source_var: str
    sink_var: str
    source_line: int
    sink_line: int
    vuln_type: str
    protection_level: ProtectionLevel      # 防护等级
    transforms: list[DataTransform]         # 数据经过的变换
    is_exploitable: bool                    # AI 辅助判定是否可实际利用
    exploit_difficulty: str = "unknown"     # easy / medium / hard / unlikely
    notes: str = ""                         # 分析备注


class DataFlowAnalyzer:
    """
    数据流分析器（第二阶段）
    ========================
    对污点追踪（Stage 1）的输出做深度分析。

    输入：Stage 1 的漏洞列表（Source→Sink 路径）
    输出：带防护等级和利用难度的增强分析结果

    用法：
        analyzer = DataFlowAnalyzer()
        enhanced = analyzer.analyze(vulns_from_stage1, project_path)
    """

    # 安全函数识别模式
    PROTECTION_PATTERNS = {
        # SQL 注入防护
        "prepared_statement": [
            r"mysqli_prepare", r"PDO::prepare", r"pg_prepare",
            r"\bprepare\s*\(.*SELECT|INSERT|UPDATE|DELETE",
        ],
        "sql_escape": [
            r"mysqli_real_escape_string", r"mysql_real_escape_string",
            r"addslashes", r"pg_escape_string",
        ],
        "sql_parameterized": [
            r"\?.*placeholder", r":\w+.*placeholder",
        ],

        # 命令注入防护
        "escapeshellarg": [r"escapeshellarg", r"escapeshellcmd"],
        "command_allowlist": [r"in_array\s*\(.*\[.*\]"],

        # XSS 防护
        "html_encode": [r"htmlspecialchars", r"htmlentities", r"strip_tags"],

        # 通用输入验证
        "type_validation": [r"is_numeric", r"is_int", r"is_float", r"ctype_digit"],
        "filter_var": [r"filter_var\s*\(.*FILTER_"],
        "regex_validation": [r"preg_match\s*\(.*/.*/"],
        "allowlist_check": [r"in_array\s*\(.*\$allowed", r"in_array\s*\(.*\$whitelist"],
    }

    # 数据变换模式
    TRANSFORM_PATTERNS = {
        DataTransform.CONCAT: [r"\.(\s*\$)", r"\$\w+\s*\.", r"\.=\s*\$"],
        DataTransform.FORMAT: [r"sprintf\s*\(.*\$", r"printf\s*\(.*\$"],
        DataTransform.ENCODE: [r"base64_encode", r"urlencode", r"rawurlencode"],
        DataTransform.DECODE: [r"base64_decode", r"urldecode"],
        DataTransform.TRUNCATE: [r"substr\s*\(.*\$", r"mb_substr\s*\(.*\$"],
        DataTransform.ESCAPE: [r"addslashes", r"mysqli_real_escape_string"],
        DataTransform.TYPE_CAST: [r"intval\s*\(.*\$", r"floatval\s*\(.*\$", r"\(int\)\s*\$"],
        DataTransform.FILTER: [r"strip_tags", r"filter_var"],
    }

    def analyze(self, vulns: list[dict], source_code_map: dict[str, str]) -> list[DataFlowFinding]:
        """对漏洞列表做数据流增强分析（向后兼容）"""
        findings = []
        for v in vulns:
            findings.append(self._analyze_single(v, source_code_map))
        return findings

    # ================================================================
    # 独立扫描（不依赖其他阶段输出）
    # ================================================================

    def analyze_independent(self, source_code_map: dict[str, str],
                            language: str) -> list[dict]:
        """
        独立扫描所有源文件，发现数据流相关的漏洞。
        使用正则模式检测危险函数调用 + 用户输入在同一代码块中。

        返回: 漏洞列表（dict 格式，与其他阶段统一）
        """
        patterns = self._get_language_patterns(language)
        if not patterns:
            return []

        vulns = []
        for file_path, source in source_code_map.items():
            lines = source.split("\n")
            vulns.extend(self._scan_file_independent(file_path, lines, patterns, language))

        # ---- 跨文件检测：项目整体有 source + sink，但分散在不同文件 ----
        all_code = "\n".join(source_code_map.values())
        for vuln_type, severity, src_pat, sink_pat, desc in patterns:
            has_src = bool(re.search(src_pat, all_code, re.IGNORECASE))
            has_snk = bool(re.search(sink_pat, all_code, re.IGNORECASE))
            if not has_src or not has_snk:
                continue
            for file_path, source in source_code_map.items():
                lines = source.split("\n")
                if not re.search(sink_pat, source, re.IGNORECASE):
                    continue
                if re.search(src_pat, source, re.IGNORECASE):
                    continue  # 同文件已检测过
                # 跨文件：该文件只有 sink，source 在别处
                src_file = ""
                for fp, src in source_code_map.items():
                    if re.search(src_pat, src, re.IGNORECASE):
                        src_file = fp
                        break
                for i, line in enumerate(lines):
                    if re.search(sink_pat, line, re.IGNORECASE):
                        # 只报告一次每个文件的每种类型
                        key = (vuln_type, file_path)
                        if key not in {(v.get("vuln_type"), v.get("file_path")) for v in vulns if v.get("pipeline_stage") == "data_flow"}:
                            vulns.append({
                                "file_path": file_path, "line_number": i + 1, "sink_line": i + 1,
                                "vuln_type": vuln_type, "severity": severity, "language": language,
                                "source_code": f"Source: {src_file}", "sink_code": line.strip(),
                                "data_flow": f"跨文件: {desc}", "pipeline_stage": "data_flow",
                            })
                        break

        return vulns

    def _get_language_patterns(self, language: str) -> list[dict]:
        """获取语言对应的检测模式"""
        ALL_PATTERNS = {
            "python": [
                # (vuln_type, severity, source_pattern, sink_pattern, description)
                ("command_execution", "critical",
                 r'(?:request\.(?:args|form|json|data|values)\.get|input\s*\(|sys\.argv)',
                 r'(?:os\.system|subprocess\.(?:call|run|Popen)|eval|exec)\s*\(',
                 "用户输入 → 命令执行"),
                ("sql_injection", "high",
                 r'(?:request\.(?:args|form|json|data|values)\.get|input\s*\(|sys\.argv)',
                 r'(?:\.execute\s*\(|raw\s*=\s*["\']SELECT|f["\'].*SELECT)',
                 "用户输入 → SQL 查询"),
                ("path_traversal", "medium",
                 r'(?:request\.(?:args|form|json|data|values)\.get|input\s*\(|sys\.argv)',
                 r'(?:open\s*\(|Path\s*\(|os\.path\.join|os\.listdir)',
                 "用户输入 → 文件路径操作"),
                ("arbitrary_file_read", "medium",
                 r'(?:request\.(?:args|form|json|data|values)\.get|input\s*\(|sys\.argv)',
                 r'(?:open\s*\(.*["\']r|read\(\)|readlines\(\)|send_file)',
                 "用户输入 → 文件读取"),
                ("ssrf", "high",
                 r'(?:request\.(?:args|form|json|data|values)\.get|input\s*\(|sys\.argv)',
                 r'requests\.(?:get|post|put|delete|patch|head)\s*\(',
                 "用户输入 → HTTP 请求"),
                ("xss", "low",
                 r'(?:request\.(?:args|form|json|data|values)\.get|input\s*\(|sys\.argv)',
                 r'(?:return\s+.*render_template|Response|Markup|make_response)',
                 "用户输入 → Web 输出"),
            ],
            "php": [
                ("command_execution", "critical",
                 r'(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|php://input)',
                 r'(?:system|exec|shell_exec|passthru|popen|proc_open|eval)\s*\(',
                 "用户输入 → 命令/代码执行"),
                ("sql_injection", "high",
                 r'(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|php://input|addslashes)',
                 r'(?:mysqli_query|mysql_query|pg_query|->query|->exec|sqlite_query)\s*\(',
                 "用户输入 → SQL 查询"),
                ("path_traversal", "medium",
                 r'(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|php://input)',
                 r'(?:include|require)(?:_once)?\s*\(?\s*\$',
                 "用户输入 → 动态文件包含"),
                ("ssrf", "high",
                 r'(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|php://input)',
                 r'(?:curl_exec|curl_setopt\s*\(.*CURLOPT_URL|file_get_contents)\s*\(',
                 "用户输入 → 网络请求"),
                ("xss", "low",
                 r'(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                 r'(?:echo|print|printf)\s+(?!.*htmlspecialchars)(?!.*htmlentities)',
                 "用户输入 → 直接输出"),
                ("arbitrary_file_read", "medium",
                 r'(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|php://input)',
                 r'(?:file_get_contents|fread|readfile|fgets)\s*\(',
                 "用户输入 → 文件读取"),
                ("file_upload", "high",
                 r'(?:\$_FILES|\$_POST|\$_REQUEST)',
                 r'(?:move_uploaded_file|is_uploaded_file)\s*\(',
                 "文件上传操作"),
                ("deserialization", "high",
                 r'(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                 r'unserialize\s*\(',
                 "用户输入 → 反序列化"),
            ],
            "c": [
                ("command_execution", "critical",
                 r'(?:fgets|scanf|argv|getenv)\s*\(',
                 r'(?:system|popen|exec[lv]p?)\s*\(',
                 "用户输入 → 命令执行"),
                ("sql_injection", "high",
                 r'(?:fgets|scanf|argv|getenv)\s*\(',
                 r'(?:mysql_query|sqlite3_exec)\s*\(',
                 "用户输入 → SQL 查询"),
            ],
            "cpp": [
                ("command_execution", "critical",
                 r'(?:fgets|scanf|std::cin|argv|getenv)\s*\(',
                 r'(?:system|popen|exec[lv]p?)\s*\(',
                 "用户输入 → 命令执行"),
                ("sql_injection", "high",
                 r'(?:fgets|scanf|std::cin|argv|getenv)\s*\(',
                 r'(?:mysql_query|sqlite3_exec)\s*\(',
                 "用户输入 → SQL 查询"),
            ],
        }
        return ALL_PATTERNS.get(language, [])

    def _scan_file_independent(self, file_path: str, lines: list[str],
                                patterns: list, language: str) -> list[dict]:
        """
        独立扫描单个文件：
        当 source 和 sink 出现在相邻代码块（同一函数体）中时报告漏洞。
        """
        vulns = []
        # 将文件按函数边界切分为代码块
        blocks = self._split_into_blocks(lines, language)

        for block_start, block_end in blocks:
            block_text = "\n".join(lines[block_start:block_end])
            for vuln_type, severity, src_pat, sink_pat, desc in patterns:
                has_source = re.search(src_pat, block_text, re.IGNORECASE)
                has_sink = re.search(sink_pat, block_text, re.IGNORECASE)
                if has_source and has_sink:
                    # 找到 sink 所在行
                    sink_line = block_start + 1
                    for i in range(block_start, block_end):
                        if re.search(sink_pat, lines[i], re.IGNORECASE):
                            sink_line = i + 1
                            break
                    vulns.append({
                        "file_path": file_path,
                        "line_number": sink_line,
                        "sink_line": sink_line,
                        "vuln_type": vuln_type,
                        "severity": severity,
                        "language": language,
                        "source_code": "",
                        "sink_code": lines[sink_line - 1].strip() if sink_line - 1 < len(lines) else "",
                        "data_flow": desc,
                        "pipeline_stage": "data_flow",
                    })

        return vulns

    def _split_into_blocks(self, lines: list[str], language: str) -> list[tuple[int, int]]:
        """将源文件按函数/类边界切分为代码块"""
        if language == "python":
            block_starts = []
            for i, line in enumerate(lines):
                if re.match(r'^\s*def\s+', line) or re.match(r'^\s*class\s+', line):
                    block_starts.append(i)
            if not block_starts:
                return [(0, len(lines))]  # 整文件作为一个块
            blocks = []
            for j, start in enumerate(block_starts):
                end = block_starts[j + 1] if j + 1 < len(block_starts) else len(lines)
                blocks.append((start, end))
            return blocks
        else:
            # PHP / C / C++: 以 { } 或 function 为边界
            blocks = []
            block_start = None
            depth = 0
            for i, line in enumerate(lines):
                if re.search(r'(?:function|void|int|char|bool|string|class)\s+\w+\s*\(', line):
                    if block_start is not None and depth == 0:
                        blocks.append((block_start, i))
                    block_start = i
                    depth = 0
                depth += line.count('{') - line.count('}')
                if depth < 0:
                    depth = 0
            if block_start is not None:
                blocks.append((block_start, len(lines)))
            if not blocks:
                blocks.append((0, len(lines)))
            return blocks

    def _analyze_single(self, vuln: dict, source_code_map: dict[str, str]) -> DataFlowFinding:
        """
        对单个漏洞做深度分析。

        分析步骤:
          1. 提取 Source 和 Sink 之间的代码块
          2. 检测安全防护模式
          3. 检测数据变换
          4. 综合评定防护等级和利用难度
        """
        file_path = vuln.get("file_path", "")
        source_code = source_code_map.get(file_path, "")
        data_flow = vuln.get("data_flow", "")
        vuln_type = vuln.get("vuln_type", "")

        # 提取 Source→Sink 之间的代码上下文
        context = self._extract_context(
            source_code,
            vuln.get("source_line", 0),
            vuln.get("sink_line", 0),
        )

        # 检测安全防护
        protections = self._detect_protections(context, vuln_type)
        protection_level = self._assess_protection(protections, vuln_type)

        # 检测数据变换
        transforms = self._detect_transforms(context)

        # 评定利用难度
        exploit_difficulty = self._assess_exploitability(
            protection_level, transforms, vuln_type
        )

        is_exploitable = protection_level in (
            ProtectionLevel.NONE, ProtectionLevel.PARTIAL, ProtectionLevel.BYPASSABLE
        )

        return DataFlowFinding(
            file_path=file_path,
            source_var=data_flow.split(" → ")[0] if " → " in data_flow else "",
            sink_var=data_flow.split(" → ")[-1] if " → " in data_flow else "",
            source_line=vuln.get("source_line", 0),
            sink_line=vuln.get("sink_line", 0),
            vuln_type=vuln_type,
            protection_level=protection_level,
            transforms=transforms,
            is_exploitable=is_exploitable,
            exploit_difficulty=exploit_difficulty,
            notes=self._generate_notes(protection_level, transforms, vuln_type),
        )

    def _extract_context(self, source_code: str, source_line: int, sink_line: int) -> str:
        """提取 Source 和 Sink 之间的代码块"""
        if not source_code:
            return ""
        lines = source_code.split("\n")
        start = max(0, min(source_line, sink_line) - 1)
        end = min(len(lines), max(source_line, sink_line))
        return "\n".join(lines[start:end])

    def _detect_protections(self, context: str, vuln_type: str) -> list[str]:
        """检测代码中的安全防护措施"""
        found = []
        for category, patterns in self.PROTECTION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    found.append(category)
                    break  # 每类只计一次
        return found

    def _detect_transforms(self, context: str) -> list[DataTransform]:
        """检测数据经过的变换"""
        found = []
        for transform, patterns in self.TRANSFORM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    found.append(transform)
                    break
        return found if found else [DataTransform.NONE]

    def _assess_protection(self, protections: list[str], vuln_type: str) -> ProtectionLevel:
        """
        综合评定安全防护等级。

        规则:
          - prepared_statement + sql_parameterized → STRONG
          - 仅 sql_escape → PARTIAL（可以绕过）
          - allowlist_check / type_validation → STRONG（白名单验证）
          - escapeshellarg 单独 → PARTIAL
          - html_encode → STRONG（XSS 防护）
          - 空防护 → NONE
        """
        if not protections:
            return ProtectionLevel.NONE

        # SQL 注入：prepared statement 是黄金标准
        if vuln_type == "sql_injection":
            if "prepared_statement" in protections or "sql_parameterized" in protections:
                return ProtectionLevel.STRONG
            if "sql_escape" in protections:
                return ProtectionLevel.PARTIAL  # 转义可能被宽字节绕过

        # 命令执行：escapeshellarg 不完美但有效
        if vuln_type == "command_execution":
            if "command_allowlist" in protections:
                return ProtectionLevel.STRONG
            if "escapeshellarg" in protections:
                return ProtectionLevel.PARTIAL

        # XSS：htmlspecialchars 是标准防护
        if vuln_type == "xss":
            if "html_encode" in protections:
                return ProtectionLevel.STRONG

        # 通用：白名单 / 类型校验 = 强防护
        if "allowlist_check" in protections or "type_validation" in protections:
            return ProtectionLevel.STRONG

        # 有防护但不完美
        return ProtectionLevel.PARTIAL

    def _assess_exploitability(
        self, protection: ProtectionLevel, transforms: list[DataTransform], vuln_type: str
    ) -> str:
        """
        综合评定利用难度。

        返回:
            "easy"     — 几乎肯定可利用
            "medium"   — 可能需要一些技巧
            "hard"     — 难度较高，需绕过防护
            "unlikely" — 极难利用或不可利用
        """
        if protection == ProtectionLevel.NONE:
            return "easy"
        if protection == ProtectionLevel.PARTIAL:
            return "medium"
        if protection == ProtectionLevel.BYPASSABLE:
            return "medium"
        if protection == ProtectionLevel.STRONG:
            return "unlikely"
        return "medium"

    def _generate_notes(
        self, protection: ProtectionLevel, transforms: list[DataTransform], vuln_type: str
    ) -> str:
        """生成人类可读的分析备注"""
        parts = []

        if protection == ProtectionLevel.NONE:
            parts.append("无任何安全防护，数据从 Source 原样流向 Sink")
        elif protection == ProtectionLevel.PARTIAL:
            parts.append("存在部分防护措施，但可能在特定条件下被绕过")
        elif protection == ProtectionLevel.STRONG:
            parts.append("存在有效防护（如参数化查询/白名单/类型校验），实际可利用性低")
        elif protection == ProtectionLevel.BYPASSABLE:
            parts.append("防护措施存在但可绕过")

        if DataTransform.ENCODE in transforms:
            parts.append("数据经过编码变换，攻击载荷可能需要相应编码")
        if DataTransform.TRUNCATE in transforms:
            parts.append("数据被截断，限制了攻击载荷长度")
        if DataTransform.TYPE_CAST in transforms:
            parts.append("数据被类型转换，非数字类攻击受限")

        return "；".join(parts) if parts else "未检测到明显特征"
