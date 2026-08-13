"""
AST 抽象语法树分析器（第三阶段）
===============================
对前两阶段无法确定的漏洞进行结构化的 AST 模式检测。

==== 作用 ====

Stage 1（污点追踪）→ 粗筛出 Source→Sink 路径
Stage 2（数据流分析）→ 检测防护措施和变换
Stage 3（AST 分析）→ 结构级语义理解，识别以下模式：

1. 参数化查询检测：
   - 识别 ? placeholder 或 :named 参数
   - 区分字符串拼接 SQL vs 参数化 SQL

2. 白名单验证模式：
   - if ($input in $allowed_list)  → 安全
   - if (in_array($x, [...]))      → 安全

3. 输出上下文检测：
   - echo 在 HTML body → XSS
   - echo 在 HTML attribute → XSS（需要不同转义）
   - echo 在 <script> → JS 注入

4. 危险函数组合模式：
   - unserialize + __destruct → POP 链风险
   - file_get_contents + eval → 代码执行
   - extract + include → 变量覆盖 + 文件包含

5. 语义等价分析：
   - $_GET['x'] → $x → mysqli_query($sql . $x) 中的实际角色
"""
from dataclasses import dataclass, field
from enum import Enum
import re


class ASTPattern(Enum):
    """AST 模式类型"""
    PARAMETERIZED_QUERY = "parameterized_query"        # 参数化查询
    STRING_CONCAT_SQL = "string_concat_sql"            # 字符串拼接 SQL
    ALLOWLIST_CHECK = "allowlist_check"                 # 白名单验证
    BLACKLIST_FILTER = "blacklist_filter"               # 黑名单过滤（不安全）
    OUTPUT_IN_SCRIPT = "output_in_script"               # 输出在 <script> 标签内
    OUTPUT_IN_ATTRIBUTE = "output_in_attribute"         # 输出在 HTML 属性中
    DANGEROUS_COMBO = "dangerous_combo"                # 危险函数组合
    EXTRACT_OVERRIDE = "extract_override"               # extract() 变量覆盖
    MAGIC_METHOD_CHAIN = "magic_method_chain"           # 魔术方法链
    HARDCODED_CREDENTIALS = "hardcoded_credentials"     # 硬编码凭据
    DEBUG_MODE = "debug_mode"                           # 调试模式开启


@dataclass
class ASTFinding:
    """
    AST 分析的单个发现
    ==================
    """
    file_path: str
    line_number: int
    pattern: ASTPattern                       # 识别出的模式
    confidence: float                         # 置信度 (0~1)
    description: str                          # 模式描述
    related_vuln_types: list[str] = field(default_factory=list)  # 相关的漏洞类型
    evidence: str = ""                        # AST 证据代码片段
    is_safe: bool = False                     # 是否为安全模式


class ASTAnalyzer:
    """
    AST 抽象语法树分析器（第三阶段）
    ==============================
    对代码进行结构级语义分析，识别安全模式（参数化查询等）和危险模式。

    输入：源文件字典 {file_path: source_code}
    输出：AST 发现列表

    支持 PHP 版本感知：通过 set_php_version() 设置版本后，
    规则引擎会根据版本自动调整规则的生效范围和严重程度。
    """

    # ... (existing class attributes)

    def __init__(self):
        self._source_map: dict[str, str] = {}
        self._php_version: str | None = None
        self._rule_engine = None  # 延迟初始化

    def set_php_version(self, version: str):
        """
        设置目标 PHP 版本，启用版本感知分析。

        设置后，宽字节注入等规则的严重程度会根据版本自动调整：
          - PHP < 5.3.6: DSN charset 被忽略，宽字节风险 → critical
          - PHP >= 5.3.6: DSN charset 可信，风险降低

        参数:
            version: PHP 版本字符串，如 "5.0", "5.3", "7.4", "8.0"
        """
        from engine.rule_engine import RuleEngine
        self._php_version = version
        self._rule_engine = RuleEngine(version)
    PARAMETERIZED_SQL_PATTERNS = [
        r'\bprepare\s*\(\s*["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)',
        r'\bexecute\s*\(\s*\[.*\]\s*\)',  # PDO execute with array
        r'\bbind_param\s*\(',              # mysqli bind_param
        r'\bbindValue\s*\(',               # PDO bindValue
    ]

    # 白名单验证模式（安全）
    # 注意：只有赋值右侧为数组字面量（[...] 或 array(...)）才视为真白名单；
    # `$allowed = $_GET['x']` 不是白名单，不能据此降级漏洞。
    ALLOWLIST_PATTERNS = [
        r'in_array\s*\(\s*\$[a-zA-Z_]\w*\s*,\s*\[',  # in_array($x, [...])
        r'\$allowed\w*\s*=\s*\[',                     # $allowed = [...
        r'\$allowed\w*\s*=\s*array\s*\(',            # $allowed = array(...
        r'\$whitelist\w*\s*=\s*(?:\[|array\s*\()',  # $whitelist = [...]
    ]

    # 黑名单/过滤模式（不可靠）
    BLACKLIST_PATTERNS = [
        r'str_replace\s*\(\s*[\'"]select[\'"]',
        r'preg_replace\s*\(\s*[\'"]/(?:select|union|drop)',
        r'strip_tags\s*\(\s*\$[a-zA-Z_]\w*',
    ]

    # 危险函数组合
    # 只在同一函数/相邻窗口内同时出现才报告；删除过于宽泛的组合
    # （如 file_get_contents + include，模板加载极常见，误报率高）。
    DANGEROUS_COMBOS = [
        (r'unserialize\s*\(', r'__destruct|__wakeup|__toString'),
        (r'file_get_contents\s*\(', r'eval\s*\('),
        (r'extract\s*\(\s*\$_(?:GET|POST|REQUEST)', r'include\s*\(\s*\$'),
        (r'move_uploaded_file\s*\(', r'\.php[\'"]'),
    ]

    # Python：eval/exec/compile 邻近出现 → 代码注入利用链（CWE-94）
    PY_CODE_INJECTION_COMBOS = [
        (r'\beval\s*\(', r'\bexec\s*\(|\bcompile\s*\('),
        (r'\bexec\s*\(', r'\bcompile\s*\('),
    ]

    # 硬编码凭据（Python/通用）：变量名含凭据关键词 + 字符串字面量赋值
    CRED_NAME_PATTERN = re.compile(
        r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:u|r|f|b)?([\'\"])(.*?)\2\s*(?:#.*)?$',
        re.MULTILINE
    )
    CRED_KEYWORDS = (
        "password", "passwd", "secret", "api_key", "api_token",
        "auth_token", "access_token", "private_key", "db_pass",
        "database_url", "jwt_secret", "hmac_secret", "signing_key",
        "webhook_secret", "client_secret",
    )
    # 明显是占位符/示例的值，不算硬编码凭据
    CREDENTIAL_PLACEHOLDERS = (
        "changeme", "change-me", "placeholder", "your-", "your_",
        "example", "xxxx", "redacted", "***", "...", "todo",
        "<secret>", "<password>", "<your", "password>", "secret>",
        "put-", "replace", "fill-", "dev-insecure", "do-not-use",
    )
    # 名字以这些后缀结尾的常量是字段名/头名，不是凭据
    CRED_EXCLUDED_SUFFIXES = ("_header", "_name", "_field", "_key_name", "_param")

    # 调试模式开启（Python）
    DEBUG_MODE_PATTERNS = [
        re.compile(r'^\s*DEBUG\s*=\s*True\b', re.MULTILINE),           # Django settings
        re.compile(r'\bDEBUG\s*=\s*True\b'),                            # 任意 DEBUG = True
        re.compile(r'app\.run\s*\([^)]*debug\s*=\s*True', re.IGNORECASE),  # Flask app.run(debug=True)
    ]

    def analyze(self, source_code_map: dict[str, str]) -> list[ASTFinding]:
        """
        对所有源文件执行 AST 模式分析。

        参数:
            source_code_map: {file_path: source_code} 映射

        返回:
            list[ASTFinding]: 所有 AST 发现
        """
        findings = []

        # 项目级预扫描：检测跨文件风险（如 db_connect.php 设了 GBK，register.php 用 PDO）
        all_code = "\n".join(source_code_map.values())
        self._project_has_gbk = bool(re.search(
            r"(?:charset|SET\s+NAMES)\s*=\s*['\"]?\s*(?:gbk|GBK|gb2312|GB2312|big5|BIG5)",
            all_code, re.IGNORECASE
        ))
        self._project_emulate_safe = bool(re.search(
            r'ATTR_EMULATE_PREPARES\s*,\s*(?:false|0|FALSE)',
            all_code
        ))
        self._source_map = source_code_map  # 保存供跨文件检测使用

        # 更多项目级特征
        self._project_has_addslashes = "addslashes" in all_code
        self._project_has_sql_query = bool(re.search(
            r'(?:mysql_query|mysqli_query|->query|->exec|sqlite_query|pg_query)\s*\(',
            all_code
        ))
        self._project_has_gbk_sql = self._project_has_gbk and self._project_has_sql_query

        # 项目级 PDO 初始化检测：找到 new PDO(...) 中的 charset
        self._project_pdo_charset = ""
        self._project_pdo_init_file = ""
        pdo_init_match = re.search(
            r'new\s+PDO\s*\([^)]*charset\s*=\s*(\w+)',
            all_code, re.IGNORECASE
        )
        if pdo_init_match:
            self._project_pdo_charset = pdo_init_match.group(1)
            # 定位 PDO 初始化所在的文件
            for fp, src in source_code_map.items():
                if re.search(
                    r'new\s+PDO\s*\([^)]*charset\s*=\s*' + re.escape(pdo_init_match.group(1)),
                    src, re.IGNORECASE
                ):
                    self._project_pdo_init_file = fp
                    break

        for file_path, source_code in source_code_map.items():
            lines = source_code.split("\n")
            file_findings = self._analyze_file(file_path, source_code, lines)
            findings.extend(file_findings)

        return findings

    def _analyze_file(self, file_path: str, source_code: str, lines: list[str]) -> list[ASTFinding]:
        """分析单个文件"""
        findings = []

        # 1. 检测参数化查询（安全模式）
        findings.extend(self._find_parameterized_queries(file_path, source_code, lines))

        # 2. 检测白名单验证（安全模式）
        findings.extend(self._find_allowlist_checks(file_path, source_code, lines))

        # 3. 检测黑名单过滤（不可靠）
        findings.extend(self._find_blacklist_filters(file_path, source_code, lines))

        # 4. 检测危险函数组合
        findings.extend(self._find_dangerous_combos(file_path, source_code, lines))

        # 5. 检测 extract() 变量覆盖
        findings.extend(self._find_extract_overrides(file_path, source_code, lines))

        # 6. 检测宽字节注入（GBK + addslashes）
        findings.extend(self._find_wide_byte_injection(file_path, source_code, lines))

        # 7. 检测不安全的 SQL 拼接（addslashes/mysql_real_escape_string 不够）
        findings.extend(self._find_weak_sql_escape(file_path, source_code, lines))

        # 8. 检测 PDO 不安全用法（emulated prepares + GBK / query 拼接）
        findings.extend(self._find_pdo_vulnerabilities(file_path, source_code, lines))

        # 9. 检测硬编码凭据
        findings.extend(self._find_hardcoded_credentials(file_path, source_code, lines))

        # 10. 检测调试模式开启
        findings.extend(self._find_debug_modes(file_path, source_code, lines))

        # 11. Python 代码注入组合（eval/exec/compile 邻近）
        findings.extend(self._find_py_code_injection_combos(file_path, source_code, lines))

        return findings

    def _find_parameterized_queries(self, file_path: str, source_code: str,
                                    lines: list[str]) -> list[ASTFinding]:
        """检测参数化查询等安全模式"""
        findings = []
        for i, line in enumerate(lines, 1):
            for pattern in self.PARAMETERIZED_SQL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # 检查前面是否有 SQL 关键字，避免误匹配
                    # 注意：用词边界（\b）防止 "from" 匹配到注释/英文单词中的子串
                    context = "\n".join(lines[max(0, i-3):min(len(lines), i+2)])
                    if re.search(r'\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|LIMIT|GROUP\s+BY|ORDER\s+BY)\b', context, re.IGNORECASE):
                        findings.append(ASTFinding(
                            file_path=file_path,
                            line_number=i,
                            pattern=ASTPattern.PARAMETERIZED_QUERY,
                            confidence=0.85,
                            description=f"检测到参数化查询模式（行 {i}），SQL 注入风险大幅降低",
                            related_vuln_types=["sql_injection"],
                            evidence=line.strip(),
                            is_safe=True,
                        ))
                        break  # 每行最多匹配一个模式
        return findings

    def _find_allowlist_checks(self, file_path: str, source_code: str,
                               lines: list[str]) -> list[ASTFinding]:
        """检测白名单验证"""
        findings = []
        for i, line in enumerate(lines, 1):
            for pattern in self.ALLOWLIST_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    context = "\n".join(lines[max(0, i-2):min(len(lines), i+3)])
                    findings.append(ASTFinding(
                        file_path=file_path,
                        line_number=i,
                        pattern=ASTPattern.ALLOWLIST_CHECK,
                        confidence=0.8,
                        description=f"检测到白名单验证模式（行 {i}），输入被限制在预定义值范围内",
                        related_vuln_types=["command_execution", "path_traversal"],
                        evidence=line.strip(),
                        is_safe=True,
                    ))
                    break
        return findings

    def _find_blacklist_filters(self, file_path: str, source_code: str,
                                lines: list[str]) -> list[ASTFinding]:
        """检测黑名单过滤（不可靠的安全措施）"""
        findings = []
        for i, line in enumerate(lines, 1):
            for pattern in self.BLACKLIST_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(ASTFinding(
                        file_path=file_path,
                        line_number=i,
                        pattern=ASTPattern.BLACKLIST_FILTER,
                        confidence=0.9,
                        description=f"检测到黑名单过滤（行 {i}），此方法不可靠，攻击者可能通过变形绕过",
                        related_vuln_types=["sql_injection", "xss"],
                        evidence=line.strip(),
                        is_safe=False,
                    ))
                    break
        return findings

    def _find_dangerous_combos(self, file_path: str, source_code: str,
                               lines: list[str]) -> list[ASTFinding]:
        """
        检测危险函数组合。

        与旧版不同，只在同一窗口（±8 行）内同时出现两个模式才报告，
        避免"整个文件里某处有 unserialize、另一处有 __destruct"这类
        高误报的宽松匹配。
        """
        findings = []
        window = 8
        reported = set()  # (combo_index, line) 去重

        for combo_idx, (combo_a, combo_b) in enumerate(self.DANGEROUS_COMBOS):
            a_lines = set()
            b_lines = set()
            for i, line in enumerate(lines, 1):
                if re.search(combo_a, line, re.IGNORECASE):
                    a_lines.add(i)
                if re.search(combo_b, line, re.IGNORECASE):
                    b_lines.add(i)

            # 两种模式都必须出现，且在同一窗口内相邻
            if not a_lines or not b_lines:
                continue
            a_sorted = sorted(a_lines)
            b_sorted = sorted(b_lines)
            for ln in a_sorted:
                near = any(abs(other - ln) <= window for other in b_sorted)
                if not near:
                    continue
                key = (combo_idx, ln)
                if key in reported:
                    continue
                reported.add(key)
                # 确定该行匹配的是哪个模式，给出准确证据
                line = lines[ln - 1] if ln - 1 < len(lines) else ""
                findings.append(ASTFinding(
                    file_path=file_path, line_number=ln,
                    pattern=ASTPattern.DANGEROUS_COMBO, confidence=0.7,
                    description=(
                        f"危险函数组合（行 {ln} 附近 ±{window} 行）："
                        "多个危险调用邻近出现，可能形成漏洞利用链"
                    ),
                    related_vuln_types=["command_execution", "deserialization"],
                    evidence=line.strip(), is_safe=False,
                ))
                break  # 每个组合只报告一次

        return findings

    def _find_extract_overrides(self, file_path: str, source_code: str,
                                lines: list[str]) -> list[ASTFinding]:
        """检测 extract() 变量覆盖"""
        findings = []
        for i, line in enumerate(lines, 1):
            if re.search(r'extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', line):
                findings.append(ASTFinding(
                    file_path=file_path,
                    line_number=i,
                    pattern=ASTPattern.EXTRACT_OVERRIDE,
                    confidence=0.95,
                    description=f"检测到 extract() 从用户输入覆盖变量（行 {i}），可能导致变量覆盖漏洞",
                    related_vuln_types=["command_execution", "path_traversal"],
                    evidence=line.strip(),
                    is_safe=False,
                ))
        return findings

    def filter_vulns(self, vulns: list[dict], ast_findings: list[ASTFinding]) -> list[dict]:
        """
        根据 AST 分析结果过滤漏洞列表。

        如果某个漏洞所在位置被 AST 识别为安全模式（如参数化查询），
        则降低其严重程度或标记为可能误报。

        参数:
            vulns:         Stage 1+2 的漏洞列表
            ast_findings:  AST 分析发现

        返回:
            list[dict]: 过滤后的漏洞列表
        """
        # 构建安全模式位置索引: {(file_path, line): [findings]}
        safe_spots: dict[tuple[str, int], list[ASTFinding]] = {}
        for f in ast_findings:
            if f.is_safe:
                key = (f.file_path, f.line_number)
                if key not in safe_spots:
                    safe_spots[key] = []
                safe_spots[key].append(f)

        filtered = []
        for v in vulns:
            fp = v.get("file_path", "")
            ln = v.get("line_number", v.get("sink_line", 0))
            sink_ln = v.get("sink_line", ln)
            source_ln = v.get("source_line", ln)

            # 检查 Sink 和 Source 附近是否有安全模式
            near_safe = False
            for check_ln in [sink_ln, source_ln, ln - 1, ln, ln + 1]:
                key = (fp, check_ln)
                if key in safe_spots:
                    near_safe = True
                    break

            if near_safe:
                # 降低严重程度：最高降为 low
                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                current = severity_order.get(v.get("severity", "medium"), 2)
                new_level = max(1, current - 2)  # 降两级
                new_severity = {4: "critical", 3: "high", 2: "medium", 1: "low"}[new_level]
                v = {**v, "severity": new_severity, "ast_filtered": True}

            filtered.append(v)

        return filtered

    def _find_wide_byte_injection(self, file_path: str, source_code: str,
                                    lines: list[str]) -> list[ASTFinding]:
        """检测宽字节注入：项目级 GBK + addslashes/SQL 查询"""
        findings = []
        has_gbk_local = bool(re.search(
            r"(?:SET\s+NAMES|SET\s+CHARACTER\s+SET|mysql_set_charset|mysqli_set_charset)\s*['(]\s*(?:gbk|GBK|gb2312|GB2312|big5|BIG5)",
            source_code, re.IGNORECASE
        ))
        has_addslashes_local = "addslashes" in source_code
        has_sql_local = bool(re.search(
            r"(?:mysql_query|mysqli_query|->query|mysql_db_query)\s*\(",
            source_code
        ))

        # 同文件检测
        if has_gbk_local and (has_addslashes_local or has_sql_local):
            for i, line in enumerate(lines, 1):
                if re.search(r"SET\s+NAMES|mysql_set_charset|SET\s+CHARACTER", line, re.IGNORECASE):
                    findings.append(ASTFinding(
                        file_path=file_path, line_number=i,
                        pattern=ASTPattern.DANGEROUS_COMBO, confidence=0.85,
                        description=f"宽字节注入风险（行 {i}）：GBK 字符集 + addslashes/SQL 查询可能被宽字节绕过",
                        related_vuln_types=["sql_injection"],
                        evidence=line.strip(), is_safe=False,
                    ))
                    break

        # 跨文件检测：项目某处有 GBK + addslashes/SQL，本文件用了 SQL 查询
        if (self._project_has_gbk_sql or self._project_has_gbk) and not has_gbk_local:
            if has_sql_local or has_addslashes_local:
                # 找 GBK 来源
                gbk_file = self._find_gbk_file()
                for i, line in enumerate(lines, 1):
                    if re.search(r"(?:mysql_query|mysqli_query|->query|addslashes)", line):
                        findings.append(ASTFinding(
                            file_path=file_path, line_number=i,
                            pattern=ASTPattern.DANGEROUS_COMBO, confidence=0.75,
                            description=(
                                f"跨文件宽字节注入风险（行 {i}）：项目使用了 GBK 字符集"
                                + (f"（{gbk_file}）" if gbk_file else "")
                                + "，SQL 查询/转义可能被宽字节绕过"
                            ),
                            related_vuln_types=["sql_injection"],
                            evidence=line.strip(), is_safe=False,
                        ))
                        break

        return findings

    def _find_gbk_file(self) -> str:
        """找到项目中包含 GBK 字符集设置的文件"""
        for fp, src in getattr(self, '_source_map', {}).items():
            if re.search(r"(?:charset|SET\s+NAMES)\s*=\s*['\"]?\s*(?:gbk|GBK|gb2312|GB2312|big5|BIG5)", src, re.IGNORECASE):
                return fp
        return ""

    def _find_pdo_init_file(self) -> str:
        """找到项目中 PDO 初始化的文件（用于跨文件宽字节注入检测）"""
        return getattr(self, '_project_pdo_init_file', '')

    def _find_weak_sql_escape(self, file_path: str, source_code: str,
                               lines: list[str]) -> list[ASTFinding]:
        """
        检测不安全的 SQL 转义方式。
        addslashes / mysql_real_escape_string 在某些条件下不足够。
        """
        findings = []
        for i, line in enumerate(lines, 1):
            # addslashes 配合用户输入
            if re.search(r"addslashes\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", line):
                # 检查后续是否有 SQL 查询
                context = "\n".join(lines[i-1:min(len(lines), i+5)])
                if re.search(r"(?:mysql_query|mysqli_query|->query)\s*\(", context):
                    findings.append(ASTFinding(
                        file_path=file_path, line_number=i,
                        pattern=ASTPattern.BLACKLIST_FILTER,
                        confidence=0.75,
                        description=(
                            f"不安全的 SQL 转义（行 {i}）：addslashes() 不能完全防止 SQL 注入，"
                            f"尤其在 GBK 等宽字节编码下可被绕过。应使用参数化查询"
                        ),
                        related_vuln_types=["sql_injection"],
                        evidence=line.strip(),
                        is_safe=False,
                    ))
        return findings

    def _find_pdo_vulnerabilities(self, file_path: str, source_code: str,
                                   lines: list[str]) -> list[ASTFinding]:
        """
        检测 PDO 相关漏洞。
        包括：emulated prepares + GBK、query()/exec() 拼接、
        prepare() 内拼接、未禁用模拟预处理。
        """
        findings = []
        has_pdo = bool(re.search(r'\bPDO\b|->query|->exec|->prepare', source_code))
        if not has_pdo:
            return findings

        has_gbk = bool(re.search(
            r"(?:charset|SET\s+NAMES)\s*=\s*['\"]?\s*(?:gbk|GBK|gb2312|GB2312|big5|BIG5)",
            source_code, re.IGNORECASE
        ))
        has_emulate = bool(re.search(
            r'ATTR_EMULATE_PREPARES\s*,\s*(?:true|1|TRUE)',
            source_code
        ))

        for i, line in enumerate(lines, 1):
            # 1. PDO::query() with concatenation
            if re.search(r'->query\s*\(\s*["\'].*\.\s*\$', line):
                findings.append(ASTFinding(
                    file_path=file_path, line_number=i,
                    pattern=ASTPattern.STRING_CONCAT_SQL,
                    confidence=0.9,
                    description=f"PDO::query() 使用字符串拼接 SQL（行 {i}），存在 SQL 注入风险。应使用 PDO::prepare() + 参数绑定",
                    related_vuln_types=["sql_injection"],
                    evidence=line.strip(), is_safe=False,
                ))

            # 2. PDO::exec() with user input
            elif re.search(r'->exec\s*\(\s*["\'].*\.\s*\$', line):
                findings.append(ASTFinding(
                    file_path=file_path, line_number=i,
                    pattern=ASTPattern.STRING_CONCAT_SQL,
                    confidence=0.85,
                    description=f"PDO::exec() 使用字符串拼接（行 {i}），存在 SQL 注入风险",
                    related_vuln_types=["sql_injection"],
                    evidence=line.strip(), is_safe=False,
                ))

            # 3. PDO::prepare() with concatenation (defeats the purpose)
            elif re.search(r'->prepare\s*\(\s*["\'].*\.\s*\$', line):
                findings.append(ASTFinding(
                    file_path=file_path, line_number=i,
                    pattern=ASTPattern.STRING_CONCAT_SQL,
                    confidence=0.7,
                    description=f"PDO::prepare() 使用字符串拼接（行 {i}），参数化查询失效",
                    related_vuln_types=["sql_injection"],
                    evidence=line.strip(), is_safe=False,
                ))

            # 4. Emulated prepares explicitly enabled (loses real prepared statement benefit)
            if has_emulate and re.search(r'ATTR_EMULATE_PREPARES', line):
                note = ""
                if has_gbk:
                    note = "，结合 GBK 字符集存在宽字节注入风险"
                findings.append(ASTFinding(
                    file_path=file_path, line_number=i,
                    pattern=ASTPattern.DANGEROUS_COMBO,
                    confidence=0.8,
                    description=f"PDO 启用了模拟预处理（行 {i}），失去了真正的参数化查询保护{note}。应设置 ATTR_EMULATE_PREPARES => false",
                    related_vuln_types=["sql_injection"],
                    evidence=line.strip(), is_safe=False,
                ))
                break  # 只报告一次

        # 5. PDO with GBK charset (even without emulated prepares explicit)
        # 使用项目级 flag，支持 db_connect.php 设 charset，其他文件用 PDO 的场景
        if has_gbk and has_pdo and not has_emulate:
            for i, line in enumerate(lines, 1):
                if re.search(r"charset\s*=\s*['\"]?\s*(?:gbk|GBK|gb2312|GB2312|big5|BIG5)", line, re.IGNORECASE):
                    findings.append(ASTFinding(
                        file_path=file_path, line_number=i,
                        pattern=ASTPattern.DANGEROUS_COMBO,
                        confidence=0.65,
                        description=f"PDO 连接使用 GBK 字符集（行 {i}），存在宽字节注入风险。确保 ATTR_EMULATE_PREPARES 为 false",
                        related_vuln_types=["sql_injection"],
                        evidence=line.strip(), is_safe=False,
                    ))
                    break

        # 6. 跨文件检测：PDO 查询 + 项目某处有 GBK 且未禁用模拟预处理
        if self._project_has_gbk and not self._project_emulate_safe and has_pdo:
            for i, line in enumerate(lines, 1):
                # 找到 PDO 连接行或第一条 PDO 查询，附加 GBK 警告
                if re.search(r'(?:new\s+PDO|->query|->exec|->prepare)', line):
                    # 找到 GBK 来源文件
                    gbk_file = ""
                    for fp, src in self._source_map.items():
                        if re.search(r"(?:charset|SET\s+NAMES)\s*=\s*['\"]?\s*(?:gbk|GBK|gb2312|GB2312|big5|BIG5)", src, re.IGNORECASE):
                            gbk_file = fp
                            break
                    findings.append(ASTFinding(
                        file_path=file_path, line_number=i,
                        pattern=ASTPattern.DANGEROUS_COMBO,
                        confidence=0.85,
                        description=(
                            f"跨文件宽字节注入风险（行 {i}）：项目使用 GBK 字符集"
                            + (f"（{gbk_file}）" if gbk_file else "")
                            + "且未禁用 PDO 模拟预处理，参数化查询可能被宽字节绕过"
                        ),
                        related_vuln_types=["sql_injection"],
                        evidence=line.strip(), is_safe=False,
                    ))
                    break

        # 7. 宽字节注入：PDO 未禁用模拟预处理（版本感知）
        if not self._project_emulate_safe and has_pdo:
            has_prepare = bool(re.search(r'->prepare\s*\(', source_code))
            has_execute_with_array = bool(re.search(r'->execute\s*\(\s*\[', source_code))
            if has_prepare and has_execute_with_array:
                # 使用规则引擎判定风险等级
                risk_level = "medium"
                extra_note = ""
                if self._rule_engine:
                    ctx = self._rule_engine.get_wide_byte_context()
                    risk_level = ctx.get("emulate_risk_level", "medium")
                    if not ctx.get("dsn_charset_trusted"):
                        extra_note = (
                            "（PHP {} < 5.3.6，DSN charset 被忽略，风险更高）"
                            .format(self._php_version or "unknown")
                        )

                pdo_init_line = 0
                pdo_charset = ""
                for i, line in enumerate(lines, 1):
                    m = re.search(
                        r'new\s+PDO\s*\([^)]*charset\s*=\s*(\w+)',
                        line, re.IGNORECASE
                    )
                    if m:
                        pdo_init_line = i
                        pdo_charset = m.group(1)
                        break
                if pdo_charset:
                    findings.append(ASTFinding(
                        file_path=file_path,
                        line_number=pdo_init_line,
                        pattern=ASTPattern.DANGEROUS_COMBO,
                        confidence=0.7,
                        description=(
                            f"宽字节注入风险（行 {pdo_init_line}）："
                            f"PDO 连接 charset 为 {pdo_charset}，但未禁用模拟预处理。"
                            f"若数据库实际字符集为 GBK，prepare/execute 内部走 "
                            f"mysql_real_escape_string 转义，可能被宽字节绕过"
                            + extra_note
                        ),
                        related_vuln_types=["sql_injection"],
                        evidence=lines[pdo_init_line - 1].strip() if pdo_init_line > 0 else "",
                        is_safe=False,
                    ))
                else:
                    pdo_init_file = self._find_pdo_init_file()
                    if pdo_init_file:
                        pdo_charset = self._project_pdo_charset or "unknown"
                        # 找到 PDO 初始化文件中的实际行号和代码
                        init_line = 1
                        init_code = ""
                        try:
                            init_src = self._source_map.get(pdo_init_file, "")
                            for li, ll in enumerate(init_src.split("\n"), 1):
                                if re.search(r'new\s+PDO\s*\(', ll):
                                    init_line = li
                                    init_code = ll.strip()
                                    break
                        except Exception:
                            pass
                        findings.append(ASTFinding(
                            file_path=pdo_init_file,
                            line_number=init_line,
                            pattern=ASTPattern.DANGEROUS_COMBO,
                            confidence=0.65,
                            description=(
                                f"跨文件宽字节注入风险：PDO 连接 charset 为 "
                                f"{pdo_charset}，但未禁用模拟预处理（ATTR_EMULATE_PREPARES=false）。"
                                f"其他文件（如 {file_path}）使用 prepare/execute 时，"
                                f"若数据库实际字符集为 GBK，参数化查询可能被宽字节绕过"
                                + extra_note
                            ),
                            related_vuln_types=["sql_injection"],
                            evidence=init_code,
                            is_safe=False,
                        ))

        return findings

    # ----------------------------------------------------------------
    # 新增检测：硬编码凭据 / 调试模式 / Python 代码注入组合
    # ----------------------------------------------------------------

    def _find_hardcoded_credentials(self, file_path: str, source_code: str,
                                    lines: list[str]) -> list[ASTFinding]:
        """
        检测硬编码凭据（CWE-798）。

        PASSWORD = 'admin123' / SECRET_KEY = 'abc...' / API_TOKEN = 'x...'
        值必须是字符串字面量，且不是明显的占位符/示例值。
        测试文件（tests/ 目录、test_*.py）中的密码属于测试数据，跳过。
        """
        norm_path = (file_path or "").replace("\\", "/").lower()
        if "/tests/" in norm_path or "/test/" in norm_path:
            return []
        fname = norm_path.split("/")[-1]
        if fname.startswith("test_") or fname.endswith("_test.py") or fname == "tests.py":
            return []
        # 种子/演示数据脚本中的凭据是示例数据，跳过
        if ("seed" in fname or fname.startswith("smoke_check")
                or fname.startswith("create_dummy")):
            return []

        findings = []
        for match in self.CRED_NAME_PATTERN.finditer(source_code):
            name = match.group(1)
            value = match.group(3).strip()
            if len(value) < 3:
                continue
            # 值内含引号 → 元组/多字符串拼接，不是单一凭据字面量
            if "'" in value or '"' in value:
                continue
            name_low = name.lower()
            # 演示数据常量（DEMO_PASSWORD 等）跳过
            if name_low.startswith("demo_") or name_low.startswith("sample_"):
                continue
            if any(name_low.endswith(s) for s in self.CRED_EXCLUDED_SUFFIXES):
                continue
            has_keyword = any(kw in name_low for kw in self.CRED_KEYWORDS)
            # KEY / xxx_KEY 这类泛名：值必须足够长（>= 12）才视为凭据，避免误报
            long_key_name = (
                name_low == "key" or name_low.endswith("key")
            ) and len(value) >= 12
            if not has_keyword and not long_key_name:
                continue
            low = value.lower()
            if any(p in low for p in self.CREDENTIAL_PLACEHOLDERS):
                continue
            if "$" in value or "{" in value or "(" in value or "%" in value:
                continue  # 插值/函数调用，不是字面量
            if low == name_low or low in ("password", "passwd", "secret", "apikey", "api_key"):
                continue  # 值等于变量名本身，通常是文档示例
            line_num = source_code[:match.start()].count("\n") + 1
            findings.append(ASTFinding(
                file_path=file_path,
                line_number=line_num,
                pattern=ASTPattern.HARDCODED_CREDENTIALS,
                confidence=0.9,
                description=(
                    f"硬编码凭据（行 {line_num}）：{name} "
                    f"以明文字符串形式硬编码在源码中，应改用环境变量/密钥管理服务"
                ),
                related_vuln_types=["hardcoded_credentials"],
                evidence=(match.group(0)[:120] + "...").strip(),
                is_safe=False,
            ))
        return findings

    def _find_debug_modes(self, file_path: str, source_code: str,
                          lines: list[str]) -> list[ASTFinding]:
        """
        检测调试模式开启（CWE-215）。

        DEBUG = True（Django settings）/ app.run(debug=True)（Flask）。
        跳过测试文件（test*.py / *_test.py），测试代码开启 debug 属正常。
        """
        fname = (file_path or "").lower().replace("\\", "/").split("/")[-1]
        if fname.startswith("test") or fname.endswith("_test.py"):
            return []

        findings = []
        for pattern in self.DEBUG_MODE_PATTERNS:
            for match in pattern.finditer(source_code):
                line_num = source_code[:match.start()].count("\n") + 1
                findings.append(ASTFinding(
                    file_path=file_path,
                    line_number=line_num,
                    pattern=ASTPattern.DEBUG_MODE,
                    confidence=0.85,
                    description=(
                        f"调试模式开启（行 {line_num}）：生产环境启用 debug 会泄露堆栈/"
                        f"配置等敏感信息，并可能暴露调试端点"
                    ),
                    related_vuln_types=["debug_mode"],
                    evidence=match.group(0).strip()[:100],
                    is_safe=False,
                ))
        return findings

    def _find_py_code_injection_combos(self, file_path: str, source_code: str,
                                       lines: list[str]) -> list[ASTFinding]:
        """
        检测 Python eval/exec/compile 邻近组合（CWE-94 代码注入）。

        eval + exec 在同一 ±8 行窗口内出现，通常是动态代码执行利用链。
        """
        findings = []
        window = 8
        for combo_a, combo_b in self.PY_CODE_INJECTION_COMBOS:
            a_lines = set()
            b_lines = set()
            for i, line in enumerate(lines, 1):
                if re.search(combo_a, line):
                    a_lines.add(i)
                if re.search(combo_b, line):
                    b_lines.add(i)
            # 两种模式都必须出现，且在同一窗口内相邻
            if not a_lines or not b_lines:
                continue
            for ln in sorted(a_lines):
                if any(abs(other - ln) <= window for other in b_lines):
                    findings.append(ASTFinding(
                        file_path=file_path,
                        line_number=ln,
                        pattern=ASTPattern.DANGEROUS_COMBO,
                        confidence=0.8,
                        description=(
                            f"Python 代码注入组合（行 {ln} 附近 ±{window} 行）："
                            "eval/exec/compile 邻近出现，可能形成动态代码执行利用链"
                        ),
                        related_vuln_types=["code_injection"],
                        evidence=lines[ln - 1].strip()[:120] if ln - 1 < len(lines) else "",
                        is_safe=False,
                    ))
                    break  # 每组合每文件报告一次
        return findings
