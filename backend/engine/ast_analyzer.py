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
    """

    # 参数化查询模式（安全）
    PARAMETERIZED_SQL_PATTERNS = [
        r'\bprepare\s*\(\s*["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)',
        r'\bexecute\s*\(\s*\[.*\]\s*\)',  # PDO execute with array
        r'\bbind_param\s*\(',              # mysqli bind_param
        r'\bbindValue\s*\(',               # PDO bindValue
        r'\?',                             # ? placeholder（需结合上下文）
        r':[a-zA-Z_]\w*\b',                # :named placeholder
    ]

    # 白名单验证模式（安全）
    ALLOWLIST_PATTERNS = [
        r'in_array\s*\(\s*\$[a-zA-Z_]\w*\s*,\s*\[',  # in_array($x, [...])
        r'\$allowed\w*\s*=',                           # $allowed = [...]  
        r'\$whitelist\w*\s*=',                         # $whitelist = [...]
        r'switch\s*\(\s*\$[a-zA-Z_]\w*\s*\)',         # switch($input)
    ]

    # 黑名单/过滤模式（不可靠）
    BLACKLIST_PATTERNS = [
        r'str_replace\s*\(\s*[\'"]select[\'"]',
        r'preg_replace\s*\(\s*[\'"]/(?:select|union|drop)',
        r'strip_tags\s*\(\s*\$[a-zA-Z_]\w*',
    ]

    # 危险函数组合
    DANGEROUS_COMBOS = [
        (r'unserialize\s*\(', r'__destruct|__wakeup|__toString'),
        (r'file_get_contents\s*\(', r'eval\s*\(|include\s*\('),
        (r'extract\s*\(\s*\$_(?:GET|POST|REQUEST)', r'include\s*\(\s*\$'),
        (r'move_uploaded_file\s*\(', r'\.php[\'"]'),
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

        return findings

    def _find_parameterized_queries(self, file_path: str, source_code: str,
                                    lines: list[str]) -> list[ASTFinding]:
        """检测参数化查询等安全模式"""
        findings = []
        for i, line in enumerate(lines, 1):
            for pattern in self.PARAMETERIZED_SQL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # 检查前面是否有 SQL 关键字，避免误匹配
                    context = "\n".join(lines[max(0, i-3):min(len(lines), i+2)])
                    if re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)', context, re.IGNORECASE):
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
        """检测危险函数组合（同文件 + 跨文件）"""
        findings = []
        text = source_code
        all_text = "\n".join(getattr(self, '_source_map', {}).values())

        for combo_a, combo_b in self.DANGEROUS_COMBOS:
            # 同文件检测
            if re.search(combo_a, text, re.IGNORECASE) and re.search(combo_b, text, re.IGNORECASE):
                for i, line in enumerate(lines, 1):
                    if re.search(combo_a, line, re.IGNORECASE) or re.search(combo_b, line, re.IGNORECASE):
                        findings.append(ASTFinding(
                            file_path=file_path, line_number=i,
                            pattern=ASTPattern.DANGEROUS_COMBO, confidence=0.7,
                            description="同文件危险函数组合，可能形成漏洞利用链",
                            related_vuln_types=["command_execution", "deserialization"],
                            evidence=line.strip(), is_safe=False,
                        ))
                        break

            # 跨文件检测：项目某处有 combo_a，本文件有 combo_b
            elif re.search(combo_a, all_text, re.IGNORECASE) and re.search(combo_b, text, re.IGNORECASE):
                for i, line in enumerate(lines, 1):
                    if re.search(combo_b, line, re.IGNORECASE):
                        # 找到 combo_a 在哪个文件
                        a_file = ""
                        for fp, src in getattr(self, '_source_map', {}).items():
                            if re.search(combo_a, src, re.IGNORECASE):
                                a_file = fp
                                break
                        findings.append(ASTFinding(
                            file_path=file_path, line_number=i,
                            pattern=ASTPattern.DANGEROUS_COMBO, confidence=0.6,
                            description=(
                                f"跨文件危险函数组合（行 {i}）："
                                + (f"{a_file} " if a_file else "")
                                + "存在关联的危险调用，可能形成漏洞利用链"
                            ),
                            related_vuln_types=["command_execution", "deserialization"],
                            evidence=line.strip(), is_safe=False,
                        ))
                        break

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

        return findings
