"""
版本感知规则引擎（Version-Aware Rule Engine）
==============================================
将审计规则从扫描器中解耦，根据编程语言版本/标准动态激活/调整规则。

支持的语言：
  - PHP（版本感知：5.0 ~ 8.0）
  - Python（版本感知：2.7 ~ 3.13）
  - C / C++（标准感知：C89 ~ C++23）

==== 设计原则 ====

1. 每条规则是一个独立的 AuditRule 数据类
2. 规则有 min_version / max_version 控制生效范围
3. 规则严重程度可根据版本/标准动态调整
4. RuleEngine 是纯函数式模块，不依赖 tree-sitter/AST

==== 使用方式 ====

    from engine.rule_engine import RuleEngine, PhpVersion

    engine = RuleEngine(PhpVersion.PHP_5_2)
    rules = engine.get_active_rules()

    # Python
    from engine.rule_engine import PythonRuleEngine, PythonVersion
    engine = PythonRuleEngine(PythonVersion.PY_3_8)

    # C/C++
    from engine.rule_engine import CppRuleEngine, CppStandard
    engine = CppRuleEngine(CppStandard.CPP_17)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re


# ========================================================================
# PHP 版本枚举
# ========================================================================

class PhpVersion(str, Enum):
    """
    PHP 版本枚举，按重要性排列。
    每个版本有对应的关键安全变更。

    安全相关里程碑：
      - 5.3.6: PDO DSN charset 支持 → 宽字节注入缓解
      - 5.4.0: 移除 register_globals / safe_mode
      - 5.5.0: preg_replace /e 废弃，mysql_* 函数废弃
      - 7.0.0: mysql_* 函数移除，preg_replace /e 移除
      - 7.2.0: create_function() 废弃，assert() 字符串求值默认关闭
      - 7.4.0: create_function() 移除
      - 8.0.0: assert() 字符串求值移除
    """
    PHP_5_0 = "5.0"    # PHP 5.0 ~ 5.3.5
    PHP_5_3 = "5.3"    # PHP 5.3.6 ~ 5.4.x
    PHP_5_5 = "5.5"    # PHP 5.5 ~ 5.6.x
    PHP_7_0 = "7.0"    # PHP 7.0 ~ 7.1.x
    PHP_7_2 = "7.2"    # PHP 7.2 ~ 7.3.x
    PHP_7_4 = "7.4"    # PHP 7.4.x
    PHP_8_0 = "8.0"    # PHP 8.0+

    # 以下为抽象版本，用于表示"未知/自动检测"
    UNKNOWN = "unknown"
    AUTO = "auto"


# ========================================================================
# 规则严重程度 / 类别
# ========================================================================

class RuleSeverity(str, Enum):
    """规则严重程度（与漏洞报告保持一致）"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleCategory(str, Enum):
    """规则类别"""
    WIDE_BYTE_INJECTION = "wide_byte_injection"
    SQL_INJECTION = "sql_injection"
    COMMAND_EXECUTION = "command_execution"
    XSS = "xss"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"
    DEPRECATED_API = "deprecated_api"


# ========================================================================
# 审计规则定义
# ========================================================================

@dataclass
class AuditRule:
    """
    单条安全审计规则。

    属性:
        rule_id:           规则唯一标识
        name:              人类可读名称
        description:       详细描述
        category:          漏洞类别
        default_severity:  默认严重程度
        min_php_version:   最小生效 PHP 版本（None = 所有版本）
        max_php_version:   最大生效 PHP 版本（None = 所有版本）
        pattern:           检测正则（用于 AST 模式匹配）
        severity_overrides: 特定版本下的严重程度覆盖
            {PhpVersion: RuleSeverity}
        confidence:        规则置信度 (0~1)
    """
    rule_id: str
    name: str
    description: str
    category: RuleCategory
    default_severity: RuleSeverity = RuleSeverity.MEDIUM
    min_php_version: Optional[str] = None      # PHP 版本号字符串，如 "5.3"（向后兼容）
    max_php_version: Optional[str] = None      # None = 无上限（向后兼容）
    min_version: Optional[str] = None           # 通用最小版本/标准
    max_version: Optional[str] = None           # 通用最大版本/标准
    pattern: str = ""                           # 检测正则
    severity_overrides: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.75


# ---- 版本对比工具函数 ----

def _version_to_tuple(v: Optional[str]) -> tuple[int, ...]:
    """将版本字符串转为可比较的元组。None 视为 (0,)"""
    if v is None:
        return ()
    parts = re.findall(r'\d+', v)
    return tuple(int(p) for p in parts)


def _version_gte(a: str, b: str) -> bool:
    """a >= b 版本比较"""
    return _version_to_tuple(a) >= _version_to_tuple(b)


def _version_lte(a: str, b: str) -> bool:
    """a <= b 版本比较"""
    return _version_to_tuple(a) <= _version_to_tuple(b)


# ========================================================================
# 规则库定义
# ========================================================================

PHP_AUDIT_RULES: list[AuditRule] = []


def _rule(**kwargs) -> AuditRule:
    """辅助函数：创建规则并注册到全局规则库"""
    r = AuditRule(**kwargs)
    PHP_AUDIT_RULES.append(r)
    return r


# ================================================================
# 宽字节注入规则
# ================================================================

_rule(
    rule_id="WIDE_BYTE_PDO_EMULATE",
    name="PDO 模拟预处理 + 非 UTF-8 数据库",
    category=RuleCategory.WIDE_BYTE_INJECTION,
    default_severity=RuleSeverity.HIGH,
    description=(
        "PDO 未禁用模拟预处理（ATTR_EMULATE_PREPARES=false），"
        "若数据库实际字符集为 GBK/BIG5/GB2312，宽字节可绕过内部转义。"
        "PHP < 5.3.6 时 DSN charset 选项被忽略，风险更高。"
    ),
    pattern=r"new\s+PDO|->prepare\s*\(",
    confidence=0.85,
)

_rule(
    rule_id="WIDE_BYTE_ADDSLASHES_GBK",
    name="GBK + addslashes 宽字节注入",
    category=RuleCategory.WIDE_BYTE_INJECTION,
    default_severity=RuleSeverity.HIGH,
    description=(
        "使用 addslashes() 对用户输入转义后拼入 SQL，"
        "在 GBK/BIG5/GB2312 字符集下可被宽字节绕过。"
    ),
    pattern=r"addslashes\s*\(",
    confidence=0.9,
)

_rule(
    rule_id="WIDE_BYTE_MYSQL_ESCAPE_GBK",
    name="GBK + mysql_real_escape_string 宽字节注入",
    category=RuleCategory.WIDE_BYTE_INJECTION,
    default_severity=RuleSeverity.MEDIUM,
    description=(
        "mysql_real_escape_string 在 GBK 字符集下已修复（PHP 5.0+），"
        "但仍建议使用参数化查询代替字符串转义。"
    ),
    pattern=r"mysql_real_escape_string\s*\(",
    confidence=0.5,
)

# ================================================================
# SQL 注入规则
# ================================================================

_rule(
    rule_id="SQLI_STRING_CONCAT",
    name="字符串拼接 SQL 查询",
    category=RuleCategory.SQL_INJECTION,
    default_severity=RuleSeverity.HIGH,
    description="SQL 语句通过字符串拼接包含用户输入，存在 SQL 注入风险。",
    pattern=r"(?:mysql_query|mysqli_query|->query|->exec)\s*\(\s*[\"'].*\.",
    confidence=0.9,
)

_rule(
    rule_id="SQLI_PDO_PREPARE_CONCAT",
    name="PDO prepare() 内字符串拼接",
    category=RuleCategory.SQL_INJECTION,
    default_severity=RuleSeverity.HIGH,
    description="PDO::prepare() 的 SQL 模板中包含字符串拼接，参数化查询失效。",
    pattern=r"->prepare\s*\(\s*[\"'].*\.\s*\$",
    confidence=0.8,
)

# ================================================================
# 已废弃 API 规则（版本感知的核心价值）
# ================================================================

_rule(
    rule_id="DEPRECATED_PREG_REPLACE_E",
    name="preg_replace() /e 修饰符",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.CRITICAL,
    max_php_version="5.4",  # PHP 5.5+ 废弃，7.0+ 移除
    description=(
        "preg_replace() 使用 /e 修饰符可执行任意 PHP 代码。"
        "PHP 5.5+ 已废弃，PHP 7.0+ 已移除。"
    ),
    pattern=r"preg_replace\s*\(\s*[\"'].*\/e[\w]*[\"']",
    confidence=0.95,
)

_rule(
    rule_id="DEPRECATED_MYSQL_FUNCTIONS",
    name="mysql_* 函数族",
    category=RuleCategory.DEPRECATED_API,
    default_severity=RuleSeverity.HIGH,
    description=(
        "使用已废弃的 mysql_* 函数族（mysql_query, mysql_connect 等）。"
        "PHP 5.5+ 已废弃，PHP 7.0+ 已移除。"
        "这些函数不支持参数化查询，容易导致 SQL 注入。"
    ),
    pattern=r"\bmysql_(?:query|connect|db_query|select_db|escape_string|real_escape_string|fetch|result)\s*\(",
    confidence=0.95,
    severity_overrides={
        "7.0": "critical",  # PHP 7.0+ 直接报 fatal error
    },
)

_rule(
    rule_id="DEPRECATED_CREATE_FUNCTION",
    name="create_function() 动态函数",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    max_php_version="7.1",  # PHP 7.2+ 废弃，7.4+ 移除
    description=(
        "create_function() 内部使用 eval()，可导致代码注入。"
        "PHP 7.2+ 已废弃，PHP 7.4+ 已移除。应使用匿名函数代替。"
    ),
    pattern=r"create_function\s*\(",
    confidence=0.95,
    severity_overrides={
        "7.2": "critical",  # 即将移除，更严重
    },
)

_rule(
    rule_id="DEPRECATED_ASSERT_STRING",
    name="assert() 字符串参数",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    max_php_version="7.1",  # PHP 7.2+ 默认禁用字符串求值
    description=(
        "assert() 接受字符串参数时可执行任意 PHP 代码。"
        "PHP 7.2+ 默认禁用，PHP 8.0+ 完全移除此行为。"
    ),
    pattern=r"assert\s*\(\s*[\"']",
    confidence=0.85,
)

# ================================================================
# 其他规则
# ================================================================

_rule(
    rule_id="DESERIALIZE_UNSAFE",
    name="unserialize() 用户可控数据",
    category=RuleCategory.DESERIALIZATION,
    default_severity=RuleSeverity.HIGH,
    description="unserialize() 反序列化用户可控数据，可能导致 POP 链攻击。",
    pattern=r"unserialize\s*\(",
    confidence=0.85,
)

_rule(
    rule_id="FILE_UPLOAD_MOVE",
    name="move_uploaded_file 路径可控",
    category=RuleCategory.FILE_UPLOAD,
    default_severity=RuleSeverity.HIGH,
    description="move_uploaded_file() 的目标路径包含用户输入，可被目录穿越利用。",
    pattern=r"move_uploaded_file\s*\(",
    confidence=0.8,
)


# ========================================================================
# 规则引擎
# ========================================================================

class RuleEngine:
    """
    版本感知规则引擎。

    核心能力：
      1. get_active_rules()      — 根据 PHP 版本筛选生效的规则
      2. adjust_severity()       — 根据版本调整规则严重程度
      3. get_rule_by_id()        — 按 ID 查找规则
      4. get_rules_by_category() — 按类别筛选规则
    """

    def __init__(self, php_version: str = PhpVersion.UNKNOWN.value):
        """
        参数:
            php_version: PHP 版本字符串（"5.0", "5.3", "7.4", "8.0" 等）
        """
        self.php_version = php_version

    @property
    def version_tuple(self) -> tuple[int, ...]:
        return _version_to_tuple(self.php_version)

    @property
    def is_php_before_5_3_6(self) -> bool:
        """PHP < 5.3.6：DSN charset 被忽略，宽字节高风险"""
        return self.php_version == PhpVersion.PHP_5_0.value

    @property
    def is_php_5_5_plus(self) -> bool:
        """PHP >= 5.5：preg_replace /e 废弃"""
        return self.version_tuple >= _version_to_tuple("5.5")

    @property
    def is_php_7_0_plus(self) -> bool:
        """PHP >= 7.0：mysql_* 移除"""
        return self.version_tuple >= _version_to_tuple("7.0")

    @property
    def is_php_7_2_plus(self) -> bool:
        """PHP >= 7.2：create_function 废弃，assert 默认安全"""
        return self.version_tuple >= _version_to_tuple("7.2")

    def get_active_rules(self) -> list[AuditRule]:
        """
        获取当前 PHP 版本下生效的所有规则。

        过滤逻辑：
          - min_php_version: 规则从该版本开始生效（含）
          - max_php_version: 规则到该版本为止生效（含）
          - 都不设 = 所有版本生效
        """
        active = []
        for rule in PHP_AUDIT_RULES:
            if self._is_rule_active(rule):
                active.append(rule)
        return active

    def _is_rule_active(self, rule: AuditRule) -> bool:
        """判断规则在当前版本下是否生效"""
        current = _version_to_tuple(self.php_version)

        # 检查最小版本
        if rule.min_php_version is not None:
            min_v = _version_to_tuple(rule.min_php_version)
            if current and current < min_v:
                return False

        # 检查最大版本
        if rule.max_php_version is not None:
            max_v = _version_to_tuple(rule.max_php_version)
            if current and current > max_v:
                return False

        return True

    def adjust_severity(self, rule_id: str, base_severity: str) -> str:
        """
        根据 PHP 版本调整规则的严重程度。

        某些漏洞在不同 PHP 版本下风险不同：
          - PHP < 5.3.6: 宽字节注入 risk higher
          - PHP 7.0+: mysql_* 直接 fatal error → critical
        """
        rule = self.get_rule_by_id(rule_id)
        if rule and self.php_version in rule.severity_overrides:
            return rule.severity_overrides[self.php_version]
        return base_severity

    def get_rule_by_id(self, rule_id: str) -> Optional[AuditRule]:
        """按 ID 查找规则"""
        for r in PHP_AUDIT_RULES:
            if r.rule_id == rule_id:
                return r
        return None

    def get_rules_by_category(self, category: str) -> list[AuditRule]:
        """按类别获取所有规则（无视版本）"""
        return [r for r in PHP_AUDIT_RULES if r.category.value == category]

    def get_active_rules_by_category(self, category: str) -> list[AuditRule]:
        """按类别获取当前版本下生效的规则"""
        return [r for r in self.get_active_rules()
                if r.category.value == category]

    # ================================================================
    # 便捷方法：为 AST 分析器提供版本上下文
    # ================================================================

    def get_wide_byte_context(self) -> dict:
        """
        返回宽字节注入检测所需的版本上下文。

        AST 分析器可以用这些信息调整检测逻辑：
          - dsn_charset_trusted: DSN charset 是否可信（PHP >= 5.3.6）
          - emulate_risk_level: 模拟预处理的风险等级
        """
        return {
            "dsn_charset_trusted": not self.is_php_before_5_3_6,
            "emulate_risk_level": (
                "critical" if self.is_php_before_5_3_6 else "medium"
            ),
            "mysql_functions_status": (
                "removed" if self.is_php_7_0_plus else
                "deprecated" if self.is_php_5_5_plus else
                "available"
            ),
            "preg_replace_e_status": (
                "removed" if self.is_php_7_0_plus else
                "deprecated" if self.is_php_5_5_plus else
                "available"
            ),
            "create_function_status": (
                "removed" if self.version_tuple >= _version_to_tuple("7.4") else
                "deprecated" if self.is_php_7_2_plus else
                "available"
            ),
        }

    def get_version_label(self) -> str:
        """获取人类可读的版本标签"""
        labels = {
            "5.0": "PHP 5.0 ~ 5.3.5",
            "5.3": "PHP 5.3.6 ~ 5.4.x",
            "5.5": "PHP 5.5 ~ 5.6.x",
            "7.0": "PHP 7.0 ~ 7.1.x",
            "7.2": "PHP 7.2 ~ 7.3.x",
            "7.4": "PHP 7.4.x",
            "8.0": "PHP 8.0+",
        }
        return labels.get(self.php_version, f"PHP {self.php_version}")

    @staticmethod
    def get_available_versions() -> list[dict]:
        """返回可选版本列表（供前端使用）"""
        return [
            {"value": "5.0", "label": "PHP 5.0 ~ 5.3.5", "note": "DSN charset 被忽略"},
            {"value": "5.3", "label": "PHP 5.3.6 ~ 5.4.x", "note": "DSN charset 可用"},
            {"value": "5.5", "label": "PHP 5.5 ~ 5.6.x", "note": "mysql_* 废弃"},
            {"value": "7.0", "label": "PHP 7.0 ~ 7.1.x", "note": "mysql_* 移除"},
            {"value": "7.2", "label": "PHP 7.2 ~ 7.3.x", "note": "create_function 废弃"},
            {"value": "7.4", "label": "PHP 7.4.x", "note": "create_function 移除"},
            {"value": "8.0", "label": "PHP 8.0+", "note": "最新版本"},
        ]


# ========================================================================
# PHP 版本自动检测
# ========================================================================

# 每条检测规则：(最低版本, 正则, 描述)
# 按版本从高到低排列，匹配到即返回该版本
_PHP_VERSION_SIGNATURES: list[tuple[str, str, str]] = [
    # PHP 8.0+
    ("8.0", r"(?<!\w)match\s*\([^)]*\)\s*\{", "match() 表达式"),
    ("8.0", r"\?\-\>\w+", "nullsafe 操作符 (?->)"),
    ("8.0", r"#\[[A-Z]\w*", "#[Attribute] 原生注解"),
    ("8.0", r"function\s+\w+\s*\([^)]*\w+\s*:\s*\w+\s*,\s*\w+\s*:\s*\w+\s*\)", "具名参数"),
    ("8.0", r"\bstr_(?:contains|starts_with|ends_with)\s*\(", "str_contains/starts_with/ends_with"),
    ("8.0", r"(?:string|int|float|bool)\s*\|\s*(?:string|int|float|bool|null)", "联合类型声明"),

    # PHP 7.4
    ("7.4", r"\w+\s*=\s*fn\s*\(", "箭头函数 fn()"),
    ("7.4", r"(?:public|protected|private)\s+(?:string|int|float|bool)\s+\$\w+", "类型化属性"),

    # PHP 7.2
    ("7.2", r"function\s+\w+\([^)]*\)\s*:\s*void", "void 返回类型"),

    # PHP 7.0
    ("7.0", r"\?\?\s*\S", "空合并运算符 ??"),
    ("7.0", r"\$\w+\s*\<\=\>\s*\$\w+", "太空船操作符 <=>"),
    ("7.0", r"function\s+\w+\([^)]*\)\s*:\s*\w+", "返回类型声明"),
    ("7.0", r"\bdeclare\s*\(\s*strict_types\s*=\s*1\s*\)", "strict_types 声明"),
    ("7.0", r"\buse\s+[A-Z].*\s+use\s+[A-Z]", "use 分组导入"),

    # PHP 5.5
    ("5.5", r"\byield\b", "yield 生成器"),
    ("5.5", r"finally\s*\{", "try-finally 块"),
    ("5.5", r"::class\b", "::class 解析"),
    ("5.5", r"\bempty\s*\(\s*\$\w+\[.+\]\s*\)", "empty() 支持表达式"),
    ("5.5", r"\barray\s*\[\s*\]\s*=\s*", "短数组语法"),

    # PHP 5.3
    ("5.3", r"\bnamespace\s+\w+", "namespace 声明"),
    ("5.3", r"\buse\s+[A-Z]\w+", "use 导入"),
    ("5.3", r"function\s*\([^)]*\)\s*use\s*\(", "闭包 use()"),
    ("5.3", r"static\s*::", "延迟静态绑定 static::"),
    ("5.3", r"\b__DIR__\b", "__DIR__ 常量"),
    ("5.3", r"\?\:", "三元简写 ?:"),
]


def detect_php_version(source_codes: dict[str, str]) -> str:
    """
    从 PHP 源码中自动检测最低所需版本。

    扫描所有源文件，查找各版本特有的语法特征，
    返回匹配到的最高版本号（即最低所需 PHP 版本）。

    参数:
        source_codes: {file_path: source_code} 映射

    返回:
        版本号字符串，如 "7.4"、"5.3"、"5.0"
    """
    detected_version = "5.0"  # 默认最低
    all_code = "\n".join(source_codes.values())

    # 排除注释和字符串
    code_only = re.sub(r'(?://[^\n]*|#\s*[^\n]*|/\*.*?\*/)', '', all_code, flags=re.DOTALL)

    for version, pattern, description in _PHP_VERSION_SIGNATURES:
        if re.search(pattern, code_only, re.IGNORECASE):
            # 找到更高版本的特征，更新检测版本
            if _version_gte(version, detected_version):
                detected_version = version

    return detected_version


def resolve_php_version(
    user_version: str | None,
    source_codes: dict[str, str],
) -> tuple[str, bool]:
    """
    解析最终使用的 PHP 版本。

    优先使用用户选择的版本；若未选择则自动检测。

    参数:
        user_version: 用户选择的版本（"7.4", "8.0" 等），None/"" 表示自动检测
        source_codes: 源文件映射

    返回:
        (最终版本号, 是否自动检测)
        如 ("7.0", True) 表示自动检测到 PHP 7.0
    """
    if user_version:
        return user_version, False

    detected = detect_php_version(source_codes)
    return detected, True


# ========================================================================
# Python 版本感知规则引擎
# ========================================================================

class PythonVersion(str, Enum):
    """Python 版本枚举。关键安全变更：
    - 2.7: print statement, input() eval, urllib 无验证
    - 3.0: print 改为函数, input() 不再 eval
    - 3.6: f-string, secrets 模块
    - 3.8: pathlib 支持更多操作
    - 3.11: subprocess 安全性增强
    """
    PY_2_7 = "2.7"
    PY_3_6 = "3.6"
    PY_3_7 = "3.7"
    PY_3_8 = "3.8"
    PY_3_9 = "3.9"
    PY_3_10 = "3.10"
    PY_3_11 = "3.11"
    PY_3_12 = "3.12"
    PY_3_13 = "3.13"


PYTHON_AUDIT_RULES: list[AuditRule] = []


def _pyrule(**kwargs) -> AuditRule:
    r = AuditRule(**kwargs)
    PYTHON_AUDIT_RULES.append(r)
    return r

# ---- Python 2.x 特有漏洞 ----

_pyrule(
    rule_id="PY_INPUT_EVAL",
    name="input() 函数代码注入 (Python 2)",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.CRITICAL,
    max_version="2.7",
    description="Python 2 中 input() 等价于 eval(raw_input())，可执行任意代码。Python 3 已移除此行为。",
    pattern=r"(?<!\.)input\s*\(",
    confidence=0.95,
)

_pyrule(
    rule_id="PY_RAW_INPUT",
    name="raw_input() 已移除 (Python 3)",
    category=RuleCategory.DEPRECATED_API,
    default_severity=RuleSeverity.LOW,
    min_version="3.0",
    description="Python 3 中 raw_input() 已被移除，在 Python 2 代码迁移到 Python 3 时会报错。",
    pattern=r"raw_input\s*\(",
    confidence=0.9,
)

# ---- 全版本通用漏洞 ----

_pyrule(
    rule_id="PY_EXEC_CODE",
    name="exec() 执行动态代码",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.CRITICAL,
    description="exec() 执行用户可控字符串作为代码。应避免使用或严格限制输入来源。",
    pattern=r"\bexec\s*\(",
    confidence=0.9,
)

_pyrule(
    rule_id="PY_EVAL_CODE",
    name="eval() 动态求值",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    description="eval() 对字符串求值，若含用户输入可导致代码执行。应使用 ast.literal_eval() 或避免 eval。",
    pattern=r"\beval\s*\(",
    confidence=0.85,
)

_pyrule(
    rule_id="PY_SUBPROCESS_SHELL",
    name="subprocess shell=True 命令注入",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    description="subprocess 使用 shell=True 且参数串联用户输入时存在命令注入风险。应使用列表参数传递。",
    pattern=r"shell\s*=\s*True",
    confidence=0.85,
)

_pyrule(
    rule_id="PY_OS_SYSTEM",
    name="os.system() 命令执行",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    description="os.system() 执行 shell 命令，若含用户输入存在命令注入。应使用 subprocess.run() 替代。",
    pattern=r"os\.system\s*\(",
    confidence=0.9,
)

_pyrule(
    rule_id="PY_OS_POPEN",
    name="os.popen() 命令执行",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.MEDIUM,
    description="os.popen() 打开管道执行命令，存在命令注入风险。",
    pattern=r"os\.popen\s*\(",
    confidence=0.85,
)

_pyrule(
    rule_id="PY_PICKLE_UNSAFE",
    name="pickle 反序列化",
    category=RuleCategory.DESERIALIZATION,
    default_severity=RuleSeverity.HIGH,
    description="pickle.loads() 反序列化不可信数据可导致任意代码执行。应使用 json 或限制 pickle 来源。",
    pattern=r"pickle\.(?:loads?|Unpickler)\s*\(",
    confidence=0.9,
)

_pyrule(
    rule_id="PY_YAML_UNSAFE",
    name="yaml.load() 不安全加载",
    category=RuleCategory.DESERIALIZATION,
    default_severity=RuleSeverity.HIGH,
    description="PyYAML 的 yaml.load() 可构造任意 Python 对象。应使用 yaml.safe_load() 替代。",
    pattern=r"yaml\.load\s*\(",
    confidence=0.9,
)

_pyrule(
    rule_id="PY_SQL_CONCAT",
    name="SQL 字符串拼接",
    category=RuleCategory.SQL_INJECTION,
    default_severity=RuleSeverity.HIGH,
    description="SQL 查询通过字符串拼接或 f-string 包含用户输入。应使用参数化查询（%s 占位符）。",
    pattern=r"(?:execute|cursor)\.*(?:f['\"]|['\"].*%)",
    confidence=0.85,
)

_pyrule(
    rule_id="PY_FSTRING_SQL",
    name="f-string SQL 注入",
    category=RuleCategory.SQL_INJECTION,
    default_severity=RuleSeverity.HIGH,
    min_version="3.6",
    description="Python 3.6+ 中使用 f-string 拼接 SQL 查询，完全绕过参数化。",
    pattern=r"execute\s*\(\s*f['\"]",
    confidence=0.9,
)

_pyrule(
    rule_id="PY_MARSHAL_UNSAFE",
    name="marshal 反序列化",
    category=RuleCategory.DESERIALIZATION,
    default_severity=RuleSeverity.MEDIUM,
    description="marshal.loads() 反序列化不可信数据可能导致代码执行。",
    pattern=r"marshal\.(?:loads?|dumps?)\s*\(",
    confidence=0.8,
)

_pyrule(
    rule_id="PY_SHELVE_UNSAFE",
    name="shelve 反序列化",
    category=RuleCategory.DESERIALIZATION,
    default_severity=RuleSeverity.MEDIUM,
    description="shelve 模块内部使用 pickle，反序列化不可信数据存在风险。",
    pattern=r"shelve\.open\s*\(",
    confidence=0.7,
)

_pyrule(
    rule_id="PY_OPEN_PATH_TRAVERSAL",
    name="open() 路径穿越",
    category=RuleCategory.PATH_TRAVERSAL,
    default_severity=RuleSeverity.HIGH,
    description="open() 的文件路径包含用户输入，可能导致目录穿越读取任意文件。应使用 os.path.basename 过滤。",
    pattern=r"\bopen\s*\([^)]*\+",
    confidence=0.8,
)

_pyrule(
    rule_id="PY_REQUESTS_NO_VERIFY",
    name="requests SSL 验证关闭",
    category=RuleCategory.SSRF,
    default_severity=RuleSeverity.MEDIUM,
    description="requests 调用设置了 verify=False，禁用 SSL 证书验证，易受中间人攻击。",
    pattern=r"verify\s*=\s*False",
    confidence=0.75,
)

_pyrule(
    rule_id="PY_TEMPLATE_INJECTION",
    name="模板注入 (Jinja2/Mako)",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.CRITICAL,
    description="模板引擎的模板字符串包含用户输入，可能导致 SSTI 服务器端模板注入。",
    pattern=r"(?:Template|Environment|render_template_string)\s*\([^)]*\+",
    confidence=0.8,
)


class PythonRuleEngine:
    """Python 版本感知规则引擎"""

    def __init__(self, python_version: str = "3.8"):
        self.python_version = python_version

    @property
    def version_tuple(self) -> tuple[int, ...]:
        return _version_to_tuple(self.python_version)

    def get_active_rules(self) -> list[AuditRule]:
        active = []
        current = self.version_tuple
        for rule in PYTHON_AUDIT_RULES:
            if rule.min_version is not None:
                min_v = _version_to_tuple(rule.min_version)
                if current and current < min_v:
                    continue
            if rule.max_version is not None:
                max_v = _version_to_tuple(rule.max_version)
                if current and current > max_v:
                    continue
            active.append(rule)
        return active

    def get_version_context(self) -> dict:
        """返回 Python 版本上下文，供扫描器使用"""
        return {
            "is_python2": self.version_tuple < (3,),
            "has_fstring": self.version_tuple >= (3, 6),
            "has_walrus": self.version_tuple >= (3, 8),
            "has_match": self.version_tuple >= (3, 10),
            "input_is_safe": self.version_tuple >= (3,),
        }


# ========================================================================
# C/C++ 标准感知规则引擎
# ========================================================================

class CppStandard(str, Enum):
    """C/C++ 标准枚举。关键安全变更：
    - C11: 移除 gets(), 添加 bounds-checking 接口
    - C++11: nullptr, std::unique_ptr, std::make_shared
    - C++17: std::string_view, std::optional
    """
    C89 = "c89"
    C99 = "c99"
    C11 = "c11"
    C17 = "c17"
    C23 = "c23"
    CPP_98 = "c++98"
    CPP_11 = "c++11"
    CPP_14 = "c++14"
    CPP_17 = "c++17"
    CPP_20 = "c++20"
    CPP_23 = "c++23"

    def is_cpp(self) -> bool:
        return self.value.startswith("c++")

    def is_c(self) -> bool:
        return not self.is_cpp()


CPP_AUDIT_RULES: list[AuditRule] = []


def _cpprule(**kwargs) -> AuditRule:
    r = AuditRule(**kwargs)
    CPP_AUDIT_RULES.append(r)
    return r

# ---- 预 C11 特有漏洞 ----

_cpprule(
    rule_id="C_GETS_FUNCTION",
    name="gets() 缓冲区溢出 (C11 已移除)",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.CRITICAL,
    max_version="c99",
    description="gets() 不检查缓冲区边界，已在 C11 中移除。应使用 fgets() 替代。",
    pattern=r"\bgets\s*\(",
    confidence=0.95,
)

# ---- 跨版本通用漏洞 ----

_cpprule(
    rule_id="C_STRCPY_UNSAFE",
    name="strcpy() 无边界检查",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    description="strcpy() 不检查目标缓冲区大小，可导致缓冲区溢出。应使用 strncpy() 或 strcpy_s()。",
    pattern=r"\bstrcpy\s*\(",
    confidence=0.9,
    severity_overrides={"c11": "critical", "c++11": "critical"},
)

_cpprule(
    rule_id="C_STRCAT_UNSAFE",
    name="strcat() 无边界检查",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    description="strcat() 拼接字符串时不检查缓冲区大小。应使用 strncat() 或 strcat_s()。",
    pattern=r"\bstrcat\s*\(",
    confidence=0.9,
)

_cpprule(
    rule_id="C_SPRINTF_UNSAFE",
    name="sprintf() 无边界检查",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    description="sprintf() 不限制输出长度，可导致缓冲区溢出。应使用 snprintf()。",
    pattern=r"\bsprintf\s*\(",
    confidence=0.9,
)

_cpprule(
    rule_id="C_SCANF_UNSAFE",
    name="scanf() 无长度限制",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.MEDIUM,
    description="scanf() 的 %s 格式符不限制输入长度。应使用 %Ns 指定最大宽度。",
    pattern=r"\bscanf\s*\([^)]*%s",
    confidence=0.85,
)

_cpprule(
    rule_id="C_SYSTEM_CALL",
    name="system() 命令执行",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    description="system() 执行 shell 命令，若参数含用户输入存在命令注入。应使用 exec 系列函数。",
    pattern=r"\bsystem\s*\(",
    confidence=0.9,
)

_cpprule(
    rule_id="C_POPEN_CALL",
    name="popen() 命令执行",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    description="popen() 通过 shell 执行命令。应避免使用或严格过滤输入。",
    pattern=r"\bpopen\s*\(",
    confidence=0.85,
)

_cpprule(
    rule_id="C_SQL_INJECTION",
    name="C 字符串拼接 SQL",
    category=RuleCategory.SQL_INJECTION,
    default_severity=RuleSeverity.HIGH,
    description="SQL 语句通过 sprintf/strcat 拼接用户输入。应使用参数化查询（占位符）。",
    pattern=r"(?:sprintf|strcat)\s*\([^)]*SELECT",
    confidence=0.8,
)

_cpprule(
    rule_id="C_FORMAT_STRING",
    name="printf 格式化字符串漏洞",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.HIGH,
    description="printf 类函数的格式字符串包含用户输入，可导致信息泄露或任意写入。",
    pattern=r"(?:printf|fprintf|sprintf)\s*\(\s*\w+\s*\)",
    confidence=0.85,
)

_cpprule(
    rule_id="C_MEMORY_LEAK",
    name="malloc 无对应 free",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.MEDIUM,
    description="malloc/calloc/realloc 分配的内存可能存在泄漏风险。建议使用 RAII 或智能指针。",
    pattern=r"\b(?:malloc|calloc|realloc)\s*\(",
    confidence=0.6,
)

_cpprule(
    rule_id="C_NO_BOUNDS_CHECK",
    name="数组越界访问风险",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.MEDIUM,
    description="C 风格数组不进行边界检查，使用用户输入作为索引可导致越界读写。",
    pattern=r"\w+\s*\[\s*\w+\s*\]",
    confidence=0.55,
)

_cpprule(
    rule_id="CXX_NEW_NO_DELETE",
    name="new 无对应 delete (C++)",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.MEDIUM,
    min_version="c++98",
    description="使用 new 分配内存但未显示释放。C++11+ 应使用 std::unique_ptr 或 std::shared_ptr。",
    pattern=r"\bnew\s+\w+",
    confidence=0.55,
    severity_overrides={"c++11": "high"},
)

_cpprule(
    rule_id="CXX_RAW_POINTER",
    name="裸指针管理 (C++)",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.LOW,
    min_version="c++11",
    description="C++11+ 中仍使用裸指针 (T*) 而非智能指针，增加内存安全和悬挂指针风险。",
    pattern=r"\w+\s*\*\s*\w+\s*=\s*new",
    confidence=0.5,
)

_cpprule(
    rule_id="C_FOPEN_PATH_TRAVERSAL",
    name="fopen() 路径穿越",
    category=RuleCategory.PATH_TRAVERSAL,
    default_severity=RuleSeverity.HIGH,
    description="fopen() 的文件路径含用户输入，可能导致目录穿越。应规范化路径并限制访问范围。",
    pattern=r"\bfopen\s*\([^)]*\+",
    confidence=0.8,
)

_cpprule(
    rule_id="C_REALLOC_NULL",
    name="realloc() 返回 NULL 风险",
    category=RuleCategory.COMMAND_EXECUTION,
    default_severity=RuleSeverity.MEDIUM,
    description="realloc() 失败时返回 NULL 且原内存未释放，直接赋值给原指针会导致内存泄漏。应使用临时变量。",
    pattern=r"\w+\s*=\s*realloc\s*\(\s*\w+",
    confidence=0.7,
)


class CppRuleEngine:
    """C/C++ 标准感知规则引擎"""

    # 标准排序（用于版本比较）
    _STANDARD_ORDER = {
        "c89": 0, "c99": 1, "c11": 2, "c17": 3, "c23": 4,
        "c++98": 10, "c++11": 11, "c++14": 12, "c++17": 13, "c++20": 14, "c++23": 15,
    }

    def __init__(self, cpp_standard: str = "c11"):
        self.cpp_standard = cpp_standard

    @property
    def is_cpp(self) -> bool:
        return self.cpp_standard.startswith("c++")

    @property
    def _order(self) -> int:
        return self._STANDARD_ORDER.get(self.cpp_standard, 0)

    def _version_gte(self, a: str, b: str) -> bool:
        """标准版本比较 a >= b"""
        return self._STANDARD_ORDER.get(a, 0) >= self._STANDARD_ORDER.get(b, 0)

    def _version_lte(self, a: str, b: str) -> bool:
        """标准版本比较 a <= b"""
        return self._STANDARD_ORDER.get(a, 0) <= self._STANDARD_ORDER.get(b, 0)

    def get_active_rules(self) -> list[AuditRule]:
        """获取当前标准下生效的规则"""
        active = []
        for rule in CPP_AUDIT_RULES:
            if rule.min_version is not None:
                if not self._version_gte(self.cpp_standard, rule.min_version):
                    continue
            if rule.max_version is not None:
                if not self._version_lte(self.cpp_standard, rule.max_version):
                    continue
            active.append(rule)
        return active

    def adjust_severity(self, rule_id: str, base_severity: str) -> str:
        """根据 C/C++ 标准调整严重程度"""
        for r in CPP_AUDIT_RULES:
            if r.rule_id == rule_id:
                if self.cpp_standard in r.severity_overrides:
                    return r.severity_overrides[self.cpp_standard]
                return base_severity
        return base_severity

    def get_standard_context(self) -> dict:
        """返回标准上下文供扫描器使用"""
        return {
            "is_cpp": self.is_cpp,
            "has_nullptr": self._version_gte(self.cpp_standard, "c++11"),
            "has_smart_ptr": self._version_gte(self.cpp_standard, "c++11"),
            "has_string_view": self._version_gte(self.cpp_standard, "c++17"),
            "gets_removed": self._version_gte(self.cpp_standard, "c11"),
        }


# ========================================================================
# Python / C 版本自动检测
# ========================================================================

_PYTHON_VERSION_SIGNATURES: list[tuple[str, str, str]] = [
    ("3.13", r"\btype\s+\w+\s*=\s*\([^)]+\)\s*:", "PEP 695 type 语句"),
    ("3.12", r"\btype\s+\w+\s*\([^)]*\)\s*:", "PEP 695 泛型语法"),
    ("3.10", r"\bmatch\s+\w+\s*:", "match-case 模式匹配"),
    ("3.9", r"list\[str\]|dict\[str,\s*int\]", "内置泛型 list[str]"),
    ("3.8", r":=\s*\w+", "海象运算符 :="),
    ("3.7", r"from\s+__future__\s+import\s+annotations", "from __future__ annotations"),
    ("3.6", r"f['\"].*\{.*\}.*['\"]", "f-string"),
    ("2.7", r"(?<!def\s)(?<!\.)(?<!import\s)\bprint\s+[^(]", "print 语句 (Python 2)"),
]

_C_VERSION_SIGNATURES: list[tuple[str, str, str]] = [
    ("c23", r"\bconstexpr\b", "C23 constexpr"),
    ("c23", r"\bnullptr\b", "C23 nullptr"),
    ("c17", r"\b_Generic\b", "C11 _Generic"),
    ("c11", r"\b_Alignas\b|\b_Alignof\b|\b_Noreturn\b", "C11 关键字"),
    ("c99", r"\/\/", "// 单行注释 (C99)"),
    ("c99", r"for\s*\(\s*(?:int|float|double|char)\s+\w+\s*=", "for 循环内声明变量 (C99)"),
]

_CPP_VERSION_SIGNATURES: list[tuple[str, str, str]] = [
    ("c++23", r"import\s+<\w+>", "C++23 import 模块"),
    ("c++20", r"\bco_await\b|\bco_yield\b|\bco_return\b", "C++20 协程"),
    ("c++20", r"\bconcept\s+\w+\s*=", "C++20 concept"),
    ("c++17", r"if\s*\(\s*constexpr", "C++17 if constexpr"),
    ("c++17", r"std::string_view", "C++17 string_view"),
    ("c++14", r"auto\s+\w+\s*\([^)]*\)\s*->\s*\w+", "C++14 返回类型推导"),
    ("c++11", r"\bnullptr\b", "C++11 nullptr"),
    ("c++11", r"std::unique_ptr|std::shared_ptr|std::make_shared", "C++11 智能指针"),
    ("c++11", r"auto\s+\w+\s*=\s*.*;", "C++11 auto 类型推导"),
]


def detect_python_version(source_codes: dict[str, str]) -> str:
    """从 Python 源码自动检测版本"""
    all_code = "\n".join(source_codes.values())
    code_only = re.sub(r'#.*', '', all_code)
    code_only = re.sub(r'(""".*?"""|\'\'\'.*?\'\'\')', '', code_only, flags=re.DOTALL)

    for version, pattern, desc in _PYTHON_VERSION_SIGNATURES:
        if re.search(pattern, code_only):
            return version
    return "3.6"  # 默认


def detect_c_version(source_codes: dict[str, str]) -> str:
    """从 C 源码自动检测标准"""
    all_code = "\n".join(source_codes.values())
    code_only = re.sub(r'(//[^\n]*|/\*.*?\*/)', '', all_code, flags=re.DOTALL)

    for version, pattern, desc in _C_VERSION_SIGNATURES:
        if re.search(pattern, code_only):
            return version
    return "c89"


def detect_cpp_version(source_codes: dict[str, str]) -> str:
    """从 C++ 源码自动检测标准"""
    all_code = "\n".join(source_codes.values())
    code_only = re.sub(r'(//[^\n]*|/\*.*?\*/)', '', all_code, flags=re.DOTALL)

    for version, pattern, desc in _CPP_VERSION_SIGNATURES:
        if re.search(pattern, code_only):
            return version
    return "c++98"

