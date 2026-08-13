#!/usr/bin/env python3
"""
CVE 规则自动更新脚本（单文件版）
===============================
从 NVD 拉取最新 CVE，直接写入 rule_engine.py 的对应位置。

用法:
    python update_cve_rules.py              # 拉最近 30 天，写入 rule_engine
    python update_cve_rules.py --days 7     # 只拉最近 7 天
    python update_cve_rules.py --dry-run    # 只看不改

原理:
    1. 调 NVD API v2 拉取 CVE 列表
    2. 过滤出 PHP / Python / C/C++ 相关漏洞
    3. 将 CVE 转为 _rule() / _pyrule() / _cpprule() 代码块
    4. 插入 rule_engine.py 末尾的 # CVE_RULES 标记处（或自动插入）

==== 配置 ====

在 backend/.env 中添加（可选，建议）:
    NVD_API_KEY=your-free-key    # https://nvd.nist.gov/developers/request-an-api-key
"""
import sys
import os
import re
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone

# =========================================================================
# 配置
# =========================================================================

BACKEND_DIR = Path(__file__).resolve().parent
RULE_ENGINE_PATH = BACKEND_DIR / "engine" / "rule_engine.py"
ENV_PATH = BACKEND_DIR / ".env"

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 100
DRY_RUN = False

# ---- 生态映射：CPE product → 我们的分类 ----
PHP_PRODUCTS = {
    "php", "laravel", "symfony", "wordpress", "drupal", "joomla",
    "magento", "yii", "cakephp", "codeigniter", "slim",
    "phpmyadmin", "composer", "phpunit", "guzzlehttp", "monolog",
    "twig", "doctrine", "phpseclib", "phpmailer", "zend",
    "typo3", "prestashop", "mediawiki", "roundcube", "squirrelmail",
    "pear", "phpbb", "vbulletin", "simple-machines-forum",
    "nextcloud", "owncloud", "moodle", "concrete5", "silverstripe",
    "laminas", "swoole", "hyperf", "thinkphp", "ecshop",
}

PHP_VENDORS = {"php", "phpmyadmin", "phpbb", "phpmailer", "phpsysinfo",
              "php-fusion", "phpgurukul", "phpjabbers", "mayurik"}

PYTHON_PRODUCTS = {
    "python", "django", "flask", "tornado", "fastapi", "sqlalchemy",
    "requests", "numpy", "scipy", "pandas", "jupyter", "pip",
    "pillow", "pyyaml", "cryptography", "jinja", "jinja2",
    "werkzeug", "gunicorn", "aiohttp", "celery", "boto3",
    "urllib3", "setuptools", "twisted", "tensorflow", "torch",
    "scikit-learn", "matplotlib", "sphinx", "docutils", "lxml",
    "ansible", "salt", "paramiko", "fabric", "pyramid", "bottle",
    "cherrypy", "web2py", "zope", "plone", "opencv-python",
}

PYTHON_VENDORS = {"python", "pypa", "psf", "djangoproject", "pallets"}

C_CPP_PRODUCTS = {
    "glibc", "openssl", "libcurl", "curl", "sqlite", "zlib",
    "libpng", "libxml2", "libxslt", "libtiff", "freetype",
    "expat", "libssh", "libssh2", "gnutls", "nettle",
    "libgcrypt", "gnupg", "linux_kernel", "linux", "kernel",
    "busybox", "bash", "sudo", "systemd", "qemu",
    "apache", "nginx", "bind", "git", "libarchive", "libpcap",
    "tcpdump", "wireshark", "libevent", "libuv", "bzip2", "xz",
    "ncurses", "readline", "pcre", "pcre2", "libsodium",
    "libressl", "boringssl", "wolfssl", "mbed-tls",
    "libvpx", "libwebp", "libgcrypt", "libgpg-error",
    "libassuan", "libksba", "ntp", "chrony", "bind9",
    "isc-dhcp", "dhcp", "dnsmasq", "memcached", "redis",
    "mariadb", "mysql", "postgresql", "sqlite3", "mongo-c-driver",
    "libmicrohttpd", "lighttpd", "vsftpd", "proftpd", "pure-ftpd",
    "openvpn", "strongswan", "libreswan", "stunnel",
}

C_VENDORS = {"gnu", "linux", "busybox", "apache", "nginx", "openssl",
             "gnupg", "wireshark", "tcpdump", "curl", "libssh",
             "isc", "mariadb", "mysql", "postgresql", "redis"}

# ---- CWE → 类别 ----
CWE_TO_CAT = {
    "CWE-89":  "sql_injection",
    "CWE-564": "sql_injection",
    "CWE-943": "sql_injection",
    "CWE-77":  "command_execution",
    "CWE-78":  "command_execution",
    "CWE-94":  "command_execution",
    "CWE-95":  "command_execution",
    "CWE-918": "ssrf",
    "CWE-22":  "path_traversal",
    "CWE-23":  "path_traversal",
    "CWE-79":  "xss",
    "CWE-80":  "xss",
    "CWE-434": "file_upload",
    "CWE-502": "deserialization",
    "CWE-915": "deserialization",
    "CWE-119": "command_execution",
    "CWE-120": "command_execution",
    "CWE-121": "command_execution",
    "CWE-122": "command_execution",
    "CWE-125": "arbitrary_file_read",
    "CWE-787": "command_execution",
    "CWE-190": "command_execution",
    "CWE-74":  "command_execution",
    "CWE-200": "arbitrary_file_read",
    "CWE-611": "arbitrary_file_read",
    "CWE-287": "auth_bypass",
    "CWE-306": "auth_bypass",
    "CWE-862": "auth_bypass",
    "CWE-532": "info_leak",
}

# ---- 类别 → RuleCategory 枚举值 ----
CAT_TO_ENUM = {
    "sql_injection":      "RuleCategory.SQL_INJECTION",
    "command_execution":  "RuleCategory.COMMAND_EXECUTION",
    "ssrf":               "RuleCategory.SSRF",
    "path_traversal":     "RuleCategory.PATH_TRAVERSAL",
    "arbitrary_file_read":"RuleCategory.PATH_TRAVERSAL",
    "xss":                "RuleCategory.XSS",
    "file_upload":        "RuleCategory.FILE_UPLOAD",
    "deserialization":    "RuleCategory.DESERIALIZATION",
    "deprecated_api":     "RuleCategory.DEPRECATED_API",
    "auth_bypass":        "RuleCategory.COMMAND_EXECUTION",
    "info_leak":          "RuleCategory.PATH_TRAVERSAL",
}

# ---- 严重程度枚举 ----
SEV_ENUM = {
    "critical": "RuleSeverity.CRITICAL",
    "high":     "RuleSeverity.HIGH",
    "medium":   "RuleSeverity.MEDIUM",
    "low":      "RuleSeverity.LOW",
    "info":     "RuleSeverity.INFO",
}

# ---- 插入标记（在 rule_engine.py 中） ----
MARKER_PHP   = "# ========================================================================\n# 规则引擎\n# ========================================================================"
MARKER_PY    = "class PythonRuleEngine:"
MARKER_CPP   = "class CppRuleEngine:"


# =========================================================================
# 核心逻辑
# =========================================================================

def get_api_key() -> str:
    """获取 NVD API Key"""
    key = os.getenv("NVD_API_KEY", "")
    if key:
        return key
    if ENV_PATH.exists():
        with open(ENV_PATH, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("NVD_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def fetch_cves(days: int = 30) -> list[dict]:
    """从 NVD 拉取最近 N 天的 CVE，只保留 PHP/Python/C/C++ 相关"""
    import urllib.request
    import urllib.error

    api_key = get_api_key()
    rate = 0.61 if api_key else 6.1
    last_req = 0.0

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    since = (datetime.now(timezone.utc) - timedelta(days=days)
             ).strftime("%Y-%m-%dT%H:%M:%S.000")

    all_cves = []
    start = 0

    while True:
        url = (f"{NVD_BASE}?pubStartDate={since}&pubEndDate={now_str}"
               f"&resultsPerPage={PAGE_SIZE}&startIndex={start}")

        # 速率限制
        elapsed = time.time() - last_req
        if elapsed < rate:
            time.sleep(rate - elapsed)

        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "CveUpdater/1.0")
            if api_key:
                req.add_header("apiKey", api_key)

            last_req = time.time()
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = int(e.headers.get("Retry-After", "30"))
                print(f"  速率限制，等待 {wait}s...")
                time.sleep(wait)
                continue
            print(f"  HTTP {e.code}: {e.reason}")
            break
        except Exception as e:
            print(f"  请求失败: {e}")
            break

        vulns = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        for item in vulns:
            cve = item.get("cve", {})
            parsed = parse_cve(cve)
            if parsed:
                all_cves.append(parsed)

        start += PAGE_SIZE
        print(f"  拉取中... {min(start, total)}/{total}")
        if start >= total:
            break

    return all_cves


def parse_cve(cve: dict) -> dict | None:
    """解析单条 CVE，返回结构化数据，不相关返回 None"""
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # 提取英文描述
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if not desc:
        return None

    # 提取 CVSS v3
    metrics = cve.get("metrics", {})
    cvss_score = 0.0
    severity = "medium"
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []):
            cvss_data = m.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "MEDIUM").lower()
            break
        if cvss_score:
            break
    if not cvss_score:
        for m in metrics.get("cvssMetricV2", []):
            cvss_data = m.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            s = cvss_score
            severity = "critical" if s >= 9 else ("high" if s >= 7 else ("medium" if s >= 4 else "low"))
            break

    # 至少 medium 才收
    if severity in ("low", "none", "info"):
        return None

    # 提取 CWE
    cwes = []
    for w in cve.get("weaknesses", []):
        for wd in w.get("description", []):
            v = wd.get("value", "")
            if v.startswith("CWE-"):
                cwes.append(v)

    # 解析 CPE → 生态
    eco_info = extract_ecosystem(cve.get("configurations", []))
    if not eco_info:
        # CPE 没匹配到，用描述关键词兜底
        eco_info = guess_ecosystem_from_desc(desc)
    if not eco_info:
        return None  # 不相关

    published = cve.get("published", "")

    return {
        "cve_id": cve_id,
        "description": desc,
        "severity": severity,
        "cvss_score": cvss_score,
        "cwes": cwes,
        "ecosystem": eco_info["ecosystem"],
        "product": eco_info["product"],
        "vendor": eco_info["vendor"],
        "version_start": eco_info["version_start"],
        "version_end": eco_info["version_end"],
        "published": published,
    }


def guess_ecosystem_from_desc(desc: str) -> dict | None:
    """
    从描述关键词推测生态系统（CPE 匹配不到时的备选方案）。
    
    返回格式同 extract_ecosystem，匹配不到返回 None。
    """
    desc_lower = desc.lower()
    
    # PHP 特征关键词
    php_keywords = [
        r'\bphp\b', r'wordpress', r'drupal', r'laravel', r'symfony',
        r'composer', r'packagist', r'\$_(GET|POST|REQUEST|SERVER|COOKIE)',
        r'\.php\b', r'mysql_query', r'mysqli_', r'preg_replace.*\/e',
        r'unserialize\s*\(', r'<?php', r'php://', r'require_once',
    ]
    for kw in php_keywords:
        if re.search(kw, desc_lower):
            return {"ecosystem": "PHP", "product": "unknown",
                    "vendor": "", "version_start": "", "version_end": ""}
    
    # Python 特征关键词
    py_keywords = [
        r'\bpython\b', r'django\b', r'flask\b', r'fastapi\b',
        r'pypi\b', r'pip\s', r'\bpyyaml\b', r'jinja2?\b',
        r'werkzeug\b', r'gunicorn\b', r'sqlalchemy\b',
        r'celery\b', r'\.py\b', r'import\s+\w+', r'pickle\.',
        r'def\s+\w+\s*\(', r'class\s+\w+\s*[:(]',
    ]
    for kw in py_keywords:
        if re.search(kw, desc_lower):
            return {"ecosystem": "Python", "product": "unknown",
                    "vendor": "", "version_start": "", "version_end": ""}
    
    return None


def extract_ecosystem(configs: list[dict]) -> dict | None:
    """从 CPE 配置提取生态系统信息"""
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if not criteria:
                    continue
                try:
                    parts = criteria.split(":")
                    if len(parts) < 5 or parts[1] != "2.3":
                        continue
                    part = parts[2]
                    vendor = parts[3] if len(parts) > 3 else ""
                    product = parts[4] if len(parts) > 4 else ""
                except (IndexError, ValueError):
                    continue

                if part != "a":  # 非应用层，只收 linux kernel
                    if product in ("linux_kernel", "linux", "kernel"):
                        return {
                            "ecosystem": "C", "product": product,
                            "vendor": vendor,
                            "version_start": match.get("versionStartIncluding", ""),
                            "version_end": match.get("versionEndExcluding", ""),
                        }
                    continue

                p = product.lower().replace("_", "-")
                if p in PHP_PRODUCTS:
                    return {
                        "ecosystem": "PHP", "product": product,
                        "vendor": vendor,
                        "version_start": match.get("versionStartIncluding", ""),
                        "version_end": match.get("versionEndExcluding", ""),
                    }
                if p in PYTHON_PRODUCTS:
                    return {
                        "ecosystem": "Python", "product": product,
                        "vendor": vendor,
                        "version_start": match.get("versionStartIncluding", ""),
                        "version_end": match.get("versionEndExcluding", ""),
                    }
                if p in C_CPP_PRODUCTS:
                    return {
                        "ecosystem": "C", "product": product,
                        "vendor": vendor,
                        "version_start": match.get("versionStartIncluding", ""),
                        "version_end": match.get("versionEndExcluding", ""),
                    }
    return None


def classify(cve: dict) -> str:
    """判断 CVE 类别"""
    for cwe in cve.get("cwes", []):
        cat = CWE_TO_CAT.get(cwe)
        if cat:
            return cat

    desc = cve["description"].lower()
    keywords = [
        (["sql injection", "sql注入"], "sql_injection"),
        (["command injection", "code execution", "rce", "remote code",
          "os command", "arbitrary code", "命令注入", "代码执行"], "command_execution"),
        (["ssrf", "server-side request forgery"], "ssrf"),
        (["path traversal", "directory traversal", "../", "路径穿越"], "path_traversal"),
        (["xss", "cross-site script"], "xss"),
        (["file upload", "unrestricted upload"], "file_upload"),
        (["deserialization", "unserialize", "pickle", "object injection"], "deserialization"),
        (["buffer overflow", "stack overflow", "缓冲区溢"], "command_execution"),
        (["format string"], "command_execution"),
        (["information disclosure", "信息泄露", "info leak"], "arbitrary_file_read"),
        (["authentication bypass", "auth bypass", "身份验证绕过"], "auth_bypass"),
        (["privilege escalation", "权限提升"], "auth_bypass"),
    ]
    for kws, cat in keywords:
        if any(kw in desc for kw in kws):
            return cat
    return "command_execution"


def extract_pattern(desc: str) -> str:
    """从描述中提取可能的检测正则"""
    if not desc:
        return ""

    # 关键词匹配
    patterns = [
        (r"(?i)sql\s*injection", r"(?:mysql_query|mysqli_query|->query|->exec|PDO::query)\s*\("),
        (r"(?i)command\s*injection|shell\s*injection|os\s*command",
         r"(?:system|exec|shell_exec|passthru|proc_open|popen)\s*\("),
        (r"(?i)eval\s*injection|code\s*execution", r"eval\s*\(.*\$"),
        (r"(?i)path\s*traversal|directory\s*traversal", r"(?:fopen|file_get_contents|include|require)_once\?.*\.\."),
        (r"(?i)cross-site|xss", r"(?:echo|print)\s*\$_(?:GET|POST|REQUEST)"),
        (r"(?i)deserialization", r"(?:unserialize|__destruct|__wakeup)\s*\("),
        (r"(?i)ssrf", r"(?:curl_exec|file_get_contents|fopen)\s*\(.*https?://"),
        (r"(?i)buffer\s*overflow|stack\s*buffer", r"(?:strcpy|sprintf|gets|memcpy)\s*\("),
        (r"(?i)format\s*string", r"(?:printf|fprintf|sprintf)\s*\(\s*\w+\s*[,\)]"),
        (r"(?i)pickle|yaml\.load", r"(?:pickle\.(?:loads?|Unpickler)|yaml\.load)\s*\("),
        (r"(?i)file\s*upload", r"move_uploaded_file\s*\("),
    ]
    for regex, pat in patterns:
        if re.search(regex, desc):
            return pat

    # 提取函数名
    funcs = re.findall(
        r'(?:function|method|via|using|through)\s+[`"\']?(\w+)[`"\']?\s*\(', desc.lower()
    )
    for f in funcs:
        if f not in ("run", "do", "get", "set", "make", "create", "use", "new"):
            return rf"\b{re.escape(f)}\s*\("

    return ""


def cve_to_php_rule(cve: dict) -> str:
    """将 CVE 转为 _rule() Python 代码块"""
    rule_id = f"CVE_{cve['cve_id'].replace('-', '_')}"
    desc_short = cve["description"][:80].replace("\\", "\\\\").replace('"', "'").replace("\n", " ").replace("\r", "")
    desc = cve["description"][:300].replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "")
    cat = classify(cve)
    sev = cve["severity"]
    cwe_str = ", ".join(cve.get("cwes", [])[:2])
    score = cve["cvss_score"]
    pattern = extract_pattern(cve["description"])
    product = cve.get("product", "")

    lines = []
    lines.append(f"_rule(")
    lines.append(f'    rule_id="{rule_id}",')
    lines.append(f'    name="[{cve["cve_id"]}] {desc_short}",')
    lines.append(f"    category={CAT_TO_ENUM.get(cat, 'RuleCategory.COMMAND_EXECUTION')},")
    lines.append(f"    default_severity={SEV_ENUM.get(sev, 'RuleSeverity.HIGH')},")

    ver_start = cve.get("version_start", "")
    ver_end = cve.get("version_end", "")
    if ver_start:
        lines.append(f'    min_version="{ver_start}",')
    if ver_end:
        lines.append(f'    max_version="{ver_end}",')

    desc_text = (
        f'    description=(\n'
        f'        "{desc}"\n'
    )
    if cwe_str:
        desc_text += f'        f" [{cwe_str}]"\n'
    desc_text += (
        f'        f" [{product}] CVSS={score:.1f} @NVD"\n'
        f'    ),'
    )
    lines.append(desc_text)

    if pattern:
        lines.append(f'    pattern=r"{pattern}",')
    lines.append(f"    confidence=0.7,")
    lines.append(f")")
    lines.append("")  # 空行隔开

    return "\n".join(lines)


def cve_to_py_rule(cve: dict) -> str:
    """将 CVE 转为 _pyrule() Python 代码块"""
    rule_id = f"PY_CVE_{cve['cve_id'].replace('-', '_')}"
    desc_short = cve["description"][:80].replace("\\", "\\\\").replace('"', "'").replace("\n", " ").replace("\r", "")
    desc = cve["description"][:300].replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "")
    cat = classify(cve)
    sev = cve["severity"]
    cwe_str = ", ".join(cve.get("cwes", [])[:2])
    score = cve["cvss_score"]
    pattern = extract_pattern(cve["description"])
    product = cve.get("product", "")

    lines = []
    lines.append(f"_pyrule(")
    lines.append(f'    rule_id="{rule_id}",')
    lines.append(f'    name="[{cve["cve_id"]}] {desc_short}",')
    lines.append(f"    category={CAT_TO_ENUM.get(cat, 'RuleCategory.COMMAND_EXECUTION')},")
    lines.append(f"    default_severity={SEV_ENUM.get(sev, 'RuleSeverity.HIGH')},")
    lines.append(
        f'    description=(\n'
        f'        "{desc}"\n'
        f'        f" [{cwe_str}]" if "{cwe_str}" else ""\n'
        f'        f" [{product}] CVSS={score:.1f} @NVD"\n'
        f'    ),'
    )
    if pattern:
        lines.append(f'    pattern=r"{pattern}",')
    lines.append(f"    confidence=0.7,")
    lines.append(f")")
    lines.append("")
    return "\n".join(lines)


def cve_to_cpp_rule(cve: dict) -> str:
    """将 CVE 转为 _cpprule() Python 代码块"""
    rule_id = f"C_CVE_{cve['cve_id'].replace('-', '_')}"
    desc_short = cve["description"][:80].replace("\\", "\\\\").replace('"', "'").replace("\n", " ").replace("\r", "")
    desc = cve["description"][:300].replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "")
    cat = classify(cve)
    sev = cve["severity"]
    cwe_str = ", ".join(cve.get("cwes", [])[:2])
    score = cve["cvss_score"]
    pattern = extract_pattern(cve["description"])
    product = cve.get("product", "")

    lines = []
    lines.append(f"_cpprule(")
    lines.append(f'    rule_id="{rule_id}",')
    lines.append(f'    name="[{cve["cve_id"]}] {desc_short}",')
    lines.append(f"    category={CAT_TO_ENUM.get(cat, 'RuleCategory.COMMAND_EXECUTION')},")
    lines.append(f"    default_severity={SEV_ENUM.get(sev, 'RuleSeverity.HIGH')},")
    lines.append(
        f'    description=(\n'
        f'        "{desc}"\n'
        f'        f" [{cwe_str}]" if "{cwe_str}" else ""\n'
        f'        f" [{product}] CVSS={score:.1f} @NVD"\n'
        f'    ),'
    )
    if pattern:
        lines.append(f'    pattern=r"{pattern}",')
    lines.append(f"    confidence=0.7,")
    lines.append(f")")
    lines.append("")
    return "\n".join(lines)


def insert_into_file(content: str, marker: str, new_code: str,
                     before: bool = True) -> str:
    """在 content 中 marker 之前（或之后）插入 new_code"""
    idx = content.find(marker)
    if idx == -1:
        print(f"  ⚠ 找不到插入标记，跳过")
        return content

    if before:
        return content[:idx] + new_code + "\n" + content[idx:]
    else:
        end = idx + len(marker)
        return content[:end] + "\n" + new_code + content[end:]


def update_rule_engine(php_rules: list[str], py_rules: list[str],
                       c_rules: list[str], dry_run: bool = False) -> dict:
    """更新 rule_engine.py，返回统计"""
    content = RULE_ENGINE_PATH.read_text(encoding="utf-8")

    # 检查是否有旧 CVE 规则（用 hash 标记清理）
    cve_re = re.compile(
        r'\n\n# ====+\n# CVE 自动生成规则.*?(?=\n\n# ====+\n# (?:规则引擎|Python 版本|C/C\+\+ 标准|PHP 版本)|$)',
        re.DOTALL,
    )
    cleaned = cve_re.sub("", content)

    stats = {"php": {"added": len(php_rules), "skipped": 0},
             "python": {"added": len(py_rules), "skipped": 0},
             "c": {"added": len(c_rules), "skipped": 0}}

    date_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC+8")

    # ---- PHP 规则：插入在 RuleEngine class 之前 ----
    if php_rules:
        header = (
            f"\n\n# {'=' * 48}\n"
            f"# CVE 自动生成规则 (PHP) — {date_str}\n"
            f"# 由 update_cve_rules.py 生成，下次运行会覆盖\n"
            f"# {'=' * 48}\n"
        )
        code = header + "\n".join(php_rules)
        cleaned = insert_into_file(cleaned, MARKER_PHP, code, before=True)

    # ---- Python 规则：插入在 PythonRuleEngine class 之前 ----
    if py_rules:
        header = (
            f"\n\n# {'=' * 48}\n"
            f"# CVE 自动生成规则 (Python) — {date_str}\n"
            f"# 由 update_cve_rules.py 生成，下次运行会覆盖\n"
            f"# {'=' * 48}\n"
        )
        code = header + "\n".join(py_rules)
        cleaned = insert_into_file(cleaned, MARKER_PY, code, before=True)

    # ---- C/C++ 规则：插入在 CppRuleEngine class 之前 ----
    if c_rules:
        header = (
            f"\n\n# {'=' * 48}\n"
            f"# CVE 自动生成规则 (C/C++) — {date_str}\n"
            f"# 由 update_cve_rules.py 生成，下次运行会覆盖\n"
            f"# {'=' * 48}\n"
        )
        code = header + "\n".join(c_rules)
        cleaned = insert_into_file(cleaned, MARKER_CPP, code, before=True)

    if not dry_run:
        RULE_ENGINE_PATH.write_text(cleaned, encoding="utf-8")

    return stats


# =========================================================================
# 主入口
# =========================================================================

def main():
    global DRY_RUN

    args = sys.argv[1:]
    days = 30
    dry = "--dry-run" in args

    for i, a in enumerate(args):
        if a == "--days" and i + 1 < len(args):
            days = int(args[i + 1])

    DRY_RUN = dry
    mode = "DRY-RUN（预览，不写入）" if dry else "写入"

    print("=" * 60)
    print(f" CVE 规则更新脚本 ({mode})")
    print("=" * 60)
    print(f"  数据源: NVD API v2")
    print(f"  日期范围: 最近 {days} 天")
    api_key = get_api_key()
    if api_key:
        print(f"  API Key: {'*' * (len(api_key) - 4)}{api_key[-4:]}")
    else:
        print(f"  API Key: 未设置（速率限制 5 req/30s）")
    print(f"  目标文件: {RULE_ENGINE_PATH}")
    print()

    # 1. 拉取
    print("[1/3] 拉取 CVE 数据...")
    cves = fetch_cves(days)
    print(f"  获取 {len(cves)} 条相关 CVE\n")

    if not cves:
        print("  没有找到相关 CVE")
        return

    # 2. 分类生成
    print("[2/3] 生成规则代码...")
    php_rules = []  # list of code strings
    py_rules = []
    c_rules = []
    counts = {"PHP": 0, "Python": 0, "C": 0}

    for cve in cves:
        eco = cve["ecosystem"]
        try:
            if eco == "PHP":
                code = cve_to_php_rule(cve)
                php_rules.append(code)
            elif eco == "Python":
                code = cve_to_py_rule(cve)
                py_rules.append(code)
            elif eco == "C":
                code = cve_to_cpp_rule(cve)
                c_rules.append(code)
            counts[eco] += 1
        except Exception as e:
            print(f"  ⚠ 生成规则失败 [{cve['cve_id']}]: {e}")

    print(f"  PHP:    {counts['PHP']} 条规则")
    print(f"  Python: {counts['Python']} 条规则")
    print(f"  C/C++:  {counts['C']} 条规则")
    print()

    # 打印几条示例
    for eco, rules in [("PHP", php_rules), ("Python", py_rules), ("C/C++", c_rules)]:
        if rules:
            example = rules[0][:200]
            print(f"  [{eco}] 示例:\n{example}...\n")

    # 3. 写入
    print("[3/3] 写入 rule_engine.py...")
    stats = update_rule_engine(php_rules, py_rules, c_rules, dry_run=dry)

    total = sum(s["added"] for s in stats.values())
    if dry:
        print(f"  [DRY-RUN] 将写入 {total} 条规则（未实际修改）")
    else:
        print(f"  [OK] 已写入 {total} 条规则")
    print(f"  PHP:    {stats['php']['added']}")
    print(f"  Python: {stats['python']['added']}")
    print(f"  C/C++:  {stats['c']['added']}")
    print()
    print("完成。下次运行此脚本时会自动覆盖旧的 CVE 规则。")


if __name__ == "__main__":
    main()
