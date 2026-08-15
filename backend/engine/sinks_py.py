"""
Python Sink 点定义（危险函数调用）
==============================
定义 Python 中所有可能的危险函数调用（数据出口/漏洞触发点）。

Sink 点类型（对应 VulnType 枚举）：
  1. SQL_INJECTION:      SQL 注入    — 用户输入拼入 SQL 语句
  2. COMMAND_EXECUTION:  命令执行    — 用户输入传给系统命令
  3. SSRF:               服务端请求伪造 — 用户控制 URL 发起的网络请求
  4. PATH_TRAVERSAL:     路径穿越    — （Python 中与任意文件读取合并）
  5. ARBITRARY_FILE_READ: 任意文件读取 — 用户控制文件路径

格式说明：
  - module:    模块全限定名
  - func:      函数名
  - vuln_type: 漏洞类型（VulnType 枚举）
  - description: 中文描述
  - dangerous_param_index: 危险参数索引（None = 所有参数）
"""
from dataclasses import dataclass, field
from enum import Enum


class VulnType(Enum):
    """
    漏洞类型枚举
    ===========
    每种类型对应一条标准的漏洞分类，也用作数据库 vuln_type 字段的值。
    """
    SQL_INJECTION = "sql_injection"              # SQL 注入
    COMMAND_EXECUTION = "command_execution"       # 命令执行/代码注入
    SSRF = "ssrf"                                # 服务端请求伪造
    PATH_TRAVERSAL = "path_traversal"            # 路径穿越
    ARBITRARY_FILE_READ = "arbitrary_file_read"  # 任意文件读取
    INSCURE_DESERIALIZATION = "insecure_deserialization"  # 不安全反序列化
    CODE_INJECTION = "code_injection"            # 代码注入（eval/exec/compile）
    OPEN_REDIRECT = "open_redirect"              # 开放重定向
    XXE = "xxe"                                  # XML 外部实体注入
    XSS = "xss"                                  # 反射型 XSS
    SSTI = "ssti"                                # 服务端模板注入
    HARDCODED_CREDENTIALS = "hardcoded_credentials"  # 硬编码凭据
    DEBUG_MODE = "debug_mode"                    # 调试模式开启


# 漏洞类型 → CWE 映射（供结果输出使用；RealVuln 等外部基准依赖 CWE 编号）
CWE_BY_TYPE: dict[str, str] = {
    "sql_injection": "CWE-89",
    "command_execution": "CWE-78",
    "code_injection": "CWE-94",
    "ssrf": "CWE-918",
    "path_traversal": "CWE-22",
    "arbitrary_file_read": "CWE-22",
    "insecure_deserialization": "CWE-502",
    "deserialization": "CWE-502",
    "open_redirect": "CWE-601",
    "xxe": "CWE-611",
    "xss": "CWE-79",
    "ssti": "CWE-94",
    "hardcoded_credentials": "CWE-798",
    "debug_mode": "CWE-215",
    "file_upload": "CWE-434",
}


@dataclass
class Sink:
    """
    Sink 点数据类
    ============
    描述一个危险函数调用点。
    """
    module: str                        # 模块全限定名
    func: str                          # 函数名
    vuln_type: VulnType                # 漏洞类型
    description: str                   # 中文描述
    # 危险参数索引：
    #   None = 所有参数都危险
    #   0    = 第 1 个参数危险
    dangerous_param_index: int | None = None


# ---- Python Sink 点全集 ----
PYTHON_SINKS: list[Sink] = [
    # ============ SQL 注入 ============
    Sink("sqlite3.Cursor", "execute", VulnType.SQL_INJECTION, "SQLite 执行",
         dangerous_param_index=0),                                                  # cursor.execute(sql)
    Sink("sqlite3.Cursor", "executemany", VulnType.SQL_INJECTION, "SQLite 批量执行",
         dangerous_param_index=0),
    Sink("sqlite3", "execute", VulnType.SQL_INJECTION, "sqlite3 模块级执行",
         dangerous_param_index=0),
    Sink("pymysql.cursors.Cursor", "execute", VulnType.SQL_INJECTION, "PyMySQL 执行",
         dangerous_param_index=0),
    Sink("MySQLdb.cursors.Cursor", "execute", VulnType.SQL_INJECTION, "MySQLdb 执行",
         dangerous_param_index=0),
    Sink("psycopg2.extensions", "execute", VulnType.SQL_INJECTION, "Psycopg2 执行",
         dangerous_param_index=0),
    Sink("django.db.connection", "execute", VulnType.SQL_INJECTION, "Django 原始 SQL",
         dangerous_param_index=0),
    Sink("records.Database", "query", VulnType.SQL_INJECTION, "Records 查询",
         dangerous_param_index=0),
    Sink("sqlalchemy.engine", "execute", VulnType.SQL_INJECTION, "SQLAlchemy 原始 SQL",
         dangerous_param_index=0),
    # 字符串拼接 + format 也是 SQL 注入的来源（通过污点追踪检测拼接模式）
    Sink("builtins.str", "format", VulnType.SQL_INJECTION, "字符串格式化拼接 SQL"),
    Sink("builtins", "fstring", VulnType.SQL_INJECTION, "f-string 拼接 SQL"),

    # ============ 命令执行 / 代码注入 ============
    Sink("os", "system", VulnType.COMMAND_EXECUTION, "os.system()",
         dangerous_param_index=0),                                                  # os.system(user_input)
    Sink("os", "popen", VulnType.COMMAND_EXECUTION, "os.popen()",
         dangerous_param_index=0),
    Sink("os", "execv", VulnType.COMMAND_EXECUTION, "os.execv()"),
    Sink("os", "execve", VulnType.COMMAND_EXECUTION, "os.execve()"),
    Sink("os", "execl", VulnType.COMMAND_EXECUTION, "os.execl()"),
    Sink("os", "execlp", VulnType.COMMAND_EXECUTION, "os.execlp()"),
    Sink("os", "execvp", VulnType.COMMAND_EXECUTION, "os.execvp()"),
    Sink("os", "spawnl", VulnType.COMMAND_EXECUTION, "os.spawnl()"),
    Sink("os", "spawnlp", VulnType.COMMAND_EXECUTION, "os.spawnlp()"),
    Sink("os", "posix_spawn", VulnType.COMMAND_EXECUTION, "os.posix_spawn()"),
    Sink("pty", "spawn", VulnType.COMMAND_EXECUTION, "pty.spawn()",
         dangerous_param_index=0),
    Sink("subprocess", "call", VulnType.COMMAND_EXECUTION, "subprocess.call()"),     # 多个参数都可能危险
    Sink("subprocess", "run", VulnType.COMMAND_EXECUTION, "subprocess.run()"),
    Sink("subprocess", "Popen", VulnType.COMMAND_EXECUTION, "subprocess.Popen()"),
    Sink("subprocess", "check_output", VulnType.COMMAND_EXECUTION, "subprocess.check_output()"),
    Sink("subprocess", "check_call", VulnType.COMMAND_EXECUTION, "subprocess.check_call()"),
    Sink("builtins", "eval", VulnType.COMMAND_EXECUTION, "eval() 代码执行",
         dangerous_param_index=0),                                                  # eval(user_input)
    Sink("builtins", "exec", VulnType.COMMAND_EXECUTION, "exec() 代码执行",
         dangerous_param_index=0),
    Sink("builtins", "compile", VulnType.COMMAND_EXECUTION, "compile() 编译执行"),
    Sink("asyncio", "create_subprocess_shell", VulnType.COMMAND_EXECUTION,
         "asyncio shell 子进程"),

    # ============ SSRF 服务端请求伪造 ============
    Sink("requests", "get", VulnType.SSRF, "requests.get()",                        # requests.get(user_url)
         dangerous_param_index=0),
    Sink("requests", "post", VulnType.SSRF, "requests.post()",
         dangerous_param_index=0),
    Sink("requests", "put", VulnType.SSRF, "requests.put()",
         dangerous_param_index=0),
    Sink("requests", "delete", VulnType.SSRF, "requests.delete()",
         dangerous_param_index=0),
    Sink("requests", "head", VulnType.SSRF, "requests.head()",
         dangerous_param_index=0),
    Sink("requests", "request", VulnType.SSRF, "requests.request()",                 # 通用请求方法
         dangerous_param_index=0),
    Sink("httpx", "get", VulnType.SSRF, "httpx.get()",                              # httpx 库（支持异步）
         dangerous_param_index=0),
    Sink("httpx", "post", VulnType.SSRF, "httpx.post()",
         dangerous_param_index=0),
    Sink("httpx", "request", VulnType.SSRF, "httpx.request()",
         dangerous_param_index=0),
    Sink("urllib.request", "urlopen", VulnType.SSRF, "urllib.urlopen()",             # 标准库 URL 打开
         dangerous_param_index=0),
    Sink("urllib.request", "urlretrieve", VulnType.SSRF, "urllib.urlretrieve()",     # URL 下载到文件
         dangerous_param_index=0),
    Sink("aiohttp", "ClientSession.get", VulnType.SSRF, "aiohttp GET", dangerous_param_index=0),
    Sink("aiohttp", "ClientSession.post", VulnType.SSRF, "aiohttp POST", dangerous_param_index=0),

    # ============ 数据库游标/连接对象（经 local_types 类型传播解析） ============
    # conn = sqlite3.connect() / pymysql.connect() ... → "db.Connection"
    # cur = conn.cursor() → "db.Cursor"
    # cur.execute(tainted_sql) → 命中下方 sink
    Sink("db.Cursor", "execute", VulnType.SQL_INJECTION, "数据库游标执行",
         dangerous_param_index=0),
    Sink("db.Cursor", "executemany", VulnType.SQL_INJECTION, "数据库游标批量执行",
         dangerous_param_index=0),
    Sink("db.Cursor", "executescript", VulnType.SQL_INJECTION, "数据库游标脚本执行",
         dangerous_param_index=0),
    Sink("db.Connection", "execute", VulnType.SQL_INJECTION, "数据库连接直接执行",
         dangerous_param_index=0),
    Sink("db.Connection", "executemany", VulnType.SQL_INJECTION, "数据库连接批量执行",
         dangerous_param_index=0),
    Sink("django.db.models.query", "raw", VulnType.SQL_INJECTION, "Django ORM raw()",
         dangerous_param_index=0),

    # ============ 路径穿越 / 任意文件读取 ============
    Sink("builtins", "open", VulnType.PATH_TRAVERSAL, "open() 用户可控路径",
         dangerous_param_index=0),
    Sink("pathlib", "Path", VulnType.PATH_TRAVERSAL, "pathlib.Path() 用户可控路径",
         dangerous_param_index=0),
    Sink("pathlib", "read_text", VulnType.PATH_TRAVERSAL, "Path.read_text()",
         dangerous_param_index=0),
    Sink("flask", "send_file", VulnType.PATH_TRAVERSAL, "Flask send_file()",
         dangerous_param_index=0),
    Sink("flask", "send_from_directory", VulnType.PATH_TRAVERSAL, "Flask send_from_directory()",
         dangerous_param_index=0),
    Sink("fastapi.responses", "FileResponse", VulnType.PATH_TRAVERSAL, "FastAPI FileResponse",
         dangerous_param_index=0),
    Sink("starlette.responses", "FileResponse", VulnType.PATH_TRAVERSAL, "Starlette FileResponse",
         dangerous_param_index=0),
    Sink("aiohttp.web", "FileResponse", VulnType.PATH_TRAVERSAL, "aiohttp FileResponse",
         dangerous_param_index=0),

    # ============ 不安全反序列化 ============
    Sink("pickle", "loads", VulnType.INSCURE_DESERIALIZATION, "pickle.loads()",
         dangerous_param_index=0),
    Sink("pickle", "load", VulnType.INSCURE_DESERIALIZATION, "pickle.load()",
         dangerous_param_index=0),
    Sink("yaml", "load", VulnType.INSCURE_DESERIALIZATION, "yaml.load() 无 SafeLoader",
         dangerous_param_index=0),
    Sink("yaml", "unsafe_load", VulnType.INSCURE_DESERIALIZATION, "yaml.unsafe_load()",
         dangerous_param_index=0),
    Sink("marshal", "loads", VulnType.INSCURE_DESERIALIZATION, "marshal.loads()",
         dangerous_param_index=0),

    # ============ XXE ============
    Sink("lxml.etree", "parse", VulnType.XXE, "lxml.etree.parse()",
         dangerous_param_index=0),
    Sink("xmltodict", "parse", VulnType.XXE, "xmltodict.parse()",
         dangerous_param_index=0),
    Sink("lxml.etree", "fromstring", VulnType.XXE, "lxml.etree.fromstring()",
         dangerous_param_index=0),
    Sink("xml.etree.ElementTree", "parse", VulnType.XXE, "ElementTree.parse()",
         dangerous_param_index=0),
    Sink("xml.etree.ElementTree", "fromstring", VulnType.XXE, "ElementTree.fromstring()",
         dangerous_param_index=0),
    Sink("xml.dom.minidom", "parse", VulnType.XXE, "minidom.parse()",
         dangerous_param_index=0),
    Sink("xml.dom.minidom", "parseString", VulnType.XXE, "minidom.parseString()",
         dangerous_param_index=0),

    # ============ 开放重定向 ============
    Sink("flask", "redirect", VulnType.OPEN_REDIRECT, "Flask redirect()",
         dangerous_param_index=0),
    Sink("django.http", "HttpResponseRedirect", VulnType.OPEN_REDIRECT, "Django HttpResponseRedirect",
         dangerous_param_index=0),
    Sink("django.http", "HttpResponsePermanentRedirect", VulnType.OPEN_REDIRECT, "Django HttpResponsePermanentRedirect",
         dangerous_param_index=0),
    Sink("fastapi.responses", "RedirectResponse", VulnType.OPEN_REDIRECT, "FastAPI RedirectResponse",
         dangerous_param_index=0),
    Sink("starlette.responses", "RedirectResponse", VulnType.OPEN_REDIRECT, "Starlette RedirectResponse",
         dangerous_param_index=0),

    # ============ SSTI / XSS ============
    Sink("flask", "render_template_string", VulnType.SSTI, "Flask render_template_string()",
         dangerous_param_index=0),
    Sink("jinja2", "Template", VulnType.SSTI, "jinja2.Template() 用户可控模板",
         dangerous_param_index=0),
    Sink("jinja2.Environment", "from_string", VulnType.SSTI, "Jinja2 from_string()",
         dangerous_param_index=0),
    Sink("markupsafe", "Markup", VulnType.XSS, "Markup() 绕过转义",
         dangerous_param_index=0),
    Sink("flask", "Response", VulnType.XSS, "Flask Response 直接输出",
         dangerous_param_index=0),
    Sink("django.http", "HttpResponse", VulnType.XSS, "Django HttpResponse 直接输出",
         dangerous_param_index=0),
    Sink("django.http", "JsonResponse", VulnType.XSS, "Django JsonResponse 直接输出",
         dangerous_param_index=0),

    # ============ 文件操作（路径穿越 / 任意文件写） ============
    Sink("os", "rename", VulnType.PATH_TRAVERSAL, "os.rename() 文件移动"),
    Sink("os", "remove", VulnType.PATH_TRAVERSAL, "os.remove() 文件删除",
         dangerous_param_index=0),
    Sink("os", "unlink", VulnType.PATH_TRAVERSAL, "os.unlink() 文件删除",
         dangerous_param_index=0),
    Sink("os", "makedirs", VulnType.PATH_TRAVERSAL, "os.makedirs() 目录创建",
         dangerous_param_index=0),
    Sink("shutil", "move", VulnType.PATH_TRAVERSAL, "shutil.move() 文件移动"),
    Sink("shutil", "copy", VulnType.PATH_TRAVERSAL, "shutil.copy() 文件复制"),
    Sink("shutil", "copyfile", VulnType.PATH_TRAVERSAL, "shutil.copyfile() 文件复制"),
    Sink("shutil", "copytree", VulnType.PATH_TRAVERSAL, "shutil.copytree() 目录复制"),
]
