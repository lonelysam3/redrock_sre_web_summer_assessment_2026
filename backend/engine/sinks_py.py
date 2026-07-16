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
]
