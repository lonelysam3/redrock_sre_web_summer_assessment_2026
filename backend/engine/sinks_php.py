"""
PHP Sink 点定义（危险函数调用）
=============================
定义 PHP 中所有可能的危险函数调用。

PHP 的 Web 特性使其攻击面特别广：
  1. SQL_INJECTION:      字符串拼接 SQL、未使用 prepared statement
  2. COMMAND_EXECUTION:   shell_exec, system, passthru, exec, popen, proc_open
  3. SSRF:                file_get_contents($url), curl_exec
  4. PATH_TRAVERSAL:      include, require, fopen($user_path)
  5. ARBITRARY_FILE_READ: file_get_contents, readfile, fread
  6. XSS:                 echo/print 直接输出未转义的用户输入
  7. FILE_UPLOAD:         move_uploaded_file, copy($tmp, $user_dest)
  8. DESERIALIZATION:     unserialize, __wakeup, __destruct 魔术方法链
"""
from dataclasses import dataclass, field
from enum import Enum


class VulnType(Enum):
    """
    漏洞类型枚举（扩展版，新增 PHP 特有类型）
    =======================================
    """
    SQL_INJECTION = "sql_injection"                # SQL 注入
    COMMAND_EXECUTION = "command_execution"         # 命令执行/代码注入
    SSRF = "ssrf"                                  # 服务端请求伪造
    PATH_TRAVERSAL = "path_traversal"              # 路径穿越
    ARBITRARY_FILE_READ = "arbitrary_file_read"    # 任意文件读取
    XSS = "xss"                                    # 跨站脚本攻击（PHP 特有高频）
    FILE_UPLOAD = "file_upload"                    # 恶意文件上传（PHP 特有）
    DESERIALIZATION = "deserialization"            # 反序列化漏洞（PHP 特有）


@dataclass
class PHPSink:
    """
    PHP Sink 点数据类
    ================
    描述 PHP 中的一个危险函数。
    """
    func_name: str                          # PHP 函数名
    vuln_type: str                          # 漏洞类型（VulnType 值）  
    description: str                        # 中文描述
    dangerous_param_index: int | None = 0   # 危险参数索引（0=第一个参数）


# ---- PHP Sink 点全集 ----
PHP_SINKS: list[PHPSink] = [
    # ============ SQL 注入 ============
    PHPSink("mysqli_query", VulnType.SQL_INJECTION.value,
            "mysqli_query() — 执行 SQL 查询", 1),
    PHPSink("mysqli_real_query", VulnType.SQL_INJECTION.value,
            "mysqli_real_query() — 执行 SQL 查询", 1),
    PHPSink("mysql_query", VulnType.SQL_INJECTION.value,
            "mysql_query() — 旧式 MySQL 查询（已废弃但广泛遗留）", 0),
    PHPSink("mysqli_prepare", VulnType.SQL_INJECTION.value,
            "mysqli_prepare() — 参数化查询（传入不安全 SQL 时仍危险）", 1),
    PHPSink("pg_query", VulnType.SQL_INJECTION.value,
            "pg_query() — PostgreSQL 查询", 0),
    PHPSink("sqlite_query", VulnType.SQL_INJECTION.value,
            "sqlite_query() — SQLite 查询", 0),
    PHPSink("PDO::query", VulnType.SQL_INJECTION.value,
            "PDO::query() — 执行 SQL（应使用 PDO::prepare）", 0),
    PHPSink("PDO::exec", VulnType.SQL_INJECTION.value,
            "PDO::exec() — 执行 SQL 语句", 0),
    PHPSink("odbc_exec", VulnType.SQL_INJECTION.value,
            "odbc_exec() — ODBC 查询", 0),

    # ============ 命令执行 / 代码注入 ============
    PHPSink("system", VulnType.COMMAND_EXECUTION.value,
            "system() — 执行外部程序并显示输出", 0),
    PHPSink("exec", VulnType.COMMAND_EXECUTION.value,
            "exec() — 执行外部程序", 0),
    PHPSink("shell_exec", VulnType.COMMAND_EXECUTION.value,
            "shell_exec() — 通过 shell 执行命令（反引号等价）", 0),
    PHPSink("passthru", VulnType.COMMAND_EXECUTION.value,
            "passthru() — 执行外部程序并直接输出", 0),
    PHPSink("popen", VulnType.COMMAND_EXECUTION.value,
            "popen() — 打开进程文件指针", 0),
    PHPSink("proc_open", VulnType.COMMAND_EXECUTION.value,
            "proc_open() — 执行命令并打开文件指针用于 I/O", 0),
    PHPSink("pcntl_exec", VulnType.COMMAND_EXECUTION.value,
            "pcntl_exec() — 在当前进程空间执行程序", 0),
    PHPSink("eval", VulnType.COMMAND_EXECUTION.value,
            "eval() — 执行 PHP 代码字符串", 0),
    PHPSink("assert", VulnType.COMMAND_EXECUTION.value,
            "assert() — 断言（可执行代码）", 0),
    PHPSink("create_function", VulnType.COMMAND_EXECUTION.value,
            "create_function() — 动态创建函数（内部用 eval）", 0),
    PHPSink("preg_replace", VulnType.COMMAND_EXECUTION.value,
            "preg_replace() — 使用 /e 修饰符可执行代码（PHP < 5.5）", 0),
    PHPSink("call_user_func", VulnType.COMMAND_EXECUTION.value,
            "call_user_func() — 动态函数调用", 0),

    # ============ SSRF 服务端请求伪造 ============
    PHPSink("file_get_contents", VulnType.SSRF.value,
            "file_get_contents() — 可读取远程 URL（SSRF 高危）", 0),
    PHPSink("curl_exec", VulnType.SSRF.value,
            "curl_exec() — cURL 执行请求", 0),
    PHPSink("curl_multi_exec", VulnType.SSRF.value,
            "curl_multi_exec() — cURL 并发执行", 0),
    PHPSink("fopen", VulnType.SSRF.value,
            "fopen() — 可打开远程 URL", 0),
    PHPSink("readfile", VulnType.SSRF.value,
            "readfile() — 读取文件并输出（支持远程）", 0),
    PHPSink("fsockopen", VulnType.SSRF.value,
            "fsockopen() — 打开 socket 连接", 0),
    PHPSink("stream_socket_client", VulnType.SSRF.value,
            "stream_socket_client() — 创建 socket 客户端", 0),

    # ============ 路径穿越 / 文件包含 ============
    PHPSink("include", VulnType.PATH_TRAVERSAL.value,
            "include() — 文件包含（可被 LFI 利用）", 0),
    PHPSink("require", VulnType.PATH_TRAVERSAL.value,
            "require() — 文件包含（致命错误版本）", 0),
    PHPSink("include_once", VulnType.PATH_TRAVERSAL.value,
            "include_once() — 文件包含（单次）", 0),
    PHPSink("require_once", VulnType.PATH_TRAVERSAL.value,
            "require_once() — 文件包含（单次，致命）", 0),
    PHPSink("file_get_contents", VulnType.PATH_TRAVERSAL.value,
            "file_get_contents() — 路径穿越可读取任意文件", 0),
    PHPSink("file_put_contents", VulnType.PATH_TRAVERSAL.value,
            "file_put_contents() — 写入任意文件", 0),
    PHPSink("unlink", VulnType.PATH_TRAVERSAL.value,
            "unlink() — 删除文件", 0),
    PHPSink("copy", VulnType.PATH_TRAVERSAL.value,
            "copy() — 复制文件", 0),
    PHPSink("rename", VulnType.PATH_TRAVERSAL.value,
            "rename() — 重命名/移动文件", 0),
    PHPSink("mkdir", VulnType.PATH_TRAVERSAL.value,
            "mkdir() — 创建目录", 0),
    PHPSink("rmdir", VulnType.PATH_TRAVERSAL.value,
            "rmdir() — 删除目录", 0),
    PHPSink("chdir", VulnType.PATH_TRAVERSAL.value,
            "chdir() — 改变目录", 0),
    PHPSink("chmod", VulnType.PATH_TRAVERSAL.value,
            "chmod() — 修改文件权限", 0),
    PHPSink("chown", VulnType.PATH_TRAVERSAL.value,
            "chown() — 修改文件所有者", 0),
    PHPSink("glob", VulnType.PATH_TRAVERSAL.value,
            "glob() — 模式匹配文件路径", 0),
    PHPSink("scandir", VulnType.PATH_TRAVERSAL.value,
            "scandir() — 列出目录内容", 0),

    # ============ 任意文件读取 ============
    PHPSink("fread", VulnType.ARBITRARY_FILE_READ.value,
            "fread() — 读取已打开文件", 0),
    PHPSink("fgets", VulnType.ARBITRARY_FILE_READ.value,
            "fgets() — 读取一行", 0),
    PHPSink("fgetcsv", VulnType.ARBITRARY_FILE_READ.value,
            "fgetcsv() — 读取 CSV 行", 0),

    # ============ XSS 跨站脚本攻击 ============
    PHPSink("echo", VulnType.XSS.value,
            "echo — 直接输出（可能存在 XSS）", 0),
    PHPSink("print", VulnType.XSS.value,
            "print — 直接输出", 0),
    PHPSink("printf", VulnType.XSS.value,
            "printf() — 格式化输出", 0),
    PHPSink("die", VulnType.XSS.value,
            "die() / exit() — 输出消息并终止", 0),

    # ============ 反序列化 ============
    PHPSink("unserialize", VulnType.DESERIALIZATION.value,
            "unserialize() — PHP 对象反序列化（可触发 POP 链）", 0),

    # ============ 文件上传 ============
    PHPSink("move_uploaded_file", VulnType.FILE_UPLOAD.value,
            "move_uploaded_file() — 移动上传文件（目的路径可控时危险）", 1),
]
