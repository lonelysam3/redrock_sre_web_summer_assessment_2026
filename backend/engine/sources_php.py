"""
PHP Source 点定义（用户输入入口）
===============================
定义 PHP 中所有可能的用户/外部输入入口。

PHP 的输入入口非常丰富：
  - 超全局变量：$_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, $_FILES
  - 输入流：php://input, file_get_contents('php://input')
  - HTTP 头：$_SERVER['HTTP_*'], getallheaders()
  - Cookie/Session：$_COOKIE, $_SESSION（session 可能被操控）
  - 文件上传：$_FILES, move_uploaded_file()
  - 命令行：$argv, $argc, getenv()
  - 数据库读取（二次注入源）
"""
from dataclasses import dataclass, field


@dataclass
class PHPSource:
    """
    PHP Source 点数据类
    ==================
    描述一个 PHP 中的外部输入入口。
    """
    source_name: str        # 标识名（如 "$_GET", "php://input"）
    description: str        # 中文描述
    # 污染模式:
    #   "value"      = 整个变量的值被污染（如 $_GET['name']）
    #   "array_item" = 数组的任意元素被污染
    #   "key"        = 数组键名也可能被污染（少用）
    taint_mode: str = "value"


# ---- PHP Source 点全集 ----
PHP_SOURCES: list[PHPSource] = [
    # ============ HTTP GET 参数 ============
    PHPSource("$_GET", "$_GET 超全局变量 — URL 查询参数",
              taint_mode="array_item"),
    PHPSource("$_REQUEST", "$_REQUEST 超全局变量 — 合并 GET/POST/COOKIE",
              taint_mode="array_item"),

    # ============ HTTP POST 参数 ============
    PHPSource("$_POST", "$_POST 超全局变量 — POST 表单数据",
              taint_mode="array_item"),

    # ============ HTTP 头信息 ============
    PHPSource("$_SERVER", "$_SERVER 超全局变量 — 服务器和执行环境信息",
              taint_mode="array_item"),
    PHPSource("getallheaders()", "getallheaders() — 获取所有 HTTP 请求头",
              taint_mode="value"),
    PHPSource("apache_request_headers()", "apache_request_headers() — Apache 方式获取请求头",
              taint_mode="value"),

    # ============ Cookie ============
    PHPSource("$_COOKIE", "$_COOKIE 超全局变量 — Cookie 值",
              taint_mode="array_item"),

    # ============ 文件上传 ============
    PHPSource("$_FILES", "$_FILES 超全局变量 — 上传文件信息（文件名可被操控）",
              taint_mode="array_item"),

    # ============ 原始输入流 ============
    PHPSource("php://input", "php://input 流 — HTTP 原始请求体",
              taint_mode="value"),
    PHPSource("file_get_contents('php://input')", "读取 HTTP 原始请求体",
              taint_mode="value"),
    PHPSource("$HTTP_RAW_POST_DATA", "$HTTP_RAW_POST_DATA — 原始 POST 数据（已废弃但仍存在）",
              taint_mode="value"),

    # ============ 环境变量 / 命令行 ============
    PHPSource("$_ENV", "$_ENV 超全局变量 — 环境变量",
              taint_mode="array_item"),
    PHPSource("getenv()", "getenv() — 获取环境变量",
              taint_mode="value"),
    PHPSource("$argv", "$argv — 命令行参数数组",
              taint_mode="array_item"),
    PHPSource("$argc", "$argc — 命令行参数数量（一般不是攻击面）",
              taint_mode="value"),

    # ============ Session ============
    PHPSource("$_SESSION", "$_SESSION 超全局变量 — Session 数据（可能被会话固定攻击操控）",
              taint_mode="array_item"),

    # ============ 文件读取 ============
    PHPSource("file_get_contents()", "file_get_contents() — 文件内容读取",
              taint_mode="value"),
    PHPSource("fread()", "fread() — 文件读取",
              taint_mode="value"),
    PHPSource("fgets()", "fgets() — 逐行读取文件",
              taint_mode="value"),
    PHPSource("file()", "file() — 将文件读入数组",
              taint_mode="value"),
    PHPSource("readfile()", "readfile() — 读取文件并输出",
              taint_mode="value"),

    # ============ 数据库读取（二次注入源） ============
    PHPSource("mysqli_fetch_assoc()", "mysqli_fetch_assoc() — 数据库读取（可能成为二次注入源）",
              taint_mode="value"),
    PHPSource("mysqli_fetch_array()", "mysqli_fetch_array() — 数据库读取",
              taint_mode="value"),
    PHPSource("PDO::fetch()", "PDO::fetch() — 数据库读取",
              taint_mode="value"),
]
