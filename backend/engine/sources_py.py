"""
Python Source 点定义（用户输入入口）
=================================
定义所有可能的用户/外部输入入口位置。

Source 点是指攻击者可控的数据来源，包括：
  - Web 请求参数（Flask / Django 的 GET/POST/JSON/Cookie/Header）
  - 标准输入（input()）
  - 命令行参数（sys.argv）
  - 环境变量（os.environ）
  - 文件内容读取

格式说明：
  - module:         模块全限定名（如 "flask.request.args"）
  - func:           函数/属性名（如 "get"）
  - description:    人类可读的描述
  - tainted_params: 被污染的参数字段（空列表 = 返回值本身是 Source）

完整路径: {module}.{func} → 如 flask.request.args.get
"""
from dataclasses import dataclass, field


@dataclass
class Source:
    """
    Source 点数据类
    ==============
    描述一个外部输入入口。
    """
    module: str          # 模块全限定名，如 "flask.request.args"
    func: str            # 函数/属性名
    description: str     # 人类可读的中文描述
    # 哪些参数被污染？
    #   - 空列表 [] = 返回值本身被污染（最常见）
    #   - 否则列出被污染的参数名
    tainted_params: list[str] = field(default_factory=list)


# ---- Python Source 点全集 ----
PYTHON_SOURCES: list[Source] = [
    # ============ Flask 框架 ============
    Source("flask.request.args", "get", "Flask GET 参数", tainted_params=[]),        # request.args.get('name')
    Source("flask.request.args", "__getitem__", "Flask GET 参数 dict 取值", tainted_params=[]),  # request.args['name']
    Source("flask.request.form", "get", "Flask POST 表单", tainted_params=[]),        # request.form.get('name')
    Source("flask.request.form", "__getitem__", "Flask POST 表单 dict 取值", tainted_params=[]),
    Source("flask.request.json", "get", "Flask JSON body", tainted_params=[]),        # request.json.get('name')
    Source("flask.request.json", "__getitem__", "Flask JSON body dict 取值", tainted_params=[]),
    Source("flask.request.values", "get", "Flask 组合参数", tainted_params=[]),        # request.values.get('name')
    Source("flask.request.values", "__getitem__", "Flask 组合参数 dict 取值", tainted_params=[]),
    Source("flask.request.cookies", "get", "Flask Cookie", tainted_params=[]),
    Source("flask.request.cookies", "__getitem__", "Flask Cookie dict 取值", tainted_params=[]),
    Source("flask.request.headers", "get", "Flask 请求头", tainted_params=[]),
    Source("flask.request.headers", "__getitem__", "Flask 请求头 dict 取值", tainted_params=[]),
    Source("flask.request", "data", "Flask 原始请求体"),                               # request.data
    Source("flask.request", "get_json", "Flask JSON body", tainted_params=[]),           # request.get_json()
    Source("flask.request", "get_data", "Flask 原始请求体", tainted_params=[]),          # request.get_data()
    Source("flask.request", "headers", "Flask 请求头"),                                # request.headers
    Source("flask.request", "cookies", "Flask Cookies"),                               # request.cookies

    # ============ Django 框架 ============
    Source("django.http.request", "GET", "Django GET 参数"),
    Source("django.http.request", "POST", "Django POST 参数"),
    Source("django.http.request.GET", "get", "Django GET 参数取值"),
    Source("django.http.request.GET", "__getitem__", "Django GET 参数 dict 取值"),
    Source("django.http.request.POST", "get", "Django POST 参数取值"),
    Source("django.http.request.POST", "__getitem__", "Django POST 参数 dict 取值"),
    Source("django.http.request.COOKIES", "get", "Django Cookie 取值"),
    Source("django.http.request.COOKIES", "__getitem__", "Django Cookie dict 取值"),
    Source("django.http.request.headers", "get", "Django 请求头取值"),
    Source("django.http.request.headers", "__getitem__", "Django 请求头 dict 取值"),

    # ============ Python 通用 ============
    Source("builtins", "input", "input() 标准输入"),                                    # 命令行交互输入
    Source("sys", "argv", "sys.argv 命令行参数"),                                       # 命令行参数列表
    Source("os", "environ", "os.environ 环境变量"),                                     # 环境变量字典
    Source("os", "getenv", "os.getenv() 环境变量"),                                     # 单个环境变量获取
    Source("builtins", "__import__", "动态导入"),                                        # import('module_name')
    Source("urllib.parse", "parse_qs", "URL 查询参数解析", tainted_params=[]),            # parse_qs(query_string)
    Source("urllib.parse", "parse_qsl", "URL 查询参数解析（列表）", tainted_params=[]),   # parse_qsl(query_string)

    # ============ 文件读取（仅当文件名也来自用户输入时才是真正的 Source）============
    # 以下已被注释：open() / Path.read_text() 在静态分析中无法区分
    # "读用户上传的文件"和"读系统配置文件"，导致误报率极高。
    # 如需此检测，建议在扫描器中实现递归污点分析：
    #   只有当 open() 的参数（文件名）也是 tainted 时，才标记返回值为 Source。
    # Source("builtins", "open", "open() 文件读取（用于读取用户文件）"),
    # Source("pathlib.Path", "read_text", "Path.read_text() 文件内容"),
    # Source("pathlib.Path", "read_bytes", "Path.read_bytes() 文件内容"),
]
