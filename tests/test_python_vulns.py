"""
测试用例 —— 包含各种漏洞的 Python 示例代码
=========================================
用作扫描器的测试输入，包含常见的 Web 安全漏洞场景。

漏洞覆盖：
  - SQL 注入（字符串拼接 vs 参数化查询）
  - 命令执行（os.system, subprocess.run）
  - SSRF（requests.get 直接使用用户 URL）
  - 安全代码（白名单验证，不应报告）

被 test_runner.py 引用，用于验证扫描器能力。
"""

# ======== SQL 注入 ========
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user/search')
def search_users():
    """
    漏洞示例：SQL 注入
    Source: request.args.get('name')  ← 用户可控输入
    Sink:   cursor.execute(query)     ← 危险 SQL 执行
    问题：  字符串拼接构建 SQL 语句，未使用参数化查询
    """
    name = request.args.get('name')         # ← SOURCE: 用户输入
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # ← 危险的字符串拼接
    cursor.execute(query)                   # ← SINK: SQL 注入
    results = cursor.fetchall()
    return str(results)

@app.route('/user/safe')
def safe_search():
    """
    安全示例：参数化查询
    即使 name 来自用户输入，使用 ? placeholder 的参数化查询是安全的。
    扫描器不应报告此函数。
    """
    name = request.args.get('name')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))  # ← 参数化查询，安全 ✓
    return str(cursor.fetchall())


# ======== 命令执行 ========
import os
import subprocess

@app.route('/ping')
def ping():
    """
    漏洞示例：命令注入
    Source: request.args.get('host')  ← 用户可控
    Sink:   os.system(f"ping {host}") ← 危险命令执行
    问题：  用户输入直接拼接到 shell 命令中
    攻击：  host=127.0.0.1; rm -rf /  可注入任意命令
    """
    host = request.args.get('host', '127.0.0.1')  # ← SOURCE: 用户输入
    os.system(f"ping -c 1 {host}")                # ← SINK: 命令注入
    return "ok"

@app.route('/exec')
def run_cmd():
    """
    漏洞示例：命令执行（subprocess + shell=True）
    Source: request.args.get('cmd')     ← 用户可控
    Sink:   subprocess.run(cmd, shell=True) ← 危险
    问题：  shell=True 允许注入任意命令
    """
    cmd = request.args.get('cmd')                  # ← SOURCE: 用户输入
    subprocess.run(cmd, shell=True)                # ← SINK: 命令注入
    return "done"


# ======== SSRF 服务端请求伪造 ========
import requests

@app.route('/fetch')
def fetch_url():
    """
    漏洞示例：SSRF
    Source: request.args.get('url')  ← 用户可控 URL
    Sink:   requests.get(url)        ← 服务端发起请求
    问题：  用户可控制请求目标，可能探测内网服务
    攻击：  url=http://169.254.169.254/latest/meta-data/ 读取云元数据
    """
    url = request.args.get('url')                  # ← SOURCE: 用户输入
    resp = requests.get(url)                       # ← SINK: SSRF
    return resp.text


# ======== 安全代码（不应报告漏洞） ========
@app.route('/safe-ping')
def safe_ping():
    """
    安全示例：白名单验证
    Source: request.args.get('host')
    虽然调用了 os.system()，但 host 被白名单验证后才使用。
    扫描器应识别为安全代码，不报告漏洞。

    注意：当前版本的扫描器主要检测 Source→Sink 路径，
    对应用层验证逻辑（如 if host in allowed）的识别能力有限，
    可能需要 AI 二次分析来排除此类误报。
    """
    host = request.args.get('host')
    allowed = {'127.0.0.1', 'localhost'}           # ← 白名单
    if host in allowed:                            # ← 白名单验证，安全 ✓
        os.system(f"ping -c 1 {host}")
    return "ok"
