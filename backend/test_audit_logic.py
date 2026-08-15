# -*- coding: utf-8 -*-
"""
审计逻辑回归测试
===============
验证误报/漏报修复的效果。

用例设计：
  T1: htmlspecialchars 只消毒 XSS，不切断命令执行（原漏报）
  T2: htmlspecialchars 正确消毒 XSS（不应报）
  T3: $allowed = $_GET['cmd'] 不是白名单（原漏报，被误降级）
  T4: 真白名单 in_array 应该降级
  T5: echo $_GET['x'] 直接 XSS（原漏报）
  T6: 危险组合跨远距离不报（原误报）
  T7: 调用图函数名泛词不再误报（read_config 等）
  T8: Python html.escape 不切断命令执行
  T9: int() 全类型消毒（SQL 注入被消毒）
  T10: 真 SQL 注入应该报（对照组）
"""
import os
import sys
import tempfile
import shutil

BACKEND = r"C:\Users\LonelySam8\.openclaw\workspace\code-audit-platform\backend"
sys.path.insert(0, BACKEND)

from engine.pipeline import AnalysisPipeline

def run_case(name, files: dict, language: str) -> list:
    tmp = tempfile.mkdtemp(prefix="audit_test_")
    try:
        for fname, content in files.items():
            path = os.path.join(tmp, fname)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        result = AnalysisPipeline().run(tmp, language)
        vulns = result.final_vulns
        print(f"\n=== {name} ({language}) === 发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"  [{v['severity']:8s}] {v['vuln_type']:20s} line {v.get('line_number', 0)}: {v.get('sink_code', '')[:80]}")
        return vulns
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ---- PHP 用例 ----

# T1: htmlspecialchars 后仍传给 system → 应报 command_execution（原漏报）
run_case("T1 htmlspecialchars 不切断命令执行", {
    "a.php": """<?php
$x = htmlspecialchars($_GET['cmd']);
system($x);
"""
}, "php")

# T2: htmlspecialchars 后 echo → 不应报 XSS（消毒有效）
run_case("T2 htmlspecialchars 消毒 XSS", {
    "b.php": """<?php
$x = htmlspecialchars($_GET['name']);
echo $x;
"""
}, "php")

# T3: $allowed = $_GET['cmd'] 不是白名单 → 应报命令执行（原被误降级为 info）
run_case("T3 伪白名单不降级", {
    "c.php": """<?php
$allowed = $_GET['cmd'];
system($allowed);
"""
}, "php")

# T5: echo $_GET['x'] 直接输出 → 应报 XSS（原漏报）
run_case("T5 直接 echo 超全局", {
    "d.php": """<?php
echo $_GET['name'];
"""
}, "php")

# T6: unserialize 与 __destruct 相距很远 → 不应报危险组合（原误报）
run_case("T6 远距离组合不误报", {
    "e.php": """<?php
$x = unserialize($_POST['data']);
echo "processing...";
echo "still processing...";
echo "more lines here";
echo "even more lines";
echo "filling space";
echo "filling space 2";
echo "filling space 3";
echo "filling space 4";
echo "filling space 5";
class Foo {
    function __destruct() {
        echo "done";
    }
}
"""
}, "php")

# T10: 对照组 - 真实 SQL 注入应报
run_case("T10 SQL 注入对照组", {
    "f.php": """<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id=" . $id;
mysqli_query($conn, $sql);
"""
}, "php")

# T4: 真白名单 in_array 应降级
run_case("T4 真白名单降级", {
    "g.php": """<?php
$allowed = ['ls', 'cat', 'pwd'];
$cmd = $_GET['cmd'];
if (in_array($cmd, $allowed)) {
    system($cmd);
}
"""
}, "php")

# ---- Python 用例 ----

# T8: html.escape 不切断命令执行（原漏报）
run_case("T8 Python escape 不切断命令", {
    "h.py": """import os, html
x = html.escape(input())
os.system(x)
"""
}, "python")

# T9: int() 全类型消毒
run_case("T9 int() 消毒", {
    "i.py": """import sqlite3
conn = sqlite3.connect(':memory:')
x = int(input())
conn.execute("SELECT * FROM t WHERE id=" + str(x))
"""
}, "python")

# ---- C 用例 ----

# C: atoi 消毒后不应报
run_case("C1 atoi 消毒", {
    "j.c": """#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
    char *s = getenv("N");
    int n = atoi(s);
    printf("%d", n);
    return 0;
}
"""
}, "c")

# C: getenv → system 应报（对照组）
run_case("C2 命令执行对照组", {
    "k.c": """#include <stdlib.h>
int main() {
    char *cmd = getenv("CMD");
    system(cmd);
    return 0;
}
"""
}, "c")

# ---- 调用图用例 ----

# T7: read_config/query_cache 这类函数名不应产生跨函数误报
run_case("T7 调用图泛词不误报", {
    "l.py": """import json
def read_config(path):
    with open(path) as f:
        return json.load(f)

def query_cache(key):
    return {}

def main():
    cfg = read_config("config.json")
    print(cfg)
"""
}, "python")

# ---- 跨函数/跨文件污点传播（v3 架构） ----

# T11: 跨文件返回传播：b.go(host) → a.build_url(host) → #ret → requests.get(u) → SSRF
run_case("T11 跨文件返回传播", {
    "a.py": "def build_url(host):\n    return 'http://' + host\n",
    "b.py": """from a import build_url
import requests

def go(host):
    u = build_url(host)
    requests.get(u)
"""
}, "python")

# T12: 同一文件内函数作用域隔离：同名变量不应跨函数串扰
# checkout 里的 order（嵌套 request.form.get 污染）不应污染 order_receipt 里的
# page 链路；但 order_receipt 自己的 order_id → order → order.notes → page →
# render_template_string 应报 SSTI。
run_case("T12 作用域隔离 + 二次传播 SSTI", {
    "s.py": """from flask import render_template_string, request

class Order:
    notes = ""

class Q:
    @staticmethod
    def get_or_404(x):
        o = Order()
        o.notes = "hello"
        return o

class OrderQuery:
    query = Q()

Order = type('OrderCls', (Order,), {'query': Q()})

def checkout():
    order = _mk(request.form.get("notes", ""))
    return order

def _mk(notes):
    o = Order()
    o.notes = notes
    return o

def order_receipt(order_id):
    order = Order.query.get_or_404(order_id)
    page = "<p>" + order.notes + "</p>"
    return render_template_string(page, order=order)
"""
}, "python")

