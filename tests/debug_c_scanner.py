"""
tree-sitter 0.26 API 调试脚本
=============================
用于验证 tree-sitter 0.26 的 API 兼容性。
检查：
  1. func.text 属性是否可用（bytes 还是 str）
  2. call_expression 节点的子节点结构
  3. assignment_expression 节点的识别情况

用法:
    python tests/debug_c_scanner.py

注意：此文件为调试/开发用途，不是正式测试。
"""
from pathlib import Path
from tree_sitter import Language, Parser
import tree_sitter_c

# 读取测试用的 C 代码
code = Path(r"C:\Users\LonelySam8\.openclaw\workspace\code-audit-platform\tests\test_c_vulns.c").read_text(encoding="utf-8")

# 初始化 tree-sitter
lang = Language(tree_sitter_c.language())
parser = Parser(lang)
tree = parser.parse(code.encode())
root = tree.root_node


def find_system(node):
    """
    在 CST 中查找所有 call_expression 节点，
    打印其 func.text 属性类型和值。
    用于确认 tree-sitter 0.26 中 func.text 的行为。
    """
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func:
            try:
                text = func.text
                print(f"  func.text: {repr(text)}")
            except AttributeError:
                print("  func.text not available（不可用）")
            # 打印各种获取方式的结果进行对比
            print(f"  func.type: {func.type}")
            print(f"  code[func.start_byte:func.end_byte]: {repr(code[func.start_byte:func.end_byte])}")
            print(f"  Text via bytes（字节方式）: {repr(code.encode()[func.start_byte:func.end_byte])}")
            try:
                print(f"  func.text (bytes decode): {repr(func.text.decode('utf-8') if isinstance(func.text, bytes) else func.text)}")
            except Exception as e:
                print(f"  Error: {e}")
    if node.type == "call_expression":
        return  # 只调试第一个
    for child in node.children:
        find_system(child)


find_system(root)

# ---- 检查 assignment_expression 节点 ----
print("\n--- Checking assignment_expression（检查赋值表达式节点）---")


def find_assign(node):
    """查找并打印所有 assignment_expression 节点"""
    if node.type == "assignment_expression":
        print(f"  Found assign at line {node.start_point[0]+1}: {repr(code[node.start_byte:node.end_byte][:80])}")
    for child in node.children:
        find_assign(child)


find_assign(root)
