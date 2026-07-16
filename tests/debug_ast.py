"""Debug tree-sitter PHP AST node structure."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from tree_sitter import Language, Parser
import tree_sitter_php

lang = Language(tree_sitter_php.language_php())
parser = Parser(lang)

code = b"<?php\n$id = $_GET['id'];\n"
tree = parser.parse(code)

def print_node(node, depth=0):
    text = code[node.start_byte:node.end_byte].decode()
    print("  " * depth + f"{node.type}: {repr(text)}")
    for child in node.children:
        print_node(child, depth + 1)

print_node(tree.root_node)
