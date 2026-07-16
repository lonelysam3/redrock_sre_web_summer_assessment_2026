import re

source = """<?php
function run() { $name = getUserInput(); $sql = buildQuery($name); executeQuery($sql); }
function runDirect() { $id = getUserId(); executeQuery("DELETE FROM users"); }
"""

# Current pattern
pattern = re.compile(r'function\s+run\s*\([^)]*\)\s*\{(.*?)\n\}', re.DOTALL)
m = pattern.search(source)
print("Current pattern:", repr(m.group(1)) if m else "NO MATCH")

# Better pattern - match balanced braces
pattern2 = re.compile(r'function\s+run\s*\([^)]*\)\s*\{([^}]*)\}', re.DOTALL)
m2 = pattern2.search(source)
print("Better pattern:", repr(m2.group(1)) if m2 else "NO MATCH")
