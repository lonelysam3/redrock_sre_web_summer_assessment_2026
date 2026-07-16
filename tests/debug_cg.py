"""Debug call graph analyzer."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from engine.call_graph_analyzer import CallGraphAnalyzer
from engine.pipeline import AnalysisPipeline

# Create test files
test_dir = '_cg_debug'
os.makedirs(test_dir, exist_ok=True)

files = {
    'input.php': '<?php\nfunction getUserInput() { return $_GET["username"]; }\nfunction getUserId() { return $_POST["id"]; }\n',
    'database.php': '<?php\nfunction buildQuery($name) { return "SELECT * FROM users WHERE name=\'" . $name . "\'"; }\nfunction executeQuery($sql) { mysqli_query($db, $sql); }\nfunction safeQuery() { mysqli_query($db, "SELECT 1"); }\n',
    'main.php': '<?php\nfunction run() { $name = getUserInput(); $sql = buildQuery($name); executeQuery($sql); }\nfunction runDirect() { $id = getUserId(); executeQuery("DELETE FROM users WHERE id=" . $id); }\n',
}

for name, content in files.items():
    with open(os.path.join(test_dir, name), 'w') as f:
        f.write(content)

# Step 1: extract functions
source_map = {}
for name in files:
    path = os.path.join(test_dir, name)
    with open(path) as f:
        source_map[path] = f.read()

a = CallGraphAnalyzer()
functions = {}
a._extract_functions(source_map, 'php', functions)
print("Functions found:", list(functions.keys()))

a._resolve_calls(source_map, 'php', functions)
for name, func in functions.items():
    print(f"  {name} @ {func.file_path}:{func.line_number}")
    print(f"    source={func.is_source} ({func.source_labels})")
    print(f"    sink={func.is_sink} ({func.sink_labels}) vuln={func.vuln_type}")
    print(f"    calls={func.calls}")

# Step 2: full pipeline
print("\n--- Full Pipeline ---")
p = AnalysisPipeline()
result = p.run(test_dir, 'php')
print(f"Stage1={result.stage1_count} Stage3={result.stage3_dangerous_patterns} Stage4={result.stage4_count} Final={result.final_count}")
for v in result.final_vulns:
    vt = v.get("vuln_type", "?")
    df = v.get("data_flow", "")
    stage = v.get("pipeline_stage", "?")
    print(f"  - {vt} | {df} | stage={stage}")

import shutil
shutil.rmtree(test_dir, ignore_errors=True)
