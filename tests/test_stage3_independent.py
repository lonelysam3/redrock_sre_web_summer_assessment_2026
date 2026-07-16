"""Test Stage 3 independently discovers vulns that Stage 1 misses."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_php_test', exist_ok=True)
with open('_php_test/index.php', 'w') as f:
    f.write("""<?php
// Safe-looking page with no obvious source-sink
$name = $_GET['name'];
echo htmlspecialchars($name);

// Dangerous function combo
$data = file_get_contents('php://input');
eval($data);

// Extract override
extract($_POST);
include $template . '.php';
""")

from engine.pipeline import AnalysisPipeline
p = AnalysisPipeline()
result = p.run('_php_test', 'php')
print("Stage1 vulns:", result.stage1_count)
print("Stage3 safe:", result.stage3_safe_patterns, "dangerous:", result.stage3_dangerous_patterns)
print("Final vulns:", result.final_count)
for v in result.final_vulns:
    vt = v.get("vuln_type", "?")
    fp = os.path.basename(v.get("file_path", "?"))
    ln = v.get("line_number", v.get("sink_line", "?"))
    sev = v.get("severity", "?")
    stage = v.get("pipeline_stage", "?")
    print(f"  - {vt} @ {fp}:{ln} [{sev}] stage={stage}")

shutil.rmtree('_php_test', ignore_errors=True)
