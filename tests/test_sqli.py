"""Test SQL injection detection across all stages."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_sqli_test', exist_ok=True)

# PHP: Classic SQL injection
with open('_sqli_test/query.php', 'w') as f:
    f.write("""<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id=" . $id;
$result = mysqli_query($db, $sql);

// Also XSS
$name = $_GET['name'];
echo "Hello " . $name;

// Also path traversal
$file = $_GET['file'];
include $file . '.php';

// Also command execution
$cmd = $_POST['cmd'];
system($cmd);

// Also SSRF
$url = $_GET['url'];
file_get_contents($url);
""")

from engine.pipeline import AnalysisPipeline
p = AnalysisPipeline()
result = p.run('_sqli_test', 'php')
print("Results per stage:")
print(f"  S1 (taint): {result.stage1_count}")
print(f"  S2 (data flow): {result.stage2_count}")
print(f"  S3 (AST): {result.stage3_count}")
print(f"  S4 (call graph): {result.stage4_count}")
print(f"  Final after dedup: {result.final_count}")
for v in result.final_vulns:
    vt = v.get("vuln_type", "?")
    ln = v.get("line_number", v.get("sink_line", "?"))
    stage = v.get("pipeline_stage", "?")
    print(f"  - {vt} @ line {ln} [{stage}]")

shutil.rmtree('_sqli_test', ignore_errors=True)
