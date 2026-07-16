"""Test wide-byte injection detection."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_gbtest', exist_ok=True)
with open('_gbtest/widebyte.php', 'w') as f:
    f.write("""<?php
// Wide-byte SQL injection vulnerability
mysql_query("SET NAMES 'gbk'");
$id = addslashes($_GET['id']);
$sql = "SELECT * FROM users WHERE id='$id'";
$result = mysql_query($sql);

// Also: addslashes without GBK
$name = addslashes($_POST['name']);
$sql2 = "SELECT * FROM users WHERE name='$name'";
mysql_query($sql2);
""")

from engine.pipeline import AnalysisPipeline
p = AnalysisPipeline()
result = p.run('_gbtest', 'php')
print(f"S1={result.stage1_count} S2={result.stage2_count} S3={result.stage3_count} S4={result.stage4_count}")
print(f"Final: {result.final_count}")
for v in result.final_vulns:
    vt = v.get("vuln_type", "?")
    ln = v.get("line_number", "?")
    stage = v.get("pipeline_stage", "?")
    desc = v.get("description", "")
    print(f"  - {vt} @ line {ln} [{stage}] {desc[:80]}")

shutil.rmtree('_gbtest', ignore_errors=True)
