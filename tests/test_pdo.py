"""Test PDO vulnerability detection."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_pdotest', exist_ok=True)
with open('_pdotest/pdo_vulns.php', 'w') as f:
    f.write("""<?php
$db = new PDO('mysql:host=localhost;dbname=test;charset=gbk', 'root', '');

// Vuln 1: PDO::query with concatenation
$id = $_GET['id'];
$db->query("SELECT * FROM users WHERE id=" . $id);

// Vuln 2: PDO::exec with user input
$name = $_POST['name'];
$db->exec("DELETE FROM users WHERE name='" . $name . "'");

// Vuln 3: PDO::prepare with concatenation (defeats prepared statement)
$uid = $_GET['uid'];
$stmt = $db->prepare("SELECT * FROM users WHERE uid=" . $uid);

// Vuln 4: Emulated prepares explicitly enabled
$db2 = new PDO('mysql:host=localhost;dbname=test2;charset=utf8', 'root', '');
$db2->setAttribute(PDO::ATTR_EMULATE_PREPARES, true);
$id2 = $_GET['id2'];
$db2->query("SELECT * FROM items WHERE id=" . $id2);
""")

from engine.pipeline import AnalysisPipeline
p = AnalysisPipeline()
result = p.run('_pdotest', 'php')
print(f"S1={result.stage1_count} S2={result.stage2_count} S3={result.stage3_count} Final={result.final_count}")
for v in result.final_vulns:
    vt = v.get("vuln_type", "?")
    ln = v.get("line_number", "?")
    stage = v.get("pipeline_stage", "?")
    desc = v.get("description", "")
    print(f"  - {vt} @ L{ln} [{stage}] {desc[:90] if desc else ''}")

shutil.rmtree('_pdotest', ignore_errors=True)
