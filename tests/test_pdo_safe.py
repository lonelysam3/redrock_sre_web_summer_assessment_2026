"""Test PDO parameterized query detection."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_pdo2', exist_ok=True)
with open('_pdo2/safe_pdo.php', 'w') as f:
    f.write("""<?php
$pdo = new PDO('mysql:host=localhost;dbname=test;charset=gbk', 'root', '');
$username = $_POST['username'];
$password = $_POST['password'];
$email = $_POST['email'];

$sql = "INSERT INTO users (username, password, email, balance) VALUES (:username, :password, :email, 100000)";
$stmt = $pdo->prepare($sql);
$stmt->execute([
    ':username' => $username,
    ':password' => $password,
    ':email' => $email
]);
""")

from engine.pipeline import AnalysisPipeline
p = AnalysisPipeline()
result = p.run('_pdo2', 'php')
print(f"S1={result.stage1_count} S2={result.stage2_count} S3={result.stage3_count} Final={result.final_count}")
print(f"Safe patterns found: {result.stage3_safe_patterns}")
for v in result.final_vulns:
    vt = v.get("vuln_type", "?")
    ln = v.get("line_number", "?")
    stage = v.get("pipeline_stage", "?")
    print(f"  {vt} @ L{ln} [{stage}] {desc[:100] if desc else ''}")

if result.final_count == 0:
    print("NOTE: No vulnerabilities detected")
else:
    print(f"DETECTED {result.final_count} issue(s) — GBK+PDO without EMULATE_PREPARES=false is genuinely vulnerable!")

shutil.rmtree('_pdo2', ignore_errors=True)
