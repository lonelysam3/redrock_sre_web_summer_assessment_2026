"""Test cross-file PDO+GBK detection."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_xfile', exist_ok=True)
with open('_xfile/db_connect.php', 'w') as f:
    f.write("""<?php
$pdo = new PDO('mysql:host=localhost;dbname=test;charset=gbk', 'root', '');
""")

with open('_xfile/register.php', 'w') as f:
    f.write("""<?php
require_once 'db_connect.php';
$username = $_POST['username'];
$sql = "INSERT INTO users (username) VALUES (:username)";
$stmt = $pdo->prepare($sql);
$stmt->execute([':username' => $username]);
""")

from engine.pipeline import AnalysisPipeline
p = AnalysisPipeline()
result = p.run('_xfile', 'php')
print(f"Found: {result.final_count} vulns")
for v in result.final_vulns:
    ln = v.get("line_number", "?")
    d = v.get("description", "")
    fp = v.get("file_path", "?")
    print(f"  {os.path.basename(fp)} L{ln}: {d[:120]}")

shutil.rmtree('_xfile', ignore_errors=True)
