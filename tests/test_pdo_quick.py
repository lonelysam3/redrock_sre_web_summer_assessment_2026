"""Quick test PDO GBK detection."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_pdoquick', exist_ok=True)
with open('_pdoquick/test.php', 'w') as f:
    f.write("""<?php
$pdo = new PDO('mysql:host=localhost;dbname=test;charset=gbk', 'root', '');
$username = $_POST['username'];
$sql = "INSERT INTO users (username) VALUES (:username)";
$stmt = $pdo->prepare($sql);
$stmt->execute([':username' => $username]);
""")

from engine.pipeline import AnalysisPipeline
p = AnalysisPipeline()
result = p.run('_pdoquick', 'php')
for v in result.final_vulns:
    ln = v.get("line_number", "?")
    d = v.get("description", "")
    print(f"L{ln}: {d}")
if result.final_count == 0:
    print("NOT DETECTED - check charset pattern")

shutil.rmtree('_pdoquick', ignore_errors=True)
