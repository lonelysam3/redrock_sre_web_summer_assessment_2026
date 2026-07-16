"""Test full vulnerability type coverage."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_coverage_test', exist_ok=True)

# PHP: all 7 vulnerability types
with open('_coverage_test/all_vulns.php', 'w') as f:
    f.write("""<?php
// SQL Injection
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id=" . $id;
mysqli_query($db, $sql);

// XSS
$name = $_GET['name'];
echo "Welcome " . $name;

// Command Execution
$cmd = $_POST['cmd'];
system($cmd);

// Path Traversal
$file = $_GET['file'];
include $file . '.php';

// SSRF
$url = $_GET['url'];
file_get_contents($url);

// Arbitrary File Read
$path = $_GET['path'];
$content = file_get_contents($path);

// File Upload
$tmp = $_FILES['upload']['tmp_name'];
move_uploaded_file($tmp, '/var/www/uploads/' . $_FILES['upload']['name']);

// Deserialization
$data = $_GET['data'];
$obj = unserialize($data);
""")

from engine.pipeline import AnalysisPipeline

p = AnalysisPipeline()
result = p.run('_coverage_test', 'php')

# Group by vuln_type
by_type = {}
for v in result.final_vulns:
    vt = v["vuln_type"]
    if vt not in by_type:
        by_type[vt] = []
    by_type[vt].append(v)

expected = ["sql_injection", "xss", "command_execution", "path_traversal",
            "ssrf", "arbitrary_file_read", "file_upload", "deserialization"]

print(f"Total vulns: {result.final_count}")
print()
for t in expected:
    found = by_type.get(t, [])
    status = "[OK]" if found else "[MISS]"
    print(f"  {status} {t}: {len(found)} found")

# Coverage summary
covered = sum(1 for t in expected if t in by_type)
print(f"\nCoverage: {covered}/{len(expected)}")

shutil.rmtree('_coverage_test', ignore_errors=True)
