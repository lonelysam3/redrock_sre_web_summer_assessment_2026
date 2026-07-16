"""Debug PHP scanner source/sink/sanitizer detection."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_taint_test', exist_ok=True)

with open('_taint_test/test.php', 'w') as f:
    f.write("""<?php
$id = $_GET['id'];
$name = $_GET['name'];
$safe_id = intval($id);
$sql = "SELECT * FROM users WHERE id=" . $id;
mysqli_query($db, $sql);
$result = mysqli_query($db, "SELECT name FROM users WHERE id=" . $safe_id);
echo "Hello " . $name;
$cmd = $_POST['cmd'];
system($cmd);
""")

from engine.php_scanner import PHPScanner

s = PHPScanner()
with open('_taint_test/test.php') as f:
    source = f.read()

# Use scan_source to properly initialize _source_bytes
vulns = s.scan_source(source, 'test.php')
print(f"Scan result: {len(vulns)} vulns")
for v in vulns:
    print(f"  - {v['vuln_type']} | {v.get('data_flow','?')} | line {v.get('sink_line','?')}")

shutil.rmtree('_taint_test', ignore_errors=True)
