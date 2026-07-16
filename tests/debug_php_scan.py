"""Debug PHP scanner with SQL injection test."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_sqli_test', exist_ok=True)
with open('_sqli_test/query.php', 'w') as f:
    f.write("""<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id=" . $id;
$result = mysqli_query($db, $sql);
$name = $_GET['name'];
echo "Hello " . $name;
$file = $_GET['file'];
include $file . '.php';
$cmd = $_POST['cmd'];
system($cmd);
$url = $_GET['url'];
file_get_contents($url);
""")

from engine.php_scanner import PHPScanner
s = PHPScanner()
vulns = s.scan_directory('_sqli_test')
print(f"PHP scanner found {len(vulns)} vulns:")
for v in vulns:
    vt = v.get("vuln_type", "?")
    ln = v.get("line_number", v.get("sink_line", "?"))
    print(f"  - {vt} @ line {ln}")
    print(f"    source: {v.get('source_code','')[:80]}")
    print(f"    sink: {v.get('sink_code','')[:80]}")

shutil.rmtree('_sqli_test', ignore_errors=True)
