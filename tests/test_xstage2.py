"""Test cross-file Stage 2 data flow."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_xstage2', exist_ok=True)
# File 1: has source (user input) but no sink
with open('_xstage2/input.php', 'w') as f:
    f.write("""<?php
$id = $_GET['id'];
$cmd = $_POST['cmd'];
$url = $_GET['url'];
$file = $_GET['file'];
""")
# File 2: has sink (dangerous calls) but no source
with open('_xstage2/handler.php', 'w') as f:
    f.write("""<?php
mysqli_query($db, $id);
system($cmd);
file_get_contents($url);
include $file . '.php';
echo $name;
""")

from engine.data_flow_analyzer import DataFlowAnalyzer
source_map = {}
for fn in ['input.php', 'handler.php']:
    with open(f'_xstage2/{fn}') as f:
        source_map[f'_xstage2/{fn}'] = f.read()

a = DataFlowAnalyzer()
vulns = a.analyze_independent(source_map, 'php')
cross = [v for v in vulns if '跨文件' in v.get('data_flow', '')]
same = [v for v in vulns if '跨文件' not in v.get('data_flow', '')]
print(f"Same-file: {len(same)}, Cross-file: {len(cross)}")
for v in cross:
    print(f"  {v['vuln_type']} @ {os.path.basename(v['file_path'])}:{v['line_number']} — {v['data_flow']}")

shutil.rmtree('_xstage2', ignore_errors=True)
