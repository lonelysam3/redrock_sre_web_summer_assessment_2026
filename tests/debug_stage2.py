"""Debug Stage 2 data flow independent scanner."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_sqli_test', exist_ok=True)
with open('_sqli_test/query.php', 'w') as f:
    f.write("""<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id=" . $id;
$result = mysqli_query($db, $sql);
""")

# Test Stage 2 independently
from engine.data_flow_analyzer import DataFlowAnalyzer

source_map = {}
with open('_sqli_test/query.php') as f:
    source_map['query.php'] = f.read()

a = DataFlowAnalyzer()
vulns = a.analyze_independent(source_map, 'php')
print(f"Stage 2 found {len(vulns)} vulns:")
for v in vulns:
    print(f"  - {v['vuln_type']} @ line {v['line_number']} [{v['pipeline_stage']}]")

# Debug: check block splitting
lines = source_map['query.php'].split('\n')
blocks = a._split_into_blocks(lines, 'php')
print(f"\nBlocks: {blocks}")
for start, end in blocks:
    block_text = '\n'.join(lines[start:end])
    has_source = '$_GET' in block_text
    has_sink = 'mysqli_query' in block_text
    print(f"  Block [{start}:{end}]: source={has_source} sink={has_sink}")

shutil.rmtree('_sqli_test', ignore_errors=True)
