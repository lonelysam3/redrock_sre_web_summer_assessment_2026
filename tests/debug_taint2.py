"""Deep debug PHP scanner with tracing."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_taint_test', exist_ok=True)
with open('_taint_test/test.php', 'w') as f:
    f.write("""<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id=" . $id;
mysqli_query($db, $sql);
$cmd = $_POST['cmd'];
system($cmd);
""")

from engine.php_scanner import PHPScanner
from engine.taint_tracker import TaintTracker

s = PHPScanner()
with open('_taint_test/test.php') as f:
    source = f.read()

source_bytes = source.encode('utf-8')
s._source_bytes = source_bytes

tree = s.parser.parse(source_bytes)
root = tree.root_node

tracker = TaintTracker(file_path='test.php')
s._walk(root, tracker, source_bytes)

print("=== Sources ===")
for name in tracker.graph.get_sources():
    node = tracker.graph.nodes[name]
    info = tracker.source_info.get(name, {})
    print(f"  {name}: origin={node.source_origin} line={node.line_number} func={info.get('source_func','')}")

print("\n=== Sinks ===")
for name in tracker.graph.get_sinks():
    node = tracker.graph.nodes[name]
    info = tracker.sink_info.get(name, {})
    print(f"  {name}: tainted={node.tainted} line={node.line_number} func={info.get('sink_func','')} type={info.get('vuln_type','')}")

print("\n=== All edges ===")
for edge in tracker.graph.edges:
    print(f"  {edge.from_node} -> {edge.to_node} ({edge.reason})")

# Check if sources have any outgoing edges
print("\n=== Source reachability ===")
for src in tracker.graph.get_sources():
    reachable = tracker.graph.find_paths(src, list(tracker.graph.get_sinks())[:1] if tracker.graph.get_sinks() else [])
    print(f"  From {src}: {len(reachable)} paths to any sink")

shutil.rmtree('_taint_test', ignore_errors=True)
