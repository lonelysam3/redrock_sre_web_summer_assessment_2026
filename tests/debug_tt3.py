"""Deep debug — check what find_paths actually sees."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_tt', exist_ok=True)
with open('_tt/test.php', 'w') as f:
    f.write("""<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id=" . $id;
mysqli_query($db, $sql);
""")

from engine.php_scanner import PHPScanner
from engine.taint_tracker import TaintTracker

s = PHPScanner()
with open('_tt/test.php') as f:
    source = f.read()
source_bytes = source.encode('utf-8')
s._source_bytes = source_bytes

tree = s.parser.parse(source_bytes)

tracker = TaintTracker(file_path='test.php')
s._walk(tree.root_node, tracker, source_bytes)

srcs = tracker.graph.get_sources()
sinks = tracker.graph.get_sinks()
print(f"Sources: {srcs}")
print(f"Sinks: {sinks}")
print(f"Adjacency: {dict(tracker.graph.adjacency)}")

for src in srcs:
    for sink in sinks:
        paths = tracker.graph.find_paths(src, sink)
        print(f"find_paths({repr(src)}, {repr(sink)}): {paths}")

shutil.rmtree('_tt', ignore_errors=True)
