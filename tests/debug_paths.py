"""Debug find_paths."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from engine.taint_tracker import TaintTracker

t = TaintTracker('test.php')

# Simulate what PHP scanner does
t.mark_source("$id", source_func="$_GET", code="$_GET['id']", line=2)
t.mark_assign("$id", "$_GET", reason="assign", line=2)
t.mark_assign("$sql", "$id", reason="assign", line=3)
t.mark_sink("$sql", sink_func="mysqli_query", vuln_type="sql_injection", code="mysqli_query($db, $sql)", line=4)

# Check
print("Sources:", t.graph.get_sources())
print("Sinks:", t.graph.get_sinks())
print("Adjacency:", dict(t.graph.adjacency))
print()

# Find paths
for src in t.graph.get_sources():
    for sink in t.graph.get_sinks():
        paths = t.graph.find_paths(src, sink)
        print(f"find_paths({src}, {sink}): {paths}")

# Analyze
results = t.analyze()
print(f"\nAnalyze results: {len(results)}")
for r in results:
    print(f"  {r['vuln_type']} | {r['data_flow']}")
