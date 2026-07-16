"""Test Stage 4 Call Graph analysis with cross-function vulnerability."""
import os, sys, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

os.makedirs('_cg_test', exist_ok=True)

# File 1: Source function
with open('_cg_test/input.php', 'w') as f:
    f.write("""<?php
function getUserInput() {
    return $_GET['username'];
}

function getUserId() {
    return $_POST['id'];
}
""")

# File 2: Pass-through + Sink
with open('_cg_test/database.php', 'w') as f:
    f.write("""<?php
function buildQuery($name) {
    return "SELECT * FROM users WHERE name='" . $name . "'";
}

function executeQuery($sql) {
    $db = new mysqli('localhost', 'root', '', 'test');
    mysqli_query($db, $sql);  // Sink!
}

// This should NOT be flagged: no source connects to it
function safeQuery() {
    $db = new mysqli('localhost', 'root', '', 'test');
    mysqli_query($db, "SELECT 1");
}
""")

# File 3: Main that connects source to sink
with open('_cg_test/main.php', 'w') as f:
    f.write("""<?php
function run() {
    $name = getUserInput();      // Source
    $sql = buildQuery($name);    // Pass-through
    executeQuery($sql);           // Sink
}

// Also has direct connection: getUserId → executeQuery
function runDirect() {
    $id = getUserId();
    executeQuery("DELETE FROM users WHERE id=" . $id);
}
""")

from engine.pipeline import AnalysisPipeline
p = AnalysisPipeline()
result = p.run('_cg_test', 'php')
print("Stage1:", result.stage1_count)
print("Stage3:", result.stage3_dangerous_patterns)
print("Stage4:", result.stage4_count)
print("Final:", result.final_count)
for v in result.final_vulns:
    vt = v.get("vuln_type", "?")
    df = v.get("data_flow", "")
    stage = v.get("pipeline_stage", "?")
    print(f"  - {vt} | {df} | stage={stage}")

shutil.rmtree('_cg_test', ignore_errors=True)
