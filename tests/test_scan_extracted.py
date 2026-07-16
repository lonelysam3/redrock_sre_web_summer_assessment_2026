"""Test scan on extracted project."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from engine import scan_project

project_path = os.path.join(
    os.path.dirname(__file__), '..', 'backend', 'test_extracted'
)
# Find the latest extracted project
for entry in sorted(os.listdir(project_path), reverse=True):
    full = os.path.join(project_path, entry)
    if os.path.isdir(full):
        project_path = full
        break

print(f"Scanning: {project_path}")
vulns = scan_project(project_path, 'python')
print(f"Found {len(vulns)} vulnerabilities:")
for v in vulns:
    vt = v.get("vuln_type", "?")
    fp = v.get("file_path", "?")
    ln = v.get("line_number", v.get("sink_line", "?"))
    sev = v.get("severity", "?")
    print(f"  - {vt} @ {fp}:{ln} [{sev}]")
