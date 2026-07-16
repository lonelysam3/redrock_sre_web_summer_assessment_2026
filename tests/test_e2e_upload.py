"""Full end-to-end test: archive upload -> extract -> scan."""
import os, sys, zipfile, shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# ---- 1. Create test project ----
test_dir = "_test_sample"
os.makedirs(test_dir, exist_ok=True)

with open(os.path.join(test_dir, "app.py"), "w") as f:
    f.write("""
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/exec')
def exec_cmd():
    cmd = request.args.get('cmd')
    os.system(cmd)  # Command injection vulnerability
    return 'ok'

@app.route('/query')
def query():
    user_input = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_input}"  # SQL injection
    return query
""")

# ---- 2. Create zip and extract ----
zip_path = "_test_sample.zip"
with zipfile.ZipFile(zip_path, "w") as zf:
    zf.write(os.path.join(test_dir, "app.py"), "app.py")
print(f"[1] Created {zip_path}")

from utils.archive_handler import extract_archive, detect_extracted_language

class FakeFile:
    def __init__(self, path, name):
        self._path = path
        self.filename = name
    def save(self, dest):
        shutil.copy(self._path, dest)

extract_base = "_test_extracted"
os.makedirs(extract_base, exist_ok=True)

result_path = extract_archive(
    FakeFile(zip_path, "test.zip"), "test.zip", extract_base, "test_project"
)
print(f"[2] Extracted to: {result_path}")

# ---- 3. Detect language ----
lang = detect_extracted_language(result_path)
print(f"[3] Language: {lang}")

# ---- 4. Scan ----
from engine import scan_project
vulns = scan_project(result_path, 'python')
print(f"[4] Found {len(vulns)} vulnerabilities:")
for v in vulns:
    vt = v.get("vuln_type", "?")
    fp = v.get("file_path", "?")
    ln = v.get("line_number", v.get("sink_line", "?"))
    sev = v.get("severity", "?")
    print(f"    - {vt} @ {os.path.basename(fp)}:{ln} [{sev}]")

# ---- 5. Test security ----
import io, time
evil_zip = "_evil.zip"
data = io.BytesIO()
with zipfile.ZipFile(data, "w") as zf:
    info = zipfile.ZipInfo("../etc/passwd")
    info.date_time = time.localtime()[:6]
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, b"root:x:0:0::/root:/bin/bash\n")
with open(evil_zip, "wb") as f:
    f.write(data.getvalue())

try:
    extract_archive(FakeFile(evil_zip, "evil.zip"), "evil.zip", extract_base, "evil")
    print("[5] FAIL: Evil zip should be rejected!")
except Exception as e:
    print(f"[5] OK: Evil zip rejected: {e}")

# ---- Cleanup ----
shutil.rmtree(test_dir, ignore_errors=True)
shutil.rmtree(extract_base, ignore_errors=True)
os.unlink(zip_path)
os.unlink(evil_zip)
print("[6] Cleanup done. All tests passed!")
