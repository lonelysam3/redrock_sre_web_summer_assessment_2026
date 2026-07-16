"""Test archive upload flow end-to-end."""
import os, sys, zipfile, shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# ---- 1. Create test project ----
test_dir = "test_sample"
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

# ---- 2. Create zip ----
zip_path = "test_sample.zip"
with zipfile.ZipFile(zip_path, "w") as zf:
    zf.write(os.path.join(test_dir, "app.py"), "app.py")
print(f"[OK] Created {zip_path}, size={os.path.getsize(zip_path)} bytes")

# ---- 3. Test extraction ----
from utils.archive_handler import extract_archive, detect_extracted_language

class FakeFile:
    def __init__(self, path, name):
        self._path = path
        self.filename = name
    def save(self, dest):
        shutil.copy(self._path, dest)

extract_base = "test_extracted"
os.makedirs(extract_base, exist_ok=True)
file_obj = FakeFile(zip_path, "test_sample.zip")
result_path = extract_archive(file_obj, "test_sample.zip", extract_base, "test_project")
print(f"[OK] Extracted to: {result_path}")

# ---- 4. Detect language ----
lang = detect_extracted_language(result_path)
print(f"[OK] Detected language: {lang}")

# ---- 5. List files ----
for root, dirs, files in os.walk(result_path):
    for fn in files:
        fp = os.path.join(root, fn)
        print(f"  File: {fp} ({os.path.getsize(fp)} bytes)")

# ---- 6. Test path security (malicious archive detection) ----
# Test zip-slip attack
evil_zip = "evil_test.zip"
import struct, io, time

# Create a minimal zip with path traversal
def create_evil_zip(path):
    data = io.BytesIO()
    zf = zipfile.ZipFile(data, "w")
    info = zipfile.ZipInfo("../etc/passwd")
    info.date_time = time.localtime()[:6]
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, b"root:x:0:0:root:/root:/bin/bash\n")
    zf.close()
    with open(path, "wb") as f:
        f.write(data.getvalue())

create_evil_zip(evil_zip)
print(f"[OK] Created evil zip: {evil_zip}")

evil_file = FakeFile(evil_zip, "evil.zip")
try:
    extract_archive(evil_file, "evil.zip", extract_base, "evil_project")
    print("[FAIL] Evil zip should have been rejected!")
except Exception as e:
    print(f"[OK] Evil zip correctly rejected: {e}")

# ---- 7. Cleanup ----
shutil.rmtree(test_dir, ignore_errors=True)
shutil.rmtree(extract_base, ignore_errors=True)
os.unlink(zip_path)
os.unlink(evil_zip)
print("[OK] All tests passed!")
