"""
沙箱执行器（动态验证基础设施）
============================
把被扫描项目复制到临时目录并作为本地子进程启动，供 AI 通过 MCP 工具
（run_target_app / send_http_request）发送真实攻击请求，用响应判定漏洞。

安全边界（当前实现）：
- 项目复制到临时目录执行，不修改原文件
- 只监听 127.0.0.1，随机空闲端口
- 请求/启动均有超时，进程树可终止
- 被扫描代码以子进程在当前用户权限下运行，但只监听 127.0.0.1 随机端口、
  有超时保护，退出自动清理。平台定位是正常代码漏洞检测，沙箱仅用于实证
  漏洞（发出真实攻击请求验证响应），此边界对正常业务代码足够。
  若未来要扫描真正恶意的第三方项目，再考虑 Docker 隔离（本机已装）。
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path

STARTUP_TIMEOUT = 40        # 应用启动最长等待（秒）
REQUEST_TIMEOUT = 12        # 单次 HTTP 请求超时（秒）
DEPS_TIMEOUT = 180          # 单个依赖安装超时（秒）
MAX_MISSING_DEPS = 3        # 最多自动补装几个缺失模块
PORT_RANGE = (5100, 5199)   # 沙箱端口范围（避开平台自身的 5000）
# 依赖安装镜像（国内网络下 PyPI 直连经常超时；官方源可用时置空即可）
PIP_INDEX_URL = os.environ.get("SANDBOX_PIP_INDEX_URL",
                                "https://pypi.tuna.tsinghua.edu.cn/simple")
# 导入名 → PyPI 包名映射（import yaml 对应 PyYAML 等）
IMPORT_TO_PIP = {
    "yaml": "PyYAML",
    "jwt": "PyJWT",
    "cv2": "opencv-python-headless",
    "bs4": "beautifulsoup4",
    "PIL": "Pillow",
    "sklearn": "scikit-learn",
    "dotenv": "python-dotenv",
    "MySQLdb": "mysqlclient",
    "yaml": "PyYAML",
}
_DEPS_CACHE = Path(tempfile.gettempdir()) / "sandbox_deps"

LAUNCHER = '''\
"""沙箱启动器：加载目标应用的 app 对象并以指定端口启动。"""
import importlib.util
import os

ENTRY = {entry!r}
PORT = int(os.environ.get("SANDBOX_PORT", "5100"))

spec = importlib.util.spec_from_file_location("target_app", ENTRY)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

app = getattr(m, "app", None)
if app is None:
    factory = getattr(m, "create_app", None)
    app = factory() if factory else None
if app is None:
    raise RuntimeError("未找到 Flask app 对象（app 或 create_app）")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False, use_reloader=False)
'''


def _free_port() -> int:
    for port in range(*PORT_RANGE):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("沙箱端口耗尽")


class SandboxApp:
    """被扫描应用的一次沙箱运行实例"""

    def __init__(self, project_path: str):
        self.project_path = str(project_path)
        self.tmpdir: str | None = None
        self.proc: subprocess.Popen | None = None
        self.port: int | None = None
        self._entry: str | None = None

    # ------------------------------------------------------------------

    def start(self) -> dict:
        """启动沙箱应用，返回 {success, port, entry, error}。"""
        if self.proc and self.proc.poll() is None:
            return {"success": True, "port": self.port,
                    "entry": self._entry, "error": ""}

        entry = self._find_entry()
        if not entry:
            return {"success": False, "port": None, "entry": "",
                    "error": "未找到可启动入口（需要 Flask 的 run.py/app.py 且含 app 或 create_app）"}

        port = _free_port()
        self.tmpdir = tempfile.mkdtemp(prefix="sandbox_")
        dst = Path(self.tmpdir) / "project"
        shutil.copytree(self.project_path, dst,
                        ignore=shutil.ignore_patterns(
                            ".git", "__pycache__", "venv", "env",
                            "node_modules", ".venv"))
        (dst / "sandbox_launcher.py").write_text(
            LAUNCHER.format(entry=entry), encoding="utf-8")

        env = dict(os.environ)
        env["SANDBOX_PORT"] = str(port)
        env["PYTHONUNBUFFERED"] = "1"

        # 启动 + 按需补装缺失模块（最多 MAX_MISSING_DEPS 个）
        deps_dirs: list[str] = []
        last_out = ""
        for _attempt in range(MAX_MISSING_DEPS + 1):
            if deps_dirs:
                env["PYTHONPATH"] = os.pathsep.join(deps_dirs) + \
                    os.pathsep + env.get("PYTHONPATH", "")
            self.proc = subprocess.Popen(
                [sys.executable, "sandbox_launcher.py"],
                cwd=str(dst),
                env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=(subprocess.CREATE_NO_WINDOW
                               if os.name == "nt" else 0),
            )
            self.port = port
            self._entry = entry

            deadline = time.time() + STARTUP_TIMEOUT
            ready = False
            while time.time() < deadline:
                if self.proc.poll() is not None:
                    last_out = (self.proc.stdout.read().decode(
                        "utf-8", errors="ignore") if self.proc.stdout else "")
                    break
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/", timeout=2) as resp:
                        resp.status  # noqa: B018 任意状态码都算已监听
                    ready = True
                    break
                except urllib.error.HTTPError:
                    ready = True  # 404/500 也说明服务已起来
                    break
                except Exception:
                    time.sleep(0.5)
            if ready:
                return {"success": True, "port": port, "entry": entry,
                        "error": ""}

            # 启动失败：解析缺失模块，按需补装后重试
            m = re.search(
                r"ModuleNotFoundError: No module named '([\w.]+)'", last_out)
            if not m:
                break
            mod = m.group(1).split(".")[0]
            new_dir = self._install_one(mod)
            if not new_dir:
                break
            deps_dirs.append(new_dir)
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                pass
            self.proc = None

        self.stop()
        return {"success": False, "port": None, "entry": entry,
                "error": f"应用启动失败: {last_out[-800:]}"}

    def request(self, method: str, path: str, params: dict | None = None,
                data: str | None = None,
                headers: dict | None = None) -> dict:
        """向沙箱应用发一次 HTTP 请求，返回响应摘要。"""
        if not self.proc or self.proc.poll() is not None:
            return {"success": False, "error": "应用未运行，请先 run_target_app"}
        url = f"http://127.0.0.1:{self.port}{path if path.startswith('/') else '/' + path}"
        if params:
            import urllib.parse
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method=method.upper(),
                                     data=(data or "").encode("utf-8") if data else None,
                                     headers=headers or {})
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                body = resp.read(8192).decode("utf-8", errors="ignore")
                return {"success": True, "status": resp.status,
                        "headers": {k.lower(): v for k, v in resp.headers.items()},
                        "body": body, "elapsed_ms": int((time.time() - t0) * 1000)}
        except urllib.error.HTTPError as e:
            body = e.read(8192).decode("utf-8", errors="ignore")
            return {"success": True, "status": e.code,
                    "headers": {k.lower(): v for k, v in e.headers.items()},
                    "body": body, "elapsed_ms": int((time.time() - t0) * 1000)}
        except Exception as e:
            return {"success": False, "error": f"请求失败: {e}"}

    def stop(self) -> dict:
        """终止沙箱应用并清理临时目录。"""
        stopped = False
        if self.proc:
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                stopped = True
            except Exception:
                pass
            self.proc = None
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
            self.tmpdir = None
        self.port = None
        return {"success": stopped}

    # ------------------------------------------------------------------

    def _install_one(self, module: str) -> str:
        """按需安装单个缺失模块（binary-only，最新版），缓存目录返回。"""
        pkg = IMPORT_TO_PIP.get(module, module)
        cached = _DEPS_CACHE / f"mod_{pkg}"
        if not (cached / "done.marker").exists():
            cached.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg,
                     "--target", str(cached), "--quiet",
                     "--only-binary=:all:",
                     "--disable-pip-version-check",
                     "-i", PIP_INDEX_URL],
                    timeout=DEPS_TIMEOUT, check=True,
                    creationflags=(subprocess.CREATE_NO_WINDOW
                                   if os.name == "nt" else 0),
                )
                (cached / "done.marker").touch()
            except Exception:
                shutil.rmtree(cached, ignore_errors=True)
                return ""
        return str(cached)

    def _find_entry(self) -> str:
        """找 Flask 启动入口：优先含 app.run 的文件。"""
        root = Path(self.project_path)
        candidates = ["run.py", "app.py", "main.py", "wsgi.py",
                      "application.py", "server.py"]
        for name in candidates:
            p = root / name
            if not p.is_file():
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
            if ("app.run" in text or "create_app" in text
                    or "= Flask(" in text):
                return str(p)
        # 兜底：任意第一层 .py 中含 create_app / Flask(
        for p in sorted(root.glob("*.py")):
            text = p.read_text(encoding="utf-8", errors="ignore")
            if "create_app" in text or "= Flask(" in text:
                return str(p)
        return ""
