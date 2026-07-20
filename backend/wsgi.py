"""
Docker 入口 — 使用 Waitress 生产级 WSGI 服务器启动应用。
与 `python app.py` 等价，但适合容器化部署。
"""
import os
from waitress import serve
from app import create_app

app = create_app()
port = int(os.getenv("PORT", "5000"))

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=port)
