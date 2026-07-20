# ============================================================
# RedRock Code Audit Platform — Docker 镜像
# ============================================================
FROM python:3.12-slim

LABEL org.opencontainers.image.title="RedRock Code Audit Platform"
LABEL org.opencontainers.image.description="四级流水线静态分析 + AI 深度验证的源码安全审计引擎"

# ---- 系统依赖 ----
# gcc / libc-dev: tree-sitter 编译原生扩展需要
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# ---- 应用目录 ----
WORKDIR /app

# ---- Python 依赖（分层缓存）----
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- 生产级 WSGI（轻量纯 Python）----
RUN pip install --no-cache-dir waitress>=3.0

# ---- 源码 ----
COPY backend/ ./backend/

# ---- 环境变量 ----
ENV PORT=5000
ENV DATA_DIR=/app/data
ENV PYTHONUNBUFFERED=1

RUN mkdir -p /app/data/uploads /app/data/extracted

EXPOSE 5000

# ---- 启动 ----
WORKDIR /app/backend
CMD ["python", "wsgi.py"]
