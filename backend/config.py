"""
Flask 应用配置文件
===============
加载环境变量，定义全局配置常量。

配置项说明：
  - SECRET_KEY:              Flask 密钥，用于 session 签名
  - SQLALCHEMY_DATABASE_URI: SQLite 数据库文件路径
  - DEEPSEEK_*:              DeepSeek AI API 连接参数（也可用于 OpenAI 兼容接口）
  - MAX_UPLOAD_SIZE_MB:      源码上传大小上限
  - UPLOAD_FOLDER:           临时上传目录
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# 加载 .env 文件中的环境变量（优先级高于系统环境变量）
load_dotenv()

# 项目根目录（backend/ 目录）
BASE_DIR = Path(__file__).resolve().parent

# Docker 部署时可通过 DATA_DIR 将数据库/上传/解压统一挂载到外部卷
# 不设置则默认放在 backend/ 下
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR)))


class Config:
    """Flask 应用配置类，所有配置集中管理"""

    # ---- Flask 核心 ----
    # 生产环境务必通过环境变量覆盖此默认密钥
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # SQLite 数据库文件
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATA_DIR / 'audit.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # 关闭修改追踪，节省内存

    # ---- DeepSeek AI API（兼容 OpenAI 接口） ----
    # 可通过环境变量覆盖，也可在 Web 设置页面动态修改（存入数据库）
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    # ---- 上传 / 扫描限制 ----
    MAX_UPLOAD_SIZE_MB = 100  # 单次上传的压缩包最大 100MB
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # Flask 请求体上限 (bytes)
    UPLOAD_FOLDER = DATA_DIR / "uploads"  # 上传文件临时存放目录
    EXTRACT_FOLDER = DATA_DIR / "extracted"  # 解压后的项目源码目录
