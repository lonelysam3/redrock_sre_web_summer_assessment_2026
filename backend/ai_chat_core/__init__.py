"""
AI Chat Core — 通用 AI 对话核心库
================================
来源：https://github.com/lonelysam3/chatbox

提供以下能力：
  - 多 Provider 抽象（OpenAI 兼容 API）
  - 模型路由（按前缀自动分发到不同 provider）
  - 流式和非流式 Chat Completion
  - 内置代码漏洞检测（AI-based vulnerability detection）
  - JSON 文件持久化配置管理

本包作为代码审计平台的 AI 基础设施层，
被 backend/ai/client.py 封装调用。
"""
from .config import chat_request, provider_config
from .core import ai_chat_core
from .router import model_route, model_router
from .service import ai_chat_service
from .settings import runtime_settings

__all__ = [
    "ai_chat_core",
    "ai_chat_service",
    "chat_request",
    "provider_config",
    "model_route",
    "model_router",
    "runtime_settings",
]
