"""
配置桥接模块
===========
在数据库配置（models.AISettings）和 chatbox 核心（ai_chat_core）之间做适配。

职责:
  1. 从数据库读取配置 → 转为 chatbox 的 provider_config
  2. 构建 ai_chat_core 实例（含模型路由）
  3. 维护客户端实例缓存，配置变更时自动重建
"""
from ai_chat_core.config import provider_config
from ai_chat_core.core import ai_chat_core
from ai_chat_core.router import model_route, model_router


def build_provider_config(settings) -> provider_config:
    """
    从数据库 AISettings 对象构建 chatbox 的 provider_config。

    参数:
        settings: models.AISettings 实例

    返回:
        provider_config: chatbox 的提供方配置
    """
    return provider_config(
        provider_id=settings.provider or "deepseek",
        api_key=settings.api_key or "",
        base_url=settings.base_url or "https://api.deepseek.com",
    )


def build_ai_chat_core(settings) -> ai_chat_core:
    """
    从数据库配置构建完整的 ai_chat_core 实例。

    路由规则:
      - deepseek-* → 默认 provider
      - gpt-*      → 默认 provider
      - o1/o3/...  → 默认 provider

    参数:
        settings: models.AISettings 实例

    返回:
        ai_chat_core: 可立即使用的 AI 对话核心
    """
    provider_id = settings.provider or "deepseek"
    providers = {
        provider_id: build_provider_config(settings),
    }
    router = model_router(
        providers=providers,
        routes=[
            model_route("deepseek-", provider_id),
            model_route("gpt-", provider_id),
            model_route("o", provider_id),
        ],
    )
    return ai_chat_core(router)
