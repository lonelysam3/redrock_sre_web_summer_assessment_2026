"""
模型路由器
=========
根据模型名称前缀自动将请求分发到对应的 AI 提供方。

用法示例:
    router = model_router(
        providers={"deepseek": ds_config, "openai": oai_config},
        routes=[
            model_route("deepseek-", "deepseek"),  # deepseek-* → DeepSeek
            model_route("gpt-", "openai"),          # gpt-* → OpenAI
            model_route("o", "openai"),             # o1, o3... → OpenAI
        ],
    )
    provider = router.resolve_provider("gpt-4o")   # → openai 的 provider
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from .config import provider_config
from .providers import open_ai_compatible_provider


@dataclass
class model_route:
    """
    模型路由规则
    ============
    model_prefix: 模型名前缀（如 "deepseek-", "gpt-"）
    provider_id:  匹配后使用哪个 provider
    """
    model_prefix: str
    provider_id: str


class model_router:
    """
    模型路由器
    =========
    维护多个 provider 和路由规则，
    根据模型名称自动选择正确的 provider 发起请求。

    路由策略：
      1. 如果调用时显式传入了 provider_id，直接使用
      2. 否则按路由规则列表顺序匹配模型名前缀
      3. 都不匹配则报错
    """

    def __init__(self, providers: Dict[str, provider_config], routes: Optional[list[model_route]] = None):
        """
        初始化路由器

        参数:
            providers: provider_id → provider_config 的映射
            routes:    路由规则列表（按优先级排列）
        """
        self.providers = providers
        self.routes = routes or []

    def resolve_provider(self, model: str, provider_id: Optional[str] = None) -> open_ai_compatible_provider:
        """
        根据模型名解析对应的 provider。

        参数:
            model:       模型名称
            provider_id: 显式指定的 provider（优先级高于路由规则）

        返回:
            open_ai_compatible_provider 实例

        异常:
            ValueError: 无法确定 provider 或 provider_id 未知
        """
        resolved = provider_id  # 显式指定优先

        if not resolved:
            # 按路由规则匹配模型前缀
            for route in self.routes:
                if model.startswith(route.model_prefix):
                    resolved = route.provider_id
                    break

        if not resolved:
            raise ValueError("No provider_id given and no matching model route found")

        config = self.providers.get(resolved)
        if not config:
            raise ValueError(f"Unknown provider_id: {resolved}")

        return open_ai_compatible_provider(config)
