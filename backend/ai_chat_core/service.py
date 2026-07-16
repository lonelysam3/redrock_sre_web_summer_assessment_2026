"""
AI 服务层
=========
将 settings、router、core 串联为统一的服务接口。

对上提供简洁的 chat() / detect_vulnerabilities() API。
对下管理配置的加载/保存/更新。

是被 app.py、web.py 以及我们的 Flask 应用调用的统一入口。
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Optional

from .config import provider_config
from .core import ai_chat_core
from .router import model_route, model_router
from .settings import (
    runtime_settings,
    load_settings,
    mask_api_key,
    resolve_settings_path,
    save_settings,
    update_settings,
)


class ai_chat_service:
    """
    AI 对话服务
    ===========
    整合了配置管理 + 模型路由 + 对话调用。

    用法:
        service = ai_chat_service(settings_path="/path/to/settings.json")
        reply = service.chat(message="Hello")
        report = service.detect_vulnerabilities(code="...", language="python")
    """

    def __init__(self, settings_path: str | None = None):
        """
        初始化服务：加载配置。

        参数:
            settings_path: 自定义配置文件路径（可选）
        """
        self.settings_path = resolve_settings_path(settings_path)
        self.settings = load_settings(self.settings_path)

    def _build_core(self) -> ai_chat_core:
        """
        构建 ai_chat_core 实例（含 router 和 provider）。

        每次调用都重建，确保使用最新配置。
        路由规则：
          - gpt-* / o* → 默认 provider
          - claude-*   → 默认 provider
          （目前所有模型都路由到同一个 provider，未来可扩展多 provider）
        """
        providers = {
            self.settings.provider_id: provider_config(
                provider_id=self.settings.provider_id,
                api_key=self.settings.api_key,
                base_url=self.settings.base_url,
            )
        }
        router = model_router(
            providers=providers,
            routes=[
                model_route("gpt-", self.settings.provider_id),
                model_route("o", self.settings.provider_id),
                model_route("claude-", self.settings.provider_id),
            ],
        )
        return ai_chat_core(router)

    def get_public_settings(self) -> Dict[str, Any]:
        """
        获取公开可见的配置信息（API Key 脱敏）。

        返回:
            dict: { provider_id, base_url, default_model, api_key_masked, settings_path }
        """
        return {
            "provider_id": self.settings.provider_id,
            "base_url": self.settings.base_url,
            "default_model": self.settings.default_model,
            "api_key_masked": mask_api_key(self.settings.api_key),
            "settings_path": str(self.settings_path),
        }

    def replace_settings(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        替换/更新配置并持久化。

        参数:
            payload: 部分配置字段字典

        返回:
            dict: 更新后的公开配置
        """
        self.settings = update_settings(self.settings, payload)
        save_settings(self.settings_path, self.settings)
        return self.get_public_settings()

    def chat(
        self,
        *,
        message: str,
        model: Optional[str] = None,
        provider_id: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        发送对话消息。

        参数:
            message:       用户消息（必需）
            model:         模型名称（默认使用配置中的 default_model）
            provider_id:   显式指定 provider（可选）
            system_prompt: 系统提示词（可选）
            temperature:   采样温度（可选）
            max_tokens:    最大 token 数（可选）

        返回:
            str: AI 回复

        异常:
            ValueError: message 为空
        """
        if not message.strip():
            raise ValueError("message is required")
        core = self._build_core()
        return core.chat(
            model=model or self.settings.default_model,
            user_message=message,
            provider_id=provider_id,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def detect_vulnerabilities(
        self,
        *,
        code: str,
        language: str = "unknown",
        model: Optional[str] = None,
        provider_id: Optional[str] = None,
    ) -> str:
        """
        AI 代码漏洞检测。

        参数:
            code:        待检测的源代码（必需）
            language:    编程语言
            model:       模型名称（默认使用配置中的 default_model）
            provider_id: 显式指定 provider（可选）

        返回:
            str: AI 安全分析报告（Markdown 格式）

        异常:
            ValueError: code 为空
        """
        if not code.strip():
            raise ValueError("code is required")
        core = self._build_core()
        return core.detect_vulnerabilities(
            code=code,
            language=language,
            model=model or self.settings.default_model,
            provider_id=provider_id,
        )

    def export_settings(self) -> runtime_settings:
        """导出当前配置"""
        return runtime_settings(**asdict(self.settings))

    @property
    def path(self) -> Path:
        """当前配置文件路径"""
        return self.settings_path
