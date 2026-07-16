"""
数据模型定义
===========
provider_config: AI 提供方连接配置
chat_request:   一次对话请求的所有参数
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass(frozen=True)
class provider_config:
    """
    AI 提供方连接配置（不可变）
    =========================
    
    provider_id:     提供方标识（如 "deepseek", "openai", "custom"）
    api_key:         API 密钥
    base_url:        API 基础地址（不包含 /chat/completions 路径）
    default_headers: 额外 HTTP 请求头
    """
    provider_id: str
    api_key: str
    base_url: str
    default_headers: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class chat_request:
    """
    一次 Chat Completion 请求（不可变）
    ==================================
    
    model:          模型名称（如 "deepseek-chat", "gpt-4o"）
    user_message:   用户消息内容
    system_prompt:  系统提示词（可选）
    temperature:    采样温度（可选，0~2）
    max_tokens:     最大输出 token 数（可选）
    stream:         是否开启流式输出
    """
    model: str
    user_message: str
    system_prompt: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: bool = True
