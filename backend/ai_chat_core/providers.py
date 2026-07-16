"""
AI Provider 实现（OpenAI 兼容 API）
=================================
封装 HTTP 调用，支持 OpenAI 兼容的 Chat Completion API。

特性：
  - 非流式调用：create_chat_completion()，返回完整响应
  - 流式调用：  stream_chat_completion()，逐 token 产出（SSE 解析）
  - 超时保护：  非流式 120s，流式 300s
  - 使用标准库 urllib，零额外依赖
"""
from __future__ import annotations

import json
from typing import Dict, Iterable, List
from urllib import error, request

from .config import chat_request, provider_config


class provider_api_error(RuntimeError):
    """Provider API 调用异常，包装 HTTP 错误和连接错误"""
    pass


class open_ai_compatible_provider:
    """
    OpenAI 兼容的 Chat Completion Provider
    ======================================
    封装了 HTTP 认证、Payload 构建、SSE 流解析等逻辑。

    用法:
        config = provider_config(provider_id="deepseek", api_key="sk-xxx",
                                 base_url="https://api.deepseek.com")
        provider = open_ai_compatible_provider(config)
        reply = provider.create_chat_completion(chat_request(
            model="deepseek-chat",
            user_message="Hello",
        ))
    """

    def __init__(self, config: provider_config):
        self.config = config

    def _headers(self) -> Dict[str, str]:
        """
        构建 HTTP 请求头。
        使用 Bearer Token 认证 + JSON Content-Type。
        可叠加 provider 自定义的 default_headers。
        """
        headers = {
            "Authorization": "Bearer " + self.config.api_key,
            "Content-Type": "application/json",
        }
        headers.update(self.config.default_headers)
        return headers

    def _build_payload(self, request_data: chat_request) -> Dict[str, object]:
        """
        构建 Chat Completion 的 JSON 请求体。

        消息结构:
          - System Prompt（如果提供）→ role: "system"
          - User Message             → role: "user"

        参数:
            request_data: chat_request 实例

        返回:
            JSON 序列化就绪的字典
        """
        messages: List[Dict[str, str]] = []
        if request_data.system_prompt:
            messages.append({"role": "system", "content": request_data.system_prompt})
        messages.append({"role": "user", "content": request_data.user_message})

        payload: Dict[str, object] = {
            "model": request_data.model,
            "messages": messages,
            "stream": request_data.stream,
        }
        # 可选参数：仅在显式设置时添加
        if request_data.temperature is not None:
            payload["temperature"] = request_data.temperature
        if request_data.max_tokens is not None:
            payload["max_tokens"] = request_data.max_tokens

        return payload

    def create_chat_completion(self, request_data: chat_request) -> str:
        """
        非流式 Chat Completion 调用。

        发送请求后等待完整响应，返回 AI 回复文本。

        参数:
            request_data: chat_request（stream 会被强制设为 False）

        返回:
            str: AI 回复的纯文本内容

        异常:
            provider_api_error: HTTP 错误 / 连接失败 / 响应格式异常
        """
        # 强制关闭流式模式
        payload = self._build_payload(chat_request(**{**request_data.__dict__, "stream": False}))

        endpoint = f"{self.config.base_url.rstrip('/')}/chat/completions"
        req = request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=120) as res:
                body = json.loads(res.read().decode("utf-8"))
        except error.HTTPError as exc:
            raise provider_api_error(
                f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='ignore')}"
            ) from exc
        except error.URLError as exc:
            raise provider_api_error(f"Connection failed: {exc.reason}") from exc

        # 从标准 OpenAI 响应格式中提取内容
        try:
            return body["choices"][0]["message"]["content"]
        except Exception as exc:
            raise provider_api_error(f"Unexpected response format: {body}") from exc

    def stream_chat_completion(self, request_data: chat_request) -> Iterable[str]:
        """
        流式 Chat Completion 调用。

        解析 SSE (Server-Sent Events) 格式的流数据，
        逐 chunk 产出 AI 回复文本。

        参数:
            request_data: chat_request（stream 会被强制设为 True）

        产出:
            Iterable[str]: 每个 chunk 是一个文本片段（通常几个 token）

        流格式:
            data: {"choices":[{"delta":{"content":"Hello"}}]}
            data: {"choices":[{"delta":{"content":" world"}}]}
            data: [DONE]

        异常:
            provider_api_error: HTTP 错误 / 连接失败
        """
        payload = self._build_payload(chat_request(**{**request_data.__dict__, "stream": True}))

        endpoint = f"{self.config.base_url.rstrip('/')}/chat/completions"
        req = request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=300) as res:  # 流式超时更长（300s）
                for raw_line in res:
                    line = raw_line.decode("utf-8", errors="ignore").strip()

                    # SSE 格式：每行以 "data:" 开头
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()

                    # 流结束信号
                    if data == "[DONE]":
                        break

                    try:
                        chunk = json.loads(data)
                        delta = chunk["choices"][0]["delta"].get("content")
                        if delta:
                            yield delta
                    except Exception:
                        continue  # 忽略无法解析的 chunk
        except error.HTTPError as exc:
            raise provider_api_error(
                f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='ignore')}"
            ) from exc
        except error.URLError as exc:
            raise provider_api_error(f"Connection failed: {exc.reason}") from exc
