"""
AI 对话核心
===========
提供高层 API：非流式聊天、流式聊天、代码漏洞检测。

基于 model_router + open_ai_compatible_provider 构建。

核心方法：
  - chat():                 普通对话（非流式）
  - chat_stream():          流式对话（逐 token 产出）
  - detect_vulnerabilities(): AI 代码漏洞检测
"""
from __future__ import annotations

from typing import Iterable, Optional

from .config import chat_request
from .router import model_router


class ai_chat_core:
    """
    AI 对话核心
    ===========
    封装了完整的 AI 调用流水线：

      model → router.resolve_provider() → provider.create_chat_completion()
                                          → provider.stream_chat_completion()

    用法:
        core = ai_chat_core(router)
        reply = core.chat(model="deepseek-chat", user_message="Hello")
        for chunk in core.chat_stream(model="deepseek-chat", user_message="Hi"):
            print(chunk, end="")
        result = core.detect_vulnerabilities(code="...", language="python", model="deepseek-chat")
    """

    def __init__(self, router: model_router):
        self.router = router

    def chat(
        self,
        *,
        model: str,
        user_message: str,
        provider_id: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        非流式对话：发送消息，等待完整回复。

        参数:
            model:          模型名称（如 "deepseek-chat"）
            user_message:   用户消息
            provider_id:    显式指定 provider（可选，默认按模型路由）
            system_prompt:  系统提示词（可选）
            temperature:    采样温度（可选，0~2）
            max_tokens:     最大输出 token 数（可选）

        返回:
            str: AI 完整回复
        """
        provider = self.router.resolve_provider(model=model, provider_id=provider_id)
        request = chat_request(
            model=model,
            user_message=user_message,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=False,
        )
        return provider.create_chat_completion(request)

    def chat_stream(
        self,
        *,
        model: str,
        user_message: str,
        provider_id: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Iterable[str]:
        """
        流式对话：逐 token 产出回复（实时打字效果）。

        参数同 chat()。

        产出:
            Iterable[str]: 每个 chunk 是一个文本片段
        """
        provider = self.router.resolve_provider(model=model, provider_id=provider_id)
        request = chat_request(
            model=model,
            user_message=user_message,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
        )
        return provider.stream_chat_completion(request)

    def detect_vulnerabilities(
        self,
        *,
        code: str,
        language: str,
        model: str,
        provider_id: Optional[str] = None,
    ) -> str:
        """
        AI 代码漏洞检测（AI-based vulnerability detection）

        ===== 工作原理 =====

        构造专业的 Security Review Prompt，包含：
          1. 角色设定：资深应用安全专家
          2. 输出格式要求：Summary / Findings / Fix Recommendations
          3. 代码上下文（语言 + 源代码）
          4. 严重程度分级：CRITICAL / HIGH / MEDIUM / LOW
          5. CWE 编号引用

        参数:
            code:        待检测的源代码
            language:    编程语言（python / c / cpp / ...）
            model:       使用的 AI 模型
            provider_id: 显式指定 provider（可选）

        返回:
            str: AI 的安全分析报告（Markdown 格式）
        """
        prompt = (
            "You are a senior application security reviewer. "
            "Analyze the provided code for real, exploitable vulnerabilities only. "
            "Return markdown with sections: Summary, Findings, and Fix Recommendations. "
            "For each finding include severity (CRITICAL/HIGH/MEDIUM/LOW), CWE if known, "
            "affected snippet reference, exploit scenario, and concrete remediation.\n\n"
            f"Language: {language}\n"
            "Code:\n"
            f"{code}"
        )
        return self.chat(
            model=model,
            provider_id=provider_id,
            user_message=prompt,
            system_prompt="Focus on security issues. Do not report style or non-security comments.",
        )
