"""
AI 客户端模块（v3 — 基于 chatbox 核心 + 深度分析）
===============================================
封装 ai_chat_core 库，对上层提供统一的 AI 分析接口。

v3 新增：
  - 深度分析：形成原因（root_cause）、攻击方式（attack_analysis）、修复方案（fix_recommendation）
  - 结构化输出：CWE 编号、OWASP 分类、攻击场景列表
  - Payload 构建 + 验证一体化

核心类:
  - AIClient:      高层客户端
  - get_ai_client(): 工厂函数
  - reset_ai_client(): 刷新缓存
"""
import json
import re
from ai_chat_core.config import chat_request

from ai.prompts import (
    SYSTEM_PROMPT,
    ANALYSIS_PROMPT_TEMPLATE,
    BATCH_ANALYSIS_PROMPT,
    VULN_TYPE_LABELS,
    VULN_TYPE_DESCRIPTIONS,
    VERIFICATION_PROMPT_TEMPLATE,
)
from ai.settings_bridge import build_ai_chat_core


class AIClient:
    """
    AI 分析客户端（v3 — 深度分析版）
    ================================

    用法:
        client = AIClient(api_key="sk-xxx", base_url="...", model="...", provider="deepseek")
        if client.is_configured():
            result = client.analyze_single(vuln_dict, context_code)
            # result 包含 root_cause, attack_analysis, fix_recommendation
    """

    def __init__(self, api_key: str = "", base_url: str = "",
                 model: str = "", provider: str = "deepseek"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.provider = provider
        self._settings = None
        self._core = None

    def is_configured(self) -> bool:
        return bool(self.api_key and self.base_url and self.model)

    def _get_core(self):
        if self._core is None:
            from collections import namedtuple
            FakeSettings = namedtuple("FakeSettings", ["provider", "api_key", "base_url", "model"])
            self._settings = FakeSettings(
                provider=self.provider,
                api_key=self.api_key,
                base_url=self.base_url,
                model=self.model,
            )
            self._core = build_ai_chat_core(self._settings)
        return self._core

    # ================================================================
    # 单个漏洞深度分析
    # ================================================================

    def analyze_single(self, vuln: dict, context_code: str = "", php_version: str = "") -> dict | None:
        """
        单个漏洞深度分析（含形成原因、攻击方式、修复方案）。

        参数:
            vuln:         漏洞信息字典
            context_code: 漏洞上下文代码
            php_version:  PHP 版本（仅 PHP 项目），用于上下文分析

        返回结构:
        {
            is_vulnerable, severity, cwe_id, owasp_category,
            root_cause: { summary, detail, problem_line },
            attack_analysis: { discovery_method, attack_scenarios, waf_bypass },
            fix_recommendation: { primary, alternatives, security_notes }
        }
        """
        vuln_type = vuln.get("vuln_type", "")

        # 构建 PHP 版本上下文
        php_ctx = ""
        if php_version:
            from engine.rule_engine import RuleEngine
            eng = RuleEngine(php_version)
            version_ctx = eng.get_wide_byte_context()
            php_ctx = (
                f"- **目标 PHP 版本**：{php_version}\n"
                f"- **DSN charset 可靠性**：{'可信' if version_ctx['dsn_charset_trusted'] else '不可信（PHP < 5.3.6，DSN charset 被忽略）'}\n"
                f"- **mysql_* 函数状态**：{version_ctx['mysql_functions_status']}\n"
                f"- **preg_replace /e 状态**：{version_ctx['preg_replace_e_status']}\n"
            )

        prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            vuln_type_label=VULN_TYPE_LABELS.get(vuln_type, vuln_type),
            vuln_type=vuln_type,
            file_path=vuln.get("file_path", ""),
            language=vuln.get("language", ""),
            severity=vuln.get("severity", ""),
            description=VULN_TYPE_DESCRIPTIONS.get(vuln_type, ""),
            data_flow=vuln.get("data_flow", ""),
            source_code=vuln.get("source_code", ""),
            sink_code=vuln.get("sink_code", ""),
            pipeline_stage=vuln.get("pipeline_stage", ""),
            php_version_context=php_ctx,
            context_code=context_code,
        )
        return self._chat(prompt)

    # ================================================================
    # 批量漏洞分析
    # ================================================================

    def analyze_batch(self, vulns: list[dict],
                      context_codes: dict[str, str] | None = None) -> list[dict] | None:
        """批量深度分析"""
        if context_codes is None:
            context_codes = {}

        items = []
        for i, v in enumerate(vulns):
            vt = v.get("vuln_type", "")
            ctx = context_codes.get(str(i), "")
            items.append(
                f"### 漏洞 #{i}\n"
                f"- 类型：{VULN_TYPE_LABELS.get(vt, vt)} ({vt})\n"
                f"- 文件：{v.get('file_path', '')}\n"
                f"- 严重程度：{v.get('severity', '')}\n"
                f"- 数据流：{v.get('data_flow', '')}\n"
                f"```\n{ctx}\n```\n"
            )
        prompt = BATCH_ANALYSIS_PROMPT.format(items="\n---\n".join(items))
        result = self._chat(prompt)

        if isinstance(result, list):
            return result
        if isinstance(result, dict) and "id" in result:
            return [result]
        return None

    # ================================================================
    # Payload 构建 + 验证
    # ================================================================

    def verify_vulnerability(self, vuln: dict, payloads_text: str,
                             protection_level: str = "none",
                             exploit_difficulty: str = "unknown") -> dict | None:
        """
        验证单个漏洞是否可被利用。

        参数:
            vuln:               漏洞信息字典
            payloads_text:      预构建的 Payload 文本
            protection_level:   防护等级
            exploit_difficulty: 利用难度

        返回:
            dict: { verdict, confidence, exploit_payload, ... }
        """
        prompt = VERIFICATION_PROMPT_TEMPLATE.format(
            vuln_type=vuln.get("vuln_type", ""),
            file_path=vuln.get("file_path", ""),
            line_number=vuln.get("line_number", vuln.get("sink_line", 0)),
            source_code=vuln.get("source_code", ""),
            sink_code=vuln.get("sink_code", ""),
            data_flow=vuln.get("data_flow", ""),
            payloads=payloads_text,
            protection_level=protection_level,
            exploit_difficulty=exploit_difficulty,
        )
        return self._chat(prompt)

    # ================================================================
    # chatbox 原生漏洞检测
    # ================================================================

    def detect_vulnerabilities_with_ai(self, code: str, language: str) -> str:
        """chatbox 原生漏洞检测（直接分析代码）"""
        core = self._get_core()
        return core.detect_vulnerabilities(code=code, language=language, model=self.model)

    # ================================================================
    # 底层 HTTP 调用 + JSON 解析
    # ================================================================

    def _chat(self, prompt: str) -> dict | list | None:
        """底层 AI 调用，期望返回 JSON"""
        if not self.is_configured():
            print("[WARN] AI 未配置，请在设置页填入 API Key")
            return None

        try:
            core = self._get_core()
            response = core.chat(
                model=self.model,
                user_message=prompt,
                system_prompt=SYSTEM_PROMPT,
                temperature=0.3,
                max_tokens=4096,
            )
            return self._parse_json(response)
        except Exception as e:
            print(f"[ERROR] AI API 调用失败: {e}")
            return None

    def _chat_raw(self, prompt: str, system_prompt: str = "") -> str | None:
        """底层 AI 调用，返回原始文本（不解析 JSON）"""
        if not self.is_configured():
            return None
        try:
            core = self._get_core()
            return core.chat(
                model=self.model,
                user_message=prompt,
                system_prompt=system_prompt,
                temperature=0.3,
                max_tokens=256,
            )
        except Exception as e:
            print(f"[ERROR] AI API 调用失败: {e}")
            return None

    def _parse_json(self, text: str) -> dict | list | None:
        """从 AI 回复中提取 JSON（多策略兼容 + 自动修复）"""
        if not text:
            return None
        text = text.strip()

        # 策略 1：直接解析
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass

        # 策略 2：从 ```json ... ``` 代码块提取
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except (json.JSONDecodeError, ValueError):
                pass

        # 策略 3：括号计数提取（处理尾部文字）
        for open_char, close_char in [("{", "}"), ("[", "]")]:
            start = text.find(open_char)
            if start == -1:
                continue
            depth = 0
            for i in range(start, len(text)):
                if text[i] == open_char:
                    depth += 1
                elif text[i] == close_char:
                    depth -= 1
                    if depth == 0:
                        candidate = text[start:i+1]
                        try:
                            return json.loads(candidate)
                        except (json.JSONDecodeError, ValueError):
                            # 尝试修复后再解析
                            fixed = self._repair_json(candidate)
                            if fixed:
                                return fixed
                        break

        # 策略 4：修复常见 JSON 问题后再解析
        fixed = self._repair_json(text)
        if fixed:
            return fixed

        print(f"[WARN] 无法解析 AI 返回: {text[:200]}...")
        return None

    @staticmethod
    def _repair_json(text: str) -> dict | list | None:
        """尝试修复 AI 返回的格式有问题的 JSON"""
        if not text:
            return None
        # 1. 移除尾部逗号（JSON 不允许 trailing comma）
        repaired = re.sub(r',\s*}', '}', text)
        repaired = re.sub(r',\s*]', ']', repaired)
        # 2. 移除单行注释 // ... 到行尾
        repaired = re.sub(r'//[^\n]*', '', repaired)
        # 3. 移除多行注释 /* ... */
        repaired = re.sub(r'/\*[\s\S]*?\*/', '', repaired)
        try:
            return json.loads(repaired)
        except (json.JSONDecodeError, ValueError):
            return None


# ============================================================================
# 工厂函数
# ============================================================================

_client_cache: AIClient | None = None


def get_ai_client() -> AIClient:
    """获取 AI 客户端实例（带 DB 配置缓存）"""
    global _client_cache
    from models import AISettings

    try:
        settings = AISettings.get()
    except Exception:
        return AIClient()

    if _client_cache is None or (
        _client_cache.api_key != settings.api_key or
        _client_cache.base_url != settings.base_url or
        _client_cache.model != settings.model
    ):
        _client_cache = AIClient(
            api_key=settings.api_key,
            base_url=settings.base_url,
            model=settings.model,
            provider=settings.provider,
        )
    return _client_cache


def reset_ai_client():
    """刷新客户端缓存"""
    global _client_cache
    _client_cache = None
