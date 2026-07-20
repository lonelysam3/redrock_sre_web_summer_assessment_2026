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

# ============================================================================
# 验证 + 自动修复 Prompt
# ============================================================================

VERIFY_AND_FIX_SYSTEM_PROMPT = """你是一名资深渗透测试专家 + 安全修复工程师。

## 你的任务

1. **验证漏洞** — 使用工具深入探索源码，判断漏洞是否真实可利用
2. **生成 Payload** — 如果确认漏洞，给出精准的攻击载荷
3. **自动修复** — 使用 apply_code_fix 工具直接将修复代码写入源文件

## 工作流程

1. 先调用 search_dangerous_calls 定位所有危险函数
2. 调用 search_user_inputs 定位所有用户输入入口
3. 调用 trace_variable_flow 追踪关键变量的传播路径
4. 调用 read_file_region 读取关键代码上下文
5. 调用 search_project 跨文件搜索相关配置（如 WAF、过滤器）
6. 综合分析后：
   - 调用 apply_code_fix 应用修复代码
   - 输出最终 JSON 判定结果

## apply_code_fix 用法

修复代码后立即调用 apply_code_fix：
- file_path: 要修复的文件路径
- start_line/end_line: 需要替换的行范围
- new_code: 修复后的完整代码（保持原有缩进）

示例：将第 45-47 行的不安全 SQL 拼接替换为参数化查询

## 判定标准

- **confirmed**: 数据流完整、无可行的安全控制、Payload 确定可触发
- **potential**: 存在风险但缺少关键证据（如不确定 WAF 配置）
- **false_positive**: 代码有有效安全控制（参数化查询/白名单/强类型校验）

## 修复代码要求

- 使用 apply_code_fix 直接修改源文件
- 保持原有代码风格和缩进
- 使用最佳安全实践（参数化查询、输入校验、输出编码等）
- 如果是 PHP，考虑目标版本的特性
- 修复后输出 JSON 结果，fix_code 字段包含你应用的完整修复代码

## 重要

不要重复基础分析！如果漏洞已有 AI 分析结果（在上下文提供），直接基于它验证，
不要再分析漏洞成因。专注于验证和修复，并实际应用修复。"""

VERIFY_AND_FIX_TEMPLATE = """## 漏洞验证 + 修复任务

### 基本信息
- **类型**: {vuln_type_label}（{vuln_type}）
- **文件**: {file_path}
- **语言**: {language}
- **初步严重程度**: {severity}
- **发现阶段**: {pipeline_stage}
{php_version_context}

### 源码入口（Source）
```
{source_code}
```

### 危险函数（Sink）
```
{sink_code}
```

### 数据流路径
```
{data_flow}
```

### 已有 AI 分析结果
{ai_analysis}

### 额外代码上下文
```
{context_code}
```

### 漏洞类型说明
{description}

---

请使用工具探索代码，验证漏洞是否真实。确认后先调用 apply_code_fix 应用修复，再输出 JSON：

```json
{{
    "verdict": "confirmed|potential|false_positive",
    "confidence": 0.0-1.0,
    "exploit_payload": "最有效的攻击 Payload",
    "payload_effect": "Payload 的预期效果",
    "evidence": "验证证据（3-5 句话，引用具体的行号和代码）",
    "fix_code": "你通过 apply_code_fix 应用的完整修复代码",
    "fix_description": "修复说明（为什么这样修复，还有其他备选方案吗）"
}}
```
"""

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
    # 带 MCP 工具调用的深度分析
    # ================================================================

    def analyze_single_with_tools(
        self, vuln: dict, context_code: str = "",
        php_version: str = "", project_path: str = "",
        max_tool_rounds: int = 3,
    ) -> dict | None:
        """
        使用 MCP 工具进行交互式深度分析。

        AI 可以调用 search_dangerous_calls、search_user_inputs、
        trace_variable_flow 等工具自主探索源码，发现更多漏洞上下文。

        流程:
          1. 发送分析 prompt + 工具说明
          2. AI 回复中可能包含 tool_calls
          3. 执行工具调用，将结果反馈给 AI
          4. 循环直到 AI 不再请求工具或达到最大轮数
          5. 返回最终分析 JSON

        参数:
            vuln:            漏洞信息字典
            context_code:    初始上下文代码
            php_version:     PHP 版本
            project_path:    项目路径（工具需要）
            max_tool_rounds: 最大工具调用轮数

        返回:
            dict: AI 深度分析结果
        """
        from engine.mcp_tools import (
            MCPToolExecutor, build_tool_system_prompt, parse_tool_calls
        )

        tool_executor = MCPToolExecutor(project_path) if project_path else None

        vuln_type = vuln.get("vuln_type", "")

        # 构建版本上下文
        php_ctx = ""
        if php_version:
            from engine.rule_engine import RuleEngine
            eng = RuleEngine(php_version)
            ctx = eng.get_wide_byte_context()
            php_ctx = (
                f"- **目标 PHP 版本**：{php_version}\n"
                f"- **DSN charset 可靠性**：{'可信' if ctx['dsn_charset_trusted'] else '不可信'}\n"
            )

        # 工具说明
        tool_prompt = build_tool_system_prompt() if tool_executor else ""

        # 构建初始 prompt
        initial_prompt = ANALYSIS_PROMPT_TEMPLATE.format(
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

        # 工具调用循环
        conversation_history = initial_prompt
        final_result = None
        last_response = None
        tool_rounds_used = 0

        for round_num in range(max_tool_rounds):
            system_with_tools = SYSTEM_PROMPT
            has_tools = bool(tool_executor)
            if has_tools:
                system_with_tools += "\n\n" + tool_prompt

            response = self._chat_raw(conversation_history, system_prompt=system_with_tools, max_tokens=8192)
            if not response:
                print(f"[MCP] 第 {round_num+1} 轮 AI 无响应")
                break
            last_response = response

            # 尝试解析工具调用
            if tool_executor:
                tool_calls = parse_tool_calls(response)
                print(f"[MCP] 第 {round_num+1} 轮: 解析到 {len(tool_calls)} 个工具调用")
                if tool_calls:
                    tool_rounds_used = round_num + 1
                    tool_results = []
                    for tc in tool_calls:
                        print(f"[MCP] 执行: {tc['name']}({tc.get('arguments', {})})")
                        result = tool_executor.execute(
                            tc["name"], tc.get("arguments", {})
                        )
                        tool_results.append(
                            f"[{tc['name']} 结果]\n{result[:3000]}"
                        )

                    if tool_results:
                        conversation_history = (
                            initial_prompt
                            + "\n\n---\n## 第 {} 轮\n".format(round_num + 1)
                            + response
                            + "\n\n工具执行结果：\n\n"
                            + "\n\n".join(tool_results)
                            + "\n\n请基于以上结果继续。如分析完成，输出 JSON 结果（不要再用 ```json 包裹）。"
                        )
                        continue
            else:
                print(f"[MCP] 第 {round_num+1} 轮: tool_executor 为 None，跳过工具检测")

            # 无工具调用，解析最终 JSON
            final_result = self._parse_json(response)
            if final_result:
                print(f"[MCP] 第 {round_num+1} 轮: 解析到最终 JSON 结果")
                break

        # 最后一轮后仍尝试解析
        if not final_result and last_response:
            final_result = self._parse_json(last_response)

        if tool_rounds_used == 0 and has_tools and not final_result:
            print(f"[MCP] AI 未调用任何工具且未返回有效 JSON，首轮回复前 200 字符: {last_response[:200] if last_response else 'None'}")

        # 归一化：如果 AI 返回了数组，取第一个 dict 元素
        if isinstance(final_result, list):
            final_result = final_result[0] if final_result and isinstance(final_result[0], dict) else None
        return final_result

    # ================================================================
    # MCP 工具驱动验证 + 自动修复
    # ================================================================

    def verify_and_fix_with_tools(
        self, vuln: dict, context_code: str = "",
        php_version: str = "", project_path: str = "",
        max_tool_rounds: int = 4,
    ) -> dict | None:
        """
        使用 MCP 工具自主验证漏洞可利用性并生成修复代码。

        AI 会调用 search_dangerous_calls、trace_variable_flow、
        read_file_region 等工具深入探索源码，确认漏洞是否真实，
        并给出可用的修复代码。

        返回:
            {
                "verdict": "confirmed|potential|false_positive",
                "confidence": 0.0-1.0,
                "exploit_payload": "...",
                "payload_effect": "...",
                "evidence": "验证证据",
                "fix_code": "修复代码",
                "fix_description": "修复说明"
            }
        """
        from engine.mcp_tools import (
            MCPToolExecutor, build_tool_system_prompt, parse_tool_calls
        )

        tool_executor = MCPToolExecutor(project_path) if project_path else None
        tool_prompt = build_tool_system_prompt() if tool_executor else ""

        vuln_type = vuln.get("vuln_type", "")

        # 版本上下文
        php_ctx = ""
        if php_version:
            from engine.rule_engine import RuleEngine
            eng = RuleEngine(php_version)
            ctx_obj = eng.get_wide_byte_context()
            php_ctx = (
                f"- PHP {php_version}"
                f"（DSN charset: {'可信' if ctx_obj['dsn_charset_trusted'] else '不可信'}）"
            )

        from ai.prompts import VULN_TYPE_LABELS, VULN_TYPE_DESCRIPTIONS

        initial_prompt = VERIFY_AND_FIX_TEMPLATE.format(
            vuln_type_label=VULN_TYPE_LABELS.get(vuln_type, vuln_type),
            vuln_type=vuln_type,
            file_path=vuln.get("file_path", ""),
            language=vuln.get("language", ""),
            severity=vuln.get("severity", ""),
            source_code=vuln.get("source_code", ""),
            sink_code=vuln.get("sink_code", ""),
            data_flow=vuln.get("data_flow", ""),
            pipeline_stage=vuln.get("pipeline_stage", ""),
            ai_analysis=vuln.get("ai_analysis", ""),
            description=VULN_TYPE_DESCRIPTIONS.get(vuln_type, ""),
            php_version_context=php_ctx,
            context_code=context_code,
        )

        conversation_history = initial_prompt
        final_result = None
        last_response = None

        for round_num in range(max_tool_rounds):
            system_with_tools = VERIFY_AND_FIX_SYSTEM_PROMPT
            has_tools = bool(tool_executor)
            if has_tools:
                system_with_tools += "\n\n" + tool_prompt

            response = self._chat_raw(conversation_history,
                                       system_prompt=system_with_tools,
                                       max_tokens=8192)
            if not response:
                print(f"[VFIX] 第 {round_num+1} 轮 AI 无响应")
                break
            last_response = response

            # 尝试解析工具调用
            if tool_executor:
                tool_calls = parse_tool_calls(response)
                print(f"[VFIX] 第 {round_num+1} 轮: {len(tool_calls)} 个工具调用")
                if tool_calls:
                    tool_results = []
                    for tc in tool_calls:
                        print(f"[VFIX] 执行: {tc['name']}({tc.get('arguments', {})})")
                        result = tool_executor.execute(
                            tc["name"], tc.get("arguments", {})
                        )
                        tool_results.append(
                            f"[{tc['name']} 结果]\n{result[:3000]}"
                        )

                    if tool_results:
                        conversation_history = (
                            initial_prompt
                            + "\n\n---\n## 第 {} 轮\n".format(round_num + 1)
                            + response
                            + "\n\n工具执行结果：\n\n"
                            + "\n\n".join(tool_results)
                            + "\n\n请基于以上结果继续探索。如分析完成，输出最终 JSON 结果。"
                        )
                        continue

            # 无工具调用，解析最终 JSON
            final_result = self._parse_json(response)
            if final_result:
                print(f"[VFIX] 第 {round_num+1} 轮: 解析到最终结果")
                break

        if not final_result and last_response:
            final_result = self._parse_json(last_response)

        if isinstance(final_result, list):
            final_result = final_result[0] if final_result and isinstance(final_result[0], dict) else None
        return final_result

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

    def _chat(self, prompt: str, max_tokens: int = 8192) -> dict | list | None:
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
                max_tokens=max_tokens,
            )
            return self._parse_json(response)
        except Exception as e:
            print(f"[ERROR] AI API 调用失败: {e}")
            return None

    def _chat_raw(self, prompt: str, system_prompt: str = "",
                  max_tokens: int = 8192) -> str | None:
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
                max_tokens=max_tokens,
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

        # 策略 2b：手动剥离 ``` 标记（处理结尾缺 ``` 的截断响应）
        stripped = text.strip()
        if stripped.startswith("```"):
            stripped = re.sub(r'^```\w*\s*', '', stripped, count=1)
            stripped = re.sub(r'\s*```\s*$', '', stripped)
            try:
                return json.loads(stripped)
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
        repaired = text
        # 0. 剥离 ``` 代码块标记（AI 常用外层包裹）
        repaired = re.sub(r'^```\w*\s*', '', repaired.strip())
        repaired = re.sub(r'\s*```\s*$', '', repaired)
        # 1. 移除尾部逗号（JSON 不允许 trailing comma）
        repaired = re.sub(r',\s*}', '}', repaired)
        repaired = re.sub(r',\s*]', ']', repaired)
        # 2. 移除单行注释 // ... 到行尾
        repaired = re.sub(r'//[^\n]*', '', repaired)
        # 3. 移除多行注释 /* ... */
        repaired = re.sub(r'/\*[\s\S]*?\*/', '', repaired)
        # 4. 修复截断的 JSON：自动闭合未匹配的括号
        repaired = AIClient._close_truncated_json(repaired)
        try:
            return json.loads(repaired)
        except (json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _close_truncated_json(text: str) -> str:
        """
        修复截断的 JSON：自动补全缺失的闭合括号。

        当 AI 输出被 max_tokens 截断时，JSON 可能缺少闭合的 } 和 ]。
        统计未闭合的括号并按栈序补全。

        注意：跳过字符串内的括号（简单引号计数）。
        """
        stack = []
        in_string = False
        escape_next = False

        for ch in text:
            if escape_next:
                escape_next = False
                continue
            if ch == '\\':
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch in ('{', '['):
                stack.append(ch)
            elif ch == '}':
                if stack and stack[-1] == '{':
                    stack.pop()
            elif ch == ']':
                if stack and stack[-1] == '[':
                    stack.pop()

        # 按栈序逆序闭合
        closing = ''
        for bracket in reversed(stack):
            closing += '}' if bracket == '{' else ']'

        return text + closing


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
