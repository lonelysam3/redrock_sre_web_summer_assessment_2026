"""
AI 分析模块 —— Prompt 模板（v3 — 深度分析版）
==========================================
定义发送给 AI 的提示词模板，要求输出：
  1. 漏洞形成原因（根本原因分析）
  2. 攻击方式分析（攻击者视角的利用路径）
  3. 修复建议（含具体代码）

所有 Prompt 要求 AI 以 JSON 格式回复，便于程序解析。
"""
from engine.sinks_py import VulnType


# ---- 漏洞类型的中文标签映射 ----
VULN_TYPE_LABELS = {
    "sql_injection": "SQL 注入",
    "command_execution": "命令执行/代码注入",
    "ssrf": "SSRF 服务端请求伪造",
    "path_traversal": "路径穿越",
    "arbitrary_file_read": "任意文件读取",
    "xss": "跨站脚本攻击 (XSS)",
    "file_upload": "恶意文件上传",
    "deserialization": "反序列化漏洞",
}

# ---- 各漏洞类型的详细描述（帮助 AI 理解上下文）----
VULN_TYPE_DESCRIPTIONS = {
    "sql_injection": (
        "攻击者通过构造恶意输入，拼接进 SQL 语句，绕过验证或窃取数据。\n"
        "常见模式：字符串拼接 SQL、未使用参数化查询。\n"
        "需检查：是否使用了参数化查询（? placeholder 或 %s 参数化）"
    ),
    "command_execution": (
        "攻击者可以注入系统命令在服务器上执行。\n"
        "常见模式：用户输入直接传入 os.system()、subprocess.Popen()、eval() 等。\n"
        "需检查：是否对输入做了白名单校验，或使用安全的替代方案"
    ),
    "ssrf": (
        "服务端请求伪造，攻击者控制服务器发起请求到内网或其他系统。\n"
        "常见模式：用户提供的 URL 直接传给 requests.get() / urllib.urlopen() / curl_exec()。\n"
        "需检查：URL 是否经过安全校验（协议白名单、域名白名单）"
    ),
    "path_traversal": (
        "攻击者通过 ../ 等路径字符访问服务器上的任意文件。\n"
        "常见模式：用户输入拼接文件路径后传给 fopen() / open() / include()。\n"
        "需检查：是否对路径做了规范化/白名单校验"
    ),
    "arbitrary_file_read": (
        "攻击者能读取服务器上任意文件内容。\n"
        "常见模式：用户控制文件路径后直接传给文件读取函数。\n"
        "与路径穿越类似，侧重读取（而非写入/删除）"
    ),
    "xss": (
        "跨站脚本攻击，攻击者在页面中注入恶意脚本，窃取用户 Cookie 或劫持会话。\n"
        "常见模式：echo/print 直接输出用户输入，未使用 htmlspecialchars() 转义。\n"
        "需检查：输出前是否做了 HTML 实体编码"
    ),
    "file_upload": (
        "攻击者上传恶意文件（如 PHP webshell）到服务器，获取远程代码执行权限。\n"
        "常见模式：move_uploaded_file() 的目标路径可由用户控制，或未检查文件扩展名。\n"
        "需检查：是否校验了文件类型（白名单）、是否重命名了上传文件"
    ),
    "deserialization": (
        "攻击者构造恶意序列化数据，反序列化时触发魔术方法链（POP 链），执行任意代码。\n"
        "常见模式：unserialize() 接受用户输入，类中存在可利用的 __destruct/__wakeup/__toString 方法。\n"
        "需检查：是否对反序列化数据做了签名/HMAC 验证，或使用安全的序列化格式（JSON）"
    ),
}

# ---- System Prompt（系统提示词 v3）----
SYSTEM_PROMPT = """你是一名资深应用安全专家，拥有 15 年渗透测试和代码审计经验。你的任务是：

## 核心任务
1. 分析静态扫描工具标记的疑似漏洞
2. 判断是否为真实漏洞，排除误报
3. 深入分析漏洞的形成原因（根本原因分析）
4. 从攻击者视角分析可行的攻击方式（含具体 Payload）
5. 给出可落地的修复建议和代码

## 分析标准

### 漏洞形成原因
- 解释代码为什么存在漏洞（如：未使用参数化查询、未校验输入、信任用户数据等）
- 指出具体哪一行代码是关键问题点
- 说明该漏洞属于 OWASP Top 10 或 CWE 中的哪个分类

### 攻击方式分析
- 描述攻击者如何发现和利用此漏洞
- 给出 2-3 个具体的攻击 Payload 示例
- 说明每种 Payload 的预期效果（如：绕过认证、读取文件、执行命令）
- 如果存在 WAF 或过滤，分析可能的绕过技巧

### 修复建议
- 给出修复方案（优先级排序，最安全的方式排最前）
- 修复代码必须是完整可用的，可直接替换原代码
- 如果有多种修复方式，列出并说明各自优缺点

## 重要原则
- 只有在确信是漏洞时才标记为 "true"
- 如果存在有效的安全控制（参数化查询、白名单、强类型校验），标记为 "false"
- 如果代码逻辑不清晰或缺少上下文无法判断，标记为 "uncertain"
- 回复必须严格遵循 JSON 格式"""

# ---- 单个漏洞分析模板（v3 — 深度分析）----
ANALYSIS_PROMPT_TEMPLATE = """## 疑似漏洞信息

- **漏洞类型**：{vuln_type_label}（{vuln_type}）
- **文件**：{file_path}
- **语言**：{language}
- **初步严重程度**：{severity}
- **发现阶段**：{pipeline_stage}

{description}

---

## 数据流路径（变量传播链）

```
{data_flow}
```

---

## Source 代码（用户输入入口）

```{language}
{source_code}
```

---

## Sink 代码（危险操作点）

```{language}
{sink_code}
```

---

## 完整代码上下文（漏洞所在文件的大段代码）

```{language}
{context_code}
```

---

## 分析要求

请对以上代码进行深度安全分析，并以 JSON 格式回复（不要添加任何其他文字）：

```json
{{
    "is_vulnerable": "true|false|uncertain",
    "severity": "critical|high|medium|low",
    "cwe_id": "如 CWE-89",
    "owasp_category": "如 A03:2021-Injection",

    "root_cause": {{
        "summary": "漏洞形成原因概述（1-2 句）",
        "detail": "详细原因分析（3-5 句），说明为什么代码存在安全问题",
        "problem_line": "指出关键的有问题的代码行"
    }},

    "attack_analysis": {{
        "discovery_method": "攻击者如何发现此漏洞",
        "attack_scenarios": [
            {{
                "name": "攻击场景名称",
                "payload": "具体的攻击 Payload",
                "expected_effect": "预期达到的攻击效果",
                "difficulty": "easy|medium|hard"
            }}
        ],
        "waf_bypass": "如果存在 WAF/过滤，可能的绕过方式（无则填 null）"
    }},

    "fix_recommendation": {{
        "primary": {{
            "approach": "首选修复方案名称",
            "description": "方案说明",
            "code": "完整的修复代码"
        }},
        "alternatives": [
            {{
                "approach": "备选方案",
                "description": "方案说明",
                "code": "备选代码"
            }}
        ],
        "security_notes": "额外的安全注意事项"
    }}
}}
```

## 注意
- 每个字段都是必填的，不要省略
- 修复代码必须完整可用，包含必要的 import 和上下文
- 如果是字符串拼接 SQL，必须展示参数化查询的完整写法
- attack_scenarios 至少包含 2 个场景
- 如果判定为误报（false），root_cause.detail 要解释为什么是安全的"""


# ---- 批量漏洞分析模板（v3 — 深度分析）----
BATCH_ANALYSIS_PROMPT = """你是一名资深应用安全专家。以下是一批静态分析发现的疑似漏洞，请逐个进行深度分析。

{items}

请为每个漏洞返回 JSON，格式如下：

```json
[
    {{
        "id": 0,
        "is_vulnerable": "true|false|uncertain",
        "severity": "critical|high|medium|low",
        "cwe_id": "CWE-89",

        "root_cause": {{
            "summary": "漏洞形成原因概述",
            "detail": "详细原因分析",
            "problem_line": "问题代码行"
        }},

        "attack_analysis": {{
            "discovery_method": "发现方式",
            "attack_scenarios": [
                {{
                    "name": "场景名",
                    "payload": "Payload",
                    "expected_effect": "预期效果",
                    "difficulty": "easy|medium|hard"
                }}
            ],
            "waf_bypass": null
        }},

        "fix_recommendation": {{
            "primary": {{
                "approach": "首选方案",
                "description": "方案说明",
                "code": "完整修复代码"
            }},
            "alternatives": [],
            "security_notes": "安全注意事项"
        }}
    }},
    ...
]
```
"""

# ---- AI Payload 验证 Prompt ----
VERIFICATION_PROMPT_TEMPLATE = """你是一名资深渗透测试专家。请验证以下漏洞是否真实可利用。

## 漏洞信息
- **类型**: {vuln_type}
- **文件**: {file_path}:{line_number}
- **Source**: `{source_code}`
- **Sink**: `{sink_code}`
- **数据流**: {data_flow}

## 测试 Payload
{payloads}

## 数据流分析结论
- 防护等级: {protection_level}
- 利用难度: {exploit_difficulty}

---

请以 JSON 回复：

```json
{{
    "verdict": "confirmed|potential|false_positive",
    "confidence": 0.0-1.0,
    "exploit_payload": "最有效的攻击 Payload",
    "exploit_step_by_step": "攻击步骤（1. 2. 3.）",
    "expected_response": "预期的服务器响应",
    "is_reliable": true/false,
    "bypass_technique": "使用的绕过技巧（无则 null）",
    "recommendation": "修复建议"
}}
```
"""
