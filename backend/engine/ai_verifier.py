"""
AI 漏洞验证器
============
利用 AI 自动构建 Payload 并判断漏洞是否可确认。

==== 验证流程 ====

1. 从 PayloadBuilder 获取 Payload 集
2. 对每个漏洞，AI 模拟攻击场景并判断：
   - Payload 是否能触发漏洞？
   - 预期响应是什么？
   - 是否有 WAF/过滤迹象？
3. 综合判定：
   - confirmed  → Payload 很可能成功，标记为已确认
   - potential   → 无法确定，但存在风险，标记为潜在

==== 不使用实际请求 ====

出于安全考虑，本模块不发起实际的 HTTP 请求进行验证。
而是利用 AI 的代码理解能力，结合 Payload 和上下文代码，
进行"静态验证"——判断 Payload 是否可能在运行时生效。
"""
import json
import re
from dataclasses import dataclass, field
from enum import Enum


class VerificationResult(Enum):
    """
    AI 验证结果
    ===========
    CONFIRMED  = Payload 很可能成功 → 标记为 confirmed
    POTENTIAL  = 无法确定 → 标记为 potential  
    FALSE_POS  = 明显误报 → 可标记为 false_positive
    """
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    FALSE_POS = "false_positive"


@dataclass
class VerificationReport:
    """
    单个漏洞的验证报告
    ==================
    """
    vuln_id: int                            # 漏洞在列表中的索引
    file_path: str                          # 文件路径
    line_number: int                        # 行号
    vuln_type: str                          # 漏洞类型
    result: VerificationResult              # 验证结论
    confidence: float                       # 置信度 (0~1)
    verified_payload: str = ""              # 验证使用的 Payload
    payload_effect: str = ""                # 预期 Payload 效果
    evidence: str = ""                      # AI 给出的验证证据
    recommendation: str = ""                # AI 的修复建议


class AIVerifier:
    """
    AI 漏洞验证器
    =============
    对流水线输出的漏洞进行 AI 自动化验证。

    用法:
        verifier = AIVerifier(ai_client)
        reports = verifier.verify(vulns, source_code_map)
        # 根据 reports 更新漏洞状态
    """

    # 验证 Prompt 模板
    VERIFICATION_PROMPT = """你是一名资深渗透测试专家。请验证以下漏洞是否真实可利用。

## 漏洞信息

- **类型**: {vuln_type}
- **文件**: {file_path}
- **行号**: {line_number}

## 源码入口（Source）

```
{source_code}
```

## 危险函数（Sink）

```
{sink_code}
```

## 数据流路径

```
{data_flow}
```

## 数据流分析结论

- 防护等级: {protection_level}
- 利用难度: {exploit_difficulty}
- 分析备注: {data_flow_notes}

## 测试 Payload

{payloads_text}

---

请以 JSON 格式回复验证结果：

```json
{{
    "verdict": "confirmed|potential|false_positive",
    "confidence": 0.0-1.0,
    "best_payload": "最有效的 Payload",
    "payload_effect": "Payload 的预期效果",
    "evidence": "验证证据 / 判断依据（3-5 句话）",
    "recommendation": "修复建议"
}}
```

判断标准：
- "confirmed": 代码明显有漏洞，Payload 极大概率能成功
- "potential": 存在安全隐患但不确定是否能利用（如不确定是否有 WAF）
- "false_positive": 代码实际是安全的（如使用了参数化查询/白名单）
"""

    def __init__(self, ai_client):
        self.ai_client = ai_client

    def verify(
        self, vulns: list[dict], payload_sets: list,
        source_code_map: dict[str, str]
    ) -> list[VerificationReport]:
        """
        对漏洞列表逐一验证。

        参数:
            vulns:           三级流水线输出的最终漏洞列表
            payload_sets:    PayloadBuilder 生成的 Payload 集
            source_code_map: {file_path: source_code}

        返回:
            list[VerificationReport]: 验证报告
        """
        reports = []
        payload_map = {ps.target_file: ps for ps in payload_sets}

        for i, v in enumerate(vulns):
            file_path = v.get("file_path", "")
            ps = payload_map.get(file_path)

            if self.ai_client and self.ai_client.is_configured():
                report = self._ai_verify(v, ps, source_code_map, i)
            else:
                # AI 不可用时，基于数据流分析做启发式判定
                report = self._heuristic_verify(v, i)

            reports.append(report)

        # 统计
        confirmed = sum(1 for r in reports if r.result == VerificationResult.CONFIRMED)
        potential = sum(1 for r in reports if r.result == VerificationResult.POTENTIAL)
        print(f"[VERIFIER] AI 验证完成: {confirmed} confirmed, {potential} potential, "
              f"{len(reports) - confirmed - potential} false_positive")

        return reports

    def _ai_verify(self, vuln: dict, payload_set, source_code_map: dict[str, str],
                   vuln_index: int) -> VerificationReport:
        """使用 AI 进行深度验证"""
        file_path = vuln.get("file_path", "")

        # 拼装 Payload 文本
        payloads_text = "无预定义 Payload"
        if payload_set and payload_set.payloads:
            payloads_text = "\n".join(
                f"- `{p.value}` ({p.description}), 预期: {p.expected_result}"
                for p in payload_set.payloads[:5]  # 最多 5 个
            )

        prompt = self.VERIFICATION_PROMPT.format(
            vuln_type=vuln.get("vuln_type", ""),
            file_path=file_path,
            line_number=vuln.get("line_number", vuln.get("sink_line", 0)),
            source_code=vuln.get("source_code", ""),
            sink_code=vuln.get("sink_code", ""),
            data_flow=vuln.get("data_flow", ""),
            protection_level=vuln.get("protection_level", "none"),
            exploit_difficulty=vuln.get("exploit_difficulty", "unknown"),
            data_flow_notes=vuln.get("data_flow_notes", ""),
            payloads_text=payloads_text,
        )

        try:
            response = self.ai_client._chat(prompt)
            # 归一化：AI 可能返回 list 或 dict
            r = response
            if isinstance(r, list):
                r = r[0] if r and isinstance(r[0], dict) else None
            if isinstance(r, dict):
                verdict_str = r.get("verdict", "potential")
                verdict_map = {
                    "confirmed": VerificationResult.CONFIRMED,
                    "potential": VerificationResult.POTENTIAL,
                    "false_positive": VerificationResult.FALSE_POS,
                }
                verdict = verdict_map.get(verdict_str, VerificationResult.POTENTIAL)

                return VerificationReport(
                    vuln_id=vuln_index,
                    file_path=file_path,
                    line_number=vuln.get("line_number", vuln.get("sink_line", 0)),
                    vuln_type=vuln.get("vuln_type", ""),
                    result=verdict,
                    confidence=r.get("confidence", 0.5),
                    verified_payload=r.get("best_payload", ""),
                    payload_effect=r.get("payload_effect", ""),
                    evidence=r.get("evidence", ""),
                    recommendation=r.get("recommendation", ""),
                )
        except Exception as e:
            print(f"[VERIFIER] AI 验证异常: {e}")

        # 回退：启发式判定
        return self._heuristic_verify(vuln, vuln_index)

    def _heuristic_verify(self, vuln: dict, vuln_index: int) -> VerificationReport:
        """
        启发式验证（当 AI 不可用时）。

        基于 Stage 2 数据流分析的结论做判定。
        """
        protection = vuln.get("protection_level", "none")
        exploit_difficulty = vuln.get("exploit_difficulty", "unknown")
        is_exploitable = vuln.get("is_exploitable", True)
        ast_filtered = vuln.get("ast_filtered", False)

        if ast_filtered or protection == "strong":
            result = VerificationResult.FALSE_POS
            confidence = 0.7
        elif is_exploitable and exploit_difficulty in ("easy", "medium"):
            result = VerificationResult.CONFIRMED
            confidence = 0.6
        else:
            result = VerificationResult.POTENTIAL
            confidence = 0.4

        return VerificationReport(
            vuln_id=vuln_index,
            file_path=vuln.get("file_path", ""),
            line_number=vuln.get("line_number", vuln.get("sink_line", 0)),
            vuln_type=vuln.get("vuln_type", ""),
            result=result,
            confidence=confidence,
            verified_payload=vuln.get("ai_payload", ""),
            payload_effect="启发式判定，未使用 AI 精确验证",
            evidence=f"防护等级: {protection}, 利用难度: {exploit_difficulty}",
            recommendation="",
        )

    def apply_verification(self, vulns: list[dict], reports: list[VerificationReport]) -> list[dict]:
        """
        将验证结果应用到漏洞列表，更新状态。

        confirmed → status = "confirmed"
        potential → status = "potential"
        false_positive → status = "false_positive"

        返回:
            更新了 status 的漏洞列表
        """
        for report in reports:
            idx = report.vuln_id
            if idx < len(vulns):
                if report.result == VerificationResult.CONFIRMED:
                    vulns[idx]["status"] = "confirmed"
                    vulns[idx]["ai_payload"] = report.verified_payload
                    vulns[idx]["ai_payload_result"] = "success"
                    vulns[idx]["ai_payload_evidence"] = report.evidence
                elif report.result == VerificationResult.POTENTIAL:
                    vulns[idx]["status"] = "potential"
                    vulns[idx]["ai_payload"] = report.verified_payload
                    vulns[idx]["ai_payload_result"] = "failed"
                    vulns[idx]["ai_payload_evidence"] = report.evidence
                elif report.result == VerificationResult.FALSE_POS:
                    vulns[idx]["status"] = "false_positive"

        return vulns
