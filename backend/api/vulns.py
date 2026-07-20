"""
漏洞管理 REST API
===============
提供漏洞的查询、筛选、状态更新和 AI 分析触发接口。

路由前缀: /api/vulns

端点:
  GET    /api/vulns              — 列出漏洞（可按 scan_id/type/severity/status 筛选）
  GET    /api/vulns/<id>         — 获取单个漏洞详情
  PATCH  /api/vulns/<id>         — 更新漏洞状态（人工审核）
  POST   /api/vulns/<id>/analyze — 手动触发 AI 分析
"""
from flask import Blueprint, request, jsonify
from models import db, Vulnerability

# 创建蓝图，挂载到 /api/vulns
vulns_bp = Blueprint("vulns", __name__)


@vulns_bp.route("", methods=["GET"])
def list_vulns():
    """
    查询漏洞列表（支持多维度筛选）
    ============================
    可选查询参数:
      - scan_id:  按扫描任务筛选
      - type:     按漏洞类型筛选 (sql_injection / command_execution / ssrf / ...)
      - severity: 按严重程度筛选 (critical / high / medium / low)
      - status:   按审核状态筛选 (pending / confirmed / false_positive / reviewed)

    返回:
        JSON 数组，按严重程度倒序排列
    """
    scan_id = request.args.get("scan_id")
    vuln_type = request.args.get("type")
    severity = request.args.get("severity")
    status = request.args.get("status")

    query = Vulnerability.query

    # 动态添加过滤条件（只添加实际传入的参数）
    if scan_id:
        query = query.filter_by(scan_task_id=int(scan_id))
    if vuln_type:
        query = query.filter_by(vuln_type=vuln_type)
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)

    # 按严重程度倒序：critical > high > medium > low
    vulns = query.order_by(Vulnerability.severity.desc()).all()
    return jsonify([_serialize(v) for v in vulns])


@vulns_bp.route("/<int:vuln_id>", methods=["GET"])
def get_vuln(vuln_id: int):
    """
    获取单个漏洞的完整详情

    参数:
        vuln_id: 漏洞 ID

    返回:
        JSON 对象，包含漏洞的所有字段
        404 如果漏洞不存在
    """
    v = db.session.get(Vulnerability, vuln_id)
    if not v:
        return jsonify({"error": "不存在"}), 404
    return jsonify(_serialize(v))


@vulns_bp.route("/<int:vuln_id>", methods=["PATCH"])
def update_vuln(vuln_id: int):
    """
    更新漏洞的审核状态（人工判定）

    请求体:
        { "status": "confirmed" | "false_positive" | "reviewed" }

    参数:
        vuln_id: 漏洞 ID

    返回:
        更新后的漏洞完整信息
    """
    v = db.session.get(Vulnerability, vuln_id)
    if not v:
        return jsonify({"error": "不存在"}), 404

    data = request.get_json()
    if "status" in data:
        v.status = data["status"]  # 更新审核状态

    db.session.commit()
    return jsonify(_serialize(v))


@vulns_bp.route("/<int:vuln_id>/analyze", methods=["POST"])
def analyze_vuln(vuln_id: int):
    """
    手动触发单个漏洞的 AI 二次分析
    ==============================
    提取漏洞所在代码的上下文，发送给 AI 进行深度分析。
    分析结果会写回数据库的 ai_* 字段。

    参数:
        vuln_id: 漏洞 ID

    返回:
        更新后的漏洞完整信息（含 AI 分析结果）
    """
    v = db.session.get(Vulnerability, vuln_id)
    if not v:
        return jsonify({"error": "不存在"}), 404

    from ai.client import get_ai_client
    from utils.code_extractor import extract_source_context

    # 获取 AI 客户端
    client = get_ai_client()

    # 检查 API Key 是否已配置
    if not client.is_configured():
        return jsonify({
            "error": "AI 未配置",
            "detail": "请先在设置页面配置 API Key、Base URL 和模型"
        }), 400

    # 提取漏洞周围的上下文代码（前 5 行到后 3 行）
    ctx = extract_source_context(
        v.file_path,
        max(1, v.line_number - 5),   # 从漏洞行前 5 行开始
        v.line_number + 3,           # 到漏洞行后 3 行结束
    )

    # 获取 PHP 版本（仅 PHP 项目生效）
    php_version = ""
    try:
        if v.scan_task and v.scan_task.project:
            php_version = v.scan_task.project.php_version or ""
    except Exception:
        pass

    # 调用 AI 进行分析
    result = client.analyze_single({
        "file_path": v.file_path,
        "vuln_type": v.vuln_type,
        "severity": v.severity,
        "language": v.language,
        "data_flow": v.data_flow or "",
        "source_code": v.source_code or "",
        "sink_code": v.sink_code or "",
        "pipeline_stage": v.pipeline_stage or "",
    }, ctx, php_version=php_version)

    # 如果 AI 返回了结果，写入数据库
    if result:
        import json
        r = result
        if isinstance(r, list):
            r = r[0] if r and isinstance(r[0], dict) else None
        if isinstance(r, dict):
            v.ai_analysis = json.dumps(r, ensure_ascii=False)
            v.ai_is_vulnerable = r.get("is_vulnerable", "uncertain")
            v.ai_severity = r.get("severity", v.severity)
            v.ai_cwe_id = r.get("cwe_id", "")
            v.ai_owasp_category = r.get("owasp_category", "")
            # 嵌套对象需要序列化为 JSON 字符串
            v.ai_root_cause = json.dumps(r.get("root_cause", {}), ensure_ascii=False)
            v.ai_attack_vector = json.dumps(r.get("attack_analysis", {}), ensure_ascii=False)
            v.ai_fix_suggestion = json.dumps(r.get("fix_recommendation", {}), ensure_ascii=False)
            # fix_code 是字符串，直接存
            fix = r.get("fix_recommendation", {})
            if isinstance(fix, dict):
                primary = fix.get("primary", {})
                v.ai_fix_code = primary.get("code", "") if isinstance(primary, dict) else ""
        db.session.commit()

        # ---- 自动 Payload 构建 + 验证 ----
        try:
            _verify_single_vuln(v)
        except Exception:
            pass

    return jsonify(_serialize(v))


@vulns_bp.route("/analyze-all", methods=["POST"])
def analyze_all_vulns():
    """
    一键 AI 分析 — 批量分析扫描任务中所有未分析的漏洞。

    查询参数:
        scan_id: 扫描任务 ID（必填）

    返回:
        { ok: true, analyzed: N, failed: N }
    """
    scan_id = request.args.get("scan_id")
    if not scan_id:
        return jsonify({"error": "缺少 scan_id 参数"}), 400

    from ai.client import get_ai_client
    from utils.code_extractor import extract_source_context

    client = get_ai_client()
    if not client.is_configured():
        return jsonify({
            "error": "AI 未配置",
            "detail": "请先在设置页面配置 API Key、Base URL 和模型"
        }), 400

    # 获取该扫描下所有尚未 AI 分析的漏洞
    vulns = (Vulnerability.query
             .filter_by(scan_task_id=int(scan_id))
             .filter(Vulnerability.ai_is_vulnerable == None)
             .all())

    if not vulns:
        return jsonify({"ok": True, "analyzed": 0, "message": "所有漏洞已分析完毕"})

    analyzed = 0
    failed = 0
    import json

    # 获取 PHP 版本
    php_version = ""
    try:
        if vulns and vulns[0].scan_task and vulns[0].scan_task.project:
            php_version = vulns[0].scan_task.project.php_version or ""
    except Exception:
        pass

    for v in vulns:
        try:
            ctx = extract_source_context(
                v.file_path,
                max(1, v.line_number - 5),
                v.line_number + 3,
            )
            result = client.analyze_single({
                "file_path": v.file_path,
                "vuln_type": v.vuln_type,
                "severity": v.severity,
                "language": v.language,
                "data_flow": v.data_flow or "",
                "source_code": v.source_code or "",
                "sink_code": v.sink_code or "",
                "pipeline_stage": v.pipeline_stage or "",
            }, ctx, php_version=php_version)

            if result:
                r = result
                if isinstance(r, list):
                    r = r[0] if r and isinstance(r[0], dict) else None
                if isinstance(r, dict):
                    v.ai_analysis = json.dumps(r, ensure_ascii=False)
                    v.ai_is_vulnerable = r.get("is_vulnerable", "uncertain")
                    v.ai_severity = r.get("severity", v.severity)
                    v.ai_cwe_id = r.get("cwe_id", "")
                    v.ai_owasp_category = r.get("owasp_category", "")
                    v.ai_root_cause = json.dumps(r.get("root_cause", {}), ensure_ascii=False)
                    v.ai_attack_vector = json.dumps(r.get("attack_analysis", {}), ensure_ascii=False)
                    v.ai_fix_suggestion = json.dumps(r.get("fix_recommendation", {}), ensure_ascii=False)
                    fix = r.get("fix_recommendation", {})
                    if isinstance(fix, dict):
                        primary = fix.get("primary", {})
                        v.ai_fix_code = primary.get("code", "") if isinstance(primary, dict) else ""
                    analyzed += 1
            else:
                failed += 1

            db.session.commit()  # 逐条提交，即使某条失败也不影响前面的
        except Exception as e:
            failed += 1
            print(f"[AI] 分析漏洞 #{v.id} 失败: {e}")

    # 自动触发 Payload 构建 + 验证
    verified = 0
    try:
        from engine.payload_builder import PayloadBuilder
        from engine.ai_verifier import AIVerifier, VerificationResult

        analyzed_vulns = (Vulnerability.query
                         .filter_by(scan_task_id=int(scan_id))
                         .filter(Vulnerability.ai_is_vulnerable.isnot(None))
                         .all())

        if analyzed_vulns:
            source_code_map = {}
            for v in analyzed_vulns:
                if v.file_path and v.file_path not in source_code_map:
                    try:
                        with open(v.file_path, encoding='utf-8', errors='ignore') as f:
                            source_code_map[v.file_path] = f.read()
                    except Exception:
                        source_code_map[v.file_path] = v.source_code or ""

            vuln_dicts = []
            for v in analyzed_vulns:
                vuln_dicts.append({
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "vuln_type": v.vuln_type,
                    "severity": v.severity,
                    "language": v.language,
                    "source_code": v.source_code or "",
                    "sink_code": v.sink_code or "",
                    "data_flow": v.data_flow or "",
                    "protection_level": "none",
                    "exploit_difficulty": "unknown",
                })

            builder = PayloadBuilder(client)
            payload_sets = builder.build_payloads(vuln_dicts, source_code_map)
            verifier = AIVerifier(client)
            reports = verifier.verify(vuln_dicts, payload_sets, source_code_map)

            for report in reports:
                if report.vuln_id < len(analyzed_vulns):
                    av = analyzed_vulns[report.vuln_id]
                    av.ai_payload = report.verified_payload
                    av.ai_payload_evidence = report.evidence
                    if report.result == VerificationResult.CONFIRMED:
                        av.status = "confirmed"
                        av.ai_payload_result = "success"
                        verified += 1
                    elif report.result == VerificationResult.POTENTIAL:
                        av.status = "potential"
                        av.ai_payload_result = "failed"
                    elif report.result == VerificationResult.FALSE_POS:
                        av.status = "false_positive"
                        av.ai_payload_result = "failed"
                    else:
                        av.status = "potential"
                        av.ai_payload_result = "uncertain"
            db.session.commit()
    except Exception as e:
        print(f"[VERIFY] 自动验证失败: {e}")

    return jsonify({
        "ok": True,
        "analyzed": analyzed,
        "failed": failed,
        "total": len(vulns),
        "verified": verified,
    })


def _serialize(v: Vulnerability) -> dict:
    """
    将 Vulnerability ORM 对象序列化为 JSON 友好格式。

    参数:
        v: Vulnerability 数据库模型实例

    返回:
        dict: 包含所有字段的字典，时间字段转为 ISO 格式字符串
    """
    return {
        "id": v.id,
        "scan_task_id": v.scan_task_id,
        "file_path": v.file_path,
        "line_number": v.line_number,
        "vuln_type": v.vuln_type,
        "severity": v.severity,
        "language": v.language,
        # 引擎输出
        "source_code": v.source_code,
        "sink_code": v.sink_code,
        "data_flow": v.data_flow,
        "context_code": v.context_code,
        # AI 分析结果
        "ai_is_vulnerable": v.ai_is_vulnerable,
        "ai_severity": v.ai_severity,
        "ai_root_cause": v.ai_root_cause,
        "ai_fix_suggestion": v.ai_fix_suggestion,
        "ai_fix_code": v.ai_fix_code,
        "ai_confidence": v.ai_confidence,
        # Payload 验证
        "ai_payload": v.ai_payload,
        "ai_payload_result": v.ai_payload_result,
        "ai_payload_evidence": v.ai_payload_evidence,
        # 人工审核状态
        "status": v.status,
        "created_at": v.created_at.isoformat() if v.created_at else None,
    }


def _verify_single_vuln(v: Vulnerability):
    """
    对单个已 AI 分析的漏洞进行 Payload 构建 + 验证。
    用于手动分析接口的自动验证。
    """
    from engine.payload_builder import PayloadBuilder
    from engine.ai_verifier import AIVerifier, VerificationResult
    from ai.client import get_ai_client

    client = get_ai_client()
    if not client.is_configured():
        return

    source_code_map = {}
    try:
        if v.file_path:
            with open(v.file_path, encoding='utf-8', errors='ignore') as f:
                source_code_map[v.file_path] = f.read()
    except Exception:
        source_code_map[v.file_path] = v.source_code or ""

    vuln_dict = {
        "file_path": v.file_path,
        "line_number": v.line_number,
        "vuln_type": v.vuln_type,
        "severity": v.severity,
        "language": v.language,
        "source_code": v.source_code or "",
        "sink_code": v.sink_code or "",
        "data_flow": v.data_flow or "",
        "protection_level": "none",
        "exploit_difficulty": "unknown",
    }

    builder = PayloadBuilder(client)
    payload_sets = builder.build_payloads([vuln_dict], source_code_map)
    verifier = AIVerifier(client)
    reports = verifier.verify([vuln_dict], payload_sets, source_code_map)

    if reports:
        report = reports[0]
        v.ai_payload = report.verified_payload
        v.ai_payload_evidence = report.evidence
        if report.result == VerificationResult.CONFIRMED:
            v.status = "confirmed"
            v.ai_payload_result = "success"
        elif report.result == VerificationResult.POTENTIAL:
            v.status = "potential"
            v.ai_payload_result = "failed"
        elif report.result == VerificationResult.FALSE_POS:
            v.status = "false_positive"
            v.ai_payload_result = "failed"
        else:
            v.status = "potential"
            v.ai_payload_result = "uncertain"
        db.session.commit()
