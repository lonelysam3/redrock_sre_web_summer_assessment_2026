"""
代码审计平台 — 主应用入口（Flask Web 应用）
========================================
提供以下功能：
  1. Web 界面：项目管理、扫描历史、漏洞详情、AI 设置
  2. REST API：项目管理、扫描触发、漏洞查询、AI 分析
  3. 后台扫描：异步执行代码扫描，完成后自动触发 AI 分析

==== 启动方式 ====

    python backend/app.py
    # 访问 http://localhost:5000

==== 架构概览 ====

   前端（Jinja2 模板 + 原生 JS）
       │
       ▼
   Flask 路由层（app.py）
       ├──→ REST API（api/projects.py, scans.py, vulns.py）
       └──→ 后台线程（扫描引擎 + AI 分析）
              │
              ├──→ 扫描引擎（engine/）
              │     ├──→ PythonScanner（AST 分析）
              │     └──→ CScanner（tree-sitter 分析）
              │
              └──→ AI 客户端（ai/client.py）
                    └──→ DeepSeek / OpenAI / 自定义 API
"""
import os
import sys
import threading
from pathlib import Path
from datetime import datetime
from flask import Flask

# 确保 backend 目录在 Python 路径中（支持从任意位置启动）
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import Config
from models import db, Project, ScanTask, Vulnerability, AISettings
from engine import scan_project
from ai.client import get_ai_client, reset_ai_client


def _migrate_db():
    """
    简易数据库迁移：为已有表添加新列。
    生产环境建议使用 Flask-Migrate。
    """
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)

    # 为 projects 表添加 source_type 和 original_filename 列
    if "projects" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("projects")}
        if "source_type" not in cols:
            db.session.execute(
                text("ALTER TABLE projects ADD COLUMN source_type VARCHAR(20) DEFAULT 'local'")
            )
        if "original_filename" not in cols:
            db.session.execute(
                text("ALTER TABLE projects ADD COLUMN original_filename VARCHAR(500)")
            )
        if "php_version" not in cols:
            db.session.execute(
                text("ALTER TABLE projects ADD COLUMN php_version VARCHAR(20)")
            )

    # 为 vulnerabilities 表补充 AI 深度分析相关列（create_all 可能遗漏）
    if "vulnerabilities" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("vulnerabilities")}
        missing = [
            ("ai_cwe_id", "VARCHAR(20)"),
            ("ai_owasp_category", "VARCHAR(50)"),
            ("ai_attack_vector", "TEXT"),
            ("pipeline_stage", "VARCHAR(50)"),
            ("ai_payload", "TEXT"),
            ("ai_payload_result", "TEXT"),
            ("ai_payload_evidence", "TEXT"),
        ] + [
            ("source_file", "VARCHAR(500)"),
            ("source_line", "INTEGER"),
            ("description", "TEXT"),
        ]
        for col_name, col_type in missing:
            if col_name not in cols:
                db.session.execute(
                    text(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}")
                )

    db.session.commit()


def create_app() -> Flask:
    """
    Flask 应用工厂函数
    ==================
    按以下步骤创建并配置应用：
      1. 初始化 Flask 实例（配置模板和静态文件路径）
      2. 加载配置（从 config.py + 环境变量）
      3. 初始化数据库（SQLAlchemy + 自动建表）
      4. 注册 API 蓝图（/api/projects, /api/scans, /api/vulns）
      5. 注册页面路由（/, /project/<id>, /scan/<id>, /settings）
      6. 注册健康和设置 API

    返回:
        Flask: 已配置的 Flask 应用实例
    """
    # ---- 1. 创建 Flask 应用 ----
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # ---- 2. 加载配置 ----
    app.config.from_object(Config)
    # 设置上传文件大小上限
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH

    # ---- 3. 初始化数据库 ----
    db.init_app(app)
    with app.app_context():
        # 启用 SQLite 外键约束 + WAL 模式（允许并发读写）
        from sqlalchemy import event, text
        @event.listens_for(db.engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging, 允许多线程并发
            cursor.close()
        # 自动创建所有缺失的表（开发环境友好，生产环境应用 migrate）
        db.create_all()
        # 简易迁移：为已有 projects 表添加新字段
        _migrate_db()

    # ---- 4. 注册 API 蓝图 ----
    # 各蓝图提供 RESTful API，挂载在 /api 下
    from api.projects import projects_bp
    from api.scans import scans_bp
    from api.vulns import vulns_bp
    app.register_blueprint(projects_bp, url_prefix="/api/projects")
    app.register_blueprint(scans_bp, url_prefix="/api/scans")
    app.register_blueprint(vulns_bp, url_prefix="/api/vulns")

    from flask import render_template, request, jsonify
    import json as _json

    # ---- 自定义 Jinja2 过滤器：安全解析 JSON 字符串 ----
    @app.template_filter('from_json')
    def from_json_filter(value):
        """将 JSON 字符串安全解析为 Python dict，失败返回 None"""
        if not value or not isinstance(value, str):
            return None
        try:
            return _json.loads(value)
        except (ValueError, TypeError, _json.JSONDecodeError):
            return None

    # ---- 5. 页面路由 ----
    # 这些路由返回 Jinja2 渲染的 HTML 页面

    @app.route("/")
    def index():
        """
        首页：显示所有项目和创建表单。
        项目按创建时间倒序排列。
        """
        projects = Project.query.order_by(Project.created_at.desc()).all()
        return render_template("index.html", projects=projects)

    @app.route("/project/<int:project_id>")
    def project_detail(project_id: int):
        """
        项目详情页：显示项目信息和扫描历史列表。
        扫描记录按创建时间倒序排列。

        参数:
            project_id: 项目 ID（URL 路径参数）
        """
        project = db.session.get(Project, project_id)
        if not project:
            return "项目不存在", 404

        # 获取该项目的所有扫描（最新的在前）
        scans = (ScanTask.query
                 .filter_by(project_id=project_id)
                 .order_by(ScanTask.created_at.desc())
                 .all())
        return render_template("project.html", project=project, scans=scans)

    @app.route("/scan/<int:scan_id>")
    def scan_detail(scan_id: int):
        """
        扫描详情页：显示扫描结果和所有发现的漏洞。

        漏洞按严重程度（高→低）排序，同级按行号排序。
        同时显示关联的项目信息。
        无漏洞时显示安全报告（含扫描文件清单）。

        参数:
            scan_id: 扫描任务 ID
        """
        scan = db.session.get(ScanTask, scan_id)
        if not scan:
            return "扫描任务不存在", 404

        # 获取该次扫描的所有漏洞，按严重程度排列
        vulns = (Vulnerability.query
                 .filter_by(scan_task_id=scan_id)
                 .order_by(Vulnerability.severity.desc(),    # 严重程度优先
                           Vulnerability.line_number)         # 行号其次
                 .all())

        # 收集扫描文件清单（用于无漏洞时的安全报告）
        scanned_files = []
        if scan.status == "done" and len(vulns) == 0:
            try:
                project_path = scan.project.repo_path
                from pathlib import Path as _Path
                scanned_files = sorted(
                    str(_.relative_to(project_path))
                    for _ in _Path(project_path).rglob("*")
                    if _.is_file() and not _.name.startswith(".")
                )[:200]  # 最多显示 200 个文件
            except Exception:
                pass

        # AI 分析进度（analyzing 状态时有用）
        ai_analyzed_count = 0
        if scan.status == "analyzing":
            ai_analyzed_count = Vulnerability.query.filter_by(
                scan_task_id=scan_id
            ).filter(Vulnerability.ai_is_vulnerable != None).count()

        return render_template(
            "scan.html",
            scan=scan,
            vulns=vulns,
            project=scan.project,
            scanned_files=scanned_files,
            ai_analyzed_count=ai_analyzed_count,
        )

    @app.route("/project/<int:project_id>/new-scan", methods=["POST"])
    def new_scan(project_id: int):
        """
        触发新扫描（API 端点，前端 JS 调用）。

        请求体 JSON（可选）:
            { "auto_ai": true }  — 扫描后自动 AI 分析

        返回:
            JSON: { scan_id, status: "running" }
        """
        project = db.session.get(Project, project_id)
        if not project:
            return jsonify({"error": "项目不存在"}), 404

        auto_ai = False
        try:
            data = request.get_json(silent=True) or {}
            auto_ai = data.get("auto_ai", False)
        except Exception:
            pass
        # 兜底：也支持 query string 和 form data
        if not auto_ai:
            auto_ai = request.args.get("auto_ai", "").lower() in ("1", "true")
        if not auto_ai:
            auto_ai = request.form.get("auto_ai", "").lower() in ("1", "true")

        # 创建扫描任务记录
        scan = ScanTask(
            project_id=project_id,
            status="running",
            started_at=datetime.utcnow(),
        )
        db.session.add(scan)
        db.session.commit()

        # 启动后台线程
        thread = threading.Thread(
            target=_run_scan_background,
            args=(app, scan.id, project.repo_path, project.language, auto_ai),
            daemon=True,
        )
        thread.start()

        return jsonify({"scan_id": scan.id, "status": "running"})

    # ---- 6. AI 设置页面和 API ----

    @app.route("/settings", methods=["GET"])
    def settings_page():
        """
        AI 设置页面：显示当前 AI 配置。
        用户可在此页配置 API Key、模型、Base URL 等。
        """
        settings = AISettings.get()
        return render_template("settings.html", settings=settings)

    @app.route("/api/settings/ai", methods=["GET"])
    def get_ai_settings():
        """
        获取当前 AI 配置（API 接口）。

        返回:
            JSON: { api_key（脱敏后）, base_url, model, provider }
        """
        s = AISettings.get()
        return jsonify({
            # API Key 脱敏显示：只显示最后 4 位，前面用 *** 替代
            "api_key": "***" + s.api_key[-4:] if s.api_key else "",
            "base_url": s.base_url,
            "model": s.model,
            "provider": s.provider,
        })

    @app.route("/api/settings/ai", methods=["POST"])
    def update_ai_settings():
        """
        更新 AI 配置。

        请求体 JSON:
            { api_key?, base_url?, model?, provider? }
            - api_key 如果以 "***" 开头（即用户未修改掩码字段），则保留原值
            - 其他字段直接覆盖

        返回:
            JSON: { ok: true }
        """
        data = request.get_json()
        s = AISettings.get()

        # API Key：只有用户输入了新值（不以 *** 开头）才更新
        if data.get("api_key") and not data["api_key"].startswith("***"):
            s.api_key = data["api_key"]

        if data.get("base_url"):
            s.base_url = data["base_url"].rstrip("/")  # 去掉末尾斜杠

        if data.get("model"):
            s.model = data["model"]

        if data.get("provider"):
            s.provider = data["provider"]

        db.session.commit()

        # 配置变更后刷新 AI 客户端缓存，使新配置立即生效
        reset_ai_client()
        return jsonify({"ok": True})

    @app.route("/api/settings/ai/test", methods=["POST"])
    def test_ai_connection():
        """
        测试 AI API 连接是否正常。

        创建一个临时 AIClient，发送简单的测试请求。
        如果 AI 返回 "OK"，则连接成功。

        返回:
            JSON: { ok: true, message: "连接成功" }
              或  { ok: false, error: "..." }
        """
        from ai.client import AIClient
        s = AISettings.get()
        client = AIClient(
            api_key=s.api_key,
            base_url=s.base_url,
            model=s.model,
            provider=s.provider,
        )

        if not client.is_configured():
            return jsonify({"ok": False, "error": "API Key 未配置"})

        # 发送最简单的测试消息（使用原始文本接口，不需要 JSON）
        result = client._chat_raw("请回复一个词：OK")
        if result and "OK" in result.upper():
            return jsonify({"ok": True, "message": "连接成功"})
        if result:
            return jsonify({"ok": True, "message": f"连接成功（回复: {result[:50]}）"})

        return jsonify({"ok": False, "error": "连接失败，请检查配置"})

    @app.route("/api/settings/ai/models", methods=["GET"])
    def fetch_models():
        """
        从配置的 API 获取可用模型列表。
        调用 OpenAI 兼容的 /v1/models 端点，返回模型 ID 列表。
        """
        import urllib.request
        import urllib.error
        import json as _json

        s = AISettings.get()
        if not s.api_key:
            return jsonify({"ok": False, "error": "请先填写 API Key"}), 400
        if not s.base_url:
            return jsonify({"ok": False, "error": "请先填写 API 地址"}), 400

        url = f"{s.base_url.rstrip('/')}/models"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {s.api_key}")
        req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = _json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return jsonify({
                "ok": False,
                "error": f"API 返回 {e.code}: {e.reason}"
            }), 502
        except Exception as e:
            return jsonify({
                "ok": False,
                "error": f"请求失败: {str(e)}"
            }), 502

        # 解析模型列表
        models = []
        for m in body.get("data", []):
            mid = m.get("id", "")
            if mid:
                models.append(mid)

        if not models:
            return jsonify({"ok": False, "error": "未获取到任何模型"}), 502

        # 排序：优先 chat 模型在前
        models.sort(key=lambda x: (
            not any(k in x.lower() for k in ("chat", "gpt", "claude", "deepseek", "qwen")),
            x
        ))

        return jsonify({"ok": True, "models": models})

    # ---- 7. 健康检查 ----
    @app.route("/health")
    def health():
        """健康检查端点"""
        return jsonify({"status": "ok"})

    @app.route("/api/scan/<int:scan_id>/debug", methods=["GET"])
    def debug_scan(scan_id: int):
        """
        调试端点：查看扫描任务详细状态。
        用于排查扫描状态不更新的问题。
        """
        scan = db.session.get(ScanTask, scan_id)
        if not scan:
            return jsonify({"error": "不存在"}), 404
        return jsonify({
            "id": scan.id,
            "project_id": scan.project_id,
            "status": scan.status,
            "total_files": scan.total_files,
            "scanned_files": scan.scanned_files,
            "vulns_found": scan.vulns_found,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
        })

    return app


# ========================================================================
# 后台任务
# ========================================================================

import time

def _commit_with_retry(db_session, label: str = "", max_retries: int = 5, delay: float = 0.5):
    """
    带重试的数据库提交，处理 SQLite 并发写入冲突。
    失败时 rollback 后重试，避免 session 脏状态。
    """
    for attempt in range(max_retries):
        try:
            db_session.session.commit()
            return
        except Exception as e:
            print(f"[WARN] {label} 提交失败 (尝试 {attempt+1}/{max_retries}): {e}", flush=True)
            db_session.session.rollback()
            if attempt < max_retries - 1:
                time.sleep(delay * (attempt + 1))
            else:
                print(f"[ERROR] {label} 提交最终失败", flush=True)
                raise


def _run_scan_background(app: Flask, scan_id: int, project_path: str, language: str, auto_ai: bool = False):
    """
    后台线程：执行代码扫描（v2 — 四级流水线 + AI 自动验证）。

    参数:
        app:          Flask 应用实例
        scan_id:      扫描任务 ID
        project_path: 项目源码路径
        language:     编程语言
        auto_ai:      扫描完成后是否自动触发 AI 分析
    """
    with app.app_context():
        scan = db.session.get(ScanTask, scan_id)
        if not scan:
            return

        try:
            # ---- 执行四级流水线扫描 ----
            print(f"[SCAN] 开始四级流水线扫描: {project_path} ({language})")
            from engine import scan_with_verification
            from engine.rule_engine import resolve_php_version
            from ai.client import get_ai_client as _get_client

            ai_client = _get_client()
            user_php = getattr(scan.project, 'php_version', None) if scan.project else None

            # 解析最终 PHP 版本：用户选择优先，否则自动检测
            if language == "php":
                from engine.pipeline import AnalysisPipeline as _AP
                _tmp_pipeline = _AP()
                source_map = _tmp_pipeline._collect_source_files(project_path, language)
                resolved_version, auto_detected = resolve_php_version(
                    user_php, source_map
                )
                effective_version = resolved_version
                if auto_detected and scan.project:
                    scan.project.php_version = f"auto({resolved_version})"
                    db.session.commit()
            else:
                effective_version = user_php

            vulns, verification_reports = scan_with_verification(
                project_path, language, ai_client=None, php_version=effective_version
            )

            # ---- 统计 ----
            scan.total_files = sum(
                1 for _ in Path(project_path).rglob("*") if _.is_file()
            )
            scan.scanned_files = scan.total_files
            scan.vulns_found = len(vulns)
            scan.status = "done"
            scan.finished_at = datetime.utcnow()

            # ---- 保存漏洞记录 ----
            for i, v in enumerate(vulns):
                vuln = Vulnerability(
                    scan_task_id=scan_id,
                    file_path=v["file_path"],
                    line_number=v.get("line_number", v.get("sink_line", 0)),
                    source_file=v.get("source_file", None),
                    source_line=v.get("source_line", None),
                    vuln_type=v.get("vuln_type", ""),
                    severity=v.get("severity", "medium"),
                    language=v.get("language", language),
                    source_code=v.get("source_code", ""),
                    sink_code=v.get("sink_code", ""),
                    data_flow=v.get("data_flow", ""),
                    pipeline_stage=v.get("pipeline_stage", "taint"),
                    description=v.get("description", ""),
                    status=v.get("status", "pending"),
                    ai_payload=v.get("ai_payload", ""),
                    ai_payload_result=v.get("ai_payload_result", ""),
                    ai_payload_evidence=v.get("ai_payload_evidence", ""),
                )
                db.session.add(vuln)

            # ---- 提交（带重试 + rollback，处理 SQLite 并发写入冲突）----
            print(f"[SCAN] 准备提交: status=done, vulns={len(vulns)}, files={scan.total_files}", flush=True)
            _commit_with_retry(db, f"[SCAN] 扫描结果提交")
            print(f"[SCAN] 提交成功!", flush=True)

            confirmed_count = sum(
                1 for v in vulns if v.get("status") == "confirmed"
            )
            potential_count = sum(
                1 for v in vulns if v.get("status") == "potential"
            )
            print(f"[SCAN] 扫描完成: {len(vulns)} 个漏洞, "
                  f"{confirmed_count} confirmed, {potential_count} potential")

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            print(f"[ERROR] 扫描失败: {e}")
            print(tb)
            # 尝试标记失败状态
            try:
                scan.status = "failed"
                _commit_with_retry(db, f"[SCAN] 失败状态提交")
            except Exception as e2:
                print(f"[ERROR] 无法更新扫描状态: {e2}")

    # ---- 扫描完成后自动触发 AI 深度分析 ----
    if auto_ai:
        print(f"[SCAN] auto_ai=True, starting AI analysis check...")
        with app.app_context():
            try:
                client = get_ai_client()
                print(f"[SCAN] AI client: key={'***' if client.api_key else 'EMPTY'}, url={client.base_url}, model={client.model}, configured={client.is_configured()}")
                s = db.session.get(ScanTask, scan_id)
                if client.is_configured() and s and s.vulns_found > 0:
                    if s.status == "done":
                        s.status = "analyzing"
                        db.session.commit()
                    analyzed, total = _run_ai_analysis_on_vulns(scan_id, project_path, client, sys.stderr)
                    s = db.session.get(ScanTask, scan_id)
                    if s:
                        s.status = "done"
                        db.session.commit()
                else:
                    print("[INFO] AI 未配置，跳过 AI 深度分析")
            except Exception as e:
                import traceback
                print(f"[ERROR] AI 深度分析失败: {e}")
                traceback.print_exc()


def _run_ai_analysis(app: Flask, scan_id: int):
    """
    后台执行 AI 二次分析。

    将扫描发现的漏洞批量发送给 AI，进行深度分析和误报排除。
    批处理大小：每次 5 个漏洞（防止单次请求 token 超限）。

    流程:
      1. 获取该次扫描的所有漏洞记录
      2. 提取每个漏洞的上下文代码
      3. 分批发送给 AI
      4. 将 AI 分析结果写回 Vulnerability 表

    参数:
        app:     Flask 应用实例
        scan_id: 扫描任务 ID
    """
    with app.app_context():
        scan = db.session.get(ScanTask, scan_id)
        if not scan or scan.vulns_found == 0:
            return  # 没有漏洞，跳过

        vulns = Vulnerability.query.filter_by(scan_task_id=scan_id).all()
        client = get_ai_client()
        if not client.is_configured():
            return

        # ---- 准备漏洞数据 ----
        vuln_data = []           # 发送给 AI 的漏洞摘要
        context_codes = {}       # 每个漏洞的上下文代码（按索引编号）

        from utils.code_extractor import extract_source_context

        for i, v in enumerate(vulns):
            vuln_data.append({
                "file_path": v.file_path,
                "vuln_type": v.vuln_type,
                "severity": v.severity,
                "language": v.language,
                "data_flow": v.data_flow,
            })
            # 提取漏洞所在代码的上下文（前 5 行到当前行）
            context_codes[str(i)] = extract_source_context(
                v.file_path,
                v.line_number - 5 if v.line_number > 5 else 1,
                v.line_number,
            )

        # ---- 分批发送给 AI（每批 5 个漏洞）----
        batch_size = 5
        for start in range(0, len(vuln_data), batch_size):
            batch_vulns = vuln_data[start:start + batch_size]

            # 收集这批漏洞的上下文代码
            batch_contexts = {
                str(i): context_codes.get(str(start + i), "")
                for i in range(len(batch_vulns))
            }

            # 调用 AI 批量分析
            results = client.analyze_batch(batch_vulns, batch_contexts)

            if results:
                import json as json_mod
                for i, result in enumerate(results):
                    idx = start + i  # 全局索引
                    if idx < len(vulns):
                        v = vulns[idx]
                        # ---- 将 AI 深度分析结果写入数据库 ----
                        v.ai_analysis = json_mod.dumps(result, ensure_ascii=False)
                        v.ai_is_vulnerable = (result.get("is_vulnerable", "uncertain") or "uncertain").lower()
                        v.ai_severity = result.get("severity", v.severity)
                        v.ai_cwe_id = result.get("cwe_id", "")
                        v.ai_owasp_category = result.get("owasp_category", "")

                        # 形成原因（结构化存储）
                        rc = result.get("root_cause", {})
                        if isinstance(rc, dict):
                            v.ai_root_cause = json_mod.dumps(rc, ensure_ascii=False)
                        else:
                            v.ai_root_cause = str(rc) if rc else ""

                        # 攻击方式分析（结构化存储）
                        atk = result.get("attack_analysis", {})
                        if isinstance(atk, dict):
                            v.ai_attack_vector = json_mod.dumps(atk, ensure_ascii=False)
                        else:
                            v.ai_attack_vector = str(atk) if atk else ""

                        # 修复建议 + 代码
                        fix = result.get("fix_recommendation", {})
                        if isinstance(fix, dict):
                            v.ai_fix_suggestion = json_mod.dumps(fix, ensure_ascii=False)
                            # 提取首要修复方案的代码
                            primary = fix.get("primary", {})
                            v.ai_fix_code = primary.get("code", "") if isinstance(primary, dict) else ""
                        else:
                            v.ai_fix_suggestion = str(fix) if fix else ""
                            v.ai_fix_code = result.get("fix_code", "")

        db.session.commit()


# ========================================================================
# 可导入的后台扫描（供 upload 使用）
# ========================================================================

def _run_ai_analysis_on_vulns(scan_id: int, project_path: str, client, log):
    """对扫描发现的所有漏洞逐个进行 AI 深度分析。log 可以是 stderr 或任何有 write/flush 的对象。"""
    import json as _json
    from utils.code_extractor import extract_source_context
    from models import db, ScanTask

    # 兼容：如果传了 sys 模块而不是 sys.stderr
    if not hasattr(log, 'write'):
        import sys
        log = sys.stderr

    # 获取 PHP 版本
    php_version = ""
    scan = db.session.get(ScanTask, scan_id)
    if scan and scan.project:
        php_version = scan.project.php_version or ""

    vulns = Vulnerability.query.filter_by(scan_task_id=scan_id).all()
    analyzed = 0
    for v in vulns:
        try:
            # 从实际文件中提取代码
            actual_source = (v.source_code or "").replace("{", "{{").replace("}", "}}")
            actual_sink = (v.sink_code or "").replace("{", "{{").replace("}", "}}")
            sink_file = v.file_path
            sink_line = v.line_number

            # 跨文件漏洞：从 source 文件提取代码
            source_file = getattr(v, 'source_file', None) or ""
            if source_file and source_file != sink_file:
                try:
                    with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                        sf_lines = f.readlines()
                        sln = max(0, getattr(v, 'source_line', 1) - 1)
                        if sln < len(sf_lines):
                            actual_source = sf_lines[sln].rstrip()
                except Exception:
                    pass

            # 从 sink 文件提取代码（回退到 DB 字段）
            try:
                with open(sink_file, 'r', encoding='utf-8', errors='ignore') as f:
                    file_lines = f.readlines()
                    ln = max(0, sink_line - 1)
                    if ln < len(file_lines):
                        actual_sink = file_lines[ln].rstrip() or actual_sink
            except Exception:
                pass

            ctx = extract_source_context(
                sink_file,
                max(1, sink_line - 10),
                sink_line + 5,
                context_lines=15,
            )
            # 跨文件：追加 source 文件的上下文
            if source_file and source_file != sink_file:
                src_ctx = extract_source_context(
                    source_file,
                    max(1, getattr(v, 'source_line', 1) - 3),
                    getattr(v, 'source_line', 1) + 3,
                    context_lines=8,
                )
                ctx = f"=== SOURCE 文件: {source_file} ===\n{src_ctx}\n\n=== SINK 文件: {sink_file} ===\n{ctx}"

            # ---- 预取 data_flow / description 中引用的其他文件 ----
            import re as _re
            ref_files = set()
            for text_field in [v.data_flow or "", v.sink_code or ""]:
                for m in _re.finditer(r'([\w./-]+\.(?:php|py|c|cpp|h))\b', text_field):
                    candidate = m.group(1)
                    # 尝试匹配项目中的实际文件
                    for fp in [os.path.join(project_path, candidate) if project_path else "",
                               os.path.join(os.path.dirname(v.file_path), candidate) if v.file_path else ""]:
                        if fp and os.path.isfile(fp):
                            ref_files.add(fp)
                            break
            # 去掉已经在 context 中的文件
            ref_files.discard(sink_file)
            ref_files.discard(source_file)
            # 预取并追加到 context
            for rf in list(ref_files)[:3]:  # 最多 3 个额外文件
                try:
                    rf_ctx = extract_source_context(rf, 1, min(60, sum(1 for _ in open(rf, encoding='utf-8', errors='ignore'))), context_lines=3)
                    ctx += "\n\n=== 引用的文件: {} ===\n{}".format(rf, rf_ctx)
                except Exception:
                    pass

            result = client.analyze_single_with_tools({
                "file_path": v.file_path,
                "vuln_type": v.vuln_type,
                "severity": v.severity,
                "language": v.language,
                "data_flow": (v.data_flow or "").replace("{", "{{").replace("}", "}}"),
                "source_code": actual_source,
                "sink_code": actual_sink,
                "pipeline_stage": v.pipeline_stage or "",
            }, ctx.replace("{", "{{").replace("}", "}}"), php_version=php_version,
               project_path=project_path or os.path.dirname(v.file_path) if v.file_path else "")

            if result:
                # AI 可能返回 dict 或 list；如果是 list，取首项 dict
                r = result
                if isinstance(r, list):
                    r = r[0] if r and isinstance(r[0], dict) else None
                if isinstance(r, dict):
                    v.ai_analysis = _json.dumps(r, ensure_ascii=False)
                    v.ai_is_vulnerable = r.get("is_vulnerable", "uncertain")
                    v.ai_severity = r.get("severity", v.severity)
                    v.ai_cwe_id = r.get("cwe_id", "")
                    v.ai_owasp_category = r.get("owasp_category", "")
                    v.ai_root_cause = _json.dumps(r.get("root_cause", {}), ensure_ascii=False)
                    v.ai_attack_vector = _json.dumps(r.get("attack_analysis", {}), ensure_ascii=False)
                    v.ai_fix_suggestion = _json.dumps(r.get("fix_recommendation", {}), ensure_ascii=False)
                    fix = r.get("fix_recommendation", {})
                    if isinstance(fix, dict):
                        primary = fix.get("primary", {})
                        v.ai_fix_code = primary.get("code", "") if isinstance(primary, dict) else ""
                    analyzed += 1

            db.session.commit()
        except Exception as e:
            import traceback as _tb
            log.write(f"[AI] vuln #{v.id} failed: {e}\n")
            _tb.print_exc(file=log)
            log.flush()

    log.write(f"[AI] analyzed {analyzed}/{len(vulns)} vulns\n")
    log.flush()
    return analyzed, len(vulns)


def run_scan_in_thread(app, scan_id: int, project_path: str, language: str, auto_ai: bool = False):
    """后台线程中执行扫描。"""
    import traceback, sys as _sys

    with app.app_context():
        scan = db.session.get(ScanTask, scan_id)
        if not scan:
            _sys.stderr.write(f"[SCAN] scan {scan_id} not found\n")
            _sys.stderr.flush()
            return
        try:
            from engine import scan_with_verification
            from engine.rule_engine import resolve_php_version
            from ai.client import get_ai_client
            from models import Vulnerability

            _sys.stderr.write(f"[SCAN] start {scan_id}\n")
            _sys.stderr.flush()

            user_php = getattr(scan.project, 'php_version', None) if scan.project else None

            # 解析最终 PHP 版本
            if language == "php":
                from engine.pipeline import AnalysisPipeline
                source_map = AnalysisPipeline()._collect_source_files(project_path, language)
                resolved_version, auto_detected = resolve_php_version(user_php, source_map)
                effective_version = resolved_version
                if auto_detected and scan.project:
                    scan.project.php_version = f"auto({resolved_version})"
                    db.session.commit()
            else:
                effective_version = user_php

            # 不传 ai_client，跳过耗时的 AI Payload 验证，只跑四级流水线
            vulns, _ = scan_with_verification(project_path, language, ai_client=None, php_version=effective_version)
            n = len(vulns)
            _sys.stderr.write(f"[SCAN] got {n} vulns, committing...\n")
            _sys.stderr.flush()

            scan.total_files = sum(1 for _ in Path(project_path).rglob("*") if _.is_file())
            scan.scanned_files = scan.total_files
            scan.vulns_found = n
            scan.status = "done"
            scan.finished_at = datetime.utcnow()

            for v in vulns:
                db.session.add(Vulnerability(
                    scan_task_id=scan_id,
                    file_path=v["file_path"], line_number=v.get("line_number", 0),
                    source_file=v.get("source_file", None),
                    source_line=v.get("source_line", None),
                    vuln_type=v.get("vuln_type", ""), severity=v.get("severity", "medium"),
                    language=v.get("language", language),
                    source_code=v.get("source_code", ""), sink_code=v.get("sink_code", ""),
                    data_flow=v.get("data_flow", ""), pipeline_stage=v.get("pipeline_stage", "taint"),
                    description=v.get("description", ""),
                    status=v.get("status", "pending"),
                ))

            db.session.commit()
            _sys.stderr.write(f"[SCAN] committed {n} vulns\n")
            _sys.stderr.flush()

            # ---- 自动触发 AI 深度分析（如果用户选择开启）----
            if auto_ai:
                ai_client = get_ai_client()
                if ai_client.is_configured() and n > 0:
                    scan.status = "analyzing"
                    db.session.commit()
                    _sys.stderr.write(f"[SCAN] starting AI analysis of {n} vulns...\n")
                    _sys.stderr.flush()
                    analyzed, total = _run_ai_analysis_on_vulns(scan_id, project_path, ai_client, _sys.stderr)
                    if analyzed >= total:
                        scan.status = "done"
                        _sys.stderr.write(f"[SCAN] AI analysis complete ({analyzed}/{total})\n")
                    else:
                        _sys.stderr.write(f"[SCAN] AI analysis partial ({analyzed}/{total}), {total - analyzed} failed\n")
                    db.session.commit()
                    _sys.stderr.flush()
        except Exception:
            traceback.print_exc(file=_sys.stderr)
            _sys.stderr.flush()
            try:
                db.session.rollback()
                scan.status = "failed"
                db.session.commit()
            except Exception:
                pass


# ========================================================================
# 程序入口
# ========================================================================

if __name__ == "__main__":
    # 创建应用
    app = create_app()

    # 从环境变量 PORT 读取端口号（默认 5000）
    port = int(os.getenv("PORT", 5000))

    # 启动开发服务器
    # host="0.0.0.0" 使服务监听所有网络接口（允许局域网访问）
    # debug=True 开启热重载和详细错误页面（生产环境应关闭）
    app.run(host="0.0.0.0", port=port, debug=True)
