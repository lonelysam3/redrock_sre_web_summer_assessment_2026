"""
项目管理 REST API
===============
提供项目的创建、查询、删除接口。

路由前缀: /api/projects

端点:
  GET    /api/projects              — 列出所有项目（按创建时间倒序）
  POST   /api/projects/upload       — 上传压缩包创建项目（唯一创建方式）
  DELETE /api/projects/<id>         — 删除项目（级联删除关联数据并清理解压文件）
"""
import os
import threading
from datetime import datetime
from flask import Blueprint, request, jsonify
from models import db, Project, ScanTask
from config import Config

# 创建蓝图，挂载到 /api/projects
projects_bp = Blueprint("projects", __name__)


@projects_bp.route("", methods=["GET"])
def list_projects():
    """
    获取所有项目列表
    ================
    按创建时间倒序排列，最新的在前。

    返回:
        JSON 数组，每个元素包含项目的 id, name, language, repo_path, created_at
    """
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return jsonify([{
        "id": p.id,                                             # 项目 ID
        "name": p.name,                                         # 项目名称
        "language": p.language,                                 # 编程语言
        "repo_path": p.repo_path,                               # 源码路径
        "created_at": p.created_at.isoformat() if p.created_at else None,  # ISO 格式时间
    } for p in projects])


@projects_bp.route("", methods=["POST"])
def create_project():
    """
    本地路径创建已禁用。
    仅允许通过上传压缩包方式创建项目（POST /api/projects/upload）。
    """
    return jsonify({
        "error": "不支持直接输入路径创建项目，请通过 POST /api/projects/upload 上传压缩包"
    }), 405


@projects_bp.route("/<int:project_id>", methods=["DELETE"])
def delete_project(project_id: int):
    """
    删除项目
    ========
    级联删除：项目下的所有扫描任务和漏洞记录会被自动删除（由外键 CASCADE 保证）。
    如果项目是通过上传创建的，同时清理解压后的文件。

    参数:
        project_id: 项目 ID（URL 路径参数）

    返回:
        200 { deleted: true }
        404 { error: "项目不存在" }
    """
    project = db.session.get(Project, project_id)
    if not project:
        return jsonify({"error": "项目不存在"}), 404

    repo_path = project.repo_path
    source_type = project.source_type

    # 显式删除关联的漏洞和扫描任务（防止 ORM cascade 失效）
    for scan in project.scans:
        for vuln in scan.vulnerabilities:
            db.session.delete(vuln)
        db.session.delete(scan)
    db.session.flush()

    db.session.delete(project)
    db.session.commit()

    # 如果项目是上传的压缩包解压而来，清理磁盘上的解压文件
    if source_type == "upload" and repo_path:
        from utils.archive_handler import cleanup_extracted
        cleanup_extracted(repo_path)

    return jsonify({"deleted": True})


@projects_bp.route("/upload", methods=["POST"])
def upload_project():
    """
    上传压缩包并创建项目
    ===================
    接收一个压缩包文件（zip/tar.gz/tar.bz2/tar），安全解压后创建项目并自动触发扫描。

    表单字段:
      - file:      压缩包文件（multipart/form-data，必填）
      - name:      项目名称（可选，默认使用文件名）
      - language:  编程语言（可选，默认自动检测）
      - auto_scan:  是否自动开始扫描（默认 true）

    安全措施:
      - 不允许直接输入绝对路径（仅通过文件上传）
      - 压缩包内容经过 zip-slip / 路径穿越 / 绝对路径 安全校验
      - 解压到隔离目录，不暴露系统路径

    返回:
        201 Created + 项目信息
        400 Bad Request（文件缺失、格式不支持、安全检查失败）
        413 文件过大
    """
    from utils.archive_handler import (
        extract_archive,
        ArchiveSecurityError,
        ArchiveExtractionError,
    )

    # ---- 1. 文件检查 ----
    if "file" not in request.files:
        return jsonify({"error": "请选择要上传的压缩包文件"}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "文件名为空"}), 400

    # 项目名称：优先用表单字段，次选文件名（去掉扩展名）
    name = (request.form.get("name", "") or "").strip()
    if not name:
        # 从文件名生成项目名
        name = os.path.splitext(file.filename)[0]
        # 处理 .tar.gz 等双扩展名
        if name.endswith(".tar"):
            name = name[:-4]
    if not name:
        name = "uploaded_project"

    # 长度限制
    if len(name) > 200:
        name = name[:200]

    # ---- 2. 语言设置（必选） ----
    language = (request.form.get("language", "") or "").strip()

    ALLOWED_LANGUAGES = {"python", "c", "cpp", "php"}
    if language not in ALLOWED_LANGUAGES:
        return jsonify({
            "error": f"请选择编程语言: {', '.join(sorted(ALLOWED_LANGUAGES))}"
        }), 400

    # ---- 2b. 项目名重复检查 ----
    if Project.query.filter_by(name=name).first():
        return jsonify({
            "error": f"项目名 \"{name}\" 已存在，请使用其他名称"
        }), 400

    # ---- 3. 是否自动扫描 ----
    auto_scan = request.form.get("auto_scan", "true").lower() != "false"
    # ---- 3b. 是否自动 AI 分析 ----
    auto_ai = request.form.get("auto_ai", "0") == "1"

    # ---- 3c. PHP 版本（仅 PHP 项目生效） ----
    php_version = (request.form.get("php_version", "") or "").strip() or None

    # ---- 4. 执行解压 ----
    extract_base = str(Config.EXTRACT_FOLDER)

    try:
        project_path = extract_archive(
            file_stream=file,
            original_filename=file.filename,
            extract_base=extract_base,
            project_name=name,
        )
    except ArchiveSecurityError as e:
        return jsonify({
            "error": f"压缩包安全检查失败: {e}",
            "detail": "压缩包内可能包含不安全的路径（如绝对路径或路径穿越）"
        }), 400
    except ArchiveExtractionError as e:
        return jsonify({
            "error": f"解压失败: {e}",
            "detail": "请检查文件格式是否正确，以及压缩包大小是否在限制范围内"
        }), 400
    except Exception as e:
        return jsonify({
            "error": f"解压过程发生错误: {e}"
        }), 500

    # ---- 5. 创建项目记录 ----
    project = Project(
        name=name,
        repo_path=project_path,
        language=language,
        source_type="upload",
        original_filename=file.filename,
        php_version=php_version,
    )
    db.session.add(project)
    db.session.commit()

    response_data = {
        "id": project.id,
        "name": project.name,
        "language": language,
        "repo_path": project_path,
        "source_type": "upload",
        "original_filename": file.filename,
    }

    # ---- 7. 自动触发扫描 ----
    if auto_scan:
        scan = ScanTask(
            project_id=project.id,
            status="running",
            started_at=datetime.utcnow(),
        )
        db.session.add(scan)
        db.session.commit()

        # 在后台线程中执行扫描
        from flask import current_app
        app = current_app._get_current_object()

        thread = threading.Thread(
            target=_trigger_scan_background,
            args=(app, scan.id, project_path, language, auto_ai),
            daemon=True,
        )
        thread.start()

        response_data["scan_id"] = scan.id
        response_data["scan_status"] = "running"

    return jsonify(response_data), 201


def _trigger_scan_background(app, scan_id: int, project_path: str, language: str, auto_ai: bool = False):
    """后台线程：直接调用 app.run_scan_in_thread"""
    from app import run_scan_in_thread
    run_scan_in_thread(app, scan_id, project_path, language, auto_ai=auto_ai)
