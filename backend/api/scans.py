"""
扫描任务 REST API
===============
提供扫描任务的查询和删除接口。

路由前缀: /api/scans

端点:
  GET    /api/scans?project_id=<id>  — 列出扫描任务（可按项目筛选）
  DELETE /api/scans/<id>             — 删除扫描任务
"""
from flask import Blueprint, request, jsonify
from models import db, Project, ScanTask

# 创建蓝图，挂载到 /api/scans
scans_bp = Blueprint("scans", __name__)


@scans_bp.route("", methods=["GET"])
def list_scans():
    """
    查询扫描任务列表
    ================
    可选查询参数:
      - project_id: 筛选指定项目的扫描任务

    返回:
        JSON 数组，按创建时间倒序，最多返回 50 条
    """
    project_id = request.args.get("project_id")
    query = ScanTask.query

    # 如果指定了项目 ID，添加过滤条件
    if project_id:
        query = query.filter_by(project_id=int(project_id))

    # 按创建时间倒序，限制 50 条（避免一次性加载过多数据）
    scans = query.order_by(ScanTask.created_at.desc()).limit(50).all()
    return jsonify([{
        "id": s.id,                                               # 任务 ID
        "project_id": s.project_id,                               # 所属项目 ID
        "status": s.status,                                       # 状态: pending/running/done/failed
        "total_files": s.total_files,                             # 项目总文件数
        "scanned_files": s.scanned_files,                         # 已扫描文件数
        "vulns_found": s.vulns_found,                             # 发现的漏洞数
        "started_at": s.started_at.isoformat() if s.started_at else None,    # 开始时间
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,  # 完成时间
        "created_at": s.created_at.isoformat() if s.created_at else None,     # 创建时间
    } for s in scans])


@scans_bp.route("/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id: int):
    """
    删除扫描任务
    ============
    同时删除关联的所有漏洞记录。

    参数:
        scan_id: 扫描任务 ID

    返回:
        200 { deleted: true }
        404 { error: "不存在" }
    """
    scan = db.session.get(ScanTask, scan_id)
    if not scan:
        return jsonify({"error": "不存在"}), 404

    db.session.delete(scan)
    db.session.commit()
    return jsonify({"deleted": True})
