"""
数据库模型定义
===========
使用 SQLAlchemy ORM 定义以下数据表：
  1. projects         — 待审计的源码项目
  2. scan_tasks       — 每次扫描任务
  3. vulnerabilities  — 扫描发现的漏洞记录
  4. ai_settings      — AI 服务配置（单例表，全局一份）

关系：
  Project (1) ──< (N) ScanTask (1) ──< (N) Vulnerability
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# 全局数据库对象，由 app.py 中 init_app() 初始化
db = SQLAlchemy()


class Project(db.Model):
    """
    审计项目表
    ==========
    每个项目对应一个源码目录，可以是 Python、C 或 C++ 项目。
    一个项目可以有多次扫描。
    """
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)                           # 自增主键
    name = db.Column(db.String(200), nullable=False)                       # 项目名称（用于界面展示）
    language = db.Column(db.String(50), nullable=False)                    # 编程语言: python / c / cpp
    repo_path = db.Column(db.String(500), nullable=False)                  # 源码在磁盘上的绝对路径
    source_type = db.Column(db.String(20), default="local")                 # 来源: local(本地路径) / upload(压缩包上传)
    original_filename = db.Column(db.String(500), nullable=True)           # 上传的原始文件名（仅 upload 类型）
    created_at = db.Column(db.DateTime, default=datetime.utcnow)           # 创建时间

    # 反向关系：通过 project.scans 获取所有关联的扫描任务
    # cascade="all, delete-orphan": 删除项目时自动级联删除所有扫描和漏洞
    scans = db.relationship(
        "ScanTask",
        backref=db.backref("project", single_parent=True),
        lazy="dynamic",
        cascade="all, delete-orphan",
    )


class ScanTask(db.Model):
    """
    扫描任务表
    ==========
    每次触发扫描都会创建一条记录，记录扫描进度和结果统计。
    扫描在后台线程中异步执行。
    """
    __tablename__ = "scan_tasks"

    id = db.Column(db.Integer, primary_key=True)                           # 自增主键
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)  # 所属项目
    status = db.Column(db.String(20), default="pending")                   # 状态: pending → running → done/failed
    total_files = db.Column(db.Integer, default=0)                         # 项目总文件数
    scanned_files = db.Column(db.Integer, default=0)                       # 已扫描文件数
    vulns_found = db.Column(db.Integer, default=0)                         # 发现的漏洞总数
    started_at = db.Column(db.DateTime, nullable=True)                     # 扫描开始时间
    finished_at = db.Column(db.DateTime, nullable=True)                    # 扫描完成时间
    created_at = db.Column(db.DateTime, default=datetime.utcnow)           # 任务创建时间

    # 反向关系：通过 scan_task.vulnerabilities 获取该次扫描的所有漏洞
    vulnerabilities = db.relationship(
        "Vulnerability",
        backref=db.backref("scan_task", single_parent=True),
        lazy="dynamic",
        cascade="all, delete-orphan",
    )


class Vulnerability(db.Model):
    """
    漏洞记录表
    ==========
    存储扫描引擎发现的每个潜在漏洞的详细信息。
    包含引擎分析结果和 AI 二次分析结果。
    """
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)                           # 自增主键
    scan_task_id = db.Column(db.Integer, db.ForeignKey("scan_tasks.id", ondelete="CASCADE"), nullable=False)  # 所属扫描任务
    file_path = db.Column(db.String(500), nullable=False)                  # 漏洞所在文件路径
    line_number = db.Column(db.Integer, nullable=False)                    # 漏洞所在行号
    vuln_type = db.Column(db.String(50), nullable=False)                   # 漏洞类型: sql_injection/command_execution/ssrf/path_traversal/arbitrary_file_read
    severity = db.Column(db.String(20), nullable=False)                    # 严重程度: critical/high/medium/low
    language = db.Column(db.String(20), nullable=False)                    # 编程语言: python/c/cpp

    # ---- 引擎输出的关键路径信息 ----
    source_code = db.Column(db.Text, nullable=True)                        # Source 点（用户输入入口）的代码片段
    sink_code = db.Column(db.Text, nullable=True)                          # Sink 点（危险函数调用）的代码片段
    data_flow = db.Column(db.Text, nullable=True)                          # 变量从 Source 到 Sink 的传播链
    context_code = db.Column(db.Text, nullable=True)                       # 漏洞周围的上下文代码

    # ---- AI 二次分析结果 ----
    ai_analysis = db.Column(db.Text, nullable=True)                        # AI 返回的原始 JSON（完整分析结果）
    ai_is_vulnerable = db.Column(db.String(20), nullable=True)             # AI 判定: true(确认漏洞) / false(误报) / uncertain(不确定)
    ai_severity = db.Column(db.String(20), nullable=True)                  # AI 重新评定的严重程度
    ai_cwe_id = db.Column(db.String(20), nullable=True)                    # CWE 编号（如 CWE-89）
    ai_owasp_category = db.Column(db.String(50), nullable=True)            # OWASP 分类（如 A03:2021-Injection）
    ai_root_cause = db.Column(db.Text, nullable=True)                      # AI 分析的漏洞形成原因（根因）
    ai_attack_vector = db.Column(db.Text, nullable=True)                   # AI 分析的攻击方式（攻击场景 + Payload）
    ai_fix_suggestion = db.Column(db.Text, nullable=True)                  # AI 修复建议
    ai_fix_code = db.Column(db.Text, nullable=True)                        # AI 给出的修复代码
    ai_confidence = db.Column(db.Float, nullable=True)                     # AI 判定的置信度 (0~1)

    # ---- 分析流水线追踪 ----
    pipeline_stage = db.Column(db.String(50), nullable=True)               # 发现该漏洞的分析阶段: taint(污点分析) / data_flow(数据流) / ast(AST分析)

    # ---- AI 自动验证（Payload 构建 + 验证）----
    ai_payload = db.Column(db.Text, nullable=True)                         # AI 构建的攻击 Payload
    ai_payload_result = db.Column(db.Text, nullable=True)                  # Payload 验证结果（success/failed/uncertain）
    ai_payload_evidence = db.Column(db.Text, nullable=True)                # Payload 验证证据（响应片段等）

    # ---- 最终判定 ----
    status = db.Column(db.String(20), default="pending")                   # pending(待处理) / confirmed(AI验证成功) / potential(AI无法确认) / false_positive(误报) / reviewed(已审查)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)           # 记录创建时间


class AISettings(db.Model):
    """
    AI 配置表（单例模式）
    ===================
    全局只有一行记录（id=1），存储 AI 服务的连接参数。
    用户可通过 Web 设置页面随时修改，修改后即时生效（缓存刷新）。
    """
    __tablename__ = "ai_settings"

    id = db.Column(db.Integer, primary_key=True, default=1)                # 固定为 1，保证单例
    api_key = db.Column(db.String(200), default="")                        # API 密钥（存储在本地数据库中）
    base_url = db.Column(db.String(300), default="https://api.deepseek.com")  # API 基础地址
    model = db.Column(db.String(100), default="deepseek-chat")             # 模型名称
    provider = db.Column(db.String(50), default="deepseek")                # 提供方标识: deepseek/openai/custom
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)           # 最后更新时间

    @staticmethod
    def get():
        """
        获取全局 AI 配置（懒初始化）
        ========================
        首次调用时如果数据库中没有记录，自动创建 id=1 的默认记录。
        之后每次调用返回同一条记录，实现单例模式。
        """
        settings = db.session.get(AISettings, 1)
        if settings is None:
            # 首次：创建默认配置行
            settings = AISettings(id=1)
            db.session.add(settings)
            db.session.commit()
        return settings
