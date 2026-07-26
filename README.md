# Code Audit Platform

源码安全审计引擎，支持 Python / C / C++ / PHP 四种语言，覆盖 SQL 注入、命令执行、SSRF、路径穿越等漏洞类型。内置版本感知规则引擎和 AI 深度分析。

## 功能

- 上传源码压缩包（zip/tar.gz），自动解压并扫描
- 四级独立流水线：污点追踪 → 数据流分析 → AST 模式匹配 → 调用图分析
- Python / C / C++ 版本和标准选择，PHP 版本感知规则
- AI 深度分析：形成原因、攻击方式、修复建议
- AI Payload 验证：自动构建攻击向量并验证漏洞真实性
- 深色/浅色主题切换，跟随系统

## 使用方法

```bash
# 克隆并安装依赖
git clone https://github.com/lonelysam3/redrock_sre_web_summer_assessment_2026.git
cd redrock_sre_web_summer_assessment_2026
pip install -r requirements.txt

# 启动
cd backend
python app.py
# 访问 http://localhost:5000
```

### Docker

```bash
docker compose up -d
# 访问 http://localhost:5000
```

### 配置

在 `backend/.env` 中配置 AI API（也可在 Web 设置页面配置）：

```env
DEEPSEEK_API_KEY=sk-xxxxxxxx
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
```

## 技术路线

| 层级 | 技术 |
|------|------|
| Web 框架 | Flask + Jinja2 |
| 数据库 | SQLite + SQLAlchemy ORM |
| AST 解析 | tree-sitter (Python/PHP/C/C++) |
| 污点追踪 | 邻接表 + BFS 路径搜索 |
| AI 集成 | OpenAI 兼容接口 (DeepSeek/GPT/自定义) |
| 前端 | Vanilla JS + CSS 变量主题系统 |
