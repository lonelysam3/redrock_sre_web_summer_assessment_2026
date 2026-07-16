# 🔍 代码审计平台 — 使用文档

> 基于静态分析 + AI 双重验证的源码安全审计工具  
> 支持 Python / C / C++，自动检测 SQL 注入、命令执行、SSRF 等漏洞

---

## 目录

- [项目概述](#项目概述)
- [系统架构](#系统架构)
- [快速开始](#快速开始)
- [配置指南](#配置指南)
- [使用流程](#使用流程)
- [支持的漏洞类型](#支持的漏洞类型)
- [API 接口文档](#api-接口文档)
- [目录结构](#目录结构)
- [开发指南](#开发指南)

---

## 项目概述

代码审计平台是一个 **Web 端源码安全扫描工具**，工作流程如下：

```
选择项目 → 静态扫描（引擎） → AI 二次分析 → 人工审核
```

1. **静态扫描引擎** — 解析源码 AST/CST，用污点追踪算法检测 Source→Sink 路径
2. **AI 二次分析** — 将扫描结果发送给大模型，判断误报、给出修复建议
3. **人工审核** — 在 Web 界面标记确认/误报，跟踪漏洞修复状态

### 核心能力

| 能力 | 说明 |
|------|------|
| 多语言支持 | Python（AST）、C/C++（tree-sitter） |
| 污点追踪 | BFS 变量传播分析，自动发现 Source→Sink 路径 |
| AI 融合 | 支持 DeepSeek / OpenAI / 自定义 API，批量分析 |
| Web 界面 | 项目管理、扫描结果、筛选器、AI 分析结果展示 |
| 配置热切换 | AI 配置实时生效，无需重启 |

---

## 系统架构

```
┌─────────────────────────────────────────────────┐
│                    前端（Jinja2 + 原生 JS）        │
│    index.html  project.html  scan.html  settings │
└───────────────────┬─────────────────────────────┘
                    │ REST API
┌───────────────────▼─────────────────────────────┐
│                  Flask 路由层（app.py）            │
│    /api/projects   /api/scans   /api/vulns       │
│    /api/settings   后台线程（扫描 + AI 分析）       │
└───────┬───────────────────────────┬─────────────┘
        │                           │
┌───────▼──────────┐    ┌───────────▼─────────────┐
│   扫描引擎        │    │      AI 分析层            │
│  ┌─────────────┐ │    │  ┌─────────────────────┐ │
│  │ PythonScanner│ │    │  │   ai/client.py      │ │
│  │ (AST 分析)   │ │    │  │   (v2: 基于 chatbox) │ │
│  ├─────────────┤ │    │  ├─────────────────────┤ │
│  │ CScanner     │ │    │  │  ai_chat_core/       │ │
│  │ (tree-sitter)│ │    │  │  ├─ providers.py     │ │
│  ├─────────────┤ │    │  │  ├─ router.py        │ │
│  │ TaintTracker │ │    │  │  ├─ core.py          │ │
│  │ (污点追踪)   │ │    │  │  ├─ service.py       │ │
│  └─────────────┘ │    │  │  └─ settings.py      │ │
└──────────────────┘    │  └─────────────────────┘ │
                        └─────────────────────────┘
                                    │
                        ┌───────────▼─────────────┐
                        │   DeepSeek / OpenAI     │
                        │   / 自定义 API           │
                        └─────────────────────────┘
```

### 数据流

```
Source（用户输入入口）
  │  request.args.get('name')
  ▼
中间变量传播
  │  query = "SELECT * FROM users WHERE name=" + name
  ▼
Sink（危险函数调用）
  │  cursor.execute(query)
  ▼
引擎报告 → AI 二次确认 → 人工审核
```

---

## 快速开始

### 环境要求

- Python 3.10+
- pip

### 安装

```bash
# 1. 克隆或进入项目目录
cd code-audit-platform

# 2. 安装依赖
pip install -r requirements.txt

# 3. （可选）配置环境变量
# 创建 backend/.env 文件，写入:
#   DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxx
#   DEEPSEEK_BASE_URL=https://api.deepseek.com
#   DEEPSEEK_MODEL=deepseek-chat

# 4. 启动服务
cd backend
python app.py
```

启动后访问 **http://localhost:5000**

### 默认端口

通过环境变量 `PORT` 可自定义端口：

```bash
# Windows
set PORT=8080 && python app.py

# Linux/macOS
PORT=8080 python app.py
```

---

## 配置指南

### AI 服务配置

在浏览器中访问 **http://localhost:5000/settings**，配置 AI 连接参数：

| 字段 | 说明 | 示例 |
|------|------|------|
| AI 提供方 | 选择 API 平台 | DeepSeek / OpenAI / 自定义 |
| API Key | API 密钥 | `sk-xxxxxxxxxxxxxxxx` |
| API 地址 | Base URL（不含路径） | `https://api.deepseek.com` |
| 模型名称 | 使用的模型 | `deepseek-chat` |

#### 各平台默认配置

| 平台 | API 地址 | 模型 |
|------|---------|------|
| DeepSeek | `https://api.deepseek.com` | `deepseek-chat` |
| OpenAI | `https://api.openai.com` | `gpt-4o` |
| 本地 Ollama | `http://localhost:11434/v1` | `qwen2.5:7b`（或其他已拉取的模型） |

> 💡 **Ollama 本地部署**：无需 API Key，随便填一个字符串即可。速度取决于本机算力。

### 密钥安全

API Key 存储在 **本地 SQLite 数据库**（`backend/audit.db`）中，不会上传到任何服务器。Web 界面中仅显示脱敏后的最后 4 位。

---

## 使用流程

### 1. 创建项目

在首页填写：

- **项目名称**：任意标识，如 "my-web-app"
- **源码路径**：磁盘上的绝对路径，如 `D:/projects/my-web-app`
- **语言**：选择 Python / C / C++，或选择"自动检测"

点击"创建"。

### 2. 开始扫描

进入项目详情页 → 点击 **▶ 开始扫描**。

扫描在后台线程中异步执行，页面每 2 秒自动轮询状态。

### 3. 查看结果

扫描完成后，点击"查看"进入扫描详情页：

- **统计卡片**：按 Critical / High / Medium / Low 统计漏洞分布
- **筛选器**：按类型、严重程度、文件名筛选
- **漏洞卡片**：每条漏洞显示 Source 代码、数据流路径、Sink 代码

### 4. AI 分析

扫描完成后会自动触发 AI 批量分析。你也可以：

- 点击单个漏洞右侧的 **🤖 AI 分析** 按钮手动分析
- AI 会返回：**是否真漏洞**、**根因**、**修复建议**、**修复代码**

### 5. 人工审核

每个漏洞可用下拉框标记状态：

| 状态 | 含义 |
|------|------|
| 待处理 | 默认状态，尚未审核 |
| 已确认 | 确认为真实漏洞，需要修复 |
| 误报 | 确认不是漏洞 |
| 已审查 | 已处理完毕 |

---

## 支持的漏洞类型

### Python

| 漏洞类型 | 严重程度 | 示例 Source | 示例 Sink |
|---------|---------|------------|----------|
| SQL 注入 | 🔴 High | `request.args.get('id')` | `cursor.execute(query)` |
| 命令执行 | 🔴 Critical | `request.args.get('cmd')` | `os.system(cmd)` |
| SSRF | 🟠 High | `request.args.get('url')` | `requests.get(url)` |
| 路径穿越 | 🟡 Medium | `request.form.get('file')` | `open(path)` |

### C/C++

| 漏洞类型 | 严重程度 | 示例 Source | 示例 Sink |
|---------|---------|------------|----------|
| 命令执行 | 🔴 Critical | `getenv("USER")` | `system(cmd)` |
| 路径穿越 | 🟠 High | `scanf("%s", buf)` | `fopen(buf, "r")` |
| 任意文件读取 | 🟡 Medium | `argv[1]` | `read(fd, buf, n)` |

### Source 点（用户输入入口）

- **Flask 框架**：`request.args.get()`、`request.form.get()`、`request.json.get()`、`request.headers`、`request.cookies`
- **Django 框架**：`request.GET`、`request.POST`
- **标准输入**：`input()`、`sys.argv`、`os.environ`
- **C 语言**：`getenv()`、`scanf()`、`fgets()`、`recv()`、`argv`

### Sink 点（危险函数）

- **SQL 注入**：`cursor.execute()`、`cursor.executemany()`、`connection.execute()`
- **命令执行**：`os.system()`、`subprocess.run()`、`eval()`、`exec()`
- **SSRF**：`requests.get()`、`httpx.get()`、`urllib.urlopen()`
- **路径穿越**：`open()`、`fopen()`、`os.remove()`、`stat()`

### 消毒函数（Sanitizer）

以下函数会"清洗"污点数据，如果在 Source→Sink 路径中出现，则不会被报告为漏洞：

- `int()`、`float()`：类型强转
- `html.escape()`、`cgi.escape()`：HTML 转义
- `bleach.clean()`：通用清洗

---

## API 接口文档

服务启动后，所有 API 挂载在 `http://localhost:5000`。

### 项目管理

#### `GET /api/projects`

获取所有项目列表（按创建时间倒序）。

**响应示例**：

```json
[
  {
    "id": 1,
    "name": "my-web-app",
    "language": "python",
    "repo_path": "D:/projects/my-web-app",
    "created_at": "2026-07-15T03:00:00"
  }
]
```

#### `POST /api/projects`

创建新项目。

**请求体**：

```json
{
  "name": "my-web-app",
  "repo_path": "D:/projects/my-web-app",
  "language": "python"
}
```

**响应**：`201 Created` + `{ "id": 1, "name": "my-web-app" }`

#### `DELETE /api/projects/<id>`

删除项目（级联删除关联扫描和漏洞数据）。

---

### 扫描管理

#### `GET /api/scans?project_id=<id>`

查询扫描任务列表（支持按项目筛选，最多 50 条）。

**响应示例**：

```json
[
  {
    "id": 5,
    "project_id": 1,
    "status": "done",
    "total_files": 42,
    "scanned_files": 42,
    "vulns_found": 7,
    "started_at": "2026-07-15T03:05:00",
    "finished_at": "2026-07-15T03:05:12",
    "created_at": "2026-07-15T03:05:00"
  }
]
```

#### `POST /project/<project_id>/new-scan`

触发新扫描（后台异步执行）。

**响应**：`{ "scan_id": 5, "status": "running" }`

> 前端应轮询 `GET /api/scans?project_id=<id>` 检查状态，`status` 变为 `done` 或 `failed` 时停止轮询。

#### `DELETE /api/scans/<id>`

删除扫描任务及关联漏洞。

---

### 漏洞管理

#### `GET /api/vulns?scan_id=<id>&type=<type>&severity=<severity>&status=<status>`

查询漏洞列表，支持多维度筛选。

**查询参数**：

| 参数 | 可选值 |
|------|--------|
| `scan_id` | 扫描任务 ID |
| `type` | `sql_injection` / `command_execution` / `ssrf` / `path_traversal` / `arbitrary_file_read` |
| `severity` | `critical` / `high` / `medium` / `low` |
| `status` | `pending` / `confirmed` / `false_positive` / `reviewed` |

**响应示例**：

```json
[
  {
    "id": 23,
    "scan_task_id": 5,
    "file_path": "app.py",
    "line_number": 17,
    "vuln_type": "sql_injection",
    "severity": "high",
    "language": "python",
    "source_code": "name = request.args.get('name')",
    "sink_code": "cursor.execute(query)",
    "data_flow": "name -> query",
    "ai_is_vulnerable": "true",
    "ai_severity": "high",
    "ai_root_cause": "用户输入直接拼接到 SQL 语句，未使用参数化查询",
    "ai_fix_suggestion": "改用 ? placeholder 参数化查询",
    "ai_fix_code": "cursor.execute(\"SELECT ... WHERE name = ?\", (name,))",
    "status": "pending"
  }
]
```

#### `GET /api/vulns/<id>`

获取单个漏洞详情。

#### `PATCH /api/vulns/<id>`

更新漏洞状态（人工审核）。

**请求体**：

```json
{ "status": "confirmed" }
```

#### `POST /api/vulns/<id>/analyze`

手动触发 AI 分析。

---

### AI 配置

#### `GET /api/settings/ai`

获取当前 AI 配置（API Key 脱敏）。

**响应**：

```json
{
  "api_key": "***cdef",
  "base_url": "https://api.deepseek.com",
  "model": "deepseek-chat",
  "provider": "deepseek"
}
```

#### `POST /api/settings/ai`

更新 AI 配置。

**请求体**：

```json
{
  "api_key": "sk-new-key",
  "base_url": "https://api.deepseek.com",
  "model": "deepseek-chat",
  "provider": "deepseek"
}
```

> API Key 传入以 `***` 开头的掩码值会保留原密钥不修改。

#### `POST /api/settings/ai/test`

测试 AI 连接是否正常。

---

### 健康检查

#### `GET /health`

```json
{ "status": "ok" }
```

---

## 目录结构

```
code-audit-platform/
├── requirements.txt              # Python 依赖
│
├── backend/
│   ├── app.py                    # Flask 主应用（路由、后台任务）
│   ├── config.py                 # 全局配置（数据库、API Key）
│   ├── models.py                 # 数据库模型（ORM）
│   ├── audit.db                  # SQLite 数据库（自动生成）
│   │
│   ├── engine/                   # 扫描引擎
│   │   ├── __init__.py           # 统一入口 + 去重
│   │   ├── taint_tracker.py      # 污点追踪核心（BFS 路径分析）
│   │   ├── python_scanner.py     # Python AST 扫描器
│   │   ├── c_scanner.py          # C/C++ tree-sitter 扫描器
│   │   ├── sources_py.py         # Python Source 点定义
│   │   ├── sources_c.py          # C/C++ Source 点定义
│   │   ├── sinks_py.py           # Python Sink 点定义
│   │   └── sinks_c.py            # C/C++ Sink 点定义
│   │
│   ├── ai/                       # AI 分析模块
│   │   ├── client.py             # AI 客户端（基于 chatbox 核心）
│   │   ├── prompts.py            # Prompt 模板
│   │   └── settings_bridge.py    # DB 配置 → chatbox 配置桥接
│   │
│   ├── ai_chat_core/             # 通用 AI 对话核心库
│   │   ├── config.py             # provider_config / chat_request 数据模型
│   │   ├── providers.py          # OpenAI 兼容 Provider（流式+非流式）
│   │   ├── router.py             # 模型路由器
│   │   ├── core.py               # 对话 + 漏洞检测核心
│   │   ├── service.py            # 服务层（settings + router + core）
│   │   └── settings.py           # JSON 配置持久化
│   │
│   ├── api/                      # REST API 蓝图
│   │   ├── projects.py           # 项目管理 API
│   │   ├── scans.py              # 扫描任务 API
│   │   └── vulns.py              # 漏洞管理 API
│   │
│   ├── utils/
│   │   └── code_extractor.py     # 代码片段提取 + 语言检测
│   │
│   ├── templates/                # Jinja2 页面模板
│   │   ├── index.html            # 首页（项目列表 + 创建表单）
│   │   ├── project.html          # 项目详情（扫描历史 + 触发按钮）
│   │   ├── scan.html             # 扫描结果（漏洞列表 + 筛选器）
│   │   └── settings.html         # AI 配置页面
│   │
│   └── static/css/
│       └── style.css             # Catppuccin Mocha 主题样式
│
└── tests/
    ├── test_runner.py            # 扫描器验证脚本
    └── test_python_vulns.py      # 漏洞测试用例
```

---

## 开发指南

### 添加新的 Source 点

编辑 `engine/sources_py.py`（Python）或 `engine/sources_c.py`（C/C++）：

```python
# 示例：添加 FastAPI 的 Query 参数支持
Source("fastapi", "Query", "FastAPI Query 参数", tainted_params=[]),
```

### 添加新的 Sink 点

编辑 `engine/sinks_py.py`：

```python
# 示例：添加 aiosqlite 的 SQL 执行
Sink("aiosqlite.core", "execute", VulnType.SQL_INJECTION, "aiosqlite 异步执行",
     dangerous_param_index=0),
```

### 添加新的 AI Provider

在 `ai_chat_core/router.py` 中添加路由规则即可：

```python
model_route("claude-", "anthropic"),  # claude-* 路由到 anthropic
```

然后在 Web 设置页面配置 anthropic 的 API Key 和 Base URL。

### 调试扫描引擎

```bash
cd tests

# 运行 Python 扫描器测试
python test_runner.py

# 查看 tree-sitter 兼容性
python debug_c_scanner.py
```

### 运行单元测试

```bash
cd tests
python test_runner.py
```

预期输出：

```
==================================================
Testing Python Scanner（测试 Python 扫描器）
==================================================
Found N vulnerabilities（发现 N 个漏洞）:

  🔴 [CRITICAL] command_execution
  🟠 [HIGH] sql_injection
  🟠 [HIGH] ssrf

✅ Python scanner detects all expected vulnerability types!
```

---

## 常见问题

### Q: 扫描没有发现漏洞？

检查以下几点：
1. 项目路径是否正确（绝对路径，目录存在且包含源码文件）
2. 语言选择是否正确（Python 和 C/C++ 使用不同的解析器）
3. C/C++ 扫描需要 tree-sitter，确认已安装：`pip install tree-sitter tree-sitter-c tree-sitter-cpp`

### Q: AI 分析失败？

1. 确认 API Key 正确
2. 确认 Base URL 格式正确（不带 `/chat/completions` 后缀）
3. 使用"测试连接"按钮验证
4. 查看终端输出的错误日志

### Q: 如何判断器扫描安全代码（如用参数化查询的 SQL）？

- 使用参数化查询（`?` 或 `%s` placeholder）的 SQL 不会被标记
- 使用白名单验证的命令执行不会被标记
- 不确定的情况交给 AI 二次分析

### Q: 数据库在哪？可以备份吗？

数据库文件位于 `backend/audit.db`（SQLite）。直接复制该文件即可备份。API Key 也存储在此文件中。

---

## 许可

MIT License
