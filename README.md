# RedRock Code Audit Platform

四级流水线静态分析 + AI 深度验证的源码安全审计引擎。基于污点追踪、数据流分析、AST 模式匹配、调用图分析四级独立流水线，支持 Python / C / C++ / PHP 四种语言，覆盖 SQL 注入、命令执行、XSS、SSRF 等 8 种漏洞类型。内置 PHP 版本感知规则引擎，可根据目标 PHP 版本动态调整检测策略。

## 快速开始

### 环境要求

- Python 3.10+
- Git

### 安装

```bash
# 克隆仓库
git clone git@github.com:lonelysam3/redrock_sre_web_summer_assessment_2026.git
cd redrock_sre_web_summer_assessment_2026

# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 配置

在 `backend/` 目录下创建 `.env` 文件（可选，也可以在 Web 设置页面配置）：

```env
# Flask 密钥（生产环境请修改）
SECRET_KEY=your-secret-key-here

# AI API 配置（兼容 OpenAI 接口，支持 DeepSeek 等）
DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxx
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
```

### 启动

```bash
cd backend
python app.py
```

服务启动后访问 http://localhost:5000 即可使用。

### 使用流程

1. **上传项目** — 首页拖拽或选择项目源码压缩包（.zip / .tar.gz），选择语言类型（PHP 项目可指定目标版本）
2. **开始扫描** — 点击「开始扫描」触发四级流水线分析，后台异步执行，页面自动刷新进度
3. **查看报告** — 扫描完成后进入报告页，漏洞按严重程度排列，点击展开详情（Source → Sink 数据流路径、所在代码行）
4. **AI 深度分析** — 点击「AI 分析」按钮逐条分析漏洞，AI 会自主调用 MCP 工具搜索源码上下文，输出 CWE 编号、OWASP 分类、攻击向量和修复建议
5. **Payload 自动验证** — AI 分析后自动构建攻击 Payload 并验证漏洞可利用性，标记为 ✅AI确认漏洞 或 ❓AI不确定
6. **AI 设置** — 在设置页面配置 API Key、Base URL 和模型，配置即时生效无需重启

### 项目结构

```
backend/
├── app.py                    # Flask 入口 + 后台扫描线程 + DB 迁移
├── models.py                 # SQLAlchemy ORM
├── config.py                 # 配置文件
├── requirements.txt          # Python 依赖
├── engine/                   # 四级扫描引擎
│   ├── pipeline.py           # 流水线编排 + 去重
│   ├── rule_engine.py        # PHP 版本感知规则引擎
│   ├── taint_tracker.py      # 污点图数据结构 + BFS 路径搜索
│   ├── php_scanner.py        # PHP tree-sitter 扫描器
│   ├── python_scanner.py     # Python AST 扫描器
│   ├── c_scanner.py          # C/C++ tree-sitter 扫描器
│   ├── data_flow_analyzer.py # 数据流独立扫描 + 跨文件检测
│   ├── ast_analyzer.py       # AST 模式分析 + 宽字节/PDO检测
│   ├── call_graph_analyzer.py# 调用图跨函数分析
│   ├── mcp_tools.py          # MCP 工具集（AI 自主搜索源码）
│   ├── sources_php.py        # PHP Source 点定义
│   ├── sinks_php.py          # PHP Sink 点定义
│   ├── payload_builder.py    # AI Payload 构建
│   └── ai_verifier.py         # AI Payload 验证
├── ai/                       # AI 分析模块
│   ├── client.py             # AI 客户端
│   ├── prompts.py            # Prompt 模板
│   └── settings_bridge.py    # 配置适配
├── api/                      # REST API
│   ├── projects.py           # 项目管理（上传/删除）
│   ├── scans.py              # 扫描任务
│   └── vulns.py              # 漏洞查询/AI分析
├── utils/                    # 工具模块
│   ├── archive_handler.py    # 压缩包安全解压
│   ├── code_extractor.py     # 代码上下文提取
│   └── path_security.py      # 路径安全校验
├── templates/                # Jinja2 页面
│   ├── index.html            # 首页
│   ├── project.html          # 项目详情
│   ├── scan.html             # 扫描报告
│   └── settings.html         # AI 设置
└── static/                   # CSS
```

## 技术架构

```
前端 (Jinja2 + Vanilla JS)
    │
    ▼
Flask 路由层 — REST API + 页面渲染
    │
    ├── 后台线程 — 异步扫描 + AI 分析
    │     │
    │     ├── Pipeline 流水线编排器
    │     │   ├── Stage 1: 污点追踪 (tree-sitter AST)
    │     │   ├── Stage 2: 数据流分析 (正则模式 + 代码块切分)
    │     │   ├── Stage 3: AST 模式分析 (危险组合 + 宽字节)
    │     │   └── Stage 4: 调用图分析 (BFS 跨函数)
    │     │
    │     └── AI 客户端 → LLM (DeepSeek / OpenAI)
    │
    └── SQLite (SQLAlchemy ORM)
```

## 技术栈

| 层次 | 技术 |
|------|------|
| Web 框架 | Flask + Jinja2 |
| 数据库 | SQLite + SQLAlchemy ORM |
| AST 解析 | tree-sitter (Python/PHP/C/C++ grammars) |
| 污点追踪 | 基于邻接表的变量传播图 + BFS 路径搜索 |
| AI 集成 | ai_chat_core，支持 DeepSeek / OpenAI / 自定义 API |
| 前端 | Vanilla JS，无框架依赖 |

## 四级流水线

四个阶段完全独立扫描，互不感知对方结果，最终合并去重。每个阶段有独立的扫描策略和检测维度。

### Stage 1 — 污点追踪

基于 tree-sitter 生成的 CST 遍历源码 AST，识别 Source 点（用户输入入口，如 `$_GET`、`$_POST`、`request.args.get`）和 Sink 点（危险函数调用，如 `mysqli_query`、`system`、`eval`）。通过 BFS 在污点传播图中搜索 Source → Sink 的变量传播路径，检测是否存在未经消毒的数据流。

- `taint_tracker.py` — TaintGraph 数据结构（邻接表 + BFS 路径搜索），TaintTracker 协调器
- `php_scanner.py` / `python_scanner.py` / `c_scanner.py` — 各语言的 tree-sitter 解析器，定义 Source/Sink 检测逻辑
- `sources_php.py` / `sinks_php.py` — PHP Source 点（15 种超全局变量和输入流）和 Sink 点（50+ 危险函数）的声明式定义
- 消毒函数过滤：`int()`、`html.escape()` 等经过的路径自动排除

### Stage 2 — 数据流分析

使用正则模式匹配，将源文件按函数边界切分为代码块，在每个代码块内检测 Source 模式与 Sink 模式是否共存。同时支持跨文件检测：当 Source 在 A 文件、Sink 在 B 文件时，提取两端的代码行并标注跨文件路径。

- `data_flow_analyzer.py` — 独立扫描器，包含 PHP/Python/C/C++ 四套正则模式，覆盖 8 种漏洞类型
- 跨文件检测：项目级 Source+Sink 共存判断 → 定位到具体 sink 文件和 source 文件 → 提取两端的实际代码行
- 代码块切分：PHP/C/C++ 按 `function` 关键字 + 花括号深度切分，Python 按 `def`/`class` + 缩进切分

### Stage 3 — AST 模式分析

结构级语义理解，不依赖数据流。识别参数化查询等安全模式（用于降级误报），检测危险函数组合、宽字节注入、已废弃 API 等。

- `ast_analyzer.py` — 正则模式匹配器，8 种检测方法
- 参数化查询识别：`?` placeholder / `:named` 参数 / `bind_param` / `bindValue`
- PDO 漏洞检测：`query()`/`exec()` 拼接SQL、`prepare()` 内拼接、模拟预处理 + GBK 宽字节
- 跨文件宽字节检测：db_connect.php 设 PDO → register.php 用 prepare/execute → 标记 PDO 初始化行
- 集成 PHP 版本感知：通过 `set_php_version()` 接入 RuleEngine，动态调整风险等级

### Stage 4 — 调用图分析

跨函数跨文件 BFS 调用链分析。从 Source 函数出发，追踪调用关系直到到达 Sink 函数，检测间接调用路径中的漏洞。

- `call_graph_analyzer.py` — 函数定义提取 + 调用关系图构建 + BFS 路径搜索

## PHP 版本感知规则引擎

独立模块，与扫描器解耦。根据目标 PHP 版本（5.0~8.0）自动调整规则的生效范围、严重程度和检测逻辑。

- `rule_engine.py` — 核心模块
  - `PhpVersion` 枚举：7 个里程碑版本（5.0 / 5.3 / 5.5 / 7.0 / 7.2 / 7.4 / 8.0）
  - `AuditRule` 数据类：每条规则有 `min/max_php_version` 版本区间和 `severity_overrides` 版本覆盖
  - `RuleEngine` 类：`get_active_rules()` 按版本筛选，`get_wide_byte_context()` 提供 DSN 可靠性上下文
  - `detect_php_version()`：源码自动检测，扫描 18 种版本签名（`match()`、`fn()`、`??`、`yield`、`namespace` 等）
  - 11 条内置规则：宽字节注入 ×3、SQL 注入 ×2、命令执行 ×3、反序列化、文件上传、废弃 API

**版本差异示例**：`preg_replace /e` 修饰符在 PHP 5.4 以下为 Critical，5.5~5.6 降级为 High，7.0+ 规则直接不生效（函数已移除）。

## AI 深度分析

扫描完成后自动将发现的漏洞逐条发送给 LLM 进行深度分析，生成形成原因、攻击方式和修复建议。

- `ai/client.py` — AI 客户端，封装 analyze_single / analyze_batch / analyze_single_with_tools
- `ai/prompts.py` — System Prompt + 结构化的 JSON 分析模板，要求 AI 输出 CWE 编号、OWASP 分类、攻击场景列表
- `ai/settings_bridge.py` — 适配 ai_chat_core 库的配置桥接
- 版本上下文注入：PHP 项目的分析 prompt 自动包含目标 PHP 版本、DSN charset 可靠性、废弃 API 状态等信息
- 跨文件漏洞分析：同时提供 Source 文件和 Sink 文件的代码上下文

### MCP 工具调用

AI 分析过程中可以调用 6 个代码搜索工具，自主探索源码中的危险函数和用户输入：

- `search_dangerous_calls` — 搜索文件中所有危险函数调用（SQL 查询、命令执行、文件包含、反序列化等），按类别分组返回
- `search_user_inputs` — 搜索文件中所有用户输入入口（`$_GET`、`$_POST`、`php://input` 等 11 种）
- `read_file_region` — 按行号读取代码上下文
- `search_project` — 跨文件正则搜索（如搜索 `new PDO` 定位数据库连接）
- `trace_variable_flow` — 追踪变量在文件中的所有赋值和使用位置
- `list_project_files` — 列出项目文件结构
- `apply_code_fix` — 直接修改源文件，应用安全修复（自动 .bak 备份）

AI 收到漏洞后转入三轮工具调用循环：自主搜索 Source/Sink 点 → 追踪变量传播 → 读取上下文 → 综合判断输出结果。

- `engine/mcp_tools.py` — MCP 工具定义、执行器和 prompt 生成

### AI Payload 自动验证 + 修复

AI 深度分析完成后，自动进入 MCP 工具驱动的验证 + 修复阶段：

1. **MCP 工具探索** — AI 自主调用 `search_dangerous_calls` 定位所有危险函数、`search_user_inputs` 定位输入入口、`trace_variable_flow` 追踪变量传播、`search_project` 跨文件搜索安全控制
2. **Payload 构建** — 确认漏洞后，结合源码上下文生成精准的攻击 Payload
3. **自动修复** — AI 调用 `apply_code_fix` 工具直接修改源文件，应用修复代码（自动创建 .bak 备份）
4. **状态标记**：
   - `confirmed`（✅ AI 确认漏洞）— MCP 工具证实数据流完整、无有效安全控制
   - `potential`（❓ AI 不确定）— 存在风险但缺少关键证据
   - `false_positive`（🚫 误报）— 代码有有效安全控制

验证结果写入 `status`、`ai_payload`、`ai_payload_result`、`ai_payload_evidence`、`ai_fix_code` 字段。

## 数据模型

- `models.py` — SQLAlchemy ORM，四张表
  - `projects`：项目名、语言、PHP 版本、源码路径
  - `scan_tasks`：扫描状态、文件计数、漏洞计数
  - `vulnerabilities`：漏洞详情 + AI 分析结果（CWE/OWASP/根因/攻击向量/修复方案）+ 跨文件 source 定位
  - `ai_settings`：单例配置表，API Key / Base URL / 模型
