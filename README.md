# Code Audit Platform

**中文** | [English](README.en.md)

源码安全审计平台：上传项目 → 静态扫描 → AI 深度分析 → **沙箱动态攻击验证** → AI 自动修复，全流程 Web 可视化。

支持 Python / PHP / C / C++ 四种语言，覆盖 SQL 注入、命令执行、SSRF、反序列化、XXE、SSTI、XSS（含模板 XSS）、路径穿越、ZIP Slip、开放重定向、硬编码凭据等漏洞类型。内置版本感知规则引擎、项目级过程间污点分析引擎，以及可借助 MCP 工具在沙箱中**真实攻击目标应用**的 AI 验证体系。

## 功能

- **项目上传**：上传源码压缩包（zip/tar.gz），自动解压、按语言扫描
- **静态扫描引擎**：项目级过程间污点分析（跨文件/跨函数数据流）+ 数据流富化 + AST 模式分析 + 调用图补充 + 模板 XSS 分析 + ZIP Slip 检测
- **AI 深度分析**：每个漏洞自动生成形成原因、攻击方式、修复建议（AI 用 MCP 工具探索源码）
- **AI Payload 验证**：AI 构建攻击向量；对 Web 类漏洞，平台在**本地沙箱中真实启动目标应用**，AI 发送实际 HTTP 攻击请求（支持多步攻击链、认证绕过、multipart 上传）、对比响应判定漏洞真假，最终结果统一收集（确认/不确定/误报）
- **AI 自动修复**：AI 生成修复代码并直接应用到源码（改前自动 `.bak` 备份），可勾选自动执行或对单个漏洞手动触发
- **版本感知规则引擎**：PHP/Python/C/C++ 按目标版本动态激活规则、调整严重度
- **Web 界面**：项目列表 → 项目详情 → 扫描结果三级页面；严重度/验证状态排序筛选、数据流展示、深浅色主题（HarmonyOS Sans 字体、玻璃拟态动效）

## 运行流程

### 1. 整体流程

```
用户上传源码包 (zip/tar.gz)
        │
        ▼
┌──────────────────┐     ┌───────────────────────────────────┐
│ 项目创建          │     │ 新扫描（可选勾选）                   │
│ 解压到 extracted/ │ ──► │ ☑ AI 分析   ☑ Payload 验证          │
│ 选择语言/版本      │     │ ☑ 自动修复                         │
└──────────────────┘     └──────────────┬────────────────────┘
                                        │ 后台线程异步执行
                                        ▼
                        ┌───────────────────────────────┐
                        │ 静态扫描流水线（多级引擎）         │
                        │ 见下方「扫描引擎流水线」          │
                        └──────────────┬────────────────┘
                                       │ 漏洞列表入库（CWE/严重度/数据流）
                                       ▼
                        ┌───────────────────────────────┐
                        │ AI 深度分析（每个漏洞）           │
                        │ MCP 工具探索源码 → 成因/攻击/修复  │
                        └──────────────┬────────────────┘
                                       ▼
                        ┌───────────────────────────────┐
                        │ Payload 验证（勾选时）           │
                        │ 沙箱真实攻击 → confirmed/       │
                        │ potential/false_positive      │
                        └──────────────┬────────────────┘
                                       ▼
                        ┌───────────────────────────────┐
                        │ AI 修复（勾选/手动）             │
                        │ apply_code_fix + .bak 备份     │
                        └──────────────┬────────────────┘
                                       ▼
                               扫描结果页：浏览/筛选/排序
```

### 2. 扫描引擎流水线

```
源文件（Python AST / PHP·C·C++ tree-sitter 解析）
  │
  ▼
┌─────────────────────────────────────┐
│ Stage 1: 污点追踪（地面真相）          │
│ • 项目级单一污点图，跨文件/跨函数      │
│ • 作用域命名空间（模块,函数）          │
│ • return 值传播 + 调用点链接          │
│   （实参→形参、被调 #ret→调用点变量）  │
│ • 模块属性链接（import db; db.c）     │
│ • 局部类型推断（游标/连接对象）        │
│ • 消毒函数识别（int/html.escape/...） │
│ • 逐 source BFS + spread 独立 visited │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ Stage 2: 数据流富化                    │
│ • 防护等级评定（none/partial/strong/  │
│   bypassable）                       │
│ • 利用难度判定（easy~unlikely）        │
│ • 数据变换历史追踪                    │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ Stage 3: AST 模式分析（过滤+补充）      │
│ • 参数化查询识别 → 降级 SQL 误报       │
│ • 白名单验证检测 → 降级误报            │
│ • 补充：反序列化链/硬编码凭据/调试模式/  │
│   危险组合（unserialize+__destruct 等）│
│ 3b. ZIP Slip 检测（CWE-22 变体）      │
│ 3c. 模板 XSS 分析（|safe/autoescape   │
│     off/<script> 插值 + 视图→模板链接） │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ Stage 4: 调用图补充（跨文件调用链）      │
└──────────────┬──────────────────────┘
               │
               ▼
       去重 → CWE 标注 → 入库
```

**架构原则**：Stage 1 是地面真相；Stage 2/3/4 不独立扫描（防止已过滤的误报被粗正则重新引入）；富化在 Stage 2、过滤在 Stage 3、补充在 Stage 4。

### 3. AI 深度分析

每个漏洞（或「全部分析」）调用 AI，AI 借助 MCP 工具自主探索源码后输出 JSON 结果：

| MCP 工具 | 用途 |
|---|---|
| `search_dangerous_calls` | 搜索文件中的危险函数调用 |
| `search_user_inputs` | 定位用户输入入口 |
| `trace_variable_flow` | 追踪变量传播路径 |
| `read_file_region` | 读取文件指定行区间（支持相对路径/文件名后缀回退） |
| `search_project` | 跨文件正则搜索 |
| `list_project_files` | 查看项目文件清单 |
| `run_target_app` / `stop_target_app` | 启动/停止沙箱中的目标应用（仅验证流程） |
| `send_http_request` | 发 HTTP 请求（支持查询参数、表单体、multipart 文件上传） |

输出：漏洞形成原因、攻击方式、修复建议，以及初步判定（confirmed / potential / false_positive）。

### 4. Payload 验证（沙箱动态攻击）

静态分析对 SQL 注入这类漏洞只能"猜"是否可利用。平台内置**沙箱执行器**，让 AI 真刀真枪地攻击：

1. **平台预启动**：对 Web 可攻击的漏洞类型（SQLi/XSS/SSRF/SSTI/路径穿越/开放重定向/反序列化等），验证开始前自动把目标项目复制到临时目录、作为子进程启动（127.0.0.1 随机端口；缺失依赖按需自动安装并缓存）
2. **AI 发动攻击**：模型通过 MCP 工具 `send_http_request` 先发正常请求做基线，再发攻击 Payload，对比状态码/报错/内容差异；`run_target_app` / `stop_target_app` 控制应用生命周期。支持的能力：
   - **多步攻击链**：注册→登录→下单→访问，一轮内连续发多个请求（验证轮数 8 轮，装得下完整链）
   - **认证门禁绕过**：路由需要登录时，AI 会先搜索种子数据/初始化脚本里的测试账户，登录后再攻击
   - **multipart 文件上传**：`send_http_request` 的 `files` 参数可上传恶意文件（如 pickle RCE 载荷），覆盖反序列化/文件上传类漏洞
   - **相对路径解析**：MCP 读文件工具支持相对路径与文件名后缀回退，AI 不会因路径写错而找不到接口
3. **判定与证据**：输出 `verdict`（confirmed/potential/false_positive）、`confidence`、`exploit_payload` 和完整证据链（基线 vs 攻击响应对比）

### 4.1 判定结果收集

AI 完成 Payload 构建与模拟攻击后，最终判定统一写回页面展示字段：

| 验证结果 | 记为 | 页面徽章 | 统计卡片 |
|---|---|---|---|
| confirmed | 确认漏洞 | ✅ 确认漏洞 | AI确认漏洞 +1 |
| potential | 不确定 | ⚠️ 不确定 | AI不确定 +1 |
| false_positive | 误报 | ❌ 误报 | — |

> 说明：平台定位是**正常代码的漏洞检测**，沙箱用于实证漏洞（真实发出攻击请求验证响应）。被扫描代码在临时副本中运行、只监听本机随机端口、有超时保护、退出自动清理。

### 5. AI 修复（与验证分离）

- 修复是独立流程：验证阶段**不暴露** `apply_code_fix`（即使模型请求也会被执行器拒绝），杜绝"点分析就改代码"
- 触发方式：扫描时勾选「自动修复」，或结果页对单个漏洞点「修复」
- 机制：`apply_code_fix(file_path, start_line, end_line, new_code)` 按行区间替换，改前自动生成 `.bak` 备份文件

### 6. 结果浏览

- 严重度排序（critical → high → medium → low，后端 `SEVERITY_RANK` + 前端双重修复）
- AI 判定徽章：✅ 确认 / ⚠️ 潜在 / ❌ 误报 / 未分析
- 漏洞详情：数据流路径、sink 代码、CWE 编号、AI 分析全文、修复前后代码对比

## 支持的漏洞类型

| 漏洞类型 | CWE | Python | PHP | C/C++ |
|---|---|---|---|---|
| 命令执行/代码注入 | CWE-78/94 | ✅ | ✅ | ✅ |
| SQL 注入 | CWE-89 | ✅ | ✅ | ✅ |
| 不安全反序列化 | CWE-502 | ✅ | ✅ | — |
| SSRF | CWE-918 | ✅ | ✅ | — |
| XXE | CWE-611 | ✅ | — | — |
| 路径穿越/任意文件读取 | CWE-22 | ✅ | ✅ | ✅ |
| ZIP Slip | CWE-22 | ✅ | — | — |
| 开放重定向 | CWE-601 | ✅ | ✅ | — |
| SSTI（服务端模板注入） | CWE-94 | ✅ | — | — |
| XSS（含模板 XSS） | CWE-79 | ✅ | ✅ | — |
| 文件上传 | CWE-434 | — | ✅ | — |
| 硬编码凭据 | CWE-798 | ✅ | — | — |
| 调试模式开启 | CWE-215 | ✅ | — | — |

## 引擎检测能力

- **项目级过程间污点分析**：跨文件/跨函数的污点图，return 值传播、调用点实参→形参链接、模块属性链接、作用域命名空间隔离同名变量
- **局部类型推断**：`conn = sqlite3.connect()` → `cur = conn.cursor()` → `cur.execute()` 的游标类型传播，命中真实世界最常见的 SQL 注入写法
- **Source 全覆盖**：`request.args.get('x')`、`request.args['x']`、`request.data`、`request.get_json()`、Django `request.GET['x']`、`sys.argv`、`os.environ`、`parse_qs`、Flask-RESTX `api.payload` 等
- **Sink 后缀回退**：`cursor.execute` / `conn.execute` / `db.session.execute` / `Model.objects.raw` 等数据库命名模式；os.exec*/spawn*、xmltodict、flask.Response、文件操作等新 sink
- **字典/属性污点传播**：`x = data.get('k')`、`x = d['k']`、`obj.attr` 从已污染对象传播
- **消毒函数按类型区分**：`int()` 全类型消毒、`html.escape` 仅消 XSS、`shlex.quote` 仅消命令注入
- **模板 XSS 分析**：扫描 `.html/.j2` 的 `|safe`（跳过字面量）、autoescape off、`<script>` 内插值，并通过视图→模板变量链接降低误报
- **依赖目录排除**：venv / site-packages / node_modules / dist 等自动跳过
- **CWE 标准标注**：每条发现输出 CWE 编号，可直接对接外部基准

## 基准评测（RealVuln Benchmark v2.0.0）

使用 [RealVuln Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark)（66 个真实 Python 仓库、1,903 个人工标注漏洞、279 个 FP 诱饵）对静态引擎做全量评测：

| 指标 | 本平台 | Semgrep | SonarQube | Snyk* |
|---|---:|---:|---:|---:|
| TP | 253 | 134 | 274 | 121 |
| FP | **136** | 905 | 1587 | 280 |
| 精确率 | **0.650** | 0.129 | 0.147 | 0.302 |
| 召回率 | **13.3%** | 7.0% | 14.4% | 17.7% |
| F2 Score | **15.8** | 7.7 | 14.5 | 19.3 |

\* Snyk 官方数据仅覆盖 25/66 仓库。

- **F2 是 Semgrep 的 2 倍，超过 SonarQube**，精确率是 Semgrep 的 5 倍、误报率低一个数量级
- 分族召回：命令注入 **78%**、开放重定向 **47%**、SSRF **46%**、XXE **45%**、XSS 26%（模板分析器从 5% 提升到 30% 后回落）、SQL 注入 23%、路径穿越 23%
- 评测方法、分族数据、复现步骤见 [docs/评测报告.md](docs/评测报告.md)（中文）/ [docs/evaluation-report.md](docs/evaluation-report.md)（英文）

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

### AI 配置

在 `backend/.env` 中配置 AI API（也可在 Web「AI 设置」页面配置并测试连通性）：

```env
DEEPSEEK_API_KEY=sk-xxxxxxxx
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
```

AI 设置页内置常见平台预设：DeepSeek（`deepseek-v4-flash`）、OpenAI（`gpt-4.1`）、本地 Ollama（`qwen2.5`），也可自定义任意 OpenAI 兼容接口。

## 技术路线

| 层级 | 技术 |
|------|------|
| Web 框架 | Flask + Jinja2 |
| 数据库 | SQLite + SQLAlchemy ORM |
| AST/CST 解析 | Python AST + tree-sitter (PHP/C/C++) |
| 污点追踪 | 项目级污点图 + BFS 路径搜索 + 消毒函数识别 + 局部类型推断 + 字典/属性/return 传播 |
| 规则引擎 | 版本感知规则调度（min/max_version + severity_overrides） |
| 模板分析 | 模板 XSS 检测 + 视图→模板变量链接 |
| AI 集成 | OpenAI 兼容接口（DeepSeek/GPT/自定义）+ MCP 工具协议（JSON/XML 调用解析、重试、解析加固） |
| 沙箱验证 | 子进程沙箱（临时副本 + 随机端口 + 按需依赖安装 + HTTP 攻击验证） |
| 前端 | Vanilla JS + CSS 变量主题系统 + HarmonyOS Sans + 玻璃拟态/极光动效 |

## 目录结构

```
backend/
├── app.py                    # Flask 入口（路由、扫描任务编排）
├── models.py                 # 数据模型（漏洞/项目/扫描任务 + 严重度排序）
├── engine/                   # 静态分析引擎（多级流水线）
│   ├── pipeline.py           # 流水线编排（去重、CWE 标注、目录排除）
│   ├── python_scanner.py     # Python 扫描器（AST + 项目级污点追踪）
│   ├── php_scanner.py        # PHP 扫描器（tree-sitter + 会话污染追踪）
│   ├── c_scanner.py          # C/C++ 扫描器
│   ├── taint_tracker.py      # 污点图（跨文件/跨函数 BFS）
│   ├── sinks_py.py           # Python 危险函数表 + CWE 映射
│   ├── sources_py.py         # Python 输入源表
│   ├── ast_analyzer.py       # AST 模式分析（参数化查询/凭据/调试模式/ZIP Slip）
│   ├── template_analyzer.py  # 模板 XSS 分析（|safe + 视图→模板链接）
│   ├── sandbox.py            # 沙箱执行器（动态攻击验证基础设施）
│   ├── mcp_tools.py          # MCP 工具集（源码探索/修复/沙箱攻击）
│   ├── ai_verifier.py        # AI 验证流程封装
│   └── payload_builder.py    # Payload 构建
├── ai/                       # AI 客户端与提示词
├── ai_chat_core/             # OpenAI 兼容对话核心（模型路由）
├── api/                      # REST API（项目/扫描/漏洞/设置）
├── static/                   # 前端资源（CSS、HarmonyOS Sans 字体）
├── templates/                # Jinja2 页面
├── docs/                     # 评测报告等文档
└── test_audit_logic.py       # 审计逻辑回归测试（14 用例）
```
