# Code Audit Platform

**中文** | [English](README.en.md)

源码安全审计引擎，支持 Python / C / C++ / PHP 四种语言，覆盖 SQL 注入、命令执行、SSRF、反序列化、开放重定向、XXE、SSTI、硬编码凭据等漏洞类型。内置版本感知规则引擎和 AI 深度分析。

## 功能

- 上传源码压缩包（zip/tar.gz），自动解压并扫描
- 四级分层流水线：污点追踪 → 数据流富化 → AST 过滤补充 → 调用图补充
- Python / C / C++ 版本和标准选择，PHP 版本感知规则
- AI 深度分析：形成原因、攻击方式、修复建议
- AI Payload 验证：自动构建攻击向量并验证漏洞真实性
- 现代极简前端：渐变极光背景、气泡/网格装饰、滚动收缩玻璃横幅、HarmonyOS Sans 中文字体
- 深色/浅色主题切换，跟随系统

## 四级流水线架构

```
源文件
  │
  ▼
┌─────────────────────────────────┐
│ Stage 1: 污点追踪 (地面真相)      │  ← AST/CST 解析 + BFS
│ • Source→Sink 变量传播分析       │     变量传播路径搜索
│ • 局部类型推断（游标/连接对象）    │
│ • 下标/属性 source + dict 传播    │
│ • 消毒函数识别（int/html.escape）  │
│ • 单一文件内完整数据流追踪        │
└──────────────┬──────────────────┘
               │ vulns (基准)
               ▼
┌─────────────────────────────────┐
│ Stage 2: 数据流分析 (富化)        │  ← 对 Stage 1 结果做深度分析
│ • 防护等级评定（none/partial/     │
│   strong/bypassable）            │
│ • 利用难度判定（easy~unlikely）    │
│ • 数据变换历史追踪               │
└──────────────┬──────────────────┘
               │ vulns (富化)
               ▼
┌─────────────────────────────────┐
│ Stage 3: AST 模式分析 (过滤+补充)  │  ← 语义级模式匹配
│ • 参数化查询识别 → 降级 SQL 误报  │
│ • 白名单验证检测 → 降级误报       │
│ • 补充结构性问题（反序列化链、   │
│   硬编码凭据、调试模式、危险组合）│
└──────────────┬──────────────────┘
               │ vulns (过滤 + 补充)
               ▼
┌─────────────────────────────────┐
│ Stage 4: 调用图分析 (补充)        │  ← 跨文件调用链
│ • 跨函数调用链追踪               │
│ • 补充单文件分析漏掉的跨文件漏洞  │
└──────────────┬──────────────────┘
               │
               ▼
          最终漏洞列表
```

### 架构原则

- **Stage 1 是地面真相** — 所有后续阶段围绕 Stage 1 结果工作
- **Stage 2/3/4 不独立扫描** — 这杜绝了"Stage 1 已过滤的误报被后续阶段的粗正则重新引入"
- **分层职责清晰** — 富化在 Stage 2、过滤在 Stage 3、补充在 Stage 4

### 支持的漏洞类型

| 漏洞类型 | 严重度 | Python | PHP | C/C++ |
|---------|--------|--------|-----|-------|
| 命令执行/代码注入 | Critical | ✅ | ✅ | ✅ |
| SQL 注入 | High | ✅ | ✅ | ✅ |
| 不安全反序列化 | High | ✅ | ✅ | — |
| SSRF | High | ✅ | ✅ | — |
| XXE | High | ✅ | — | — |
| 路径穿越/任意文件读取 | Medium | ✅ | ✅ | ✅ |
| 开放重定向 | Medium | ✅ | ✅ | — |
| SSTI（服务端模板注入） | Critical | ✅ | — | — |
| XSS | Low | ✅ | ✅ | — |
| 文件上传 | High | — | ✅ | — |
| 硬编码凭据 | High | ✅ | — | — |
| 调试模式开启 | Low | ✅ | — | — |

### 引擎检测能力（Python）

- **局部类型推断**：`conn = sqlite3.connect()` → `cur = conn.cursor()` → `cur.execute()` 的游标返回值类型传播，命中真实世界最常见的 SQL 注入写法
- **Source 全覆盖**：`request.args.get('x')`、`request.args['x']`（下标）、`request.data`、`request.get_json()`、Django `request.GET['x']`、`sys.argv`、`os.environ`、`parse_qs` 等
- **Sink 后缀回退**：`cursor.execute` / `conn.execute` / `db.session.execute` / `Model.objects.raw` 等数据库命名模式
- **字典访问污点传播**：`x = data.get('k')` / `x = d['k']` 从已污染对象传播
- **消毒函数按类型区分**：`int()` 全类型消毒、`html.escape` 仅消 XSS、`shlex.quote` 仅消命令注入
- **依赖目录排除**：venv / site-packages / node_modules / dist 等第三方与构建产物自动跳过
- **CWE 标准标注**：每条发现输出 CWE 编号（eval/exec → CWE-94，os.system → CWE-78 等），可直接对接外部基准

## 基准评测（RealVuln Benchmark v2.0.0）

使用 [RealVuln Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark)（66 个真实 Python 仓库、1,903 个人工标注漏洞、279 个 FP 诱饵）对静态引擎（Python 部分）做了全量评测：

| 指标 | 本平台 | Semgrep | SonarQube | Snyk* |
|---|---:|---:|---:|---:|
| TP | 109 | 134 | 274 | 121 |
| FP | **22** | 905 | 1587 | 280 |
| 精确率 | **0.832** | 0.129 | 0.147 | 0.302 |
| 召回率 | 0.057 | 0.070 | 0.144 | 0.177 |
| F2 Score | 7.0 | 7.7 | 14.5 | 19.3 |
| 误报率 | **7.3%** | 77% | 85% | 71% |

\* Snyk 官方数据仅覆盖 25/66 仓库。

- **F2 与 Semgrep 持平，精确率是它的 6.5 倍，误报率低一个数量级**，279 个 FP 诱饵零踩中。
- 分族召回超过 Semgrep 的：代码注入 56%、命令注入 30%、SSRF 20%、开放重定向 18%、硬编码凭据 13%。
- 人类编写代码精确率 0.86（TP=56, FP=9）；LLM 生成代码精确率 0.80（TP=53, FP=13）。
- 完整评测报告（方法、修复清单、分族数据、复现步骤）见 [docs/evaluation-report.md](docs/evaluation-report.md)（英文） / [docs/评测报告.md](docs/评测报告.md)（中文）。

## 版本感知规则引擎

规则引擎将审计规则从扫描器中解耦，根据目标项目的语言版本/标准动态激活和调整规则。

### 设计理念

相同代码在不同语言版本下的安全风险截然不同。例如：

- `preg_replace('/p/e')` — PHP 5.5+ 中 /e 修饰符已废弃，PHP 7.0+ 已移除 → 低于这些版本才是高危
- `create_function()` — PHP 7.2 废弃，PHP 7.4 移除 → 版本决定了是否需要告警
- `mysql_query()` — 在 PHP 5.x 是标准 API，在 PHP 7.0+ 是已移除的危险残留

规则引擎根据用户指定（或自动检测）的版本号，只激活与该版本相关的规则，并动态调整严重程度。

### 支持的语言与版本范围

| 语言 | 版本范围 | 关键里程碑 |
|------|---------|-----------|
| PHP | 5.0 ~ 8.0 | 5.3 PDO charset / 5.5 preg_replace / 7.0 mysql_* / 8.0 assert |
| Python | 2.7 ~ 3.13 | 2.7 EOL / 3.6 f-strings / 3.8 walrus operator |
| C/C++ | C89 ~ C++23 | C99 gets / C11 gets_removed / C++17 filesystem |

### 规则结构

每条规则是一个独立的 `AuditRule` 数据类：

- `min_version` / `max_version` — 控制规则的生效版本范围
- `default_severity` — 默认严重程度
- `severity_overrides` — 特定版本下动态调整严重程度（如某 API 在旧版是高危，新版降为 info）
- `confidence` — 规则置信度 (0~1)

### 自动版本检测

PHP 项目支持从源码自动检测版本：扫描 `composer.json`、特征函数调用、语法特征等，给出最佳匹配版本。用户也可在 Web 界面手动指定。

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

在 `backend/.env` 中配置 AI API（也可在 Web「AI 设置」页面配置）：

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
| 污点追踪 | 邻接表 + BFS 路径搜索 + 消毒函数识别 + 局部类型推断（游标/连接对象）+ 字典访问传播 |
| 规则引擎 | 版本感知规则调度（min/max_version + severity_overrides） |
| 数据流分析 | 正则模式 + 防护等级评估 + 利用难度判定 |
| AST 模式分析 | 语义级模式匹配（参数化查询/白名单/反序列化链/硬编码凭据/调试模式/危险组合） |
| AI 集成 | OpenAI 兼容接口 (DeepSeek/GPT/自定义) |
| 前端 | Vanilla JS + CSS 变量主题系统 + HarmonyOS Sans + 玻璃拟态/极光动效 |

## 目录结构

```
backend/
├── app.py                    # Flask 入口（路由、扫描任务编排）
├── engine/                   # 静态分析引擎（四级流水线）
│   ├── pipeline.py           # 流水线编排（去重、CWE 标注、目录排除）
│   ├── python_scanner.py     # Python 扫描器（AST + 污点追踪 + 局部类型推断）
│   ├── php_scanner.py        # PHP 扫描器（tree-sitter + 会话污染追踪）
│   ├── c_scanner.py          # C/C++ 扫描器
│   ├── taint_tracker.py      # 污点图（BFS 路径搜索）
│   ├── sinks_py.py           # Python 危险函数表 + CWE 映射
│   ├── sources_py.py         # Python 输入源表
│   └── ast_analyzer.py       # AST 模式分析（参数化查询/硬编码凭据/调试模式等）
├── ai/                       # AI 深度分析（提示词、客户端）
├── ai_chat_core/             # OpenAI 兼容对话核心（模型路由）
├── api/                      # REST API（项目/扫描/漏洞）
├── static/                   # 前端资源（CSS、HarmonyOS Sans 字体）
├── templates/                # Jinja2 页面
├── docs/                     # 评测报告等文档
└── test_audit_logic.py       # 审计逻辑回归测试
```
