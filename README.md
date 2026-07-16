# 🔍 RedRock SRE — 代码审计平台

> 四级流水线静态分析 + AI 深度验证的源码安全审计工具  
> 支持 Python / C / C++ / PHP，自动检测 8 种漏洞类型

---

## 快速开始

```bash
pip install -r requirements.txt
cd backend
python app.py
# 访问 http://localhost:5000
```

---

## 使用方式

1. 上传压缩包（zip / tar.gz / tar.bz2 / tar）
2. 选择编程语言，勾选是否自动 AI 分析
3. 自动解压 → 四级流水线扫描 → AI 深度分析
4. 查看漏洞报告，一键 AI 分析全部漏洞

---

## 四级扫描引擎

| 阶段 | 方式 | 说明 |
|------|------|------|
| Stage 1 | 污点追踪 | AST 级 Source→Sink 变量传播分析 |
| Stage 2 | 数据流 | 正则模式同块 Source+Sink 检测 + 跨文件 |
| Stage 3 | AST 模式 | 危险函数组合 / PDO GBK 宽字节 / addslashes |
| Stage 4 | 调用图 | 跨函数跨文件 BFS 调用链分析 |

四个阶段完全独立扫描，最后合并去重。

---

## 漏洞覆盖

SQL 注入 · XSS · SSRF · 命令执行 · 文件上传 · 路径穿越 · 任意文件读取 · 反序列化

含 GBK 宽字节注入、PDO 模拟预处理、addslashes 不足等 PHP 专项检测。

---

## 配置 AI

访问 `/settings` 配置 API Key、Base URL、模型。支持 DeepSeek / OpenAI / 自定义兼容 API。

---

## 项目结构

```
backend/
├── app.py              # Flask 入口 + 后台扫描
├── models.py           # ORM (SQLite)
├── engine/             # 四级扫描引擎
│   ├── pipeline.py     # 流水线编排
│   ├── taint_tracker.py
│   ├── python_scanner.py / php_scanner.py / c_scanner.py
│   ├── data_flow_analyzer.py
│   ├── ast_analyzer.py
│   └── call_graph_analyzer.py
├── ai/                 # AI 客户端 + Prompt
├── api/                # REST API
├── utils/              # 压缩包安全解压 / 代码提取
├── templates/          # Jinja2 页面
└── static/             # CSS
tests/                  # 测试用例
```
