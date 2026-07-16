"""
污点追踪引擎（Taint Tracking Engine）
==================================
代码审计平台的核心分析算法，用于检测用户可控数据是否流向危险函数。

==== 核心思想 ====

1. 从 AST/CST 中提取所有变量赋值关系（a ← b 意味着 b 的污点会传给 a）
2. 标记 Source 点（污点源：用户输入入口，如 request.args.get()）
3. 标记 Sink 点（危险出口：如 cursor.execute(), os.system()）
4. BFS 广度优先搜索：从每个 Source 出发，沿赋值图传播污点
5. 如果某条路径从 Source 到达 Sink 且中间无消毒函数 → 报告漏洞

==== 数据结构 ====

TaintNode: 污点图中的节点，代表一个被追踪的变量
  - name:      变量名
  - tainted:   是否已被污染
  - is_source: 是否为污点源
  - is_sink:   是否为危险出口

TaintEdge: 污点图中的边，表示变量间污染传播关系
  - from_node → to_node: 污染从 from 传播到 to
  - reason: 传播原因（赋值 / 拼接 / 函数参数传递等）

TaintGraph: 污点传播图（有向图）
  - 使用邻接表存储变量间关系
  - 支持 BFS 路径查找

==== 消毒函数（Sanitizer）====

某些函数可以将污点数据"清洗"为安全数据，例如：
  - int(), float(): 类型转换消解 SQL 注入和命令注入
  - html.escape():  HTML 转义消解 XSS
  - bleach.clean(): 内容清洗库

如果在 Source → Sink 路径中出现消毒函数，则不报告漏洞。
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field


@dataclass
class TaintNode:
    """
    污点图中的节点
    =============
    代表一个被追踪的变量或表达式。

    属性:
        name:          变量名（唯一标识）
        source_origin: 来自哪个 Source 函数（仅 source 节点有值）
        tainted:       是否已被污染标记
        is_source:     是否为污点源（用户输入入口）
        is_sink:       是否为危险出口
        code_snippet:  变量定义的代码片段（用于报告展示）
        line_number:   变量定义所在行号
    """
    name: str                          # 变量名
    source_origin: str | None = None   # 来自哪个 Source 函数（仅 source 节点有值）
    tainted: bool = False              # 是否已被污染
    is_source: bool = False            # 是否为 Source 点
    is_sink: bool = False              # 是否为 Sink 点
    code_snippet: str = ""             # 变量定义代码片段
    line_number: int = 0               # 变量定义所在行号

    def __hash__(self):
        # 用 (name, line_number) 作为哈希键，支持同名不同行的变量
        return hash((self.name, self.line_number))


@dataclass
class TaintEdge:
    """
    污点图中的边
    ===========
    表示变量间的污染传播关系。

    属性:
        from_node: 污染来源变量名
        to_node:   污染目标变量名
        reason:    传播原因（如 "assignment" 赋值 / "concat" 拼接 / "func_arg" 函数传参）
    """
    from_node: str
    to_node: str
    reason: str = ""                    # 传播原因，用于调试和报告


@dataclass
class TaintGraph:
    """
    污点传播图
    =========
    使用邻接表（adjacency dict）存储有向图。

    属性:
        nodes:     节点字典 {name: TaintNode}
        edges:     边列表 [TaintEdge, ...]
        adjacency: 邻接表 {from_node: [to_node, ...]}
    """
    nodes: dict[str, TaintNode] = field(default_factory=dict)   # 节点字典
    edges: list[TaintEdge] = field(default_factory=list)        # 边列表
    adjacency: dict[str, list[str]] = field(default_factory=dict)  # 邻接表

    def add_node(self, node: TaintNode):
        """
        向图中添加一个节点。
        如果节点名已存在则覆盖，同时初始化邻接表条目。
        """
        self.nodes[node.name] = node
        if node.name not in self.adjacency:
            self.adjacency[node.name] = []

    def add_edge(self, from_var: str, to_var: str, reason: str = ""):
        """
        向图中添加一条有向边：from_var → to_var。
        表示污点从 from_var 传播到 to_var。
        """
        self.edges.append(TaintEdge(from_var, to_var, reason))
        # 确保邻接表中有 from_var 的条目
        if from_var not in self.adjacency:
            self.adjacency[from_var] = []
        self.adjacency[from_var].append(to_var)

    def get_sources(self) -> list[str]:
        """返回所有 Source 节点的名称列表"""
        return [n for n in self.nodes if self.nodes[n].is_source]

    def get_sinks(self) -> list[str]:
        """返回所有 Sink 节点的名称列表"""
        return [n for n in self.nodes if self.nodes[n].is_sink]

    def find_paths(self, source: str, sink: str) -> list[list[str]]:
        """
        用 BFS 广度优先搜索找出从 source 到 sink 的所有路径。

        参数:
            source: 起点变量名
            sink:   终点变量名

        返回:
            路径列表，每条路径为变量名序列（如 ["user_input", "query", "execute"]）

        注意事项：
            - 最大深度限制为 20，防止无限循环
            - 每条路径中不包含重复节点（避免环）
        """
        if source not in self.adjacency:
            return []

        paths = []                     # 存储所有找到的路径
        queue = deque([[source]])      # BFS 队列，每个元素是一条部分路径
        visited_paths = set()          # 避免重复探索相同路径
        max_depth = 20                 # 最大深度限制，防止无限递归

        while queue:
            path = queue.popleft()     # 取出队首的路径
            current = path[-1]         # 当前路径的最后一个节点

            # 深度限制检查
            if len(path) > max_depth:
                continue

            # 到达目标：记录路径
            if current == sink:
                paths.append(path)
                continue

            # 探索邻居节点
            for neighbor in self.adjacency.get(current, []):
                if neighbor not in path:  # 防止在路径中形成环
                    path_key = tuple(path + [neighbor])
                    if path_key not in visited_paths:
                        visited_paths.add(path_key)
                        queue.append(path + [neighbor])

        return paths


class TaintTracker:
    """
    污点追踪器
    ==========
    扫描单个文件，构建污点图，检测漏洞路径。

    使用方式（五步走）:
        1. 创建追踪器
           tracker = TaintTracker(file_path="app.py")

        2. 标记 Source 点（用户输入入口）
           tracker.mark_source("user_input", source_func="request.args.get")

        3. 标记赋值关系（变量传播）
           tracker.mark_assign("query", "user_input", reason="concat")

        4. 标记 Sink 点（危险函数调用）
           tracker.mark_sink("query", sink_func="cursor.execute")

        5. 执行分析
           results = tracker.analyze()
    """

    def __init__(self, file_path: str = ""):
        """
        初始化追踪器

        参数:
            file_path: 被扫描的源文件路径（用于报告输出）
        """
        self.graph = TaintGraph()                          # 污点传播图
        self.file_path = file_path                         # 源文件路径
        self.source_info: dict[str, dict] = {}             # Source 节点详细信息 {var_name: {source_func, code, line}}
        self.sink_info: dict[str, dict] = {}               # Sink 节点详细信息 {var_name: {sink_func, vuln_type, code, line}}

    def mark_source(self, var_name: str, source_func: str = "",
                    code: str = "", line: int = 0):
        """
        标记一个变量为污点源（用户输入入口）。

        调用此方法后，该变量被视为"已被污染"，分析时会从它出发搜索到 Sink 的路径。

        参数:
            var_name:    变量名
            source_func: Source 函数全名（如 "flask.request.args.get"）
            code:        对应的源代码片段
            line:        所在行号
        """
        node = TaintNode(
            name=var_name,
            source_origin=source_func,
            tainted=True,         # Source 节点的数据默认已被污染
            is_source=True,
            code_snippet=code,
            line_number=line,
        )
        self.graph.add_node(node)
        self.source_info[var_name] = {
            "source_func": source_func,
            "code": code,
            "line": line,
        }

    def mark_sink(self, var_name: str, sink_func: str = "",
                  vuln_type: str = "", code: str = "", line: int = 0):
        """
        标记一个变量传入了危险函数（Sink 点）。

        参数:
            var_name:  传入的变量名
            sink_func: Sink 函数全名（如 "sqlite3.Cursor.execute"）
            vuln_type: 漏洞类型字符串
            code:      对应的源代码片段
            line:      所在行号
        """
        # 如果变量尚未在图中，先创建节点
        if var_name not in self.graph.nodes:
            self.graph.add_node(TaintNode(name=var_name, line_number=line))
        self.graph.nodes[var_name].is_sink = True
        self.sink_info[var_name] = {
            "sink_func": sink_func,
            "vuln_type": vuln_type,
            "code": code,
            "line": line,
        }

    def mark_assign(self, to_var: str, from_var: str, reason: str = "assignment",
                    code: str = "", line: int = 0):
        """
        记录变量赋值关系：to_var ← from_var

        例如：query = "SELECT * FROM users WHERE name=" + user_input
        → mark_assign("query", "user_input", reason="concat")

        同时自动传播污点标记：如果 from_var 被污染，to_var 也会被标记为污染。

        参数:
            to_var:   被赋值的变量
            from_var: 赋值的来源变量
            reason:   传播原因（"assignment" / "concat" / "aug_assign" 等）
            code:     对应的源代码片段
            line:     所在行号
        """
        # 确保目标节点存在
        if to_var not in self.graph.nodes:
            self.graph.add_node(TaintNode(
                name=to_var, code_snippet=code, line_number=line
            ))
        # 确保来源节点存在
        if from_var not in self.graph.nodes:
            self.graph.add_node(TaintNode(name=from_var))

        # 添加传播边
        self.graph.add_edge(from_var, to_var, reason)

        # 污点自动传播：如果来源变量已被污染，目标变量也被标记为污染
        if self.graph.nodes[from_var].tainted:
            self.graph.nodes[to_var].tainted = True

    def mark_concat(self, result_var: str, parts: list[str],
                    code: str = "", line: int = 0):
        """
        记录字符串拼接操作：result = part1 + part2 + ...

        参数:
            result_var: 拼接结果的变量名
            parts:      参与拼接的各部分变量名列表
            code:       对应的源代码片段
            line:       所在行号
        """
        if result_var not in self.graph.nodes:
            self.graph.add_node(TaintNode(
                name=result_var, code_snippet=code, line_number=line
            ))
        for part in parts:
            # 如果参与拼接的任一部分被污染，结果也被污染
            if part in self.graph.nodes and self.graph.nodes[part].tainted:
                self.graph.nodes[result_var].tainted = True
            # 添加拼接边
            self.mark_assign(result_var, part, reason="concat", code=code, line=line)

    def mark_func_arg(self, func_name: str, param_name: str, arg_var: str,
                      code: str = "", line: int = 0):
        """
        记录函数调用参数传递：func(param=arg_var)

        参数:
            func_name:  函数名
            param_name: 参数名
            arg_var:    传入的变量名
            code:       对应的源代码片段
            line:       所在行号
        """
        key = f"{func_name}::{param_name}"  # 合成键：函数名::参数名
        if key not in self.graph.nodes:
            self.graph.add_node(TaintNode(
                name=key, code_snippet=code, line_number=line
            ))
        self.mark_assign(key, arg_var, reason="func_arg", code=code, line=line)

    def analyze(self) -> list[dict]:
        """
        执行完整的污点分析，返回所有发现的漏洞路径。

        流程:
            1. 获取所有 Source 和 Sink 节点
            2. 对每个 (source, sink) 对进行 BFS 路径搜索
            3. 检查路径上是否有消毒函数（sanitizer），过滤掉安全路径
            4. 格式化输出漏洞报告

        返回:
            list[dict]: 漏洞报告列表，每个字典包含：
                - source_var, sink_var: 变量名
                - source_func, sink_func: 函数名
                - vuln_type: 漏洞类型
                - source_code, sink_code: 代码片段
                - data_flow: 传播路径字符串 "var1 → var2 → var3"
                - path: 路径节点列表
                - file: 文件路径
        """
        results = []
        sources = self.graph.get_sources()   # 所有 Source 节点
        sinks = self.graph.get_sinks()       # 所有 Sink 节点

        # 消毒函数集合：如果路径中经过这些函数，则认为数据已被清洗
        sanitizers = {"int", "float", "escape", "html.escape", "cgi.escape", "bleach.clean"}

        visited_pairs = set()  # 避免重复处理相同的 (source, sink) 对

        for source in sources:
            source_node = self.graph.nodes[source]   # Source 节点对象
            for sink in sinks:
                sink_node = self.graph.nodes[sink]   # Sink 节点对象
                pair = (source, sink)

                # 跳过已处理的 source-sink 对
                if pair in visited_pairs:
                    continue
                visited_pairs.add(pair)

                # 用 BFS 找出所有从 source 到 sink 的路径
                paths = self.graph.find_paths(source, sink)
                if not paths:
                    continue  # 没有路径，不是漏洞

                # 检查每条路径上是否有消毒函数
                for path in paths:
                    # 如果路径上任何节点是消毒函数，跳过此路径
                    if any(s in sanitizers for s in path):
                        continue

                    # 收集 source 和 sink 的详细信息
                    si = self.source_info.get(source, {})
                    ski = self.sink_info.get(sink, {})

                    # 构造漏洞报告
                    results.append({
                        "source_var": source,
                        "sink_var": sink,
                        "source_func": si.get("source_func", ""),
                        "sink_func": ski.get("sink_func", ""),
                        "vuln_type": ski.get("vuln_type", ""),
                        "source_code": si.get("code", ""),
                        "sink_code": ski.get("code", ""),
                        # 数据流路径：用箭头连接各变量
                        "data_flow": " → ".join(path),
                        "source_line": si.get("line", 0),
                        "sink_line": ski.get("line", 0),
                        "path": path,
                        "file": self.file_path,
                    })
                    break  # 一个 source-sink 对只报告一次（取第一条有效路径）

        return results

    def reset(self):
        """
        重置追踪器状态，清空所有数据和图结构。
        用于扫描完一个文件后重置，准备扫描下一个文件。
        """
        self.graph = TaintGraph()
        self.source_info = {}
        self.sink_info = {}
