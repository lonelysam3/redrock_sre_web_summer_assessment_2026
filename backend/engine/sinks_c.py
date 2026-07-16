"""
C/C++ Sink 点定义（危险函数调用）
=============================
定义 C/C++ 中所有可能的危险函数调用。

涵盖类型：
  - COMMAND_EXECUTION:  命令执行（system, popen, exec* 系列）
  - PATH_TRAVERSAL:     路径穿越（fopen, open, stat 等文件操作）
  - ARBITRARY_FILE_READ: 任意文件读写（read, fread, write 等）
"""
from dataclasses import dataclass
from engine.sinks_py import VulnType


@dataclass
class CSink:
    """
    C/C++ Sink 点数据类
    ==================
    描述一个 C 语言的危险函数调用。
    """
    func: str                                  # 函数名（如 "system", "fopen"）
    vuln_type: VulnType                        # 漏洞类型枚举
    description: str                           # 中文描述
    # 危险参数索引：
    #   None = 所有参数都可能危险
    #   0    = 第 1 个参数是危险参数
    dangerous_param_index: int | None = None


# ---- C/C++ Sink 点全集 ----
C_SINKS: list[CSink] = [
    # ============ 命令执行 ============
    CSink("system", VulnType.COMMAND_EXECUTION, "system() 执行命令", dangerous_param_index=0),
    CSink("popen", VulnType.COMMAND_EXECUTION, "popen() 管道执行", dangerous_param_index=0),
    # exec* 系列：替换当前进程，参数是命令/程序路径
    CSink("execve", VulnType.COMMAND_EXECUTION, "execve() 替换进程"),
    CSink("execvp", VulnType.COMMAND_EXECUTION, "execvp() 替换进程"),
    CSink("execl", VulnType.COMMAND_EXECUTION, "execl() 替换进程"),
    CSink("execle", VulnType.COMMAND_EXECUTION, "execle() 替换进程"),
    CSink("execlp", VulnType.COMMAND_EXECUTION, "execlp() 替换进程"),
    CSink("execvpe", VulnType.COMMAND_EXECUTION, "execvpe() 替换进程"),
    # Windows 进程创建
    CSink("CreateProcess", VulnType.COMMAND_EXECUTION, "Windows 创建进程"),
    CSink("CreateProcessA", VulnType.COMMAND_EXECUTION, "Windows 创建进程 (ANSI)"),
    CSink("CreateProcessW", VulnType.COMMAND_EXECUTION, "Windows 创建进程 (Unicode)"),
    CSink("ShellExecute", VulnType.COMMAND_EXECUTION, "Windows Shell 执行"),
    CSink("WinExec", VulnType.COMMAND_EXECUTION, "Windows 执行"),

    # ============ 路径穿越 / 任意文件操作 ============
    CSink("fopen", VulnType.PATH_TRAVERSAL, "fopen() 文件打开", dangerous_param_index=0),
    CSink("open", VulnType.PATH_TRAVERSAL, "open() 文件打开", dangerous_param_index=0),
    CSink("openat", VulnType.PATH_TRAVERSAL, "openat() 文件打开",                 # openat 的文件路径是第 2 个参数
          dangerous_param_index=1),
    CSink("opendir", VulnType.PATH_TRAVERSAL, "opendir() 打开目录", dangerous_param_index=0),
    CSink("freopen", VulnType.PATH_TRAVERSAL, "freopen() 重定向文件"),
    CSink("remove", VulnType.PATH_TRAVERSAL, "remove() 删除文件", dangerous_param_index=0),
    CSink("rename", VulnType.PATH_TRAVERSAL, "rename() 重命名文件"),
    CSink("chmod", VulnType.PATH_TRAVERSAL, "chmod() 修改权限", dangerous_param_index=0),
    CSink("stat", VulnType.PATH_TRAVERSAL, "stat() 文件信息", dangerous_param_index=0),
    CSink("lstat", VulnType.PATH_TRAVERSAL, "lstat() 文件信息", dangerous_param_index=0),
    CSink("access", VulnType.PATH_TRAVERSAL, "access() 文件权限检查", dangerous_param_index=0),
    CSink("realpath", VulnType.PATH_TRAVERSAL, "realpath() 规范化路径（可用于绕过安全检查）"),
    CSink("mkdir", VulnType.PATH_TRAVERSAL, "mkdir() 创建目录", dangerous_param_index=0),

    # ============ 任意文件读取 / 写入 ============
    CSink("read", VulnType.ARBITRARY_FILE_READ, "read() 文件读取"),
    CSink("fread", VulnType.ARBITRARY_FILE_READ, "fread() 文件读取"),
    CSink("fgets", VulnType.ARBITRARY_FILE_READ, "fgets() 文件读取"),
    CSink("fscanf", VulnType.ARBITRARY_FILE_READ, "fscanf() 格式化读取"),
    CSink("write", VulnType.ARBITRARY_FILE_READ, "write() 文件写入"),
    CSink("fwrite", VulnType.ARBITRARY_FILE_READ, "fwrite() 文件写入"),

    # ============ 动态加载（也视为命令执行，可能加载恶意库） ============
    CSink("dlopen", VulnType.COMMAND_EXECUTION, "dlopen() 动态加载"),
    CSink("LoadLibrary", VulnType.COMMAND_EXECUTION, "Windows 动态加载"),
    CSink("LoadLibraryA", VulnType.COMMAND_EXECUTION, "Windows 动态加载"),
]
