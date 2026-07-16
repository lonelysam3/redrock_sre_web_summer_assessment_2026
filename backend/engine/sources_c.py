"""
C/C++ Source 点定义（外部输入入口）
================================
定义 C/C++ 程序中所有可能的用户/外部输入入口。

涵盖：
  - 命令行参数（main 函数的 argv）
  - 环境变量（getenv）
  - 标准输入/文件输入（scanf, fgets, read 等）
  - 网络输入（recv, recvfrom）
  - Windows 命令行参数（GetCommandLineW）

格式说明：
  - func:           C 函数名
  - description:    中文描述
  - tainted_params:
      None  = 返回值被污染
      [0]   = 第一个参数（索引从 0 开始）被污染
      [1]   = 第二个参数被污染（如 scanf 的第 1 个参数是 format，第 2 个才是 buffer）
      空列表 = 不做参数标记（用于特殊函数如 gets，其本身返回污染值）
"""
from dataclasses import dataclass, field


@dataclass
class CSource:
    """
    C/C++ Source 点数据类
    ===================
    描述一个 C 语言的外部输入入口。
    """
    func: str                                    # 函数名
    description: str                             # 中文描述
    # 哪些参数被污染
    #   None = 返回值
    #   [] = 第一个参数指针
    #   [0, 1] = 第 0 和第 1 个参数
    tainted_params: list[int] | None = None


# ---- C/C++ Source 点全集 ----
C_SOURCES: list[CSource] = [
    # ============ 命令行参数 ============
    CSource("main_argv", "main() 的 argv 参数", tainted_params=[1]),           # argv 是第二个参数
    CSource("main_argc_argv", "main(argc, argv) 命令行参数", tainted_params=[1]),

    # ============ 环境变量 ============
    CSource("getenv", "getenv() 环境变量"),                                    # 返回值是环境变量值
    CSource("secure_getenv", "secure_getenv() 环境变量"),                       # glibc 安全版本

    # ============ 标准输入 / 文件输入 ============
    CSource("scanf", "scanf() 标准输入", tainted_params=[1]),                  # arg0=format, arg1=buffer（buffer 被污染）
    CSource("fscanf", "fscanf() 文件输入", tainted_params=[1]),                # 同上
    CSource("fgets", "fgets() 读取字符串", tainted_params=[0]),                # 第一个参数（buffer）被写入
    CSource("gets", "gets() 读取字符串（本身也危险）", tainted_params=[0]),      # 经典危险函数
    CSource("getc", "getc() 读取字符"),                                       # 返回值是输入字符
    CSource("fgetc", "fgetc() 读取字符"),
    CSource("getchar", "getchar() 读取字符"),
    CSource("read", "read() 读取", tainted_params=[1]),                        # fd, buf, count; buf 被污染
    CSource("recv", "recv() socket 接收", tainted_params=[1]),                  # socket 接收数据
    CSource("recvfrom", "recvfrom() socket 接收", tainted_params=[1]),
    CSource("readline", "readline() 读取行"),

    # ============ Windows 命令行参数 ============
    CSource("GetCommandLineW", "Windows 命令行"),                               # Win32 API
    CSource("CommandLineToArgvW", "Windows 命令行解析"),                         # 解析后的参数

    # ============ 文件读取 / 内存映射 ============
    CSource("readfile", "文件读取"),
    CSource("mmap", "内存映射文件"),                                            # mmap 返回的文件内容
]
