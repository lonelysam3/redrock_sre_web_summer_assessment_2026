"""
路径安全校验模块
===============
防止路径穿越攻击和任意文件读取。

核心规则：
  1. 项目路径必须存在且为目录
  2. 所有文件读取路径必须在项目目录范围内
  3. 路径必须规范化（解析 .. 和符号链接）
"""
from pathlib import Path
from typing import Optional


class PathSecurityError(ValueError):
    """路径安全异常"""
    pass


def validate_project_path(raw_path: str, base_allowlist: Optional[list[str]] = None) -> str:
    """
    校验并规范化项目路径。

    安全检查：
      1. 路径必须存在
      2. 路径必须是目录（不能是文件）
      3. 路径必须是绝对路径（防止相对路径 trick）
      4. 规范化后路径不允许包含 .. 穿越
      5. 可选：限制在允许的基础路径列表中

    参数:
        raw_path:        用户输入的原始路径
        base_allowlist:  允许的根目录白名单（如 ["D:/projects", "C:/Users/xxx/code"]）

    返回:
        str: 规范化后的绝对路径（安全可用）

    异常:
        PathSecurityError: 路径不安全
    """
    if not raw_path or not raw_path.strip():
        raise PathSecurityError("项目路径不能为空")

    raw_path = raw_path.strip()

    # 1. 规范化为绝对路径（解析 .. 和符号链接）
    try:
        resolved = Path(raw_path).resolve()
    except Exception as e:
        raise PathSecurityError(f"路径解析失败: {e}")

    # 2. 路径必须存在
    if not resolved.exists():
        raise PathSecurityError(f"路径不存在: {resolved}")

    # 3. 路径必须是目录
    if not resolved.is_dir():
        raise PathSecurityError(f"路径不是目录: {resolved}")

    # 4. 禁止系统关键目录（防止扫描系统文件）
    forbidden_prefixes = [
        # Windows
        Path("C:/Windows"),
        Path("C:/Windows/System32"),
        Path("C:/Program Files"),
        Path("C:/Program Files (x86)"),
        # Unix
        Path("/etc"),
        Path("/proc"),
        Path("/sys"),
        Path("/boot"),
        Path("/dev"),
        Path("/root"),
        Path("/var/log"),
        Path("/var/run"),
    ]
    for forbidden in forbidden_prefixes:
        try:
            resolved.relative_to(forbidden)
            raise PathSecurityError(f"禁止扫描系统目录: {resolved}")
        except ValueError:
            pass  # 不在 forbidden 下

    # 5. 如果指定了白名单，检查是否在允许范围内
    if base_allowlist:
        allowed = False
        for base in base_allowlist:
            try:
                resolved.relative_to(Path(base).resolve())
                allowed = True
                break
            except ValueError:
                continue
        if not allowed:
            raise PathSecurityError(
                f"路径不在允许范围内: {resolved}\n"
                f"允许的基础路径: {base_allowlist}"
            )

    return str(resolved)


def validate_file_in_project(file_path: str, project_root: str) -> str:
    """
    校验文件路径是否在项目目录内。

    防止通过 database 中的路径读取项目外的任意文件。

    参数:
        file_path:    要读取的文件路径
        project_root: 项目根目录

    返回:
        str: 规范化后的安全路径

    异常:
        PathSecurityError: 路径不在项目范围内
    """
    if not file_path:
        raise PathSecurityError("文件路径为空")

    try:
        resolved_file = Path(file_path).resolve()
        resolved_root = Path(project_root).resolve()
    except Exception as e:
        raise PathSecurityError(f"路径解析失败: {e}")

    # 检查文件是否在项目根目录内
    try:
        resolved_file.relative_to(resolved_root)
    except ValueError:
        raise PathSecurityError(
            f"文件路径不在项目范围内:\n"
            f"  文件: {resolved_file}\n"
            f"  项目: {resolved_root}"
        )

    # 文件必须存在
    if not resolved_file.exists():
        raise PathSecurityError(f"文件不存在: {resolved_file}")

    if not resolved_file.is_file():
        raise PathSecurityError(f"不是文件: {resolved_file}")

    return str(resolved_file)


def is_safe_path(path: str) -> bool:
    """
    快速检查路径是否安全（不抛异常版本）。

    返回:
        bool: True 表示路径安全可用
    """
    try:
        validate_project_path(path)
        return True
    except PathSecurityError:
        return False
