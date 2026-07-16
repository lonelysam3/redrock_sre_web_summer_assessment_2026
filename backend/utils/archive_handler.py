"""
压缩包安全解压模块
================
安全解压用户上传的压缩包，防止以下攻击：
  1. Zip-Slip（路径穿越）—— 文件名包含 ../ 试图解压到目标目录之外
  2. 绝对路径写入 —— 文件名以 / 或 C:\\ 开头试图写入系统任意位置
  3. 符号链接攻击 —— 归档中的符号链接指向系统敏感文件

支持的格式: zip, tar.gz, tar.bz2, tar, tar.xz

安全策略:
  - 所有文件路径在解压前必须通过安全校验
  - 解压到隔离的临时目录中
  - 每个解压单独一个子目录，以项目名+时间戳命名
"""
import os
import shutil
import tarfile
import zipfile
import tempfile
from pathlib import Path
from typing import Optional
from datetime import datetime


class ArchiveSecurityError(ValueError):
    """压缩包安全异常——包含不安全内容的归档"""
    pass


class ArchiveExtractionError(ValueError):
    """压缩包解压异常——解压过程中的一般错误"""
    pass


# 允许的压缩包扩展名
ALLOWED_EXTENSIONS = {".zip", ".tar", ".gz", ".bz2", ".xz"}

# 最大压缩包大小（解压后的文件总大小上限，防止压缩炸弹）
MAX_EXTRACTED_SIZE_MB = 200
MAX_EXTRACTED_SIZE_BYTES = MAX_EXTRACTED_SIZE_MB * 1024 * 1024

# 解压后的单文件最大大小
MAX_SINGLE_FILE_SIZE_MB = 50
MAX_SINGLE_FILE_SIZE_BYTES = MAX_SINGLE_FILE_SIZE_MB * 1024 * 1024

# 文件数上限（防止大量小文件攻击）
MAX_FILE_COUNT = 10000


def is_archive_ext_allowed(filename: str) -> bool:
    """
    检查文件名后缀是否为允许的压缩包格式。

    参数:
        filename: 原始文件名

    返回:
        bool: True 表示允许
    """
    name_lower = filename.lower()
    for ext in ALLOWED_EXTENSIONS:
        if name_lower.endswith(ext):
            return True
    return False


def _validate_extract_path(member_name: str, extract_root: Path) -> Path:
    """
    校验压缩包内单个文件的路径安全性。

    安全规则:
      1. 不允许绝对路径（如 /etc/passwd, C:\\Windows\\system32\\...）
      2. 不允许路径穿越（如 ../../etc/passwd）
      3. 不允许空文件名或目录遍历
      4. 解析后路径必须严格在 extract_root 之内

    参数:
        member_name:  压缩包中的文件/目录名（原始路径）
        extract_root: 解压目标根目录（已解析的绝对路径）

    返回:
        Path: 安全的目标路径

    异常:
        ArchiveSecurityError: 路径不安全
    """
    # ---- 1. 空路径检查 ----
    if not member_name or not member_name.strip():
        raise ArchiveSecurityError("压缩包内包含空路径")

    member_name = member_name.strip()

    # ---- 2. 绝对路径检查 ----
    # Windows: 盘符路径 (C:\...) 或 UNC 路径 (\\...)
    # Unix: 以 / 开头
    member_path = Path(member_name)
    if member_path.is_absolute():
        raise ArchiveSecurityError(
            f"压缩包内包含绝对路径，拒绝解压: {member_name}"
        )
    # 额外检查：Windows 盘符形式（Path 可能不认为 c:foo 是绝对的但仍是危险路径）
    if len(member_name) >= 2 and member_name[1] == ":":
        raise ArchiveSecurityError(
            f"压缩包内包含 Windows 盘符路径，拒绝解压: {member_name}"
        )

    # ---- 3. 路径穿越检查 ----
    # 将成员路径与解压根目录拼接后解析
    # 注意: 这里使用 os.path 而非 Path.resolve()，因为目标文件还不存在
    # resolve() 需要文件存在才能工作
    target = (extract_root / member_path).resolve()

    # 确保目标路径在 extract_root 下
    try:
        target.relative_to(extract_root)
    except ValueError:
        raise ArchiveSecurityError(
            f"压缩包内文件试图逃逸解压目录: {member_name}"
        )

    # ---- 4. 额外检查：路径中的每个部分都不能是 .. ----
    parts = member_path.parts
    if ".." in parts:
        raise ArchiveSecurityError(
            f"压缩包内包含路径穿越序列 (..): {member_name}"
        )

    return target


def _validate_archive_members(archive_path: str, extract_root: Path) -> tuple[int, int]:
    """
    预扫描压缩包内容，检查安全性和统计信息（解压前校验）。

    返回:
        (file_count, total_size): 文件数和总大小

    异常:
        ArchiveSecurityError: 包含不安全条目
        ArchiveExtractionError: 文件数或大小超限
    """
    file_count = 0
    total_size = 0

    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    # 校验路径安全
                    _validate_extract_path(info.filename, extract_root)
                    file_count += 1
                    total_size += info.file_size

        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, "r:*") as tf:
                for member in tf.getmembers():
                    if member.isdir():
                        continue
                    # tarfile 可能返回符号链接等特殊类型
                    if not member.isfile():
                        continue
                    # 校验路径安全
                    _validate_extract_path(member.name, extract_root)
                    file_count += 1
                    total_size += member.size
        else:
            raise ArchiveExtractionError("不支持的压缩格式")
    except (ArchiveSecurityError, ArchiveExtractionError):
        raise
    except Exception as e:
        raise ArchiveExtractionError(f"压缩包预扫描失败: {e}")

    # 文件数上限检查
    if file_count > MAX_FILE_COUNT:
        raise ArchiveExtractionError(
            f"压缩包内文件数 ({file_count}) 超过上限 ({MAX_FILE_COUNT})"
        )

    # 总大小上限检查
    if total_size > MAX_EXTRACTED_SIZE_BYTES:
        raise ArchiveExtractionError(
            f"压缩包解压后大小 ({total_size / 1024 / 1024:.1f}MB) "
            f"超过上限 ({MAX_EXTRACTED_SIZE_MB}MB)"
        )

    return file_count, total_size


def extract_archive(
    file_stream,
    original_filename: str,
    extract_base: str,
    project_name: str = "",
) -> str:
    """
    安全解压上传的压缩包文件。

    流程:
      1. 将上传的文件流保存到临时文件
      2. 预扫描压缩包内容（安全检查 + 统计）
      3. 创建隔离的解压目标目录
      4. 逐文件解压，对每个文件进行路径安全校验
      5. 清理临时压缩文件

    参数:
        file_stream:       上传的文件流对象（werkzeug FileStorage）
        original_filename: 原始文件名（用于判断格式）
        extract_base:      解压基础目录（所有压缩包解压到此目录下）
        project_name:      项目名称（用于生成子目录名）

    返回:
        str: 解压后的项目根目录绝对路径

    异常:
        ArchiveSecurityError: 压缩包内容不安全
        ArchiveExtractionError: 解压失败
    """
    # ---- 1. 格式校验 ----
    if not is_archive_ext_allowed(original_filename):
        raise ArchiveExtractionError(
            f"不支持的文件格式。允许: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # ---- 2. 创建临时文件保存上传内容 ----
    extract_base_path = Path(extract_base).resolve()
    extract_base_path.mkdir(parents=True, exist_ok=True)

    # 保存上传的压缩包到临时文件
    tmp_fd, tmp_path = tempfile.mkstemp(
        suffix="_" + original_filename, dir=str(extract_base_path)
    )
    os.close(tmp_fd)

    try:
        # 写入临时文件
        file_stream.save(tmp_path)

        # ---- 3. 创建解压目标目录 ----
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = project_name.strip().replace(" ", "_") if project_name else "unnamed"
        # 清理项目名中的特殊字符
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "_-")
        if not safe_name:
            safe_name = "unnamed"

        extract_dir_name = f"{safe_name}_{timestamp}"
        extract_dir = extract_base_path / extract_dir_name
        extract_dir.mkdir(parents=True, exist_ok=True)
        extract_dir_resolved = extract_dir.resolve()

        # ---- 4. 预扫描安全校验 ----
        _validate_archive_members(tmp_path, extract_dir_resolved)

        # ---- 5. 执行解压 ----
        extracted_count = 0
        total_extracted_size = 0

        if zipfile.is_zipfile(tmp_path):
            with zipfile.ZipFile(tmp_path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    # 每条路径再次校验（防御性编程）
                    safe_target = _validate_extract_path(
                        info.filename, extract_dir_resolved
                    )

                    # 创建父目录
                    safe_target.parent.mkdir(parents=True, exist_ok=True)

                    # 单文件大小检查
                    if info.file_size > MAX_SINGLE_FILE_SIZE_BYTES:
                        raise ArchiveExtractionError(
                            f"文件 {info.filename} 大小 ({info.file_size / 1024 / 1024:.1f}MB) "
                            f"超过上限 ({MAX_SINGLE_FILE_SIZE_MB}MB)"
                        )

                    # 读取并写入（使用 ZipFile 内置方法，避免手动 open）
                    with zf.open(info) as src, open(safe_target, "wb") as dst:
                        shutil.copyfileobj(src, dst)

                    extracted_count += 1
                    total_extracted_size += info.file_size

        elif tarfile.is_tarfile(tmp_path):
            with tarfile.open(tmp_path, "r:*") as tf:
                for member in tf.getmembers():
                    if member.isdir():
                        continue
                    if not member.isfile():
                        # 跳过符号链接、设备文件等特殊类型
                        continue

                    safe_target = _validate_extract_path(
                        member.name, extract_dir_resolved
                    )
                    safe_target.parent.mkdir(parents=True, exist_ok=True)

                    if member.size > MAX_SINGLE_FILE_SIZE_BYTES:
                        raise ArchiveExtractionError(
                            f"文件 {member.name} 大小 ({member.size / 1024 / 1024:.1f}MB) "
                            f"超过上限 ({MAX_SINGLE_FILE_SIZE_MB}MB)"
                        )

                    # 解压单个文件
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    with src, open(safe_target, "wb") as dst:
                        shutil.copyfileobj(src, dst)

                    extracted_count += 1
                    total_extracted_size += member.size

        else:
            raise ArchiveExtractionError("不支持的压缩格式")

        # ---- 6. 检查是否空压缩包 ----
        if extracted_count == 0:
            # 清理空目录
            shutil.rmtree(str(extract_dir), ignore_errors=True)
            raise ArchiveExtractionError("压缩包内没有文件")

        print(f"[ARCHIVE] 解压完成: {extracted_count} 个文件, "
              f"总大小 {total_extracted_size / 1024 / 1024:.1f}MB")

        return str(extract_dir_resolved)

    except (ArchiveSecurityError, ArchiveExtractionError):
        # 安全/解压异常：清理已创建的解压目录
        try:
            if extract_dir.exists():
                shutil.rmtree(str(extract_dir), ignore_errors=True)
        except Exception:
            pass
        raise

    finally:
        # 始终清理临时压缩文件
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def detect_extracted_language(project_path: str) -> str:
    """
    检测解压后项目目录的主要编程语言。
    遍历文件统计各语言数量，返回占比最高的。

    参数:
        project_path: 解压后的项目根目录

    返回:
        str: "python" / "c" / "cpp" / "php" / "unknown"
    """
    from collections import Counter
    from utils.code_extractor import detect_language

    counter = Counter()
    project = Path(project_path)

    for file_path in project.rglob("*"):
        if not file_path.is_file():
            continue
        # Skip hidden files (dot-prefixed filenames)
        if file_path.name.startswith("."):
            continue
        # Skip files inside hidden/special directories (relative to project root)
        try:
            rel_parts = file_path.relative_to(project).parts
        except ValueError:
            continue
        if any(p.startswith(".") for p in rel_parts):
            continue
        # Skip common non-source directories (relative to project root)
        skip_dirs = {
            "node_modules", "__pycache__", ".git", ".svn",
            "vendor", "venv", ".venv", "env", ".env",
            "dist", "build", "target", ".idea", ".vscode",
        }
        if any(p in skip_dirs for p in rel_parts):
            continue

        lang = detect_language(str(file_path))
        if lang != "unknown":
            counter[lang] += 1

    if not counter:
        return "unknown"

    return counter.most_common(1)[0][0]


def cleanup_extracted(path: str) -> bool:
    """
    清理解压目录（删除项目时调用）。

    参数:
        path: 解压目录路径

    返回:
        bool: True 表示清理成功
    """
    try:
        p = Path(path)
        if p.exists() and p.is_dir():
            shutil.rmtree(str(p))
            return True
    except Exception as e:
        print(f"[ARCHIVE] 清理失败: {e}")
    return False
