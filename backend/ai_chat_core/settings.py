"""
配置持久化模块
=============
管理 AI 配置的 JSON 文件读写。

默认配置文件路径: ~/.ai_chat_core/settings.json
可通过环境变量 AI_CHAT_CORE_SETTINGS_PATH 自定义。

配置加载优先级:
  1. 如果 JSON 文件存在 → 读取文件
  2. 如果文件不存在 → 从环境变量 AI_API_KEY / AI_BASE_URL / AI_MODEL 创建默认配置
  3. 都没有 → 报错提示用户配置
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict


# 默认配置文件的存储路径
DEFAULT_SETTINGS_PATH = Path.home() / ".ai_chat_core" / "settings.json"


@dataclass
class runtime_settings:
    """
    运行时 AI 配置
    ==============
    provider_id:   提供方标识（deepseek / openai / custom）
    api_key:       API 密钥
    base_url:      API 基础地址
    default_model: 默认使用的模型名称
    """
    provider_id: str
    api_key: str
    base_url: str
    default_model: str


class settings_error(RuntimeError):
    """配置相关错误"""
    pass


def resolve_settings_path(custom_path: str | None = None) -> Path:
    """
    解析配置文件的实际路径。

    优先级:
      1. 函数参数 custom_path
      2. 环境变量 AI_CHAT_CORE_SETTINGS_PATH
      3. 默认路径 ~/.ai_chat_core/settings.json
    """
    if custom_path:
        return Path(custom_path).expanduser().resolve()
    env_path = os.getenv("AI_CHAT_CORE_SETTINGS_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return DEFAULT_SETTINGS_PATH


def default_settings_from_env() -> runtime_settings:
    """
    从环境变量创建默认配置。

    支持的环境变量:
      - AI_PROVIDER_ID   (默认: "openai")
      - AI_API_KEY       (必需)
      - AI_BASE_URL      (默认: "https://api.openai.com/v1")
      - AI_MODEL         (默认: "gpt-4o-mini")
    """
    return runtime_settings(
        provider_id=os.getenv("AI_PROVIDER_ID", "openai"),
        api_key=os.getenv("AI_API_KEY", ""),
        base_url=os.getenv("AI_BASE_URL", "https://api.openai.com/v1"),
        default_model=os.getenv("AI_MODEL", "gpt-4o-mini"),
    )


def load_settings(path: Path) -> runtime_settings:
    """
    加载配置（自动回退到环境变量）。

    流程:
      1. 获取环境变量默认值
      2. 如果文件不存在 → 如果没有 API Key 则报错，否则创建文件
      3. 如果文件存在 → 读取并合并（文件值优先）
      4. 检查 API Key 不为空

    参数:
        path: 配置文件路径

    返回:
        runtime_settings 实例

    异常:
        settings_error: API Key 缺失或文件读写失败
    """
    defaults = default_settings_from_env()

    if not path.exists():
        if not defaults.api_key:
            raise settings_error(
                "API key is missing. Set AI_API_KEY or configure it in the web UI."
            )
        save_settings(path, defaults)
        return defaults

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise settings_error(f"Failed to read settings: {exc}") from exc

    # 合并：文件中的值覆盖环境变量默认值
    merged = {
        "provider_id": payload.get("provider_id", defaults.provider_id),
        "api_key": payload.get("api_key", defaults.api_key),
        "base_url": payload.get("base_url", defaults.base_url),
        "default_model": payload.get("default_model", defaults.default_model),
    }

    if not merged["api_key"]:
        raise settings_error(
            "API key is missing. Update settings with a valid API key."
        )

    return runtime_settings(**merged)


def save_settings(path: Path, settings: runtime_settings) -> None:
    """
    保存配置到 JSON 文件。

    自动创建父目录。写入格式化 JSON（2 空格缩进）。

    参数:
        path:     配置文件路径
        settings: runtime_settings 实例

    异常:
        settings_error: 文件写入失败
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
    except OSError as exc:
        raise settings_error(f"Failed to save settings: {exc}") from exc


def update_settings(current: runtime_settings, payload: Dict[str, Any]) -> runtime_settings:
    """
    更新配置（部分覆盖）。

    规则:
      - 如果 payload 中的字段为 None/空 → 保留当前值
      - api_key 特殊处理：提交了但为空字符串 → 保留当前值
      - 更新后检查所有字段非空

    参数:
        current: 当前配置
        payload: 要更新的字段字典

    返回:
        更新后的 runtime_settings

    异常:
        settings_error: 更新后存在空字段
    """
    provider_id = str(payload.get("provider_id") or current.provider_id).strip()
    base_url = str(payload.get("base_url") or current.base_url).strip()
    default_model = str(payload.get("default_model") or current.default_model).strip()

    # API Key 特殊处理：用户可能只改了其他字段，没填 API Key
    submitted_api_key = payload.get("api_key")
    if submitted_api_key is None:
        api_key = current.api_key
    else:
        api_key = str(submitted_api_key).strip() or current.api_key

    updated = runtime_settings(
        provider_id=provider_id,
        api_key=api_key,
        base_url=base_url,
        default_model=default_model,
    )

    # 验证所有字段非空
    if not updated.api_key:
        raise settings_error("api_key cannot be empty")
    if not updated.base_url:
        raise settings_error("base_url cannot be empty")
    if not updated.provider_id:
        raise settings_error("provider_id cannot be empty")
    if not updated.default_model:
        raise settings_error("default_model cannot be empty")

    return updated


def mask_api_key(api_key: str) -> str:
    """
    API Key 脱敏显示。

    规则:
      - 空字符串 → 返回空
      - 长度 ≤ 8 → 全部星号
      - 长密钥 → 显示前 4 位 + **** + 后 4 位

    示例:
        mask_api_key("sk-1234567890abcdef") → "sk-1**********cdef"
    """
    if not api_key:
        return ""
    if len(api_key) <= 8:
        return "*" * len(api_key)
    return f"{api_key[:4]}{'*' * (len(api_key) - 8)}{api_key[-4:]}"
