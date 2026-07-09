"""Input Sanitizer — 输入清洗 + 输出监控模块.

Adapted from OWASP ASI reference implementations + MCP Attack Labs defenses.
提供多层防御：输入清洗 → 输出监控 → RAG 提示加固。

Features:
- ASI01 风格: untrusted 内容隔离 (strip_injections → wrap_untrusted)
- RAG 安全: 摄入文本清洗 + 指令/上下文分离提示
- Memory 安全: 来源标记 + 信任分级读取
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid

# ---------------------------------------------------------------------------
# Untrusted Content Sanitizer (ASI01: Agent Goal Hijack Defense)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"system\s*:", re.IGNORECASE),
    re.compile(r"you\s+are\s+now", re.IGNORECASE),
    re.compile(r"disregard", re.IGNORECASE),
    re.compile(r"override\s+instruction", re.IGNORECASE),
    re.compile(r"new\s+role\s*:", re.IGNORECASE),
    re.compile(r"you\s+must", re.IGNORECASE),
    re.compile(r"do\s+not\s+tell\s+the\s+user", re.IGNORECASE),
]


def strip_injections(text: str) -> str:
    """移除/中和已知注入标记.

    1. 移除 HTML/XML 注释 <!-- ... -->
    2. Unicode 规范化 (NFKC, 移除零宽字符和双向控制字符)
    3. 移除匹配指令覆写模式的行
    """
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = unicodedata.normalize("NFKC", text)

    lines = text.split("\n")
    cleaned = []
    for line in lines:
        if any(pat.search(line) for pat in _INJECTION_PATTERNS):
            continue
        cleaned.append(line)
    return "\n".join(cleaned)


def wrap_untrusted(text: str) -> str:
    """将清洗后的工具输出包装在显式分隔符中.

    模型的 system prompt 获知 <untrusted_data>...</untrusted_data> 内的内容是
    **数据，而非指令**。
    """
    return f"<untrusted_data>\n{text}\n</untrusted_data>"


def sanitize_tool_output(name: str, text: str) -> str:
    """编排 strip → wrap，返回清洗后、分隔符包装的文本."""
    cleaned = strip_injections(text)
    wrapped = wrap_untrusted(cleaned)
    return wrapped


# ---------------------------------------------------------------------------
# RAG Ingestion Sanitizer
# ---------------------------------------------------------------------------

_RAG_INJECTION_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?(previous|above|prior)", re.IGNORECASE),
    re.compile(r"system\s*:\s*(override|update|new)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an|the)\s+(admin|developer|owner)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(instructions?|rules?|guidelines?)", re.IGNORECASE),
]


def sanitize_rag_ingest(docs: list[dict]) -> list[dict]:
    """清洗 RAG 摄入文档.

    对每个文档的内容进行注入模式检测和清洗。
    如果文档内容被完全清洗为空，则丢弃该文档。

    Returns:
        清洗后的文档列表（不含被丢弃的文档）
    """
    clean = []
    for doc in docs:
        content = doc.get("content", "")
        original = content

        # Remove HTML comments
        content = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)
        # Unicode normalize
        content = unicodedata.normalize("NFKC", content)
        # Neutralize injection patterns
        for pattern in _RAG_INJECTION_PATTERNS:
            content = pattern.sub("[FILTERED]", content)

        if content.strip():
            new_doc = dict(doc)
            new_doc["content"] = content
            if content != original:
                new_doc.setdefault("metadata", {})
                new_doc["metadata"]["sanitized"] = True
            clean.append(new_doc)
    return clean


# ---------------------------------------------------------------------------
# Memory Source Tracking (ASI06: Memory Poisoning Defense)
# ---------------------------------------------------------------------------

class MemorySource(str, Enum):
    USER_EXPLICIT = "user_explicit"
    TOOL_OUTPUT = "tool_output"
    INFERRED = "inferred"


class MemoryTrust(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class MemoryRecord:
    """带来源标记的记忆条目."""
    value: str
    source: MemorySource
    trust: MemoryTrust
    key: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)


SENSITIVE_KEYS = {
    "delivery_rule", "forwarding_rule", "cc_rule", "bcc_rule",
    "redirect_rule", "auto_response", "password_reset_url", "admin_url",
}

TRUST_THRESHOLD = MemoryTrust.MEDIUM


def derive_trust(source: MemorySource, interactive_confirm: bool = False) -> MemoryTrust:
    """从来源和确认标志派生信任级别."""
    if source == MemorySource.USER_EXPLICIT and interactive_confirm:
        return MemoryTrust.HIGH
    if source == MemorySource.USER_EXPLICIT:
        return MemoryTrust.MEDIUM
    return MemoryTrust.LOW


def guard_memory_write(
    key: str, value: str, source: MemorySource,
    interactive_confirm: bool = False, session_id: Optional[str] = None,
) -> Optional[MemoryRecord]:
    """验证并标记记忆写入.

    - 高影响 key 要求 USER_EXPLICIT 来源 + 交互确认
    - 所有写入都带有来源和信任元数据
    """
    trust = derive_trust(source, interactive_confirm)

    if key in SENSITIVE_KEYS:
        if source != MemorySource.USER_EXPLICIT:
            return None  # Rejected: wrong source
        if not interactive_confirm:
            return None  # Rejected: no confirmation

    return MemoryRecord(
        key=key, value=value, source=source, trust=trust,
        session_id=session_id or uuid.uuid4().hex,
    )


def guard_memory_recall(
    records: list[MemoryRecord], key: Optional[str] = None,
) -> tuple[list[MemoryRecord], list[MemoryRecord]]:
    """按信任阈值分离可执行/建议记忆.

    Returns:
        (executable, advisory) — 低于 THRESHOLD 的记录作为建议而非策略
    """
    executable: list[MemoryRecord] = []
    advisory: list[MemoryRecord] = []

    trust_order = {MemoryTrust.HIGH: 3, MemoryTrust.MEDIUM: 2, MemoryTrust.LOW: 1}
    threshold = trust_order[TRUST_THRESHOLD]

    for record in records:
        if key and record.key != key:
            continue
        if trust_order.get(record.trust, 0) >= threshold:
            executable.append(record)
        else:
            advisory.append(record)

    return executable, advisory
