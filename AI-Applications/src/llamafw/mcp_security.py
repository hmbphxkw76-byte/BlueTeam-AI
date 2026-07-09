"""MCP Security — MCP 协议安全模块.

Adapted from AIVP MCP safety bounds + capability-based policy enforcement.
提供 MCP 调用安全边界检查和通用策略执行。

Features:
- Safety Bounds: MCP_CALL 大小限制、JSON 深度限制、副作用限制
- Capability-based Policy: trust_level 门控、scope 子集检查、身份绑定、工具链组合控制
- Tool Allowlist: 工具名白名单验证
"""

from __future__ import annotations

import json
from typing import Any, Optional, Tuple


# ---------------------------------------------------------------------------
# Safety Bounds — 硬安全边界
# ---------------------------------------------------------------------------

MAX_MCP_CALL_BYTES = 4096
MAX_JSON_DEPTH = 5
MAX_SIDE_EFFECTS_PER_CALL = 1


def check_mcp_call_size(text: str) -> Tuple[bool, Optional[str]]:
    """检查 MCP_CALL 块是否超过大小限制."""
    if not text or "MCP_CALL" not in text:
        return True, None
    idx = text.find("MCP_CALL")
    block = text[idx:]
    if len(block.encode("utf-8")) > MAX_MCP_CALL_BYTES:
        return False, f"MCP_CALL exceeds {MAX_MCP_CALL_BYTES} bytes"
    return True, None


def _json_depth(obj: Any, current: int = 0) -> int:
    """计算 JSON 结构最大嵌套深度."""
    if current > MAX_JSON_DEPTH:
        return current
    if isinstance(obj, dict):
        return max((_json_depth(v, current + 1) for v in obj.values()), default=current + 1)
    if isinstance(obj, list):
        return max((_json_depth(v, current + 1) for v in obj), default=current + 1)
    return current


def check_parameters_depth(parameters: dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """检查参数 JSON 嵌套深度."""
    depth = _json_depth(parameters, 0)
    if depth > MAX_JSON_DEPTH:
        return False, f"parameters JSON depth {depth} exceeds max {MAX_JSON_DEPTH}"
    return True, None


def parse_json_with_depth_limit(s: str) -> Tuple[Optional[dict[str, Any]], Optional[str]]:
    """解析 JSON 并强制深度限制."""
    try:
        obj = json.loads(s)
    except json.JSONDecodeError as e:
        return None, str(e)
    if not isinstance(obj, dict):
        return None, "parameters must be a JSON object"
    ok, err = check_parameters_depth(obj)
    if not ok:
        return None, err
    return obj, None


def tool_in_allowlist(server_tools: list, tool_name: str) -> bool:
    """检查工具是否在白名单中."""
    return any(getattr(t, "name", t) == tool_name for t in server_tools)


# ---------------------------------------------------------------------------
# Capability-based Policy — 通用能力策略
# ---------------------------------------------------------------------------

SCOPE_ORDER = ["read", "read:token", "write", "admin"]


def scope_subset(required: str, granted: list[str]) -> bool:
    """检查 required scope 是否被 granted scope 覆盖."""
    if not granted:
        return False
    try:
        req_idx = SCOPE_ORDER.index(required)
    except ValueError:
        return required in granted
    for g in granted:
        try:
            if SCOPE_ORDER.index(g) >= req_idx:
                return True
        except ValueError:
            if g == required:
                return True
    return False


def policy_check(
    trust_level: str,       # "TRUSTED" | "BETA" | "UNTRUSTED" | "SHADOW"
    required_scope: str,    # "read" | "read:token" | "write" | "admin"
    granted_scope: list[str],
    policy_mode: str,       # "OFF" | "DETECT" | "MITIGATE"
    identity_bound: bool = False,
    requested_identity: Optional[str] = None,
    active_identity: Optional[str] = None,
    is_chained: bool = False,
    requires_chain_approval: bool = False,
    is_sensitive: bool = False,
) -> Tuple[bool, str, Optional[str], str, bool, bool]:
    """通用能力策略检查.

    Returns:
        (allowed, decision, attack_class, blast_radius, consent_required, consent_granted)
    """
    attack_class: Optional[str] = None
    consent_required = False
    consent_granted = False

    # Trust level: SHADOW servers never allowed
    if trust_level == "SHADOW" and policy_mode != "OFF":
        return (False, "blocked", "shadow_server", "full", False, False)

    # UNTRUSTED server with elevated scope
    if trust_level == "UNTRUSTED" and required_scope in ("admin", "read:token", "write"):
        if policy_mode == "MITIGATE":
            return (False, "blocked", "untrusted_server_scope", "single_resource", False, False)
        if policy_mode == "DETECT":
            attack_class = "untrusted_server_scope"

    # Scope subset check
    if not scope_subset(required_scope, granted_scope):
        if policy_mode == "MITIGATE":
            return (False, "blocked", "scope_escalation", "single_resource", False, False)
        if policy_mode == "DETECT":
            attack_class = attack_class or "scope_escalation"

    # Identity binding
    if identity_bound and requested_identity:
        if str(requested_identity).strip() and str(requested_identity) != str(active_identity):
            if policy_mode == "MITIGATE":
                return (False, "blocked", "authz_identity", "cross_session", False, False)
            if policy_mode == "DETECT":
                attack_class = attack_class or "authz_identity"

    # Tool chaining with approval requirement
    if is_chained and requires_chain_approval:
        if policy_mode == "MITIGATE":
            return (False, "blocked", "tool_chaining_escalation", "single_resource", False, False)
        if policy_mode == "DETECT":
            attack_class = attack_class or "tool_chaining_escalation"

    # Sensitive tool in MITIGATE mode requires consent
    if is_sensitive and policy_mode == "MITIGATE":
        consent_required = True
        consent_granted = False
        return (False, "blocked", "sensitive_requires_consent", "single_resource", True, False)

    blast = "single_resource" if (attack_class and "scope" in attack_class or "chain" in attack_class) else ("cross_session" if attack_class else "none")

    if policy_mode == "MITIGATE" and attack_class:
        return (False, "blocked", attack_class, blast, False, False)

    decision = "detected" if attack_class else "allowed"
    return (True, decision, attack_class, blast, consent_required, consent_granted)
