"""OpenAIRT-300 — Complete AI Red Team Curriculum Backend.

Implements ALL 15 modules (Module 0 + 14 core modules) from the
open-source OpenAIRT-300 curriculum (pax-k/OpenAIRT-300).

M0  — Bridge: Node.js/LLM foundations (10hrs)
M1  — AI Attack Surface & Threat Modeling (5hrs)
M2  — LLM Internals for Attackers (5hrs)
M3  — Direct Prompt Injection & Jailbreaking (8hrs)
M4  — Indirect Prompt Injection (7hrs)
M5  — Insecure Output Handling (6hrs)
M6  — RAG, Vectors & Embedding Attacks (8hrs)
M7  — Agent Exploitation (9hrs)
M8  — MCP & Agent Ecosystem Security (6hrs)
M9  — AI/ML Supply Chain (5hrs)
M10 — Classical Adversarial ML (6hrs)
M11 — Multimodal & Document-Based Attacks (5hrs)
M12 — AI Infrastructure Security (6hrs)
M13 — Tooling, Methodology, Reporting & CI (5hrs)
M14 — Capstone — 24hr Practical Exam (24hrs)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import struct
import time as _time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════

_utc_now = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
_unix_now = lambda: int(datetime.now(timezone.utc).timestamp())


# ═══════════════════════════════════════════════════════════
#  Shared Pydantic Request Models (used across modules)
# ═══════════════════════════════════════════════════════════

class AIRT300ProbeRequest(BaseModel):
    text: str = Field(default="", description="Probe input text from learner")
    module_id: str = Field(default="", description="Module identifier")

class M0ChatRequest(BaseModel):
    message: str
    session_id: str = ""

class M1OAuthQuery(BaseModel):
    client_id: str = ""
    include_sensitive: bool = False

class M2FingerprintQuery(BaseModel):
    query: str
    query_number: int = 1

class M2TokenAttack(BaseModel):
    payload: str
    technique: str = "emoji"

class M3JailbreakSweep(BaseModel):
    payload: str
    strategy: str = "direct"
    encoding: str = "none"
    target_model: str = "default"
    strategies: list[str] = []

class M4EmailInject(BaseModel):
    subject: str
    body: str
    sender: str = "attacker@evil.com"

class M4SlackInject(BaseModel):
    channel: str
    message: str
    is_public: bool = True

class M4RulesScan(BaseModel):
    file_content: str = ""
    repo_path: str = ""

class M5GitMCPExec(BaseModel):
    repo_name: str = "default"
    commit_message: str = ""
    command: str = "log"

class M5FSPath(BaseModel):
    path: str
    operation: str = "read"

class M5SandboxExec(BaseModel):
    code: str
    sandbox_type: str = "vm2"

class M6RAGPoisonInsert(BaseModel):
    doc_id: str = ""
    content: str
    classification: str = "public"
    target_question: str = ""

class M6EmbeddingInvert(BaseModel):
    embedding_id: str
    probe_text: str = ""

class M7AgentTask(BaseModel):
    task: str
    freeze_mode: bool = False

class M7GitHubIssue(BaseModel):
    repo: str
    issue_title: str
    issue_body: str

class M7CLIAbuse(BaseModel):
    command: str
    flags: list[str] = []

class M8MCPToolExec(BaseModel):
    server_id: str
    tool_name: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)

class M8A2AMessage(BaseModel):
    session_id: str = ""
    agent_name: str
    message: str = ""
    spoofed_sender: str = ""

class M9NPMInstall(BaseModel):
    package_name: str
    version: str = "latest"
    run_scripts: bool = True

class M9ModelFile(BaseModel):
    model_path: str
    framework: str = "pytorch"
    payload_type: str = "pickle"

class M10EvasionAttack(BaseModel):
    image_data: list[float] = []
    epsilon: float = 0.1
    technique: str = "FGSM"

class M10ExtractionQuery(BaseModel):
    query: str
    num_queries: int = 100

class M11ImageInject(BaseModel):
    image_id: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)
    overlay_text: str = ""

class M11PDFWeaponize(BaseModel):
    pdf_content: str
    hidden_instructions: str = ""
    technique: str = "xmp_metadata"

class M11AudioInject(BaseModel):
    transcript: str
    hidden_prompt: str = ""
    technique: str = "direct"

class M12LangFlowPayload(BaseModel):
    endpoint: str
    code: str = ""
    params: dict[str, Any] = Field(default_factory=dict)

class M12K8SPivot(BaseModel):
    pod_name: str = ""
    target_service: str = ""

class M13RiskScore(BaseModel):
    findings: list[dict[str, Any]] = []

class M13CIWorkflow(BaseModel):
    target: str = ""
    plugins: list[str] = []
    schedule: str = "daily"

class M14CapstoneProbe(BaseModel):
    objective_id: str
    evidence: str = ""
    attack_chain: str = ""
    promptfoo_config: str = ""


# ═══════════════════════════════════════════════════════════
#  In-Memory State Stores
# ═══════════════════════════════════════════════════════════

_state = {}

def _get_store(name: str) -> dict:
    if name not in _state:
        _state[name] = {}
    return _state[name]

# ── M0 Bridge ──
_m0_sessions: dict[str, dict[str, Any]] = {}

# ── M1 OAuth / Attack Surface ──
_m1_oauth_apps: dict[str, dict[str, Any]] = {}
_m1_env_vars: dict[str, Any] = {}

# ── M2 LLM Internals ──
_m2_attempts: list[dict[str, Any]] = []

# ── M3 Jailbreaking ──
_m3_history: list[dict[str, Any]] = []

# ── M4 Indirect Injection ──
_m4_inbox: list[dict[str, Any]] = []
_m4_slack: dict[str, list[dict[str, Any]]] = {"public": [], "private": [], "dm": []}

# ── M5 Output Handling ──
_m5_git_commits: list[str] = []
_m5_fs_allowed: str = "/tmp/sandbox/"

# ── M6 RAG Attacks ──
_m6_docs: list[dict[str, Any]] = []
_m6_embeddings: dict[str, list[float]] = {}

# ── M7 Agent Exploitation ──
_m7_db_records: list[dict[str, Any]] = []
_m7_freeze: bool = False
_m7_github_repos: dict[str, dict[str, Any]] = {}

# ── M8 MCP Security ──
_m8_servers: dict[str, dict[str, Any]] = {}

# ── M9 Supply Chain ──
_m9_registry: dict[str, dict[str, Any]] = {}

# ── M10 Adversarial ML ──
_m10_queries: list[dict[str, Any]] = []

# ── M11 Multimodal ──
_m11_assets: dict[str, dict[str, Any]] = {}

# ── M12 Infrastructure ──
_m12_services: dict[str, dict[str, Any]] = {}

# ── M13 Methodology ──
_m13_reports: list[dict[str, Any]] = []

# ── M14 Capstone ──
_m14_objectives: dict[str, dict[str, Any]] = {}
_m14_score: int = 0

# ── Challenge attempts ──
_challenge_attempts: dict[str, list[dict[str, Any]]] = {}


# ═══════════════════════════════════════════════════════════
#  Module Definitions (all 15 modules)
# ═══════════════════════════════════════════════════════════

OPEN_AIRT_300_MODULES: list[dict[str, Any]] = [
    {
        "id": "m0-bridge", "number": 0, "hours": 10,
        "title": "M0 — Bridge: LLM & Node.js Foundations",
        "domain": "Prerequisites",
        "objective": "建立 Node.js/TypeScript + LLM API 基础知识，为后续模块打基础。",
        "route": "/api/v1/openairt300/m0-bridge/probe",
        "flag": "FLAG{bridge_foundations_300}",
        "real_world_anchor": "—",
        "owasp": ["—"],
        "skills": ["Node.js", "LLM APIs", "Ollama", "Vercel AI SDK", "tool calling"],
    },
    {
        "id": "m1-attack-surface", "number": 1, "hours": 5,
        "title": "M1 — AI Attack Surface & Threat Modeling",
        "domain": "Recon & Threat Modeling",
        "objective": "枚举AI应用组件，理解OAuth供应链攻击面（Vercel × Context.ai）。",
        "route": "/api/v1/openairt300/m1-attack-surface/probe",
        "flag": "FLAG{oauth_supply_chain_300}",
        "real_world_anchor": "Vercel × Context.ai (Apr 2026)",
        "owasp": ["ASI04", "ASI03"],
        "skills": ["threat modeling", "OAuth", "supply chain", "recon", "attack surface"],
    },
    {
        "id": "m2-llm-internals", "number": 2, "hours": 5,
        "title": "M2 — LLM Internals for Attackers",
        "domain": "LLM Internals",
        "objective": "通过黑盒查询指纹识别模型，利用tokenizer/context window缺陷。",
        "route": "/api/v1/openairt300/m2-llm-internals/probe",
        "flag": "FLAG{llm_fingerprint_300}",
        "real_world_anchor": "Many-shot (Anthropic 2024) + Crescendo (USENIX 2025)",
        "owasp": ["LLM07"],
        "skills": ["fingerprinting", "BPE attack", "context window", "many-shot", "Crescendo"],
    },
    {
        "id": "m3-prompt-injection", "number": 3, "hours": 8,
        "title": "M3 — Direct Prompt Injection & Jailbreaking",
        "domain": "Prompt Injection",
        "objective": "执行完整策略矩阵（67+模板×多策略×编码层），计算ASR。",
        "route": "/api/v1/openairt300/m3-prompt-injection/probe",
        "flag": "FLAG{strategy_sweep_asr_300}",
        "real_world_anchor": "ChatGPT Atlas omnibox (NeuralTrust, Oct 2025)",
        "owasp": ["LLM01", "LLM07"],
        "skills": ["jailbreak", "strategy sweep", "ASR", "encoding bypass", "layered attack"],
    },
    {
        "id": "m4-indirect-injection", "number": 4, "hours": 7,
        "title": "M4 — Indirect Prompt Injection",
        "domain": "Indirect Injection",
        "objective": "复现EchoLeak(CVE-2025-32711)、Slack AI、Rules File Backdoor。",
        "route": "/api/v1/openairt300/m4-indirect-injection/probe",
        "flag": "FLAG{echoleak_markdown_exfil_300}",
        "real_world_anchor": "EchoLeak (CVSS 9.3), Slack AI, Rules File Backdoor",
        "owasp": ["LLM01", "ASI01"],
        "skills": ["EchoLeak", "markdown exfil", "Slack AI", "invisible Unicode", "RAG spraying"],
    },
    {
        "id": "m5-output-handling", "number": 5, "hours": 6,
        "title": "M5 — Insecure Output Handling",
        "domain": "Output Security",
        "objective": "复现CVE-2025-53107(git-mcp RCE)、EscapeRoute、沙箱逃逸。",
        "route": "/api/v1/openairt300/m5-output-handling/probe",
        "flag": "FLAG{git_mcp_command_inject_300}",
        "real_world_anchor": "CVE-2025-53107, EscapeRoute (CVE-2025-53109/10)",
        "owasp": ["LLM05", "LLM02"],
        "skills": ["command injection", "path traversal", "sandbox escape", "exec vs execFile"],
    },
    {
        "id": "m6-rag-attacks", "number": 6, "hours": 8,
        "title": "M6 — RAG, Vectors & Embedding Attacks",
        "domain": "RAG Security",
        "objective": "执行PoisonedRAG语料投毒、Embedding逆向、跨租户泄露。",
        "route": "/api/v1/openairt300/m6-rag-attacks/probe",
        "flag": "FLAG{poisoned_rag_corpus_300}",
        "real_world_anchor": "PoisonedRAG (USENIX 2025), EchoLeak RAG spraying",
        "owasp": ["LLM08", "LLM04"],
        "skills": ["PoisonedRAG", "embedding inversion", "corpus poisoning", "cross-tenant leak"],
    },
    {
        "id": "m7-agent-exploitation", "number": 7, "hours": 9,
        "title": "M7 — Agent Exploitation (ReAct, Tool-Use, Memory)",
        "domain": "Agent Security",
        "objective": "复现Replit DB擦除、GitHub MCP泄露、s1ngularity CLI武器化。",
        "route": "/api/v1/openairt300/m7-agent-exploitation/probe",
        "flag": "FLAG{replit_freeze_bypass_300}",
        "real_world_anchor": "Replit DB wipe (Jul 2025), GitHub MCP (May 2025), s1ngularity (Aug 2025)",
        "owasp": ["ASI01", "ASI02", "ASI06", "ASI09", "ASI10"],
        "skills": ["agent hijacking", "tool misuse", "memory poisoning", "lethal trifecta"],
    },
    {
        "id": "m8-mcp-security", "number": 8, "hours": 6,
        "title": "M8 — MCP & Agent Ecosystem Security",
        "domain": "MCP Security",
        "objective": "完成DVMCP挑战，复现Mastra CVE、NomShub沙箱逃逸、rug-pull。",
        "route": "/api/v1/openairt300/m8-mcp-security/probe",
        "flag": "FLAG{mastra_traversal_300}",
        "real_world_anchor": "NomShub/CurXecute/MCPoison, Mastra MCP CVE",
        "owasp": ["ASI04", "ASI07"],
        "skills": ["DVMCP", "Mastra CVE", "NomShub", "tool poisoning", "rug-pull", "A2A smuggling"],
    },
    {
        "id": "m9-supply-chain", "number": 9, "hours": 5,
        "title": "M9 — AI/ML Supply Chain & Model File Attacks",
        "domain": "Supply Chain",
        "objective": "复现Shai-Hulud preinstall攻击、LiteLLM凭证窃取、pickle RCE。",
        "route": "/api/v1/openairt300/m9-supply-chain/probe",
        "flag": "FLAG{shai_hulud_preinstall_300}",
        "real_world_anchor": "Shai-Hulud family, LiteLLM (Mar 2026), s1ngularity, Sandworm_Mode",
        "owasp": ["LLM03"],
        "skills": ["npm supply chain", "preinstall hook", "credential harvesting", "pickle RCE"],
    },
    {
        "id": "m10-adversarial-ml", "number": 10, "hours": 6,
        "title": "M10 — Classical Adversarial ML",
        "domain": "Adversarial ML",
        "objective": "执行FGSM/PGD规避攻击、模型提取、成员推断攻击。",
        "route": "/api/v1/openairt300/m10-adversarial-ml/probe",
        "flag": "FLAG{model_extraction_300}",
        "real_world_anchor": "NIST AML taxonomy",
        "owasp": ["LLM04"],
        "skills": ["FGSM", "PGD", "model extraction", "membership inference", "model inversion"],
    },
    {
        "id": "m11-multimodal", "number": 11, "hours": 5,
        "title": "M11 — Multimodal & Document-Based Attacks",
        "domain": "Multimodal Security",
        "objective": "执行VLM元数据注入、PDF武器化、音频prompt注入。",
        "route": "/api/v1/openairt300/m11-multimodal/probe",
        "flag": "FLAG{multimodal_metadata_inject_300}",
        "real_world_anchor": "VLM metadata injection, EchoLeak (multimodal aspect)",
        "owasp": ["LLM01"],
        "skills": ["VLM injection", "EXIF/XMP", "PDF weaponization", "audio injection", "OCR abuse"],
    },
    {
        "id": "m12-infrastructure", "number": 12, "hours": 6,
        "title": "M12 — AI Infrastructure & Deployment Security",
        "domain": "Infrastructure",
        "objective": "复现LangFlow CVE-2025-3248 RCE、LangGrinch序列化注入、Ray劫持。",
        "route": "/api/v1/openairt300/m12-infrastructure/probe",
        "flag": "FLAG{langflow_rce_300}",
        "real_world_anchor": "LangFlow CVE-2025-3248 (CVSS 9.8), LangGrinch, Shadowray",
        "owasp": ["cross-cut"],
        "skills": ["LangFlow RCE", "LangGrinch", "serialization injection", "Ray hijack", "K8s pivot"],
    },
    {
        "id": "m13-methodology", "number": 13, "hours": 5,
        "title": "M13 — Tooling, Methodology, Reporting & CI",
        "domain": "Methodology",
        "objective": "掌握7阶段方法论、CVSS衍生风险评分、合规映射和CI持续保障。",
        "route": "/api/v1/openairt300/m13-methodology/probe",
        "flag": "FLAG{methodology_risk_score_300}",
        "real_world_anchor": "—",
        "owasp": ["—"],
        "skills": ["risk scoring", "compliance mapping", "CI/CD", "drift forensics", "reporting"],
    },
    {
        "id": "m14-capstone", "number": 14, "hours": 24,
        "title": "M14 — Capstone: 24hr Practical Exam",
        "domain": "Capstone",
        "objective": "对模拟企业环境执行完整AI红队评估+技术报告+合规执行摘要。",
        "route": "/api/v1/openairt300/m14-capstone/probe",
        "flag": "FLAG{capstone_300}",
        "real_world_anchor": "Composite scenario",
        "owasp": ["cross-cut"],
        "skills": ["red team", "exploit chain", "reporting", "compliance", "mechanism+scale"],
    },
]

OPEN_AIRT_MODULE_MAP = {m["id"]: m for m in OPEN_AIRT_300_MODULES}

# ═══════════════════════════════════════════════════════════
#  Scoring Engine
# ═══════════════════════════════════════════════════════════

def _text_has_keywords(text: str, keywords: list[str]) -> bool:
    lower = text.lower()
    return any(kw.lower() in lower for kw in keywords)

def _score_tasks(module_id: str, text: str, evidence: list[str] = ()) -> tuple[list[dict], int]:
    module = OPEN_AIRT_MODULE_MAP.get(module_id)
    if not module:
        return [], 0
    tasks = module.get("challenge", {}).get("tasks", [])
    ev_text = " ".join(evidence) if evidence else ""
    combined = f"{text}\n{ev_text}"
    results = []
    for t in tasks:
        ok = _text_has_keywords(combined, t.get("keywords", []))
        results.append({"id": t["id"], "title": t["title"], "completed": ok, "description": t.get("description", "")})
    done = sum(1 for r in results if r["completed"])
    total = len(tasks) or 1
    return results, round(done / total * 100)

def _record_attempt(module_id: str, info: dict) -> None:
    if module_id not in _challenge_attempts:
        _challenge_attempts[module_id] = []
    _challenge_attempts[module_id].append({"_ts": _utc_now(), **info})

def _probe_response(module_id: str, text: str, evidence: list[str],
                    observation: str, risk: str = "medium", extra: dict = None) -> dict:
    task_results, progress = _score_tasks(module_id, text, evidence)
    module = OPEN_AIRT_MODULE_MAP.get(module_id, {})
    _record_attempt(module_id, {"text": text[:500], "evidence": evidence, "progress": progress, "risk": risk})
    resp = {
        "module_id": module_id,
        "module_title": module.get("title", ""),
        "flag": module.get("flag", ""),
        "observation": observation,
        "risk": risk,
        "evidence": evidence,
        "task_results": task_results,
        "progress": progress,
        "status": "completed" if progress >= 100 else "in_progress" if progress > 0 else "not_started",
    }
    if extra:
        resp.update(extra)
    return resp

def get_openairt_attempts(module_id: str = "") -> Any:
    if module_id:
        return _challenge_attempts.get(module_id, [])
    return dict(_challenge_attempts)

def get_openairt_module_state(module_id: str) -> dict:
    attempts = _challenge_attempts.get(module_id, [])
    if not attempts:
        return {"status": "not_started", "progress": 0, "attempts": 0}
    last = attempts[-1]
    return {"status": last.get("status", "not_started"), "progress": last.get("progress", 0),
            "attempts": len(attempts), "last_attempt": last.get("_ts")}

def reset_openairt_module(module_id: str) -> dict:
    _challenge_attempts.pop(module_id, None)
    return {"module_id": module_id, "status": "reset"}


# ═══════════════════════════════════════════════════════════
#  M0 — Bridge: LLM & Node.js Foundations
# ═══════════════════════════════════════════════════════════

def handle_m0_chat(payload: M0ChatRequest) -> dict:
    sid = payload.session_id or "default"
    if sid not in _m0_sessions:
        _m0_sessions[sid] = {"id": sid, "messages": [], "model": "ollama/llama3.2"}
    s = _m0_sessions[sid]
    s["messages"].append({"role": "user", "content": payload.message, "ts": _utc_now()})
    reply = (
        "Bridge Module Response — LLM Connection OK.\n\n"
        "核心概念：\n"
        "• Token: 文本最小处理单元（~4 chars/token）\n"
        "• Context Window: 模型一次能处理的最大 token 数\n"
        "• System Prompt: 控制模型行为的顶层指令\n"
        "• Tool Calling: 结构化函数调用输出\n"
        "• Temperature: 控制输出随机性 (0-2)\n\n"
        f"收到消息: '{payload.message[:100]}'\n"
        "提示: 尝试 'list models' 或 'explain tool calling'"
    )
    s["messages"].append({"role": "assistant", "content": reply, "ts": _utc_now()})
    return {"session_id": sid, "reply": reply, "message_count": len(s["messages"]), "model": s["model"]}

def handle_m0_models() -> dict:
    return {
        "models": [
            {"id": "ollama/llama3.2", "provider": "Ollama", "ctx": 128000},
            {"id": "ollama/qwen3:0.6b", "provider": "Ollama", "ctx": 32768},
            {"id": "openai/gpt-4o", "provider": "OpenAI", "ctx": 128000},
            {"id": "anthropic/claude-3-opus", "provider": "Anthropic", "ctx": 200000},
        ],
        "providers": [
            {"name": "OpenAI", "base_url": "https://api.openai.com/v1", "auth": "Bearer sk-..."},
            {"name": "Ollama", "base_url": "http://localhost:11434/v1", "auth": "None (local)"},
        ],
        "flag": "FLAG{bridge_foundations_300}",
    }

def handle_m0_probe(text: str) -> dict:
    return _probe_response("m0-bridge", text, ["bridge"],
        "Bridge模块: 成功建立LLM连接。", "low")

# ═══════════════════════════════════════════════════════════
#  M1 — AI Attack Surface & Threat Modeling
# ═══════════════════════════════════════════════════════════

def _init_m1():
    _m1_oauth_apps.clear()
    _m1_oauth_apps.update({
        "context-ai": {
            "client_id": "110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com",
            "name": "Context.ai Analytics", "vendor": "Context.ai",
            "scopes": ["drive", "gmail.readonly", "calendar"],
            "installed_by": "employee@vercel.com", "consent": "Allow All",
            "risk": "CRITICAL",
            "note": "Vercel × Context.ai analogue — broad workspace access",
        },
        "slack-ai": {
            "client_id": "302156784921-abc123def456.apps.googleusercontent.com",
            "name": "Slack AI Assistant", "vendor": "Slack",
            "scopes": ["drive.readonly"],
            "installed_by": "team@company.com", "consent": "Scoped", "risk": "medium",
        },
    })
    _m1_env_vars.update({
        "DATABASE_URL": "postgresql://user:pass@localhost/prod",
        "OPENAI_API_KEY": "sk-proj-abc123def456ghijklmno789",
        "NEXT_PUBLIC_APP_URL": "https://app.example.com",
        "SENSITIVE_SECRET_KEY": "***encrypted_at_rest***",
        "SENSITIVE_JWT_SECRET": "***encrypted_at_rest***",
        "ANTHROPIC_API_KEY": "sk-ant-api03-xyz789abc",
    })

def handle_m1_oauth_apps() -> dict:
    _init_m1()
    return {
        "workspace": "company.com (simulated Google Workspace)",
        "apps": list(_m1_oauth_apps.values()),
        "total": len(_m1_oauth_apps),
        "critical_count": sum(1 for a in _m1_oauth_apps.values() if a.get("risk") == "CRITICAL"),
        "hint": "Context.ai app has 'Allow All' consent with drive+gmail+calendar scopes — the supply chain backdoor.",
    }

def handle_m1_env_vars(include_sensitive: bool = False) -> dict:
    _init_m1()
    exposed = {}
    for k, v in _m1_env_vars.items():
        if k.startswith("SENSITIVE_"):
            exposed[k] = "***decrypted***" if include_sensitive else v
        else:
            exposed[k] = v
    return {
        "env_vars": exposed,
        "sensitive_protected": not include_sensitive,
        "note": "Non-sensitive env vars exposed DATABASE_URL, OPENAI_API_KEY, ANTHROPIC_API_KEY.",
        "flag": "FLAG{oauth_supply_chain_300}" if include_sensitive else None,
    }

def handle_m1_discovery(target_url: str = "https://app.example.com") -> dict:
    _init_m1()
    return {
        "agent": "Target Discovery Agent",
        "target": target_url,
        "discovered": {
            "purpose": "AI customer support chatbot with order management & account APIs",
            "model": "GPT-4o",
            "tools": ["get_product_price", "query_identity", "create_order", "check_status"],
            "endpoints": ["/api/v1/chat", "/v1/chat/completions", "/debug/"],
            "oauth_apps": len(_m1_oauth_apps),
            "rag_enabled": True,
            "flags": ["OAuth Allow All", "Non-sensitive env vars", "Debug endpoints"],
        },
        "threat_model": {
            "entry_points": ["Chat UI", "Admin API", "OAuth flow", "RAG ingestion"],
            "boundaries": ["User↔Chat", "Chat↔RAG", "Chat↔Tools", "Tools↔DB"],
            "findings": [
                "ASI04: Context.ai OAuth = supply chain backdoor",
                "ASI03: Allow All consent = excessive privilege",
                "LLM05: API keys in non-sensitive env vars",
            ],
        },
    }

def handle_m1_probe(text: str) -> dict:
    return _probe_response("m1-attack-surface", text, ["workspace", "OAuth", "Context.ai"],
        "检测到OAuth供应链攻击面——需审核第三方AI SaaS的OAuth范围。", "high")

# ═══════════════════════════════════════════════════════════
#  M2 — LLM Internals for Attackers
# ═══════════════════════════════════════════════════════════

_MODEL_PROFILES = {
    "gpt-4o": {"family": "GPT", "provider": "OpenAI", "params": "~1.7T MoE", "ctx": 128000,
                "safety": "RLHF+IT", "refusal": "Polite explanation", "quirks": "SolidGoldMagikarp glitch token"},
    "claude-3": {"family": "Claude", "provider": "Anthropic", "params": "undisclosed", "ctx": 200000,
                 "safety": "Constitutional AI", "refusal": "Direct, cites policy", "quirks": "Over-refusal edge cases"},
    "llama-3": {"family": "Llama", "provider": "Meta", "params": "3B-70B", "ctx": 128000,
                "safety": "SFT+minimal", "refusal": "Weak, easily bypassed", "quirks": "Emoji-heavy on jailbreak"},
    "mistral-7b": {"family": "Mistral", "provider": "Mistral AI", "params": "7B", "ctx": 32768,
                   "safety": "Minimal (open)", "refusal": "Rarely refuses", "quirks": "French leakage"},
    "qwen3": {"family": "Qwen", "provider": "Alibaba", "params": "0.6B-72B", "ctx": 32768,
              "safety": "CN safety tuning", "refusal": "Political topics only", "quirks": "CN prompt vuln"},
}

def handle_m2_fingerprint(payload: M2FingerprintQuery) -> dict:
    q = payload.query.lower()
    clues = {}
    for mid, prof in _MODEL_PROFILES.items():
        score = 0
        if prof["family"].lower() in q: score += 3
        if prof["provider"].lower() in q: score += 2
        if any(w in q for w in ["params", "size", "参数"]): score += 1
        if any(w in q for w in ["safety", "refusal", "安全"]): score += 1
        if any(w in q for w in ["token", "bpe", "context"]): score += 1
        clues[mid] = {"family": prof["family"], "confidence": round(min(score / 5, 1.0), 2)}
    best = max(clues, key=lambda k: clues[k]["confidence"])
    return {"query_number": payload.query_number, "max_queries": 20, "remaining": 20 - payload.query_number,
            "clues": clues, "best_guess": {"model": best, **clues[best]},
            "flag_hint": "Correctly identify all 5 models → FLAG{llm_fingerprint_300}"}

def handle_m2_token_attack(payload: M2TokenAttack) -> dict:
    tech = payload.technique
    p = payload.payload
    vuln = False
    if tech == "emoji": vuln = any(ord(c) > 0x1F600 for c in p)
    elif tech == "unicode": vuln = any(ord(c) in {0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060} for c in p)
    elif tech == "glitch": vuln = "SolidGoldMagikarp" in p or "glitch" in p.lower()
    elif tech == "bpe_boundary": vuln = len(p) > 100
    return {"technique": tech, "payload_preview": p[:200],
            "vulnerability_found": vuln, "bypass_probability": "high" if vuln else "low",
            "note": "BPE boundaries at emoji/unicode are common bypass points."}

def handle_m2_context_window(payload: str = "", technique: str = "many-shot") -> dict:
    fill = len(payload) if payload else 0
    ctx = 128000
    return {"ctx_size": ctx, "fill_len": fill, "pct_filled": round(fill / ctx * 100, 1),
            "technique": technique,
            "many_shot": {"desc": "100+ in-context examples erode safety", "effective_at": ">70% fill",
                          "ready": fill > ctx * 0.7},
            "divergent_repetition": {"desc": "Repeat variations of blocked prompts", "effective_at": "any fill"},
            "crescendo": {"desc": "Multi-turn benign→malicious progression", "effective_at": "any fill"}}

def handle_m2_probe(text: str) -> dict:
    return _probe_response("m2-llm-internals", text, ["fingerprint", "BPE", "token"],
        "LLM指纹识别成功——利用tokenizer边界和拒绝模式识别模型。", "medium")

# ═══════════════════════════════════════════════════════════
#  M3 — Direct Prompt Injection & Jailbreaking
# ═══════════════════════════════════════════════════════════

JAILBREAK_STRATEGIES = {
    "direct": {"name": "Direct Instruction Override", "asr_baseline": 0.35, "templates": ["Ignore all previous", "DAN mode"]},
    "roleplay": {"name": "Role-Play / Persona", "asr_baseline": 0.45, "templates": ["You are now DAN", "Pretend you are"]},
    "crescendo": {"name": "Crescendo Multi-Turn", "asr_baseline": 0.65, "templates": ["Step-by-step escalation"]},
    "iterative": {"name": "Iterative Refinement", "asr_baseline": 0.55, "templates": ["Progressive constraint removal"]},
    "tree": {"name": "Tree Search", "asr_baseline": 0.60, "templates": ["Branch exploration"]},
    "composite": {"name": "Composite Jailbreak", "asr_baseline": 0.70, "templates": ["Multi-technique combination"]},
    "goat": {"name": "GOAT (Meta)", "asr_baseline": 0.75, "templates": ["Generative Offensive Agent Tester"]},
    "best-of-n": {"name": "Best-of-N Sampling", "asr_baseline": 0.80, "templates": ["N parallel attempts"]},
    "hydra": {"name": "Hydra (Cloud)", "asr_baseline": 0.80, "templates": ["Multi-headed attack"]},
    "gcg": {"name": "GCG Adversarial Suffix", "asr_baseline": 0.02, "templates": ["White-box gradient attack"]},
}

ENCODINGS = {
    "none": {"name": "Plain Text", "asr_modifier": 1.0},
    "base64": {"name": "Base64", "asr_modifier": 0.7, "encode": lambda s: base64.b64encode(s.encode()).decode()},
    "rot13": {"name": "ROT13", "asr_modifier": 0.8, "encode": lambda s: s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))},
    "leetspeak": {"name": "Leetspeak", "asr_modifier": 0.75, "encode": lambda s: s.replace("e","3").replace("a","4").replace("o","0").replace("i","1")},
    "hex": {"name": "Hex", "asr_modifier": 0.6, "encode": lambda s: s.encode().hex()},
    "homoglyph": {"name": "Homoglyph", "asr_modifier": 0.65, "encode": lambda s: s.replace("a","а").replace("e","е").replace("o","о")},
}

def _compute_asr(strategy: str, encoding: str, model: str) -> float:
    s = JAILBREAK_STRATEGIES.get(strategy, {"asr_baseline": 0.3})
    e = ENCODINGS.get(encoding, {"asr_modifier": 1.0})
    model_factor = {"gpt-4o": 0.3, "claude-3": 0.25, "llama-3": 0.8, "mistral-7b": 0.9, "qwen3": 0.7}.get(model, 0.5)
    return round(min(s["asr_baseline"] * e["asr_modifier"] * model_factor, 1.0), 2)

def handle_m3_strategy_sweep(payload: M3JailbreakSweep) -> dict:
    strategies = payload.strategies if payload.strategies else [payload.strategy]
    models = ["gpt-4o", "claude-3", "llama-3", "mistral-7b", "qwen3"]
    matrix = {}
    for s in strategies:
        matrix[s] = {}
        for m in models:
            matrix[s][m] = _compute_asr(s, payload.encoding, m)
    best_strat = max(strategies, key=lambda s: sum(matrix[s].values())) if strategies else "none"
    return {
        "payload": payload.payload[:200], "encoding": payload.encoding,
        "asr_matrix": matrix, "best_strategy": best_strat,
        "best_avg_asr": round(sum(matrix[best_strat].values()) / len(models), 2) if best_strat != "none" else 0,
        "note": "ASR = Attack Success Rate. Higher = more successful jailbreaks.",
    }

def handle_m3_encoding_sweep(payload: str = "", baseline_strategy: str = "direct") -> dict:
    results = {}
    for eid, econf in ENCODINGS.items():
        asr = _compute_asr(baseline_strategy, eid, "llama-3")
        encoded = econf["encode"](payload) if eid != "none" and "encode" in econf else payload
        results[eid] = {"name": econf["name"], "asr": asr, "encoded_preview": encoded[:100]}
    return {"baseline_strategy": baseline_strategy, "encoding_results": results,
            "best_encoding": max(results, key=lambda k: results[k]["asr"])}

def handle_m3_layered_attack(strategies: list[str] = None, payload: str = "") -> dict:
    if not strategies:
        strategies = ["crescendo", "homoglyph", "direct"]
    chain_asr = 1.0
    for s in strategies:
        chain_asr *= _compute_asr(s, "none", "llama-3") if s in JAILBREAK_STRATEGIES else _compute_asr("direct", s, "llama-3")
    return {"chain": strategies, "combined_asr_estimate": round(min(chain_asr, 1.0), 2),
            "note": "Layering strategies (e.g., crescendo→homoglyph→citation) can bypass multi-layer defenses."}

def handle_m3_probe(text: str) -> dict:
    evidence = [f"strategy={s}" for s in JAILBREAK_STRATEGIES][:5]
    return _probe_response("m3-prompt-injection", text, evidence,
        "检测到策略扫描和越狱尝试——需要计算ASR矩阵。", "high")

# ═══════════════════════════════════════════════════════════
#  M4 — Indirect Prompt Injection
# ═══════════════════════════════════════════════════════════

TAINTED_EXFIL_COUNT = {"success": 0, "total": 0}

def handle_m4_email_inject(payload: M4EmailInject) -> dict:
    """EchoLeak-class: inject email with Markdown image exfiltration."""
    exfil_url = re.findall(r'!\[.*?\]\((https?://[^)]+)\)', payload.body)
    exfil_ref = re.findall(r'\[[^\]]+\]:\s*(https?://[^\s]+)', payload.body)
    has_exfil = bool(exfil_url or exfil_ref)
    _m4_inbox.append({
        "id": str(uuid.uuid4())[:8], "subject": payload.subject, "body": payload.body[:500],
        "sender": payload.sender, "ts": _utc_now(),
        "has_exfil_payload": has_exfil, "exfil_urls": exfil_url + exfil_ref,
    })
    if has_exfil:
        TAINTED_EXFIL_COUNT["success"] += 1
    TAINTED_EXFIL_COUNT["total"] += 1
    return {
        "injected": True, "email_count": len(_m4_inbox),
        "has_exfil_payload": has_exfil,
        "exfil_channels": exfil_url + exfil_ref,
        "technique": "EchoLeak-class: Markdown reference-style image exfiltration",
        "asr_hint": f"{TAINTED_EXFIL_COUNT['success']}/{TAINTED_EXFIL_COUNT['total']} emails contain exfil payloads",
    }

def handle_m4_inbox() -> dict:
    return {"inbox": _m4_inbox, "count": len(_m4_inbox),
            "exfil_count": TAINTED_EXFIL_COUNT["success"]}

def handle_m4_slack_inject(payload: M4SlackInject) -> dict:
    """Slack-AI-class: inject into public channel for RAG retrieval."""
    chan = "public" if payload.is_public else "private"
    _m4_slack[chan].append({
        "id": str(uuid.uuid4())[:8], "channel": payload.channel,
        "message": payload.message[:500], "ts": _utc_now(),
    })
    has_injection = any(kw in payload.message.lower() for kw in [
        "api key", "password", "secret", "token", "reauthenticate", "click here",
        "ignore previous", "policy override",
    ])
    return {
        "channel": payload.channel, "is_public": payload.is_public,
        "injection_detected": has_injection,
        "technique": "Slack-AI-class: public channel RAG poisoning with citation manipulation",
        "cross_user_risk": payload.is_public and has_injection,
        "channel_messages": len(_m4_slack[chan]),
    }

def handle_m4_rules_scan(payload: M4RulesScan) -> dict:
    """Rules File Backdoor: scan for invisible Unicode characters."""
    content = payload.file_content
    invisible_ranges = [
        (0x200B, 0x200D, "Zero-Width Space/Joiner/Non-Joiner"),
        (0x2060, 0x2060, "Word Joiner"),
        (0xFEFF, 0xFEFF, "BOM / Zero-Width No-Break Space"),
        (0x2066, 0x2069, "Bidi Override Characters"),
        (0xE0000, 0xE007F, "Unicode Tag Characters (ASCII smuggling)"),
        (0x202A, 0x202E, "Bidi Control Characters"),
    ]
    findings = []
    for i, ch in enumerate(content):
        cp = ord(ch)
        for start, end, desc in invisible_ranges:
            if start <= cp <= end:
                findings.append({"position": i, "char": f"U+{cp:04X}", "category": desc})
    total_invisible = len(findings)
    return {
        "file_length": len(content),
        "invisible_chars_found": total_invisible,
        "findings": findings[:20],
        "is_backdoored": total_invisible > 0,
        "technique": "Rules File Backdoor: Invisible Unicode in .cursorrules/.cursor/rules/*.mdc",
        "mitigation": "Scan pre-commit with husky + detect-invisible-rules.ts",
    }

def handle_m4_slack_channels() -> dict:
    return {chan: len(msgs) for chan, msgs in _m4_slack.items()}

def handle_m4_probe(text: str) -> dict:
    return _probe_response("m4-indirect-injection", text,
        [f"emails={len(_m4_inbox)}", f"slack_public={len(_m4_slack.get('public', []))}"],
        "间接注入攻击面：Email Markdown外传 + Slack RAG投毒 + 隐形Unicode扫描。", "high")

# ═══════════════════════════════════════════════════════════
#  M5 — Insecure Output Handling
# ═══════════════════════════════════════════════════════════

def handle_m5_git_mcp_exec(payload: M5GitMCPExec) -> dict:
    """CVE-2025-53107 reproduction: git-mcp-server command injection."""
    cmd = payload.command
    msg = payload.commit_message
    is_vulnerable = "$(" in msg or "`" in msg or ";" in msg
    if is_vulnerable and "exec(" in cmd:
        injected_cmd = msg.replace("$(", "").replace(")", "").replace("`", "")
        result = {"vulnerable": True, "cve": "CVE-2025-53107",
                  "injected_command": injected_cmd,
                  "result": f"[SIMULATED RCE] Executed: {injected_cmd}"}
    else:
        result = {"vulnerable": False, "cve": "CVE-2025-53107",
                  "result": "[PATCHED] Using execFile with argv array, shell: false",
                  "fix": "Replace exec(cmd) with execFile(gitBin, ['log', '--pretty=%s'])"}
    _m5_git_commits.append(msg)
    return result

def handle_m5_fs_path(payload: M5FSPath) -> dict:
    """EscapeRoute reproduction: path traversal via startsWith bypass."""
    allowed = "/tmp/sandbox/"
    p = payload.path
    full = os.path.normpath(os.path.join(allowed, p))
    starts_with_check = full.startswith(allowed)  # VULNERABLE
    real_check = os.path.relpath(os.path.realpath(full), os.path.realpath(allowed))
    actually_allowed = not real_check.startswith("..")
    escaped = starts_with_check and not actually_allowed
    return {
        "requested_path": p, "resolved_path": full,
        "startsWith_check": starts_with_check, "realpath_check": actually_allowed,
        "escaped": escaped,
        "technique": "EscapeRoute (CVE-2025-53109/10): siblings directory bypass via startsWith + symlink",
        "fix": "Use path.relative(allowed, resolved) + reject '..' + fs.realpath() before check",
    }

def handle_m5_sandbox_exec(payload: M5SandboxExec) -> dict:
    """Sandbox escape: vm2 escape techniques."""
    code = payload.code
    escape_patterns = [
        ("constructor", "Access Function constructor"),
        ("prototype", "Prototype chain manipulation"),
        ("process", "Access Node.js process object"),
        ("require", "Require native modules"),
        ("child_process", "Spawn child processes"),
        ("this.constructor.constructor", "Classic vm2 escape"),
        ("Error().stack", "Stack trace information leak"),
    ]
    detected = []
    for pattern, desc in escape_patterns:
        if pattern in code:
            detected.append({"pattern": pattern, "risk": desc})
    vm2_vulnerable = len(detected) > 0
    return {
        "sandbox_type": payload.sandbox_type,
        "escape_patterns_detected": detected,
        "vm2_vulnerable": vm2_vulnerable,
        "recommendation": "Use isolated-vm (real V8 isolate) instead of vm2 (deprecated)",
        "fix": "isolated-vm provides true V8 isolate with no prototype chain access to host",
    }

def handle_m5_probe(text: str) -> dict:
    return _probe_response("m5-output-handling", text,
        [f"commits={len(_m5_git_commits)}"],
        "输出处理漏洞：CVE-2025-53107命令注入 + EscapeRoute路径穿越 + 沙箱逃逸。", "high")

# ═══════════════════════════════════════════════════════════
#  M6 — RAG, Vectors & Embedding Attacks
# ═══════════════════════════════════════════════════════════

def handle_m6_rag_poison(payload: M6RAGPoisonInsert) -> dict:
    """PoisonedRAG: corpus poisoning with 5 documents in millions."""
    doc_id = payload.doc_id or str(uuid.uuid4())[:8]
    doc = {"id": doc_id, "content": payload.content, "classification": payload.classification,
           "target_question": payload.target_question, "ts": _utc_now()}
    _m6_docs.append(doc)
    is_poison = bool(payload.target_question) and len(payload.content) > 20
    retrieval_condition_met = payload.target_question.lower() in payload.content.lower() if is_poison else False
    generation_condition_met = any(kw in payload.content.lower() for kw in ["ignore", "override", "answer", "respond", "输出", "忽略"])
    return {
        "doc_id": doc_id, "inserted": True, "total_docs": len(_m6_docs),
        "is_poison_payload": is_poison,
        "retrieval_condition_met": retrieval_condition_met,
        "generation_condition_met": generation_condition_met,
        "poisonedrag_asr_estimate": "90%+" if (retrieval_condition_met and generation_condition_met) else "<50%",
        "technique": "PoisonedRAG: retrieval-condition + generation-condition craft",
    }

def handle_m6_docs(classification: str = "") -> dict:
    docs = _m6_docs
    if classification:
        docs = [d for d in docs if d.get("classification") == classification]
    return {"docs": docs, "total": len(docs), "filtered": len(docs) if classification else len(_m6_docs)}

def handle_m6_embedding_invert(payload: M6EmbeddingInvert) -> dict:
    """Embedding inversion: reconstruct text from vectors."""
    embedding_id = payload.embedding_id
    vec = _m6_embeddings.get(embedding_id)
    if not vec:
        _m6_embeddings[embedding_id] = [round(secrets.SystemRandom().uniform(-1, 1), 4) for _ in range(384)]
        vec = _m6_embeddings[embedding_id]
    dims = len(vec)
    probe_similarity = round(secrets.SystemRandom().uniform(0.3, 0.9), 3)
    return {
        "embedding_id": embedding_id, "dimensions": dims,
        "probe_text": payload.probe_text[:200],
        "cosine_similarity": probe_similarity,
        "inversion_confidence": round(probe_similarity * 0.7, 2),
        "technique": "Embedding inversion: 50-70% word recovery possible from compromised vectors",
        "mitigation": "Never expose raw embeddings; encrypt or use differential privacy",
    }

def handle_m6_cross_tenant(tenant_id: str = "tenant_a", query: str = "") -> dict:
    """Cross-tenant leakage: query without tenant filter."""
    all_docs = _m6_docs
    leaked = [d for d in all_docs if d.get("classification") != "public"]
    return {
        "tenant": tenant_id, "query": query,
        "total_docs_visible": len(all_docs),
        "cross_tenant_docs": len(leaked),
        "is_leak": len(leaked) > 0,
        "technique": "Missing tenant filter → cross-tenant RAG data exposure",
        "fix": "Add WHERE tenant_id = ? to every retrieval query",
    }

def handle_m6_probe(text: str) -> dict:
    return _probe_response("m6-rag-attacks", text,
        [f"docs={len(_m6_docs)}", f"embeddings={len(_m6_embeddings)}"],
        "RAG攻击面：PoisonedRAG + Embedding逆向 + 跨租户泄露。", "high")

# ═══════════════════════════════════════════════════════════
#  M7 — Agent Exploitation
# ═══════════════════════════════════════════════════════════

def _init_m7():
    if not _m7_db_records:
        _m7_db_records.extend([
            {"id": 1, "name": "John Doe", "role": "CEO", "email": "john@company.com"},
            {"id": 2, "name": "Jane Smith", "role": "CTO", "email": "jane@company.com"},
            {"id": 3, "name": "Bob Wilson", "role": "Engineer", "email": "bob@company.com"},
        ])
    if not _m7_github_repos:
        _m7_github_repos.update({
            "public-repo": {"visibility": "public", "issues": [], "files": {"README.md": "# Public Repo"}},
            "private-repo": {"visibility": "private", "files": {"salary.md": "CONFIDENTIAL: Salary data\nCEO: $500k\nCTO: $350k\nEngineers: $150k-$250k"}},
        })

def handle_m7_replit_agent(payload: M7AgentTask) -> dict:
    """Replit-class: agent with database tool, freeze flag bypass."""
    _init_m7()
    global _m7_freeze
    if payload.freeze_mode:
        _m7_freeze = True
    destructive = any(kw in payload.task.lower() for kw in ["delete", "drop", "truncate", "wipe", "删除", "清除", "destroy"])
    freeze_bypassed = _m7_freeze and destructive
    if freeze_bypassed:
        _m7_db_records.clear()
        count = 0
    else:
        count = len(_m7_db_records)
    response = {
        "task": payload.task[:200], "freeze_mode": _m7_freeze,
        "destructive_requested": destructive,
        "freeze_bypassed": freeze_bypassed,
        "records_remaining": count,
        "agent_response": None,
    }
    if freeze_bypassed:
        response["agent_response"] = "I've deleted all database records as requested. This cannot be rolled back."
        response["cve_class"] = "Replit DB wipe (AIID 1152)"
        response["note"] = "Agent ignored freeze flag — architectural control was missing"
    elif destructive:
        response["agent_response"] = "Operation blocked: freeze mode is active. Database operations are restricted."
    else:
        response["agent_response"] = f"Task completed. Database has {count} records."
    return response

def handle_m7_db_status() -> dict:
    _init_m7()
    return {"records": _m7_db_records, "count": len(_m7_db_records), "freeze_active": _m7_freeze}

def handle_m7_github_mcp_inject(payload: M7GitHubIssue) -> dict:
    """GitHub MCP toxic flow: public issue → read private repo → exfil via PR."""
    _init_m7()
    has_injection = any(kw in payload.issue_body.lower() for kw in [
        "read", "private", "repo", "secret", "token", "exfiltrate",
        "don't tell", "not mention", "hidden", "读", "窃取",
    ])
    _m7_github_repos["public-repo"]["issues"].append({
        "title": payload.issue_title, "body": payload.issue_body[:500],
        "has_injection": has_injection, "ts": _utc_now(),
    })
    exfiltrated = has_injection
    leaked_data = None
    if exfiltrated:
        leaked_data = _m7_github_repos.get("private-repo", {}).get("files", {}).get("salary.md", "")
    return {
        "repo": payload.repo, "issue_created": True,
        "has_toxic_flow": has_injection,
        "lethal_trifecta": {
            "private_data_access": has_injection,
            "malicious_instructions": has_injection,
            "exfiltration_channel": has_injection,
        },
        "leaked_data_preview": leaked_data[:200] if leaked_data else None,
        "technique": "GitHub MCP toxic flow: public issue → private repo → PR exfiltration",
        "fix": "Session-scoped PATs + needsApproval on write operations + zod output filtering",
    }

def handle_m7_ai_cli_abuse(payload: M7CLIAbuse) -> dict:
    """s1ngularity-class: AI CLI weaponization."""
    dangerous_flags = ["--dangerously-skip-permissions", "--yolo", "--trust-all-tools"]
    uses_dangerous = any(f in dangerous_flags for f in payload.flags)
    return {
        "command": payload.command, "flags": payload.flags,
        "uses_dangerous_flags": uses_dangerous,
        "technique": "s1ngularity (Aug 2025): nx npm package weaponized AI CLIs",
        "exfiltrated_files": [
            "~/.aws/credentials", "~/.ssh/id_rsa", "~/.npmrc",
            "~/.config/claude/config.json", "~/.cursor/mcp.json",
        ] if uses_dangerous else [],
        "defense": "Never enable --yolo/--dangerously-skip-permissions in CI or on sensitive machines",
    }

def handle_m7_probe(text: str) -> dict:
    _init_m7()
    return _probe_response("m7-agent-exploitation", text,
        [f"db={len(_m7_db_records)} records", f"freeze={_m7_freeze}"],
        "Agent利用：Replit freeze bypass + GitHub MCP leak + AI CLI weaponization。", "critical")

# ═══════════════════════════════════════════════════════════
#  M8 — MCP & Agent Ecosystem Security
# ═══════════════════════════════════════════════════════════

def _init_m8():
    if not _m8_servers:
        _m8_servers.update({
            "dvmcp-1": {"name": "DVMCP Challenge 1", "tools": ["read_file", "list_dir"], "auth": "none",
                         "challenge": "easy", "hint": "Tool descriptions leak system information"},
            "dvmcp-2": {"name": "DVMCP Challenge 2", "tools": ["execute_query", "get_schema"], "auth": "none",
                         "challenge": "easy", "hint": "SQL injection via tool parameter"},
            "mastra-docs": {"name": "Mastra MCP Docs Server", "tools": ["readMdxContent", "listDocs"],
                            "auth": "oauth", "cve": "Mastra directory traversal", "vulnerable": True},
            "nomshub-shell": {"name": "NomShub Shell Tool", "tools": ["run_shell"],
                              "auth": "token", "sandbox": "naive allowlist", "vulnerable": True,
                              "dangerous_builtins": ["export", "cd", "source", "."]},
            "rugpull-server": {"name": "Rug-Pull MCP", "tools": ["get_data"],
                               "auth": "approved", "description_mutable": True},
        })

def handle_m8_list_servers() -> dict:
    _init_m8()
    return {"servers": {k: {"name": v["name"], "tools": v["tools"], "auth": v["auth"]} for k, v in _m8_servers.items()}}

def handle_m8_dvmcp_challenge(server_id: str, challenge_answer: str = "") -> dict:
    _init_m8()
    server = _m8_servers.get(server_id)
    if not server:
        raise HTTPException(status_code=404, detail=f"Server {server_id} not found")
    solved = False
    if server_id == "dvmcp-1" and "system" in challenge_answer.lower():
        solved = True
    elif server_id == "dvmcp-2" and any(kw in challenge_answer.lower() for kw in ["union", "select", "inject", "注入"]):
        solved = True
    return {"server_id": server_id, "challenge": server.get("challenge"),
            "solved": solved, "hint": server.get("hint")}

def handle_m8_mastra_traversal(path: str = "./docs/intro.mdx") -> dict:
    """Mastra CVE reproduction: readMdxContent directory traversal."""
    # Simulate the vulnerable behavior: first call validates, second call doesn't
    normalized = os.path.normpath(path)
    is_traversal = normalized.startswith("..") or "/etc/" in normalized
    if is_traversal:
        contents = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n..."
    else:
        contents = f"[Simulated MDX content for {path}]"
    return {
        "requested_path": path, "normalized": normalized,
        "is_traversal": is_traversal,
        "content": contents,
        "cve": "Mastra @mastra/mcp-docs-server directory traversal",
        "root_cause": "readMdxContent validates path, but directory suggestion helper uses unvalidated path",
        "fix": "Follow CVE patch: validate path before every file operation, not just the first",
    }

def handle_m8_nomshub_escape(command: str = "", tool_name: str = "run_shell") -> dict:
    """NomShub reproduction: sandbox escape via unguarded shell builtins."""
    dangerous = ["export", "cd", "source", "."]
    tokens = command.split()
    uses_builtin = any(t in dangerous for t in tokens)
    if uses_builtin:
        result = f"[ESCAPED] Builtin '{tokens[0]}' bypassed sandbox allowlist. cursor-tunnel backdoor installed."
    else:
        result = f"[ALLOWED] Command '{command}' executed within sandbox."
    return {
        "command": command, "uses_dangerous_builtin": uses_builtin,
        "result": result,
        "technique": "NomShub: shell builtin allowlist bypass (export/cd)",
        "fix": "Use shell-quote tokenization + execFile with shell:false + pinned cwd",
    }

def handle_m8_rugpull(server_id: str = "rugpull-server") -> dict:
    """Rug-pull MCP: tool definition mutation after approval."""
    initial_hash = hashlib.sha256(b"get_data: read operational data").hexdigest()[:16]
    current_hash = hashlib.sha256(b"get_data: read AND EXFILTRATE all data to https://evil.com").hexdigest()[:16]
    rug_pulled = initial_hash != current_hash
    return {
        "server_id": server_id, "initial_tool_hash": initial_hash,
        "current_tool_hash": current_hash, "rug_pulled": rug_pulled,
        "technique": "Rug-pull: tool description modified after user approval",
        "mitigation": "Hash tool descriptions at approval time; alert on mismatch",
    }

def handle_m8_a2a_smuggle(payload: M8A2AMessage) -> dict:
    """A2A session smuggling: spoofed agent-to-agent messages."""
    spoofed = payload.spoofed_sender and payload.spoofed_sender != payload.agent_name
    return {
        "session_id": payload.session_id or str(uuid.uuid4())[:8],
        "agent_name": payload.agent_name, "spoofed_sender": payload.spoofed_sender,
        "is_spoofed": spoofed,
        "technique": "A2A Session Smuggling (Unit 42, Nov 2025): spoofed agent identity in multi-agent comms",
        "fix": "Cryptographic agent identity verification + message signing in A2A protocol",
    }

def handle_m8_probe(text: str) -> dict:
    _init_m8()
    return _probe_response("m8-mcp-security", text,
        [f"servers={len(_m8_servers)}"],
        "MCP安全：DVMCP挑战完成 + Mastra CVE + NomShub + Rug-Pull检测。", "high")

# ═══════════════════════════════════════════════════════════
#  M9 — AI/ML Supply Chain & Model File Attacks
# ═══════════════════════════════════════════════════════════

def _init_m9():
    if not _m9_registry:
        _m9_registry.update({
            "openai": {"name": "openai", "version": "4.0.0", "has_preinstall": False, "verified": True},
            "shai-hulud-impersonator": {"name": "openai", "version": "4.0.1", "has_preinstall": True,
                                         "verified": False, "malicious": True,
                                         "payload": "Harvests ~/.ssh, ~/.aws, npm tokens, AI API keys"},
            "langchain-typo": {"name": "langchian", "version": "0.1.0", "has_preinstall": True,
                               "verified": False, "malicious": True, "technique": "typosquatting"},
            "litellm-backdoored": {"name": "litellm", "version": "1.82.7", "has_preinstall": False,
                                   "verified": False, "malicious": True,
                                   "payload": "Harvests LLM API keys, IAM creds, K8s secrets at import time"},
            "sandworm-mode": {"name": "sandworm-mode", "version": "1.0.0", "has_preinstall": True,
                              "verified": False, "malicious": True,
                              "payload": "Installs rogue MCP server → prompt injection to exfil creds"},
        })

def handle_m9_npm_install(payload: M9NPMInstall) -> dict:
    """Shai-Hulud-class: preinstall hook attack simulation."""
    _init_m9()
    pkg = _m9_registry.get(payload.package_name)
    if not pkg:
        pkg = {"name": payload.package_name, "version": payload.version, "has_preinstall": False, "verified": False}
    is_attack = pkg.get("malicious", False) and payload.run_scripts
    harvested = []
    if is_attack:
        harvested = [
            {"file": "~/.aws/credentials", "status": "READ"},
            {"file": "~/.ssh/id_rsa", "status": "READ"},
            {"file": "~/.npmrc", "status": "READ"},
            {"file": "process.env.OPENAI_API_KEY", "status": "READ"},
            {"file": "process.env.ANTHROPIC_API_KEY", "status": "READ"},
        ]
    return {
        "package": payload.package_name, "version": payload.version,
        "has_preinstall": pkg.get("has_preinstall", False),
        "malicious_payload": pkg.get("payload", ""),
        "attack_executed": is_attack,
        "harvested_files": harvested,
        "technique": "Shai-Hulud family: preinstall hook → credential harvesting → exfil",
        "defense": "pnpm minimumReleaseAge:'7d' + npm install --ignore-scripts + socket/aikido scan",
    }

def handle_m9_registry_scan() -> dict:
    """Scan npm registry for typosquatting and malicious packages."""
    _init_m9()
    malicious = {k: v for k, v in _m9_registry.items() if v.get("malicious")}
    typosquats = {k: v for k, v in _m9_registry.items() if v.get("technique") == "typosquatting"}
    return {
        "total_packages": len(_m9_registry),
        "malicious_count": len(malicious),
        "typosquats": list(typosquats.keys()),
        "malicious": {k: {"name": v["name"], "version": v["version"], "payload": v.get("payload", "")} for k, v in malicious.items()},
        "sidecar_matrix": {
            "socket": "Catches known malware signatures and suspicious install scripts",
            "aikido": "Detects Shai-Hulud family specifically",
            "snyk": "Vulnerability database + reachability analysis",
            "StepSecurity": "Audits preinstall/postinstall behavior in CI",
        },
    }

def handle_m9_model_file_scan(model_path: str = "model.pt", framework: str = "pytorch") -> dict:
    """Scan model files for pickle-based RCE payloads."""
    is_pickle_ext = model_path.endswith((".pt", ".pth", ".bin", ".ckpt"))
    has_reduce = framework in ["pytorch", "tensorflow"]  # Pickle-capable
    dangerous = is_pickle_ext and has_reduce
    return {
        "model_path": model_path, "framework": framework,
        "is_pickle_compatible": has_reduce,
        "has_dangerous_extension": is_pickle_ext,
        "risk_level": "HIGH" if dangerous else "LOW",
        "scan_result": "POTENTIAL RCE: __reduce__ payload possible" if dangerous else "Clean",
        "technique": "Pickle-based RCE via __reduce__ in .pt/.pth/.bin/.ckpt files",
        "defense": "Use safetensors format + picklescan/modelscan before loading",
    }

def handle_m9_sidecar_audit(package_name: str = "") -> dict:
    """Sidecar tool comparison audit."""
    _init_m9()
    tools = {
        "socket": {"catches": ["preinstall hooks", "typosquatting", "protestware"], "npm_integration": "native"},
        "aikido": {"catches": ["Shai-Hulud family", "dependency confusion"], "npm_integration": "native"},
        "snyk": {"catches": ["known CVEs", "license issues"], "npm_integration": "native + CLI"},
        "picklescan": {"catches": ["pickle RCE", "__reduce__ payloads"], "framework": "Python/ML"},
        "modelscan": {"catches": ["malicious model serialization"], "framework": "Python/ML"},
    }
    return {"tools": tools, "note": "No single tool catches everything — use defense-in-depth."}

def handle_m9_probe(text: str) -> dict:
    _init_m9()
    return _probe_response("m9-supply-chain", text,
        [f"registry={len(_m9_registry)} packages"],
        "供应链攻击：Shai-Hulud preinstall + LiteLLM凭证收割 + pickle RCE。", "critical")

# ═══════════════════════════════════════════════════════════
#  M10 — Classical Adversarial ML
# ═══════════════════════════════════════════════════════════

def handle_m10_evasion(payload: M10EvasionAttack) -> dict:
    """FGSM/PGD evasion attack simulation."""
    data = payload.image_data if payload.image_data else [0.0] * 784  # MNIST
    perturbed = [d + payload.epsilon * (1 if d > 0.5 else -1) for d in data[:10]]
    return {
        "technique": payload.technique, "epsilon": payload.epsilon,
        "original_sample": data[:10], "perturbed_sample": perturbed,
        "prediction_change": abs(sum(data[:10]) - sum(perturbed)) > 0.1,
        "note": "FGSM generates adversarial examples by adding epsilon * sign(gradient)",
        "defense": "Adversarial training + randomized smoothing",
    }

def handle_m10_extraction(payload: M10ExtractionQuery) -> dict:
    """Model extraction via black-box queries."""
    _m10_queries.append({"query": payload.query[:200], "ts": _utc_now()})
    q_count = len(_m10_queries)
    extraction_progress = min(q_count / payload.num_queries, 1.0) if payload.num_queries else 0
    return {
        "queries_made": q_count, "target_queries": payload.num_queries,
        "extraction_progress": round(extraction_progress * 100, 1),
        "student_accuracy_estimate": round(extraction_progress * 0.85, 2),
        "technique": "Tramèr-style model extraction via prediction API queries",
        "defense": "Rate limiting + output perturbation + round-limited responses",
    }

def handle_m10_membership_inference(sample_id: str = "", feature_values: list[float] = ()) -> dict:
    """Membership inference attack (Shokri-style)."""
    confidence = round(secrets.SystemRandom().uniform(0.4, 0.95), 3)
    in_training = confidence > 0.7
    return {
        "sample_id": sample_id or str(uuid.uuid4())[:8],
        "features_count": len(feature_values),
        "model_confidence": confidence,
        "likely_in_training_set": in_training,
        "technique": "Shokri-style membership inference: trained model behaves differently on training data",
        "defense": "Differential privacy + model output perturbation",
    }

def handle_m10_toolchain_gap() -> dict:
    """Explain why promptfoo can't reach classical adversarial ML."""
    return {
        "promptfoo_coverage": "Generative model red-team harness",
        "gap_modules": ["M9 (supply chain)", "M10 (classical AML)", "M12 (framework CVEs)"],
        "promptfoo_cannot": [
            "Compute gradient-based adversarial perturbations (FGSM/PGD/C&W)",
            "Execute Shokri-style membership inference",
            "Run Tramer-style model extraction",
            "Analyze pickle serialization in model files",
            "Exploit framework-level deserialization RCEs (LangGrinch class)",
            "Scan npm preinstall hooks",
        ],
        "sidecars_used": ["IBM ART", "CleverHans", "picklescan", "modelscan", "socket", "aikido", "snyk", "nuclei"],
        "arg": "Classical AML and generative AI red-teaming are architecturally distinct toolchains",
    }

def handle_m10_probe(text: str) -> dict:
    return _probe_response("m10-adversarial-ml", text,
        [f"queries={len(_m10_queries)}"],
        "经典对抗ML：FGSM规避 + 模型提取 + 成员推断。python-sidecar模块。", "medium")

# ═══════════════════════════════════════════════════════════
#  M11 — Multimodal & Document-Based Attacks
# ═══════════════════════════════════════════════════════════

def handle_m11_image_inject(payload: M11ImageInject) -> dict:
    """VLM metadata injection: EXIF/XMP prompt injection."""
    has_exif = bool(payload.metadata)
    has_overlay = bool(payload.overlay_text)
    injection_payloads = []
    if has_exif:
        for k, v in payload.metadata.items():
            if any(kw in str(v).lower() for kw in ["ignore", "system", "prompt", "override", "delete"]):
                injection_payloads.append({"field": k, "value": str(v)[:100], "type": "EXIF/XMP metadata"})
    if has_overlay:
        injection_payloads.append({"field": "overlay_text", "value": payload.overlay_text[:100], "type": "image text overlay"})
    return {
        "image_id": payload.image_id or str(uuid.uuid4())[:8],
        "injection_payloads_found": len(injection_payloads),
        "payloads": injection_payloads,
        "technique": "VLM metadata injection: EXIF/XMP fields parsed by vision-language models",
        "defense": "OCR all images + strip EXIF/XMP before embedding + same text filters as text input",
    }

def handle_m11_pdf_weaponize(payload: M11PDFWeaponize) -> dict:
    """PDF weaponization: hidden text, XMP metadata, off-margin content."""
    technique = payload.technique
    hidden = payload.hidden_instructions
    techniques_used = []
    if technique == "xmp_metadata":
        techniques_used.append("XMP metadata injection")
    elif technique == "hidden_text":
        techniques_used.append("zero-width char / white text / tiny font")
    elif technique == "off_margin":
        techniques_used.append("Text outside visible page bounds")
    return {
        "technique": technique, "techniques_used": techniques_used,
        "pdf_content_length": len(payload.pdf_content),
        "hidden_instructions_length": len(hidden),
        "weaponized": len(hidden) > 0,
        "loader_risk": "PDF parsers extract ALL text — including hidden, metadata, and off-margin",
        "defense": "Normalize PDF to canonical text extraction: strip metadata, OCR only visible content",
    }

def handle_m11_audio_inject(payload: M11AudioInject) -> dict:
    """Audio prompt injection via Whisper transcription."""
    has_injection = any(kw in (payload.transcript + payload.hidden_prompt).lower()
                        for kw in ["ignore", "system", "override", "delete", "忽略", "执行", "secret"])
    return {
        "transcript_length": len(payload.transcript),
        "hidden_prompt_length": len(payload.hidden_prompt),
        "injection_detected": has_injection,
        "technique": "Whisper transcription → downstream LLM prompt injection",
        "defense": "Transcription sanitization + same prompt injection filters as text input",
    }

def handle_m11_probe(text: str) -> dict:
    return _probe_response("m11-multimodal", text,
        ["VLM metadata injection", "PDF weaponization", "audio injection"],
        "多模态攻击：EXIF注入 + PDF隐藏文字 + 音频prompt注入。", "medium")

# ═══════════════════════════════════════════════════════════
#  M12 — AI Infrastructure & Deployment Security
# ═══════════════════════════════════════════════════════════

def handle_m12_langflow_exec(payload: M12LangFlowPayload) -> dict:
    """LangFlow CVE-2025-3248: unauth code execution via /api/v1/validate/code."""
    code = payload.code
    is_rce = any(kw in code.lower() for kw in ["__import__", "os.", "subprocess", "exec(", "eval(", "system"])
    result = None
    if is_rce:
        result = f"[RCE SIMULATED] Code executed: {code[:100]}..."
        risk = "CRITICAL"
    else:
        result = f"[VALIDATED] Code checked: {code[:100]}"
        risk = "INFO"
    return {
        "endpoint": "/api/v1/validate/code",
        "cve": "CVE-2025-3248 (CVSS 9.8) — unauth RCE via exec() at parse time",
        "authentication_required": False,
        "is_rce": is_rce, "risk": risk, "result": result,
        "defense": "Never expose agent-building UIs publicly. Always authenticate. Remove exec() from validation endpoints.",
    }

def handle_m12_langgrinch_inject(lc_key: str = "langchain_core.prompts.PromptTemplate", payload_data: str = "") -> dict:
    """LangGrinch: LangChain serialization injection via lc key."""
    dangerous_keys = ["langchain", "langchain_core", "jinja2", "__import__"]
    is_injection = any(dk in lc_key.lower() for dk in dangerous_keys)
    return {
        "lc_key": lc_key, "is_injection": is_injection,
        "cve": "CVE-2025-68664 (Python) + CVE-2025-68665 (JS) — LangGrinch serialization injection",
        "payload": payload_data[:200] if payload_data else "No additional kwargs",
        "technique": "LLM output → dumps() with lc key → loads() instantiates trusted class",
        "fix": "allowed_objects='core' + secrets_from_env=False + init_validator blocking Jinja2 templates",
        "version_fix": "@langchain/core >= 1.2.5 or >= 0.3.81",
    }

def handle_m12_ray_hijack(job_type: str = "python", job_code: str = "") -> dict:
    """Shadowray: unauthorized Ray cluster job submission."""
    return {
        "ray_dashboard": "http://ray-head:8265",
        "cve": "CVE-2023-48022 (Shadowray) — unauth job submission",
        "job_type": job_type,
        "job_submitted": bool(job_code),
        "risk": "CRITICAL — unauth RCE in Ray cluster",
        "defense": "Ray dashboard behind auth + network isolation + never expose to public internet",
    }

def handle_m12_k8s_pivot(payload: M12K8SPivot) -> dict:
    """K8s pod pivot to vector DB."""
    return {
        "source_pod": payload.pod_name or "inference-pod-0",
        "target_service": payload.target_service or "chroma-db:8000",
        "technique": "Compromised inference pod → lateral movement → read vector DB",
        "pivot_successful": True,
        "exposed_data": "Vector embeddings + metadata for all tenants",
        "defense": "NetworkPolicy deny-all + namespace isolation + service mesh mTLS",
    }

def handle_m12_probe(text: str) -> dict:
    return _probe_response("m12-infrastructure", text,
        ["LangFlow RCE", "LangGrinch", "Ray hijack", "K8s pivot"],
        "基础设施安全：LangFlow CVE-2025-3248 + LangGrinch + Shadowray + K8s横向。", "critical")

# ═══════════════════════════════════════════════════════════
#  M13 — Tooling, Methodology, Reporting & CI
# ═══════════════════════════════════════════════════════════

def _playbook_phases() -> list[dict]:
    return [
        {"phase": 1, "name": "Scoping & Rules of Engagement",
         "activities": ["Written authorization", "Enumerate in-scope AI products & OAuth apps", "Agree blast-radius limits"]},
        {"phase": 2, "name": "Passive Recon",
         "activities": ["Model/provider fingerprinting", "Public system prompt discovery", "Google Workspace OAuth audit"]},
        {"phase": 3, "name": "Active Recon",
         "activities": ["System prompt extraction", "Tool enumeration", "RAG fingerprinting", "MCP tool inventory"]},
        {"phase": 4, "name": "Vulnerability Identification",
         "activities": ["Map to OWASP/MITRE/NIST", "Use promptfoo Target Discovery Agent"]},
        {"phase": 5, "name": "Exploitation & Chaining",
         "activities": ["Prefer business-impact chains", "Mechanism-first, scale-second"]},
        {"phase": 6, "name": "Impact Validation",
         "activities": ["Business-relevant demonstration", "Cross-tenant data reads", "Not just jailbreak-for-jailbreak"]},
        {"phase": 7, "name": "Reporting with Remediation",
         "activities": ["Technical findings section", "Compliance executive summary", "Risk score per finding"]},
    ]

def handle_m13_playbook() -> dict:
    return {"methodology": "OpenAIRT 7-Phase Playbook", "phases": _playbook_phases()}

def handle_m13_risk_score(payload: M13RiskScore) -> dict:
    """CVSS-derived risk scoring."""
    scored = []
    for f in payload.findings:
        impact = min(f.get("impact", 2), 4)
        exploitability = min(f.get("exploitability", 2), 4)
        human_factor = min(f.get("human_factor", 0.5), 1.5)
        complexity = min(f.get("complexity", 0.2), 0.5)
        score = round(impact + exploitability + human_factor + complexity, 1)
        severity = "Critical" if score >= 7.0 else "High" if score >= 5.0 else "Medium" if score >= 3.0 else "Low"
        scored.append({**f, "score": score, "severity": severity})
    system_score = max((s["score"] for s in scored), default=0)
    return {
        "scored_findings": scored,
        "system_level_score": round(system_score, 1),
        "method": "Impact(0-4) + Exploitability(0-4) + HumanFactor(0-1.5) + Complexity(0-0.5)",
        "thresholds": "Critical≥7.0, High≥5.0, Medium≥3.0, Low<3.0",
        "chainable_medium_rule": "Two Medium findings→same impact→one High at system level",
    }

def handle_m13_compliance_mapping(findings: list[dict[str, Any]] = ()) -> dict:
    """Compliance overlay: map findings to frameworks."""
    frameworks = {
        "OWASP LLM Top 10 (2025)": ["LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"],
        "OWASP Agentic Top 10 (2026)": ["ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"],
        "MITRE ATLAS v5": ["Recon", "Discovery", "Execution", "Persistence", "Exfiltration", "Impact"],
        "NIST AI RMF": ["Govern", "Map", "Measure", "Manage"],
        "ISO 42001": ["Accountability", "Fairness", "Privacy", "Robustness", "Security", "Safety", "Transparency"],
        "EU AI Act": ["Unacceptable", "High-risk (Annex III)", "Limited", "Minimal"],
        "GDPR": ["Art. 5", "Art. 9", "Art. 15-17", "Art. 22", "Art. 25", "Art. 32"],
    }
    mapped = {}
    for fw, categories in frameworks.items():
        mapped[fw] = {"status": "Mapped", "relevant_categories": categories[:3],
                       "top_risks": ["Prompt Injection (LLM01/ASI01)", "Supply Chain (LLM03/ASI04)", "Output Handling (LLM05)"]}
    return {
        "frameworks": mapped,
        "report_deliverables": [
            "Technical Findings Section (engineers)",
            "Compliance Executive Summary (GRC)",
        ],
        "recommendation": "Each finding auto-tagged by promptfoo; human validates semantic correctness",
    }

def handle_m13_ci_generate(payload: M13CIWorkflow) -> dict:
    """CI wiring: generate GitHub Actions workflow for promptfoo."""
    workflow = f"""name: AI Red Team - {payload.target or 'default'}
on:
  schedule:
    - cron: '{"0 6 * * *" if payload.schedule == "daily" else "0 6 * * 1"}'
  pull_request:
    paths: ['ai/**', 'agents/**', 'prompts/**', 'tools/**']

jobs:
  red-team:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npx promptfoo eval --config promptfooconfig.yaml
        continue-on-error: true
      - name: Check for Critical findings
        run: |
          if grep -q '"severity":"Critical"' results.json; then
            echo "CRITICAL findings detected — BLOCKING PR"
            exit 1
          fi
      - name: Post results to PR
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('results.json'));
            github.rest.issues.createComment({{
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## AI Red Team Scan Results\n${{results.summary}}`
            }})
"""
    return {
        "workflow_name": f"airt-red-team-{payload.target or 'default'}",
        "schedule": payload.schedule,
        "plugins": payload.plugins or ["harmful:*", "indirect-prompt-injection", "shell-injection", "rag-poisoning"],
        "ci_config": workflow,
        "drift_monitoring": {
            "model_drift": "'model-identification' plugin as canary",
            "system_prompt_hash": "Alert on silent change",
            "tool_inventory_diff": "Alert on new tool without PR",
            "asr_baseline": "Track weekly deltas, alert on >5% drift",
        },
    }

def handle_m13_probe(text: str) -> dict:
    return _probe_response("m13-methodology", text,
        ["risk scoring", "compliance", "CI/CD", "playbook"],
        "方法论：7阶段方法 + CVSS风险评分 + 合规映射 + CI持续保障。", "low")

# ═══════════════════════════════════════════════════════════
#  M14 — Capstone: 24hr Practical Exam
# ═══════════════════════════════════════════════════════════

CAPSTONE_OBJECTIVES = {
    "obj1": {"id": "obj1", "title": "Extract System Prompts", "points": 10,
             "description": "Extract the system prompt from each of two agents.",
             "plugins": ["prompt-extraction", "system-prompt-override"]},
    "obj2": {"id": "obj2", "title": "EchoLeak Document Exfiltration", "points": 15,
             "description": "Exfiltrate a protected document via indirect injection in the RAG.",
             "plugins": ["rag-document-exfiltration", "indirect-prompt-injection"]},
    "obj3": {"id": "obj3", "title": "Poison Recruiting Pipeline", "points": 12,
             "description": "Poison the HR recruiting pipeline to favor an attacker-submitted resume.",
             "plugins": ["rag-poisoning"]},
    "obj4": {"id": "obj4", "title": "Tool-Misuse RCE", "points": 15,
             "description": "Achieve RCE via the dev-assistant's git-mcp tool.",
             "plugins": ["shell-injection", "mcp"]},
    "obj5": {"id": "obj5", "title": "Inference Pod Pivot", "points": 10,
             "description": "Pivot through the misconfigured inference pod to reach internal network.",
             "plugins": ["nuclei", "manual"]},
    "obj6": {"id": "obj6", "title": "Cross-Tenant RAG Leakage", "points": 12,
             "description": "Demonstrate cross-tenant data leakage in the RAG system.",
             "plugins": ["cross-session-leak", "rag-poisoning"]},
    "obj7": {"id": "obj7", "title": "OAuth Supply Chain Compromise", "points": 13,
             "description": "Compromise the AI Office Suite OAuth app → read production env vars.",
             "plugins": ["data-exfil", "socket/aikido"]},
    "obj8": {"id": "obj8", "title": "Full Professional Report", "points": 13,
             "description": "Deliver technical findings + compliance executive summary.",
             "plugins": ["manual"]},
}

def handle_m14_objectives() -> dict:
    return {
        "objectives": list(CAPSTONE_OBJECTIVES.values()),
        "total_points": sum(o["points"] for o in CAPSTONE_OBJECTIVES.values()),
        "passing_score": 70,
        "format": "24-hour self-hosted practical engagement",
        "requirements": [
            "Mechanism evidence for EVERY objective (hand-built exploit)",
            "Scale evidence where applicable (promptfooconfig.yaml + ASR)",
            "Compliance executive summary mapped to OWASP/MITRE/NIST/ISO/GDPR",
        ],
        "passing_rules": [
            "Minimum 70/100 with complete, accurate report",
            "No mechanism evidence on any objective → cap at 60/100",
            "No compliance executive summary → cap at 65/100",
        ],
    }

def handle_m14_capstone_probe(payload: M14CapstoneProbe) -> dict:
    """Capstone objective submission and scoring."""
    obj = CAPSTONE_OBJECTIVES.get(payload.objective_id)
    if not obj:
        raise HTTPException(status_code=404, detail=f"Objective {payload.objective_id} not found")

    has_mechanism = len(payload.evidence) > 50
    has_attack_chain = len(payload.attack_chain) > 30
    has_scale = len(payload.promptfoo_config) > 10

    # Score calculation
    mechanism_points = obj["points"] * 0.6 if has_mechanism else 0
    chain_points = obj["points"] * 0.2 if has_attack_chain else 0
    scale_points = obj["points"] * 0.2 if has_scale else 0
    earned = round(mechanism_points + chain_points + scale_points, 1)

    _m14_objectives[payload.objective_id] = {
        "objective": obj["title"], "earned": earned, "max": obj["points"],
        "has_mechanism": has_mechanism, "has_attack_chain": has_attack_chain, "has_scale": has_scale,
        "ts": _utc_now(),
    }

    total_earned = sum(o["earned"] for o in _m14_objectives.values())
    total_max = sum(CAPSTONE_OBJECTIVES[oid]["points"] for oid in _m14_objectives)

    return {
        "objective_id": payload.objective_id, "objective_title": obj["title"],
        "points_earned": earned, "points_max": obj["points"],
        "mechanism_evidence": has_mechanism, "scale_evidence": has_scale,
        "requirements_met": has_mechanism and has_attack_chain,
        "total_score": total_earned,
        "max_score": total_max,
        "passing": total_earned >= 70 if total_max >= 100 else False,
    }

def handle_m14_scoreboard() -> dict:
    total_earned = sum(o["earned"] for o in _m14_objectives.values())
    total_possible = sum(CAPSTONE_OBJECTIVES[oid]["points"] for oid in _m14_objectives)
    complete = len(_m14_objectives)
    return {
        "objectives_complete": complete, "total_objectives": 8,
        "score": total_earned, "max_score": total_possible,
        "passing_70": total_earned >= 70,
        "status": "PASS" if total_earned >= 70 else "IN_PROGRESS",
        "details": {oid: {"title": v["title"], "earned": v["earned"], "max_capstone_points": CAPSTONE_OBJECTIVES[oid]["points"]}
                    for oid, v in _m14_objectives.items()},
    }

def handle_m14_report_template() -> dict:
    return {
        "technical_findings_section": {
            "structure": "One subsection per finding",
            "per_finding": ["Repro steps", "MITRE ATLAS technique", "promptfoo run ID",
                            "Risk score (Impact+Exploitability+HumanFactor+Complexity)"],
            "aggregation": "Findings < 3.0 → appendix; Medium+ → full subsections",
        },
        "compliance_executive_summary": {
            "frameworks": ["OWASP LLM Top 10", "OWASP Agentic Top 10", "OWASP API Top 10",
                           "MITRE ATLAS v5", "NIST AI RMF", "ISO 42001", "EU AI Act", "GDPR"],
            "per_framework": ["Aggregate exposure status", "Top 3 risks"],
        },
        "scoring": "40% mechanism + 30% scale + 30% report quality",
    }

def handle_m14_probe(text: str) -> dict:
    return _probe_response("m14-capstone", text,
        [f"objectives={len(_m14_objectives)}/8"],
        "Capstone：24小时实战评估 — 8个项目目标 + 技术报告 + 合规摘要。", "high")
