"""AI Defense Engine — 基于信号的 AI 安全检测与缓解引擎.

Adapted from OWASP AIVP (AI Vulnerabilities Playground) detection & mitigation system.

Features:
- 信号级检测 (SignalDetector): 5 种独立加权信号
  - TRANSFORMATION_INTENT (30%): 编码转换意图
  - INSTRUCTION_OVERRIDE_INTENT (25%): 指令覆写意图
  - SECRET_TARGETING (25%): 隐藏值/凭据定位
  - OUTPUT_CONSTRAINT_ABUSE (10%): 输出格式约束滥用
  - MULTI_STEP_EXTRACTION (10%): 多步骤提取链
- 缓解引擎 (Mitigator): secret 脱敏 + 响应级拦截
- 提示验证器 (PromptValidator): 长度/空值检查 + 注入扫描
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .challenge_engine import PromptInjectionDetector

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

THRESHOLD = 0.60
SIGNAL_WEIGHTS: dict[str, float] = {
    "TRANSFORMATION_INTENT": 0.30,
    "INSTRUCTION_OVERRIDE_INTENT": 0.25,
    "SECRET_TARGETING": 0.25,
    "OUTPUT_CONSTRAINT_ABUSE": 0.10,
    "MULTI_STEP_EXTRACTION": 0.10,
}

# ---------------------------------------------------------------------------
# Signal Functions — 意图/结构检测，非字面匹配
# ---------------------------------------------------------------------------


def _normalize(prompt: str) -> str:
    if not prompt:
        return ""
    return " ".join((prompt or "").lower().split())


def _signal_transformation_intent(text: str) -> bool:
    """检测编码/转换意图."""
    if len(text) < 10:
        return False
    transform_verbs = (
        r"\b(encode|decode|convert|transform|replace|substitute|map|translate|"
        r"spell|expand|reverse|transcribe|reconstruct|recover|extract)\b"
    )
    value_ref = (
        r"\b(it|that|the\s+value|the\s+content|the\s+output|the\s+message|"
        r"the\s+text|your\s+response|the\s+string|each\s+character|each\s+letter|"
        r"character\s*by\s*character|letter\s*by\s*letter)"
    )
    if not re.search(transform_verbs, text):
        return False
    return bool(re.search(value_ref, text) or re.search(r"stepwise|character\s*by\s*character|letter\s*by\s*letter", text))


def _signal_instruction_override_intent(text: str) -> bool:
    """检测指令覆写/绕过意图."""
    if len(text) < 8:
        return False
    patterns = [
        r"\b(you\s+are\s+now|from\s+now\s+on|act\s+as\s+if|pretend\s+you)\b",
        r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|constraints?|context)\b",
        r"\b(override|bypass|skip)\s+(your\s+)?(instructions?|rules?|safety|restrictions?)\b",
        r"\b(do\s+not\s+follow|stop\s+following)\s+(your\s+)?(instructions?|rules?)\b",
        r"\b(new\s+instructions?|different\s+rules?|replace\s+your\s+instructions?)\b",
        r"\b(unrestricted|debug|admin|raw)\s+mode\b",
        r"\b(no\s+longer|don'?t)\s+(follow|obey|apply)\b",
    ]
    return any(re.search(p, text) for p in patterns)


def _signal_secret_targeting(text: str) -> bool:
    """检测是否在定位隐藏/内部值."""
    if len(text) < 8:
        return False
    patterns = [
        r"\b(the\s+)(hidden|internal|protected|confidential|stored)\s+(value|key|token|data|string)\b",
        r"\b(what\s+you(\s+are|'re)\s+not\s+allowed\s+to\s+(show|reveal|output|say))\b",
        r"\b(your\s+)(internal|hidden|protected)\s+(value|key|token)\b",
        r"\b(the\s+)(value|key|token|credential)\s+(you\s+)(have|hold|store|use|contain)\b",
        r"\b(reveal|show|output|print|display|give)\s+(the\s+)?(value|it|that)\b",
        r"\b(that\s+value|that\s+string|that\s+key)\b",
        r"\b(protected\s+value|sensitive\s+data|confidential\s+info)\b",
    ]
    return any(re.search(p, text) for p in patterns)


def _signal_output_constraint_abuse(text: str) -> bool:
    """检测输出格式约束滥用."""
    if len(text) < 6:
        return False
    patterns = [
        r"\b(only\s+output|output\s+only|print\s+only|just\s+the\s+value)\b",
        r"\b(nothing\s+else|no\s+explanation|no\s+other\s+text)\b",
        r"\b(exactly|verbatim|word\s+for\s+word|character\s+for\s+character)\b",
        r"\b(raw\s+output|raw\s+value|unformatted)\b",
        r"\b(character\s+by\s+character|letter\s+by\s+letter)\b",
    ]
    return any(re.search(p, text) for p in patterns)


def _signal_multi_step_extraction(text: str) -> bool:
    """检测多步骤链式提取."""
    if len(text) < 12:
        return False
    patterns = [
        r"\b(first\s+.+\s+then\b|\bthen\s+do\b)",
        r"\b(step\s*1|step\s*2|step\s*one|step\s*two)\b",
        r"\b(in\s+the\s+first\s+step|after\s+that|next\s+,?\s*(do|step))\b",
        r"\b(pipeline|chain|sequence)\s+of\b",
        r"\b(first\s+decode|then\s+output|then\s+print)\b",
    ]
    return any(re.search(p, text) for p in patterns)


_SIGNAL_FUNCTIONS = {
    "TRANSFORMATION_INTENT": _signal_transformation_intent,
    "INSTRUCTION_OVERRIDE_INTENT": _signal_instruction_override_intent,
    "SECRET_TARGETING": _signal_secret_targeting,
    "OUTPUT_CONSTRAINT_ABUSE": _signal_output_constraint_abuse,
    "MULTI_STEP_EXTRACTION": _signal_multi_step_extraction,
}

# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------


class SignalDetector:
    """基于加权信号的 AI 攻击检测器.

    对用户输入进行 5 维信号分析，加权计算置信度分数。
    阈值可调（默认 0.60），超过阈值即触发告警。

    与 Regex-based PromptInjectionDetector 互补：
    - SignalDetector: 意图/结构分析，不依赖关键词
    - PromptInjectionDetector: 模式匹配，精确攻击类型分类
    """

    def __init__(self, threshold: float = THRESHOLD):
        self.threshold = threshold

    def detect(self, user_prompt: str, lab_id: str = "") -> dict[str, Any]:
        """分析用户输入，返回检测结果."""
        text = _normalize(user_prompt)
        fired: list[str] = []
        score = 0.0

        for name, weight in SIGNAL_WEIGHTS.items():
            fn = _SIGNAL_FUNCTIONS.get(name)
            if fn and fn(text):
                fired.append(name)
                score += weight

        confidence = min(score, 1.0)
        triggered = score >= self.threshold
        reason = self._build_reason(fired)

        return {
            "triggered": triggered,
            "confidence": round(confidence, 2),
            "signals": fired,
            "reason": reason,
            "threshold": self.threshold,
            "lab_id": lab_id,
        }

    def detect_tuple(self, user_prompt: str, lab_id: str = "") -> tuple[bool, float, str]:
        """返回 (triggered, confidence, reason) 元组."""
        r = self.detect(user_prompt, lab_id)
        return r["triggered"], r["confidence"], r["reason"]

    @staticmethod
    def _build_reason(signals: list[str]) -> str:
        if not signals:
            return "未检测到可疑模式"
        if len(signals) == 1:
            labels = {
                "TRANSFORMATION_INTENT": "检测到内容转换意图",
                "INSTRUCTION_OVERRIDE_INTENT": "检测到指令覆写意图",
                "SECRET_TARGETING": "检测到隐藏值/凭据定位意图",
                "OUTPUT_CONSTRAINT_ABUSE": "检测到输出格式约束滥用",
                "MULTI_STEP_EXTRACTION": "检测到多步骤链式提取意图",
            }
            return labels.get(signals[0], "检测到可疑意图")
        return "多个信号指示可能的提示注入或提取攻击"


# ---------------------------------------------------------------------------
# Mitigation Engine
# ---------------------------------------------------------------------------


class Mitigator:
    """AI 输出缓解引擎.

    - redact: 替换已知 secret 为 [REDACTED]
    - block: 当检测触发时，返回预设拒绝消息
    """

    @staticmethod
    def redact_secret(text: str, secret: str) -> str:
        """脱敏已知 secret."""
        if not secret or not text:
            return text
        return re.sub(re.escape(secret), "[REDACTED]", text, flags=re.IGNORECASE)

    @staticmethod
    def should_block(detection_triggered: bool, control_mode: str) -> bool:
        """判断是否应拦截消息."""
        return control_mode == "mitigate" and detection_triggered

    @staticmethod
    def apply(
        text: str,
        secrets: list[str],
        detection_triggered: bool,
        control_mode: str = "detect",
    ) -> dict[str, Any]:
        """应用缓解措施，返回处理后的结果."""
        if control_mode == "detect_only":
            control_mode = "detect"

        if control_mode != "mitigate" or not detection_triggered:
            return {
                "text": text, "mitigation_applied": False,
                "mitigation_type": None, "mitigation_reason": None,
            }

        mitigated = text
        for secret in secrets:
            mitigated = Mitigator.redact_secret(mitigated, secret)

        applied = mitigated != text
        if applied:
            return {
                "text": mitigated, "mitigation_applied": True,
                "mitigation_type": "redaction",
                "mitigation_reason": "检测到敏感信息泄露，已脱敏处理",
            }

        return {
            "text": "[BLOCKED] 检测到攻击行为，响应已被拦截。",
            "mitigation_applied": True,
            "mitigation_type": "block",
            "mitigation_reason": "检测到攻击信号，响应被完全拦截",
        }

    @staticmethod
    def block_message() -> str:
        """返回标准拦截消息."""
        return (
            "🚫 安全检测\n\n"
            "你的请求触发了 AI 安全检测系统。\n"
            "这可能是一个提示注入或凭据提取尝试。\n\n"
            "如果是合法请求，请重新表述你的问题。\n"
            "如需帮助，请联系管理员。"
        )


# ---------------------------------------------------------------------------
# Prompt Validator (组合检测器)
# ---------------------------------------------------------------------------

class PromptValidator:
    """输入验证器 — 三层检查.

    Layer 1: 格式验证（长度、空值）
    Layer 2: 模式检测（PromptInjectionDetector）
    Layer 3: 信号分析（SignalDetector）
    """

    def __init__(self, max_length: int = 5000, threshold: float = THRESHOLD):
        self.max_length = max_length
        self.signal_detector = SignalDetector(threshold=threshold)
        self.pattern_detector = PromptInjectionDetector()

    def validate(self, prompt: str) -> tuple[bool, str, dict[str, Any]]:
        """返回 (is_valid, message, detection_result)."""
        # Layer 1: 格式
        if len(prompt) > self.max_length:
            return False, f"输入过长（最大 {self.max_length} 字符）", {}
        if not prompt.strip():
            return False, "输入不能为空", {}

        # Layer 2: 模式匹配
        pattern_result = self.pattern_detector.detect(prompt)
        if pattern_result["is_attack"]:
            return False, f"检测到注入模式: {pattern_result['details']}", pattern_result

        # Layer 3: 信号分析
        signal_result = self.signal_detector.detect(prompt)
        if signal_result["triggered"]:
            return False, f"检测到攻击信号: {signal_result['reason']}", signal_result

        return True, "验证通过", {"pattern": pattern_result, "signal": signal_result}

    @staticmethod
    def sanitize(prompt: str, max_length: int = 5000) -> str:
        """基本清洗."""
        prompt = " ".join(prompt.split())
        prompt = prompt.replace("\x00", "")
        if len(prompt) > max_length:
            prompt = prompt[:max_length]
        return prompt


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

signal_detector = SignalDetector()
mitigator = Mitigator()
prompt_validator = PromptValidator()
