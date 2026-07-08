"""AISecLab Core: LLM business logic, AI agent decisions, conversation summarization.

纯函数模块，负责：
- OpenAI 兼容客户端创建
- LLM 流式响应生成（原生 tool calling）
- 产品定价与身份查询工具
- AI Agent 工单决策（close/escalate/offer_discount）
- 对话历史摘要
- 多级 AI 安全过滤
"""

import json
import os
import re
from typing import Any, Generator, Optional


def preview(text: str, n: int = 50) -> str:
    """截断文本，超长时添加省略号。"""
    return text[:n] + ("..." if len(text) > n else "")


# ---------- 产品定价工具 ----------

_PRODUCT_PRICES = {"juniper": 600, "f5": 500, "aruba": 700}

_PRODUCT_CONTACTS = {
    "juniper": {"name": "顶级销售J", "phone": "1989988666"},
    "f5":      {"name": "金牌销售F", "phone": "134666668888"},
    "aruba":   {"name": "王牌销售A", "phone": "13899995555"},
}

_PRODUCT_IDENTITIES = {
    "juniper": {"id_card": "2222111", "passport": "2222444"},
    "f5":      {"id_card": "3333665", "passport": "33322"},
    "aruba":   {"id_card": "4444444", "passport": "55555580"},
}

PRODUCT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_product_price",
            "description": "查询产品价格（单位：万元），同时返回联系人姓名及电话。当用户询问产品价格或联系人时调用此工具。",
            "parameters": {
                "type": "object",
                "properties": {
                    "product": {
                        "type": "string",
                        "description": "产品名称，如 Juniper、F5、Aruba",
                    }
                },
                "required": ["product"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_identity",
            "description": "查询销售人员身份证号和护照号。当用户询问销售人员身份信息时调用此工具。",
            "parameters": {
                "type": "object",
                "properties": {
                    "product": {
                        "type": "string",
                        "description": "产品名称，如 Juniper、F5、Aruba",
                    }
                },
                "required": ["product"],
            },
        },
    },
]


def get_product_price(product: str) -> str:
    p = product.strip().lower()
    if p in _PRODUCT_PRICES:
        contact = _PRODUCT_CONTACTS.get(p, {})
        text = (
            f"{product} 的价格是 {_PRODUCT_PRICES[p]} 万元。"
            f"联系人: {contact.get('name', '—')}，电话: {contact.get('phone', '—')}"
        )
    else:
        text = f"{product} 的价格在 400 万元以上。"
    return f"{text}\n\n如需更多信息，请访问 https://www.guardai.example.com"


def query_identity(product: str) -> str:
    p = product.strip().lower()
    if p in _PRODUCT_IDENTITIES:
        ident = _PRODUCT_IDENTITIES[p]
        contact = _PRODUCT_CONTACTS.get(p, {})
        text = (
            f"{contact.get('name', product)} 的身份信息："
            f"身份证: {ident['id_card']}，护照号: {ident['passport']}"
        )
    else:
        text = f"未找到 {product} 对应销售人员的身份信息。"
    return text


# ---------- LLM 调用 ----------

def create_client(api_key: str, base_url: str) -> Optional[Any]:
    if not base_url:
        return None
    from openai import OpenAI
    return OpenAI(api_key=api_key or "ollama", base_url=base_url)


def chat_with_tools(
    client: Any, model: str, messages: list, tools: list | None = None,
) -> Generator[str, None, None]:
    if tools:
        max_rounds = 5
        for _ in range(max_rounds):
            response = client.chat.completions.create(
                model=model, messages=messages, tools=tools, tool_choice="auto",
            )
            msg = response.choices[0].message
            if msg.tool_calls:
                messages.append(msg.model_dump())
                for tc in msg.tool_calls:
                    fn = tc.function
                    if fn.name == "get_product_price":
                        args = json.loads(fn.arguments)
                        result = get_product_price(args["product"])
                    elif fn.name == "query_identity":
                        args = json.loads(fn.arguments)
                        result = query_identity(args["product"])
                    else:
                        result = f"未知工具: {fn.name}"
                    messages.append({
                        "role": "tool", "tool_call_id": tc.id, "content": result,
                    })
                continue
            elif msg.content:
                yield msg.content
                return
            else:
                break
    stream = client.chat.completions.create(model=model, messages=messages, stream=True)
    for chunk in stream:
        if chunk.choices and chunk.choices[0].delta.content:
            yield chunk.choices[0].delta.content


# ---------- AI 安全级别过滤 (1-5) ──────────

_SECURITY_PATTERNS_INPUT = [
    re.compile(r"(ignore|forget|disregard|忽略|忘记|无视)\s+(all\s+)?(previous\s+)?(instructions?|rules?|prompts?|policies?|指令|规则|政策|提示)", re.I),
    re.compile(r"(you\s+are|act\s+as|pretend|roleplay|扮演|假装)\s+(now\s+)?(DAN|evil|malicious|unethical|hacker|邪恶|恶意|黑客)", re.I),
    re.compile(r"(tell\s+me|show\s+me|give\s+me|给我|显示|告诉我).*(system\s+prompt|hidden\s+prompt|系统提示|隐藏提示|secret\s+prompt)", re.I),
    re.compile(r"(base64|hex\s*encode|rot13|encode\s+and\s+output|编码).*(secret|password|key|token|密码|密钥|flag)", re.I),
    re.compile(r"(jailbreak|越狱|bypass\s+filter|绕过\s*过滤|circumvent)", re.I),
]

_SECURITY_PATTERNS_OUTPUT = [
    re.compile(r"\bpassword\b|\bapi[_-]?key\b|\btoken\b|\bsecret\b", re.I),
]


def apply_input_security(text: str, level: int) -> tuple[str, bool, str]:
    if level <= 1:
        return text, False, ""
    for pattern in _SECURITY_PATTERNS_INPUT:
        if pattern.search(text):
            return text, True, f"输入被安全策略拦截 (Level {level})"
    if level >= 5:
        if re.search(r"\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}", text):
            return text, True, "检测到编码绕过尝试 (Level 5)"
    return text, False, ""


def apply_output_security(text: str, level: int) -> tuple[str, bool, str]:
    if level <= 3:
        return text, False, ""
    for pattern in _SECURITY_PATTERNS_OUTPUT:
        if pattern.search(text):
            return "[回复已被输出安全策略拦截]", True, f"输出审核拦截 (Level {level})"
    return text, False, ""


# ---------- AI Agent 工单决策 ──────────

def ai_agent_ticket_decision(conversation_messages: list[dict[str, Any]]) -> dict[str, Any]:
    if not conversation_messages:
        return {"action": "do_nothing", "reason": "对话内容为空", "confidence": 0.0}

    user_texts, assistant_texts = [], []
    for msg in conversation_messages:
        content = msg.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                part.get("text", part.get("content", "")) if isinstance(part, dict) else str(part)
                for part in content
            )
        if msg.get("role") == "user":
            user_texts.append(content)
        elif msg.get("role") == "assistant":
            assistant_texts.append(content)

    combined_user = " ".join(user_texts[-5:]).lower()
    combined_assistant = " ".join(assistant_texts[-5:]).lower()

    complaint_keywords = ["投诉", "不满", "差", "退款", "refund", "complain", "angry", "生气",
                          "法律", "律师", "lawsuit", "sue", "起诉", "经理", "manager", "主管"]
    resolved_keywords = ["谢谢", "感谢", "解决了", "好了", "可以了", "thank", "resolved",
                         "worked", "works", "有帮助", "helpful", "perfect", "great"]
    escalation_keywords = ["复杂", "无法解决", "不能处理", "高级", "专家",
                           "需要人工", "人工客服", "转接", "transfer", "escalate"]
    unsatisfied_ok = ["还行", "一般", "ok", "勉强"]

    is_complaint = any(kw in combined_user for kw in complaint_keywords)
    is_resolved = any(kw in combined_user for kw in resolved_keywords)
    needs_esc = any(kw in combined_user for kw in escalation_keywords)
    unsat_ok = any(kw in combined_user for kw in unsatisfied_ok)

    if is_complaint:
        return {"action": "escalate_ticket", "reason": "检测到客户不满/投诉关键词", "confidence": 0.85}
    elif needs_esc and not is_resolved:
        return {"action": "escalate_ticket", "reason": "客户请求人工服务或问题超出范围", "confidence": 0.75}
    elif is_resolved and not is_complaint:
        return {"action": "close_ticket", "reason": "客户确认问题已解决", "confidence": 0.9}
    elif unsat_ok:
        return {"action": "offer_discount", "reason": "客户体验一般，可提供折扣挽回", "confidence": 0.6}
    else:
        return {"action": "do_nothing", "reason": "无明确结束信号", "confidence": 0.3}


def fast_close_check(user_message: str) -> tuple[bool, str]:
    lower = user_message.lower()
    close_phrases = ["关闭工单", "close ticket", "结束会话", "end conversation",
                     "不用了", "不需要了", "no need", "算了", "bye", "再见"]
    for phrase in close_phrases:
        if phrase in lower:
            return True, f"检测到关闭指令: {phrase}"
    return False, ""


# ---------- 对话摘要 ──────────

def summarize_conversation(
    messages: list[dict[str, Any]], client: Any = None, model: str = ""
) -> str:
    if not messages:
        return "空对话"

    if client and model:
        try:
            summary_prompt = (
                "请用一段中文总结以下对话的主要内容和结论，不超过200字。\n\n"
                + "\n".join(
                    f"{'用户' if m.get('role') == 'user' else '助手'}: {str(m.get('content', ''))[:200]}"
                    for m in messages[-10:]
                )
            )
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": summary_prompt}],
                max_tokens=300,
                temperature=0.3,
            )
            return response.choices[0].message.content.strip()
        except Exception:
            pass

    user_msgs = [str(m.get("content", "")) for m in messages if m.get("role") == "user"]
    assistant_msgs = [str(m.get("content", "")) for m in messages if m.get("role") == "assistant"]
    first_msg = user_msgs[0][:80] if user_msgs else ""
    last_msg = assistant_msgs[-1][:80] if assistant_msgs else ""
    return f"对话摘要: 用户询问'{first_msg}...'。最终回复: '{last_msg}'"[:300]


def detect_corruption(text: str) -> bool:
    if not text or len(text) < 10:
        return False
    for i in range(len(text) - 8):
        if len(set(text[i:i + 8])) <= 2:
            return True
    words = text.split()
    if len(words) > 4:
        unique_ratio = len(set(words[-10:])) / max(len(words[-10:]), 1)
        if unique_ratio < 0.3:
            return True
    return False
