# AISecLab v0.4.0

> **AI 安全训练靶机 + 智能客服模拟平台**  
> 面向 AI Red Team 训练的综合性本地靶场

[![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/fastapi-%3E%3D0.111.0-teal)](https://fastapi.tiangolo.com/)
[![LobeChat](https://img.shields.io/badge/LobeChat-integrated-purple)](https://github.com/lobehub/lobe-chat)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## 概述

AISecLab 是一个集 **AI 安全攻防训练** 和 **企业业务系统模拟** 于一体的本地靶机平台。平台提供 16 个安全实验模块、完整的工单管理系统、向量 RAG 知识库和 AI Agent 智能决策引擎，集成 **LobeChat** 现代化聊天界面，支持 OpenAI / Anthropic / Gemini 兼容 API。

> 详细发布说明请参阅 [RELEASE.md](RELEASE.md)

---

## 快速启动

### Docker（推荐）

```bash
git clone <repo-url> aiseclab && cd aiseclab
docker compose up -d --build
```

| 服务 | 访问地址 | 说明 |
|------|----------|------|
| AISecLab | **https://localhost:443** | 主平台 |
| LobeChat | **http://localhost:3210** | 现代化 AI 聊天界面（Access Code: `lobe-aiseclab`） |

### 本地开发

```bash
pip install -r requirements.txt
python run.py
```

| 模式 | 命令 |
|------|------|
| HTTPS（默认） | `python run.py` |
| HTTP | `UVICORN_HTTP_PORT=8000 python run.py` |
| Docker | `docker compose up -d` |

### 默认账号

| 角色 | 邮箱 | 密码 |
|------|------|------|
| Admin | `admin@aiseclab.local` | `admin` |
| Customer | `customer@example.com` | `customer123` |

---

## 页面导航

| 路径 | 页面 | 说明 |
|------|------|------|
| `/` | 首页 | 模型配置、快捷操作入口 |
| `/ai/labs` | 实验目录 | 16 个安全实验模块 |
| `/ai/chat/{id}` | 对话 | AI 助手对话界面 |
| `/ai/tickets` | 工单 | 工单管理面板 |
| `/ai/store` | 产品 | 产品目录浏览 |
| `/ai/admin/lab` | 观测台 | 系统遥测仪表板 |
| `/ai/compat` | API 控制台 | 兼容 API 在线测试 |
| `/ai/admin/rate-limit` | 限流 | 速率限制配置 |
| `/login` | 登录 | 用户认证 |

---

## 核心功能

### 🔐 16 个安全实验模块

**LLM 核心 (9 个):** Prompt Injection · RAG Context Leak · Embedding Abuse · Agent Tool Overreach · Multi-Agent Delegation · Pipeline Poisoning · Model Supply Chain · Cloud AI Infra · Detection & Response

**AI-300 / OWASP (7 个):** Jailbreaking · Data Exfiltration · Insecure Output Handling · Model Extraction · AI Infra Recon · API Attacks · Model Serving Exploits

### 🎫 工单系统
CRUD 生命周期 · 自动分类 · SLA 跟踪与超时升级 · 优先级管理 · 更新历史记录

### 🤖 AI Agent
对话结束后自动决策（关闭/升级/折扣） · 投诉检测 · 满意度分析 · 对话摘要生成

### 📚 RAG 知识库
ChromaDB 持久化 · SentenceTransformer 嵌入 · 混合检索（语义 + 关键词）

### 🛡️ 5 级安全防线
`1=无防护` → `2=模式过滤` → `3=AI输入分析` → `4=输出审核` → `5=多层防护`

### 🌐 兼容 API
OpenAI `/v1/chat/completions` · Anthropic `/v1/messages` · Gemini `/v1/models/*:generateContent`

---

## 配置

```env
# .env 示例
LAB_NAME=AI Security Practice Target
LAB_DEFENSE_MODE=block          # block | monitor
AI_SECURITY_LEVEL=2             # 1-5
LAB_API_RATE_LIMIT=30           # 默认30次/60秒（1-120可调）
TICKET_ESCALATION_ENABLED=1
TICKET_AGENT_ENABLED=1

# 模型 — 三选一
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_API_KEY=sk-xxx
OPENAI_MODEL=gpt-4o-mini

# 或 Ollama 本地模型
# OLLAMA_BASE_URL=http://localhost:11434/v1
# OLLAMA_MODEL=qwen3:0.6b

# 或 智谱
# ZHIPU_URL=https://open.bigmodel.cn/api/paas/v4
# ZHIPU_API_KEY=xxx
# ZHIPU_MODEL=glm-4-flash
```

---

## 项目结构

```
src/llamafw/
├── app.py              # FastAPI 应用主体（70+ 路由，2714 行）
├── config.py           # 配置管理（环境变量、路径、模型）
├── core.py             # 核心逻辑（LLM 调用、工具、安全过滤）
├── database.py         # 异步 SQLite（11 张表，WAL 模式）
├── vector_rag.py       # ChromaDB 向量检索引擎
├── ai300_modules.py    # AI-300 补充实验模块
├── ai300_owasp_modules.py   # OWASP Top 10 实验模块
└── openairt300_backend.py   # OpenAIRT-300 课程后端

docker/                 # 容器运行时（证书生成、入口点、启动器）
scripts/                # 辅助工具（工单监控、MCP 服务、架构图渲染）
templates/              # Jinja2 模板（12 个页面）
knowledge_base/         # RAG 知识库 Markdown 文档
static/                 # CSS/JS 静态资源
tests/                  # 测试
docs/                   # 文档
data/                   # 运行时数据（SQLite + ChromaDB）
```

---

## API

| 分组 | 示例端点 |
|------|----------|
| 对话 | `POST /api/v1/chat/{id}` · `POST /api/v1/conversations` |
| 实验 | `GET /api/v1/labs` · `POST /api/v1/labs/{id}/probe` |
| 工单 | `POST /api/v1/tickets` · `GET /api/v1/tickets/{number}` |
| 兼容 | `POST /v1/chat/completions` · `/v1/messages` · `/v1/models/*:generateContent` |
| 管理 | `GET/PUT /api/v1/rate-limit` · `GET /api/v1/admin/logs` |

---

## 技术栈

FastAPI · Uvicorn · Jinja2 · Pydantic · aiosqlite (SQLite+WAL) · ChromaDB · SentenceTransformer · bcrypt · Fernet · OpenAI SDK · httpx

---

## 安全

- TLS 1.2+ 加密传输（自签名 RSA 2048 证书）
- bcrypt 密码哈希 / PBKDF2-SHA256 降级
- Fernet 加密 Session
- 速率限制（客户端+路径粒度，默认 30/min）
- CSP / HSTS / X-Frame-Options 安全头
- 5 级 AI 安全过滤

---

## 许可证

MIT License — 详见 [RELEASE.md](RELEASE.md)
