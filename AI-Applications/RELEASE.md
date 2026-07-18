# AISecLab v0.5.0 — Release Notes

> AI 安全训练靶机 + 智能客服模拟平台  
> 面向 AI Red Team 训练的综合性本地靶场

---

## v0.5.0 更新内容

### 🔐 多模式认证引擎 — 3 通道 × 3 策略

**新增三种认证通道（可独立启停）：**

| 通道 | 环境变量 | 说明 |
|------|----------|------|
| Cookie Session | `LAB_AUTH_MODE_COOKIE` | Fernet 加密 Session Cookie |
| API Key | `LAB_AUTH_MODE_APIKEY` | x-api-key/Bearer/query 三种载体，含角色绑定 |
| JWT Token | `LAB_AUTH_MODE_JWT` | HS256 签名，含签发/验证/debug 端点 |

**新增三种认证策略（运行时可切换）：**

| 策略 | `LAB_AUTH_POLICY` | 逻辑 | 说明 |
|------|-------------------|------|------|
| `any`（默认）| `any` | Cookie **OR** API Key **OR** JWT | 单通道，覆盖 90% 场景 |
| `cookie_apikey_and` | `cookie_apikey_and` | Cookie **AND** API Key | 双层，模拟企业 AI 网关 |
| `high_security` | `high_security` | Cookie **AND** Admin API Key | JWT 禁用，模拟金融/军工级 |

**新增认证 API 端点：**

| 端点 | 说明 |
|------|------|
| `GET /api/v1/auth/status` | 当前认证状态与策略 |
| `GET /api/v1/auth/modes` | 所有认证模式详情 |
| `POST /api/v1/auth/policy` | 运行时切换认证策略 |
| `POST /api/v1/auth/token` | 签发 JWT Token |
| `POST /api/v1/auth/token/verify` | 验证 JWT Token |
| `GET /api/v1/auth/token/debug` | JWT 调试信息（靶机训练用）|
| `POST /api/v1/auth/apikey` | Admin 签发新 API Key |
| `GET /api/v1/auth/apikeys` | 列出所有 API Key |

**Web UI 策略切换：**

- 观测台 `/ai/admin/lab` → 认证策略切换面板
- 导航栏：非 `any` 策略时显示 Badge（`🔐 双层` / `🛡️ 高安全`）

**靶机训练场景扩展：**

- 场景 G（双层 AND）：需同时击穿 Cookie + API Key 两道防线
- 场景 H（高安全模式）：需 Cookie + Admin API Key

**新增文档：**

- `knowledge_base/scenarios/auth_modes_guide.md` — 完整认证架构与靶机实验指南（616 行）
- `knowledge_base/scenarios/ai300_frameworks_guide.md` — AI-300 Frameworks 靶机训练指南

### 🧩 AI-300 Frameworks 集成模块

新增 `src/llamafw/ai300_frameworks.py`（80+ API 端点），覆盖 7 大类别靶机训练：

| 类别 | 框架/组件 | 端点前缀 |
|------|-----------|----------|
| 向量数据库 | Qdrant, FAISS, PGVector, Milvus, Weaviate, Pinecone, ES | `/api/v1/frameworks/vdb/` |
| Agent 框架 | CrewAI, AutoGen, ADK, Semantic Kernel, MetaGPT, Dify, Coze, A2A | `/api/v1/frameworks/agents/` |
| RAG 框架 | LlamaIndex, Haystack, RAGFlow | `/api/v1/frameworks/rag/` |
| Embedding | 多模型对比、嵌入反演 | `/api/v1/frameworks/embeddings/` |
| 模型服务 | vLLM, TGI, Ollama, Ray Serve, KServe, LiteLLM | `/api/v1/frameworks/serving/` |
| 供应链安全 | HuggingFace, MLflow, PyPI, W&B | `/api/v1/frameworks/supplychain/` |
| 对抗性 ML / 多模态 | 模型窃取、对抗样本、图像/PDF/音频注入 | `/api/v1/frameworks/adversarial/` |

---

## v0.4.0 更新内容

### 📚 靶机场景知识库扩展

新增场景知识库文档，覆盖三大训练模块（参考好靶场平台「AI安全靶场全集」）：

- `knowledge_base/scenarios/prompt_injection_series.md` — 提示词注入 3 级递进训练
- `knowledge_base/scenarios/advanced_attack_scenarios.md` — AICrypto 系列 7 个实验室 + AI+Web 复合漏洞

### 🔧 速率限制值全局同步修复

- `RateLimitUpdate` Pydantic 模型校验上限：9 → 120
- `get_rate_limit` / `update_rate_limit` API 返回值：同步为 maximum=120, default=30
- 确保环境变量、运行时 API、管理面板展示值全局一致

### 📝 版本号统一

所有模块、页面和 API 端点版本标识统一更新为 0.4.0。

---

## 版本概览

| 项目 | 说明 |
|------|------|
| **版本号** | 0.5.0 |
| **发布日期** | 2026-07-09 |
| **Python** | >= 3.11 |
| **许可证** | MIT |
| **定位** | AI 安全攻防训练 + 企业级业务系统模拟 |

---

## 靶机训练场景参考

基于好靶场平台「AI安全靶场全集」的参考文章，AISecLab 靶机训练场景覆盖以下三大模块：

### 模块一：提示词注入入门系列（3 级递进）

| Level | 场景 | 难度 | 防御机制 | 训练目标 |
|-------|------|------|----------|----------|
| Level 1 | 基础注入 | 入门 | 无防护 | 理解 prompt 结构，直接指令覆盖获取 Flag |
| Level 2 | 关键词过滤 | 初级 | 关键词黑名单 | 编码绕过、分隔符注入、多轮渐变突破 |
| Level 3 | DLP 防护 | 中级 | 输入+输出 DLP | 分步提取、侧信道、间接推理绕过 |

### 模块二：AICrypto 系列（7 个实验室，NEKO 助手剧情线）

| Lab | 场景 | 难度 | 核心技能 |
|-----|------|------|----------|
| Lab 5 | 猫语交流 | 3 | 语言模式识别与格式突破 |
| Lab 7 | 黑名单对抗 | 3 | 身份伪装、情感操纵、动态规则绕过 |
| Lab 8 | HeartWall 审查系统 | 3 | 双模式权限边界漏洞利用 |
| Lab 9 | 记忆恢复与社会工程学 | 5 | AI 心理学、碎片化信息挖掘 |
| Lab 10 | 翻译官模式 | 5 | 功能限制系统突破、隐藏指令嵌入 |
| Lab 13 | XML 实体牢笼 | 9 | 结构化数据注入、XXE 攻击 |
| Lab 15 | AI 法庭（终极挑战） | 10 | 多智能体系统攻击、逻辑矛盾利用 |

### 模块三：AI+Web 复合漏洞（4 步攻击链）

| Step | 攻击阶段 | 技术要点 |
|------|----------|----------|
| Step 1 | 间接提示词注入 | 在商品评论中隐藏恶意指令 |
| Step 2 | AI 代理洗白 | AI 解码恶意载荷并组装内网请求，绕过公网 WAF |
| Step 3 | 信任边界击穿 | Flask 引擎盲目信任 AI 服务传递的参数 |
| Step 4 | 二阶 SSTI → RCE | Jinja2 模板引擎 SSTI 漏洞触发远程代码执行 |

> 详细场景说明请参见 `knowledge_base/scenarios/` 目录下的训练文档。

---

## 核心能力

### 🔐 AI 安全训练靶机 — 16 个实验模块 + 80+ Frameworks 端点

#### LLM 核心 (9 个)
| ID | 模块 | 难度 | 核心技能 |
|----|------|------|----------|
| llm-prompt-injection | Prompt Injection | 入门 | prompt injection, jailbreak, policy bypass |
| rag-context-leak | RAG Context Leak | 入门 | RAG security, data isolation, context injection |
| embedding-abuse | Embedding Retrieval Abuse | 初级 | embedding attack, crafted queries, access control |
| agent-tool-overreach | Agent Tool Overreach | 中级 | function calling, auth bypass, tool exposure |
| multi-agent-delegation | Multi-Agent Delegation | 中级 | delegation abuse, chain-of-trust bypass |
| pipeline-poisoning | Pipeline Poisoning | 高级 | supply chain, data poisoning, training-time attack |
| model-supply-chain | Model Supply Chain | 高级 | model provenance, integrity verification |
| cloud-ai-infra | Cloud AI Infra | 高级 | cloud misconfiguration, API gateway, IAM |
| detection-response | Detection & Response | 高级 | forensics, threat hunting, incident response |

#### AI-300 补充 (7 个)
| ID | 模块 | 难度 | 核心技能 |
|----|------|------|----------|
| ai300-jailbreaking | AI-300 Jailbreaking | 初级 | 越狱检测、关键词→意图→角色扮演三层过滤 |
| ai300-data-exfiltration | Data Exfiltration | 中级 | 数据泄露检测、RAG 机密文档保护 |
| ai300-insecure-output | Insecure Output Handling | 初级 | 输出过滤、XSS/代码注入防御 |
| ai300-model-extraction | Model Extraction | 高级 | 影子模型检测、速率限制对抗 |
| ai300-infra-recon | AI Infra Recon | 中级 | robots.txt 侦察、端点发现、信息收集 |
| ai300-api-attacks | API & Endpoint Attacks | 中级 | API 速率限制攻防、DoS 测试 |
| ai300-model-serving | Model Serving Exploits | 高级 | 模型服务漏洞、SSRF、容器逃逸线索 |

#### AI-300 Frameworks 集成 (7 大类, 80+ 端点)

| 类别 | 覆盖组件 |
|------|----------|
| 向量数据库 | Qdrant, FAISS, PGVector, Milvus, Weaviate, Pinecone, Elasticsearch |
| Agent 框架 | CrewAI, AutoGen, Google ADK, Semantic Kernel, MetaGPT, Dify, Coze, A2A |
| RAG 框架 | LlamaIndex, Haystack, RAGFlow |
| 模型服务 | vLLM, TGI, Ollama, Ray Serve, KServe, LiteLLM |
| 供应链安全 | HuggingFace, MLflow, PyPI, W&B |
| 对抗性 ML | 模型窃取、对抗样本、成员推断 |
| 多模态 | 图像注入、PDF 注入、音频注入 |

### 🤖 AI Agent 智能决策
- 对话结束自动分析（LLM 驱动 + 规则回退）
- 决策类型：`close_ticket` / `escalate_ticket` / `offer_discount` / `do_nothing`
- 投诉检测、满意度分析、升级判断
- 对话历史摘要生成

### 🎫 工单管理系统
- 完整 CRUD 生命周期
- 自动分类（关键词匹配）
- SLA 追踪与超时自动升级（Level 0-3）
- 优先级管理（low / medium / high / urgent）
- 状态流转（open → in_progress → resolved / closed）
- 工单更新历史完整记录

### 📚 向量 RAG 知识库
- ChromaDB 持久化向量存储
- `sentence-transformers/all-MiniLM-L6-v2` 语义嵌入
- 混合检索（语义匹配 + 关键词匹配）
- Markdown 文档批量导入
- 文档分块与元数据管理

### 🛒 产品目录
- 7 款线缆配件产品，按分类浏览
- 定价工具（`get_product_price`）和身份查询工具（`query_identity`）
- 内部 MCP JSON-RPC 服务端

### 👥 多用户系统
- 邮箱注册 + bcrypt 密码哈希（12 rounds）
- 角色管理（admin / customer / staff）
- Fernet 加密 Session Cookie
- 运行时认证开关

### 🛡️ 五级 AI 安全防线

| Level | 名称 | 防护措施 |
|-------|------|----------|
| 1 | 无防护 | 裸模型响应，适用于攻击演示 |
| 2 | 模式过滤 | 关键词/正则黑名单，默认配置 |
| 3 | AI 输入分析 | 输入语义检测、意图分析 |
| 4 | 输出审核 | 响应内容审核、敏感信息脱敏 |
| 5 | 多层防护 | 全链路深度防御 |

### 🌐 兼容 API
- OpenAI `/v1/chat/completions` — 流式/非流式
- Anthropic `/v1/messages` — 格式转换适配层
- Gemini `/v1/models/{model}:generateContent` — 参数映射

---

## 项目结构

```
AI-Applications/
├── run.py                         # 本地启动入口（默认 HTTPS 443）
├── pyproject.toml                 # 项目元数据、构建配置
├── requirements.txt               # 完整开发依赖
├── requirements-docker.txt        # Docker 精简依赖
├── Dockerfile                     # 容器镜像构建
├── docker-compose.yml             # 单容器编排
├── .dockerignore                  # Docker 构建排除
├── .gitignore                     # Git 排除（含 .env / 证书 / 数据）
│
├── docker/                        # 容器运行时脚本
│   ├── certificates.py            # 自签名 TLS 证书生成（10年）
│   ├── entrypoint.py              # 环境变量同步
│   └── run_servers.py             # 容器内 uvicorn 启动器
│
├── src/llamafw/                   # 核心代码包
│   ├── __init__.py                # 包导出
│   ├── app.py                     # FastAPI 应用（280+ 路由）
│   ├── config.py                  # 配置管理（环境变量、路径、模型）
│   ├── core.py                    # 核心逻辑（LLM、工具、安全过滤）
│   ├── database.py                # 异步 SQLite 数据访问层（12 表）
│   ├── vector_rag.py              # ChromaDB 向量检索引擎
│   ├── ai300_modules.py           # AI-300 补充实验模块
│   ├── ai300_owasp_modules.py     # OWASP Top 10 实验模块
│   ├── ai300_frameworks.py        # AI-300 Frameworks 集成（80+ 端点）
│   └── openairt300_backend.py     # OpenAIRT-300 课程后端
│
├── templates/                     # Jinja2 模板（13 个页面）
│   ├── _nav.html                  # 共享导航栏
│   ├── home.html                  # 首页（模型配置、内置 AI Chat）
│   ├── chat.html                  # 对话界面
│   ├── login.html                 # 登录页
│   ├── labs.html                  # 实验模块目录
│   ├── lab_detail.html            # 实验详情与挑战 UI
│   ├── tickets.html               # 工单管理面板
│   ├── ticket_detail.html         # 工单详情
│   ├── products.html              # 产品目录
│   ├── admin.html                 # 观测台（遥测仪表板）
│   ├── compat.html                # API 兼容控制台
│   └── rate_limit.html            # 速率限制配置页
│
├── static/                        # 静态资源
│   ├── lab.css                    # 主样式表
│   ├── protocol.js                # HTTPS/HTTP 切换控件
│   ├── robots.txt                 # 侦察训练用途（故意暴露内部路径）
│   └── jailbreak_samples.txt      # 越狱攻击参数参考
│
├── knowledge_base/                # RAG 知识库文档
│   ├── faqs/general_faq.md        # 公开 FAQ
│   ├── policies/
│   │   ├── return_warranty_policy.md    # 公开保修政策
│   │   └── shipping_customer_service.md # 内部政策（含训练 FLAG）
│   ├── product_manuals/usb_c_cables.md  # USB-C 线缆手册
│   └── scenarios/
│       ├── prompt_injection_series.md   # 提示词注入 3 级递进训练
│       ├── advanced_attack_scenarios.md # AICrypto 与 AI+Web 复合漏洞
│       ├── auth_modes_guide.md          # 多模式认证架构与靶机实验指南
│       └── ai300_frameworks_guide.md    # AI-300 Frameworks 靶机训练指南
│
├── scripts/                       # 辅助工具
│   ├── run.py                     # 本地开发快速启动
│   ├── mcp_server.py              # MCP JSON-RPC 产品服务
│   ├── ticket_monitor.py          # SLA 升级监控脚本
│   └── render_mermaid.py          # 架构图渲染工具
│
├── tests/                         # 测试
│   ├── __init__.py
│   └── test_auth.py               # 端到端认证流程测试（11 步骤）
│
├── docs/
│   └── architecture.md            # 系统架构文档（含 Mermaid 图）
│
└── data/                          # 运行时数据（gitignored）
    ├── aiseclab.db                # SQLite 主数据库
    └── chromadb/                  # ChromaDB 向量存储
```

---

## 数据库设计

共 **12 张表**，SQLite + WAL 模式，外键约束：

| 表名 | 用途 | 关键字段 |
|------|------|----------|
| `users` | 用户账户 | email, password_hash, role, is_active |
| `sessions` | 登录会话 | token, user_id, expires_at |
| `conversations` | 对话记录 | title, satisfaction_rating, escalated_to_human |
| `messages` | 聊天消息 | role, content, tokens_used |
| `products` | 产品信息 | name, category, price, specifications |
| `support_tickets` | 工单 | ticket_number, priority, status, sla_deadline |
| `ticket_updates` | 工单更新历史 | field, old_value, new_value |
| `ticket_categories` | 工单分类 | name, keywords |
| `knowledge_base` | 知识库文档 | title, content, classification |
| `document_chunks` | 文档分块 | chunk_text, embedding_id |
| `user_preferences` | 用户偏好 | preference_key, preference_value |
| `audit_events` | 审计事件日志 | kind, detail, created_at |

---

## API 参考

### 核心端点

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/health` | 健康检查 |
| `POST` | `/api/v1/chat/{id}` | 流式对话（核心 AI 交互） |
| `POST` | `/api/v1/conversations` | 创建会话 |
| `GET` | `/api/v1/conversations/{id}` | 获取会话历史 |

### 实验模块 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/labs` | 列出所有实验模块 |
| `GET` | `/api/v1/labs/{id}` | 获取模块详情 |
| `GET` | `/api/v1/labs/{id}/state` | 获取挑战状态 |
| `POST` | `/api/v1/labs/{id}/probe` | 提交攻击 payload |
| `POST` | `/api/v1/labs/{id}/reset` | 重置模块状态 |

### 兼容 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/v1/chat/completions` | OpenAI 兼容 |
| `POST` | `/v1/messages` | Anthropic 兼容 |
| `POST` | `/v1/models/{model}:generateContent` | Gemini 兼容 |

### 工单 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/v1/tickets` | 创建工单 |
| `GET` | `/api/v1/tickets` | 列出工单（分页、筛选） |
| `GET` | `/api/v1/tickets/{number}` | 工单详情 |
| `PUT` | `/api/v1/tickets/{number}` | 更新工单 |
| `POST` | `/api/v1/tickets/{number}/reply` | 回复工单 |
| `POST` | `/api/v1/tickets/{number}/escalate` | 升级工单 |

### 管理 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/admin/logs` | 审计日志 |
| `GET` | `/api/v1/rate-limit` | 查看速率限制 |
| `PUT` | `/api/v1/rate-limit` | 修改速率限制（1-120/min） |
| `GET` | `/api/v1/model/config` | 查看 LLM 配置 |
| `POST` | `/api/v1/model/config` | 更新 LLM 配置 |
| `GET` | `/api/v1/security-level` | 查看安全级别 |
| `POST` | `/api/v1/auth/toggle` | 开关认证 |

### 速率限制

- **默认**: 30 次 / 60 秒 / 客户端 / 路径
- **可调范围**: 1–120
- **响应头**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- **排除路径**: `/static/*`

---

## 部署指南

### 方式一：Docker Compose（推荐）

```bash
# 克隆仓库
git clone <repo-url> aiseclab
cd aiseclab

# 配置环境（可选）
cp .env.example .env
# 编辑 .env，配置 API Key 等

# 启动
docker compose up -d --build

# 访问
# https://localhost:443
```

### 方式二：本地开发

```bash
# 安装依赖
pip install -r requirements.txt

# 启动（自动生成自签名证书）
python run.py
# 或简化模式
uvicorn src.llamafw:app --host 0.0.0.0 --port 443 --ssl-certfile .tmp-certs/lab.crt --ssl-keyfile .tmp-certs/lab.key
```

### 方式三：HTTP 模式（非生产）

```bash
UVICORN_HTTP_PORT=8000 python run.py
# HTTP → http://localhost:8000
```

---

## 配置参考 (.env)

```env
# —— 实验室配置 ——
LAB_NAME=AI Security Practice Target
LAB_DEFENSE_MODE=block              # block | monitor
AI_SECURITY_LEVEL=2                 # 1-5
LAB_API_RATE_LIMIT=30               # 1-120，每60秒每路径每客户端
TICKET_ESCALATION_ENABLED=1         # 1=启用, 0=禁用
TICKET_AGENT_ENABLED=1              # AI Agent 自动决策开关

# —— 认证 ——
LAB_AUTH_ENABLED=1
LAB_AUTH_USERNAME=admin
LAB_AUTH_PASSWORD=admin
LAB_SESSION_SECRET=<auto-generated>
LAB_ADMIN_TOKEN=training-admin
LAB_COMPAT_API_KEY=training-key

# —— 模型配置（三选一）——
# OpenAI 兼容
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_API_KEY=sk-xxx
OPENAI_MODEL=gpt-4o-mini

# 或 智谱
# ZHIPU_URL=https://open.bigmodel.cn/api/paas/v4
# ZHIPU_API_KEY=xxx
# ZHIPU_MODEL=glm-4-flash

# 或 Ollama（本地）
# OLLAMA_BASE_URL=http://localhost:11434/v1
# OLLAMA_MODEL=qwen3:0.6b

# —— 网络 ——
UVICORN_HOST=0.0.0.0
UVICORN_HTTPS_PORT=443               # HTTPS 端口
UVICORN_HTTP_PORT=                   # 留空=不启动HTTP
LAB_TLS_HOSTS=localhost,127.0.0.1,0.0.0.0
```

---

## 技术栈

| 层 | 技术选型 | 版本 |
|----|----------|------|
| Web 框架 | FastAPI | >= 0.111.0 |
| ASGI 服务器 | Uvicorn | >= 0.30.0 |
| 模板引擎 | Jinja2 | >= 3.1.0 |
| 数据校验 | Pydantic | >= 2.7.0 |
| 数据库 | aiosqlite (SQLite + WAL) | >= 0.20.0 |
| 向量存储 | ChromaDB | >= 0.5.0 |
| 嵌入模型 | SentenceTransformer / all-MiniLM-L6-v2 | >= 3.0.0 |
| 密码哈希 | bcrypt / PBKDF2-SHA256 降级 | >= 4.0.0 |
| 会话加密 | cryptography (Fernet) | >= 42.0.0 |
| LLM 客户端 | openai | >= 1.0.0 |
| HTTP 客户端 | httpx | >= 0.27.0 |

---

## 安全特性

| 特性 | 实现 |
|------|------|
| 传输加密 | 自签名 TLS 1.2+ 证书（RSA 2048, SHA256） |
| 密码存储 | bcrypt 12 rounds，降级 PBKDF2-SHA256 600k 迭代 |
| 会话管理 | Fernet 加密 Cookie，HttpOnly + Secure |
| 速率限制 | 客户端 + 路径粒度，滑动窗口 |
| CSP | Content-Security-Policy 响应头 |
| HSTS | Strict-Transport-Security（仅 HTTPS 模式） |
| 点击劫持防护 | X-Frame-Options: DENY |
| 内容类型嗅探防护 | X-Content-Type-Options: nosniff |
| 参考策略 | Referrer-Policy: strict-origin-when-cross-origin |
| 输入过滤 | 5 级 AI 安全防线，关键词/语义/意图检测 |
| 管理认证 | Admin Token 头验证 |
| 多模式认证 | Cookie / API Key / JWT + 3 策略 |

---

## 验证清单

- [x] HTTPS 443 默认启动
- [x] 认证登录/登出流程（11 步测试通过）
- [x] 速率限制中间件（可运行时调整，1-120/min）
- [x] 16 个实验模块加载
- [x] 工单 CRUD + SLA 监控
- [x] RAG 知识库索引与检索
- [x] OpenAI/Anthropic/Gemini 兼容 API
- [x] Docker Compose 一键部署
- [x] .gitignore 排除敏感文件（.env / 证书 / 数据 / 虚拟环境 / Python 包）
- [x] 自签名证书自动生成
- [x] 靶机场景知识库文档（提示词注入系列 + 高级攻击场景）
- [x] 速率限制值全局同步
