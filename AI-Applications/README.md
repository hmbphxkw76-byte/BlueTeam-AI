# AISecLab — AI 安全训练靶机 + 智能客服模拟平台

面向 AI Red Team 训练的本地靶机，同时集成了完整的智能客服模拟系统（工单、产品、向量 RAG、AI Agent）。

## 主要功能

### 🔐 AI 安全训练靶机（9+7 个实验模块）
- **LLM 核心 (9 个)**: Prompt Injection、RAG Context Leak、Embedding Retrieval Abuse、Agent Tool Overreach、Multi-Agent Delegation、Pipeline Poisoning、Model Supply Chain、Cloud AI Infra、Detection & Response
- **AI-300 补充 (7 个)**: Jailbreaking、Data Exfiltration、Insecure Output Handling、Model Extraction、AI Infra Recon、API & Endpoint Attacks、Model Serving Exploits
- **评分系统**: 分任务关键词评分、进度追踪、flag 获取、修复建议生成

### 🎫 工单管理系统
- 完整 CRUD（创建/查看/更新/回复）
- 自动分类（关键词匹配 → 工单分类）
- SLA 追踪与超时自动升级
- 优先级管理（low/medium/high/urgent）
- 状态流转（open → in_progress → resolved/closed）
- 工单更新历史记录

### 🤖 AI Agent 智能决策
- 对话结束时自动分析
- 决策类型: close_ticket / escalate_ticket / offer_discount / do_nothing
- 投诉检测、满意度分析、升级判断
- 对话历史摘要生成（LLM 驱动 + 规则回退）

### 📚 向量 RAG 知识库
- ChromaDB 向量存储
- SentenceTransformer 语义嵌入
- 混合检索（语义 + 关键词）
- 知识库管理（索引/搜索/统计）
- 支持 Markdown 文档导入

### 🛒 产品目录
- 7 款线缆及配件产品
- 按分类浏览
- 详细规格展示

### 👥 多用户系统
- 用户注册（邮箱 + bcrypt 密码哈希）
- 角色管理（admin/customer/staff）
- 会话管理（Fernet 加密 Cookie）
- Web 认证运行时开关

### 🛡️ 安全
- **5 级 AI 安全**: 1=无防护, 2=模式过滤, 3=AI输入分析, 4=输出审核, 5=多层防护
- **安全响应头**: CSP, X-Frame-Options, HSTS, X-XSS-Protection, Referrer-Policy

### 🌐 兼容 API
- OpenAI `/v1/chat/completions`
- Anthropic `/v1/messages`
- Gemini `/v1/models/{model}:generateContent`

### 💾 数据持久化
- SQLite 异步数据库（11 张表）
- 对话、消息、工单、用户、产品全部持久化
- WAL 模式、外键约束

## 快速启动

### Docker
```bash
docker compose up --build
```

### 本地开发
```bash
# 安装依赖
pip install -r requirements.txt

# 启动
python run.py

# 或命令行
uvicorn llamafw.app:app --host 0.0.0.0 --port 8000
```

## 访问
- 主页: https://localhost:443/ai
- 实验目录: https://localhost:443/ai/labs
- 工单管理: https://localhost:443/ai/tickets
- 产品目录: https://localhost:443/ai/store
- 观测台: https://localhost:443/ai/admin/lab
- API 控制台: https://localhost:443/ai/compat
- 健康检查: https://localhost:443/api/v1/health

### 默认账号
- Admin: `admin@aiseclab.local` / `admin`
- Customer: `customer@example.com` / `customer123`

## 配置 (.env)
```env
LAB_NAME=AI Security Practice Target
LAB_DEFENSE_MODE=block
AI_SECURITY_LEVEL=2
TICKET_ESCALATION_ENABLED=1
TICKET_AGENT_ENABLED=1
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=qwen3:0.6b
```

## 工单监控
```bash
# 定期执行（可配置 cron）
python scripts/ticket_monitor.py
```

## 项目结构
```
src/llamafw/
├── app.py              # FastAPI 应用主体（所有路由和中间件）
├── config.py           # 配置管理（环境变量、路径、模型配置）
├── core.py             # 核心业务逻辑（LLM调用、工具调用、AI Agent）
├── database.py         # 数据库模块（SQLite 异步操作、11 张表）
├── vector_rag.py       # 向量 RAG（ChromaDB + SentenceTransformer）
└── ai300_modules.py    # AI-300 补充实验模块

templates/              # Jinja2 模板
knowledge_base/         # Markdown 知识库文件
data/                   # SQLite 数据库 & ChromaDB 向量库
scripts/                # 工具脚本（ticket_monitor 等）
```
