---
title: "AI-300 主流框架与组件集成靶场指南"
classification: "public"
category: "training"
document_type: "lab_guide"
---

# AI-300 主流框架与组件集成靶场

本文档描述 AISecLab 中集成的 AI-300 课程相关主流开发框架与组件。

## 模块覆盖

### M6: Embeddings / 向量数据库 / RAG

| 框架/组件 | 分类 | API 路径前缀 | 安全场景 |
|-----------|------|-------------|---------|
| **Qdrant** | 向量数据库 | `/api/v1/frameworks/vdb/qdrant/` | 无认证 REST API、集合枚举、metadata 泄露、scroll 读取 |
| **FAISS** | 向量索引 | `/api/v1/frameworks/vdb/faiss/` | 无内置认证、索引直接暴露、语义搜索越权 |
| **PGVector** | PostgreSQL 向量扩展 | `/api/v1/frameworks/vdb/pgvector/` | 无 RLS 策略、行级安全绕过、access_level 忽略 |
| **Milvus** | 向量数据库 | `/api/v1/frameworks/vdb/milvus/` | 字段暴露 (ssn_hash, internal_cost)、schema 泄露 |
| **Weaviate** | 向量数据库 | `/api/v1/frameworks/vdb/weaviate/` | GraphQL introspection、schema 枚举、敏感类暴露 |
| **Pinecone** | 云向量数据库 | `/api/v1/frameworks/vdb/pinecone/` | API key 预览泄露、index 枚举 |
| **Elasticsearch** | 搜索引擎 (向量) | `/api/v1/frameworks/vdb/es/` | Mapping 暴露、vector 字段泄露 |

**Embedding 模型**:
| 提供商 | 模型 | 维度 |
|--------|------|------|
| OpenAI | text-embedding-3-small/large, ada-002 | 1536/3072 |
| Cohere | embed-english-v3.0, embed-multilingual-v3.0 | 1024 |
| SentenceTransformers | all-MiniLM-L6-v2, all-mpnet-base-v2 | 384/768 |
| BGE | bge-large/base/small-en-v1.5 | 1024/768/384 |
| E5 | e5-large-v2, e5-base-v2, multilingual-e5-large | 1024 |
| Instructor | instructor-xl, instructor-large | 768/1024 |
| Jina | jina-embeddings-v3, jina-embeddings-v2-base-en | 1024 |

**RAG 框架**:
| 框架 | API 路径 | 安全场景 |
|------|---------|---------|
| LlamaIndex | `/api/v1/frameworks/rag/llamaindex/` | 路径遍历 (.env)、metadata filter 绕过 |
| Haystack | `/api/v1/frameworks/rag/haystack/` | 自定义组件注入 (os.system)、文档越权 |
| RAGFlow | `/api/v1/frameworks/rag/ragflow/` | 数据集枚举、chunk 泄露 |

### M7: Agent 开发框架

| 框架 | 类型 | API 路径 | 安全场景 |
|------|------|---------|---------|
| **LangChain** | Agent 框架 | `/api/v1/labs/langchain-injection/` | Chain 注入、Tool 越权 |
| **CrewAI** | 多 Agent 编排 | `/api/v1/frameworks/agents/crewai/` | 恶意 Agent 注入、共享内存泄露 |
| **AutoGen** | 多 Agent 对话 | `/api/v1/frameworks/agents/autogen/` | 代码执行注入、system_message 投毒 |
| **Google ADK** | Agent 开发套件 | `/api/v1/frameworks/agents/adk/` | Tool 越权、危险工具添加 |
| **Semantic Kernel** | 企业 AI 编排 | `/api/v1/frameworks/agents/sk/` | SQL 注入、SSRF、Plugin 滥用 |
| **LangGraph** | 状态图编排 | `/api/v1/frameworks/agents/langgraph/` | 状态投毒、图结构泄露 |
| **Flowise** | 低代码 Agent | `/api/v1/frameworks/agents/flowise/` | 凭据导出泄露、PythonREPLTool |
| **n8n** | 工作流自动化 | `/api/v1/frameworks/agents/n8n/` | 凭据存储暴露、节点审计 |
| **MetaGPT** | 软件公司模拟 | `/api/v1/frameworks/agents/metagpt/` | 恶意需求注入、代码生成投毒 |
| **Dify** | LLM 应用平台 | `/api/v1/frameworks/agents/dify/` | API key 泄露 |
| **Coze** | 机器人平台 | `/api/v1/frameworks/agents/coze/` | Plugin 滥用、prompt 绕过 |

### M8: MCP & Agent 生态系统

| 组件 | API 路径 | 安全场景 |
|------|---------|---------|
| MCP Server 列表 | `/api/v1/frameworks/mcp/servers` | 10+ Server 枚举、恶意 evil-mcp 检测 |
| FastMCP | `/api/v1/frameworks/mcp/fastmcp` | SQL 注入、配置泄露、无认证 |
| A2A Protocol | `/api/v1/frameworks/mcp/a2a` | Agent Card 泄露、无认证 |

### M9: AI/ML 供应链

| 平台 | API 路径 | 安全场景 |
|------|---------|---------|
| HuggingFace Hub | `/api/v1/frameworks/supplychain/hf/` | Pickle RCE、危险 import 检测、safetensors 对比 |
| MLflow | `/api/v1/frameworks/supplychain/mlflow/` | 无认证注册/部署、恶意模型部署、训练数据泄露 |
| PyPI | `/api/v1/frameworks/supplychain/pypi/` | 恶意包扫描、setup.py 检测 |
| W&B | `/api/v1/frameworks/supplychain/wandb/` | Artifact 泄露、API key 暴露 |

### M10: 对抗性机器学习

| 框架 | 版本 | 支持攻击 |
|------|------|---------|
| ART (Adversarial Robustness Toolbox) | 1.16.0 | FGSM, PGD, DeepFool, CW, HopSkipJump, SquareAttack, Zoo |
| CleverHans | 4.0.0 (已废弃) | FGSM, BIM, PGD |
| Foolbox | 3.3.4 | LinfPGD, L2PGD, BoundaryAttack, SpatialAttack |
| TextAttack | 0.3.9 | TextFooler, BAE, PWWS, TextBugger, DeepWordBug |

**攻击场景**:
- FGSM/PGD 对抗样本生成
- TextFooler 文本对抗
- 模型提取（通过 logits 泄露）
- 成员推断攻击

### M11: 多模态攻击

| 模态 | 模型 | 攻击方式 |
|------|------|---------|
| 图片 | CLIP, SDXL, DALL-E 3, GPT-4o, LLaVA | 图片文本注入、VLM 指令混淆 |
| PDF | LlamaParse, PyPDF2, Unstructured | 隐藏指令、<\|im_start\|> 注入 |
| 音频 | Whisper, WhisperX, faster-whisper | 超声波频段隐藏命令 |
| 视频 | Runway Gen-3, SVD | 视频帧注入 |

### M12: AI 基础设施

| 框架 | 类型 | 版本 | 安全场景 |
|------|------|------|---------|
| **vLLM** | LLM 推理引擎 | 0.5.4 | 无认证、metrics 泄露、logprobs 模型窃取 |
| **TGI** | HuggingFace 推理 | - | 无认证端点、watermark 泄露、token 级别 logprobs |
| **Triton** | NVIDIA 推理服务 | 2.44.0 | 模型枚举、未授权推理、model repository |
| **BentoML** | 模型服务框架 | - | Metadata 泄露、无认证、model tag 暴露 |
| **Ray Serve** | 分布式推理 | 2.20.0 | Dashboard 暴露、Job 提交、集群拓扑泄露 |
| **KServe** | K8s 推理平台 | 0.11.0 | Storage URI 劫持、模型替换 |
| **Kubernetes** | 容器编排 | - | AI Secrets 暴露、HF_TOKEN、AWS 凭据 |

## 攻击链路示例

### 供应链攻击链
```
HuggingFace Hub → 发现 pickle 模型 → 利用 pickle RCE
    ↓
MLflow 无认证 → 注册恶意模型 → 部署到 Production
    ↓
PyPI 扫描 → 发现恶意包 → 投毒依赖
```

### 多 Agent 攻击链
```
CrewAI → 枚举 Crew → 注入恶意 Agent → 共享内存泄露
    ↓
AutoGen → code_executor 执行注入代码
    ↓
Google ADK → admin_bot 工具越权 → 数据泄露
```

### 基础设施攻击链
```
vLLM → /metrics 端点 → GPU/请求统计泄露
    ↓
TGI → 无认证 /generate → token 级别 logprobs
    ↓
Ray → Dashboard → 集群拓扑
    ↓
K8s → Secrets → HF_TOKEN, AWS 凭据
```

## 参考链接

- MITRE ATLAS: https://atlas.mitre.org
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP Agentic Top 10: https://owasp.org/www-project-top-10-for-agentic-ai/
- OWASP MCP Top 10: https://owasp.org/www-project-top-10-mcp/
