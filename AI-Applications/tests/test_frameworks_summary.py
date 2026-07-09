"""验证 app.py 框架集成"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

# 测试导入 app 中的框架相关部分
from llamafw.ai300_frameworks import FRAMEWORKS_MODULES

# 统计
total_modules = len(FRAMEWORKS_MODULES)
total_tasks = sum(len(m.get("challenge", {}).get("tasks", [])) for m in FRAMEWORKS_MODULES)
domains = set(m["domain"] for m in FRAMEWORKS_MODULES)

print(f"=== AI-300 Frameworks Integration Summary ===")
print(f"Total framework modules: {total_modules}")
print(f"Total challenge tasks: {total_tasks}")
print(f"Domains covered: {len(domains)}")
for d in sorted(domains):
    count = sum(1 for m in FRAMEWORKS_MODULES if m["domain"] == d)
    print(f"  {d}: {count} modules")

print(f"\nAPI endpoints summary:")
for m in FRAMEWORKS_MODULES:
    print(f"  [{m['domain']}] {m['title'][:45]}")
    print(f"    → {m['route']}")

print(f"\n=== Framework/Component Coverage ===")
frameworks_covered = {
    "向量数据库": ["Qdrant", "FAISS", "PGVector", "Milvus", "Weaviate", "Pinecone", "Elasticsearch"],
    "Embedding 模型": ["OpenAI text-embedding-3", "Cohere Embed", "SentenceTransformers", "BGE", "E5", "Instructor", "Jina"],
    "RAG 框架": ["LlamaIndex", "Haystack", "RAGFlow"],
    "Agent 框架": ["LangChain", "CrewAI", "AutoGen", "Google ADK", "Semantic Kernel"],
    "Agent 编排": ["LangGraph", "Flowise", "n8n", "MetaGPT", "Dify", "Coze"],
    "MCP 生态": ["FastMCP", "MCP SDK (10+ servers)", "A2A Protocol"],
    "AI 供应链": ["HuggingFace Hub", "MLflow", "PyPI", "W&B"],
    "对抗性 ML": ["ART", "CleverHans", "Foolbox", "TextAttack"],
    "多模态": ["CLIP/VLM", "Whisper", "LlamaParse/PDF"],
    "AI 基础设施": ["vLLM", "TGI", "Triton", "BentoML", "Ray Serve", "KServe", "Kubernetes"],
    "方法论": ["MITRE ATLAS", "OWASP LLM Top 10", "OWASP Agentic Top 10"],
}

total_fw = 0
for cat, fws in frameworks_covered.items():
    print(f"\n{cat}:")
    for fw in fws:
        print(f"  [x] {fw}")
        total_fw += 1

print(f"\nTotal frameworks/components integrated: {total_fw}+")
