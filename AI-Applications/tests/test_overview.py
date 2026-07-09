"""验证 AI-300 Frameworks 元数据总览"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from llamafw.ai300_frameworks import handle_frameworks_overview, FRAMEWORKS_METADATA

# 测试 overview handler
overview = handle_frameworks_overview()
assert overview["status"] == "ok", f"Expected ok, got {overview['status']}"
print("[OK] Overview handler returns ok")

# 验证所有分类存在
expected_categories = [
    "api_interfaces", "vector_databases", "embedding_models",
    "rag_frameworks", "agent_frameworks", "mcp_ecosystem",
    "supply_chain", "adversarial_ml", "multimodal",
    "ai_infrastructure", "methodology_frameworks"
]
for cat in expected_categories:
    assert cat in FRAMEWORKS_METADATA, f"Missing category: {cat}"
    print(f"  [OK] Category '{cat}' present")

# 验证 API 接口子分类
api = FRAMEWORKS_METADATA["api_interfaces"]
for sub in ["openai_compatible", "claude_compatible", "grpc_protobuf", "rest_api_custom", "sdk_based"]:
    assert sub in api, f"Missing API interface type: {sub}"
    count = len(api[sub].get("frameworks_implementing", api[sub].get("frameworks_using", [])))
    print(f"    [OK] {sub}: {count} frameworks")

# 验证向量数据库数量
vdb = FRAMEWORKS_METADATA["vector_databases"]["databases"]
print(f"\n[OK] Vector DBs: {len(vdb)} databases")
for db in vdb:
    print(f"    - {db['name']}: {db['type']}, proto={db.get('protocols', 'N/A')}, auth={db.get('auth_methods', 'N/A')}")

# 验证 Agent 框架数量
agents = FRAMEWORKS_METADATA["agent_frameworks"]["frameworks"]
print(f"\n[OK] Agent Frameworks: {len(agents)} frameworks")
for a in agents:
    print(f"    - {a['name']}: {a['type']} (api: {a.get('api_type', 'N/A')})")

# 验证 MCP servers
mcp = FRAMEWORKS_METADATA["mcp_ecosystem"]
print(f"\n[OK] MCP Servers: {len(mcp['mcp_servers'])} servers")
for s in mcp["mcp_servers"]:
    print(f"    - {s['name']}: {len(s['tools'])} tools, risk: {s['risk'][:50]}")

# 验证供应链平台
sc = FRAMEWORKS_METADATA["supply_chain"]["platforms"]
print(f"\n[OK] Supply Chain: {len(sc)} platforms")
for p in sc:
    print(f"    - {p['name']}: {p.get('type', 'N/A')}")

# 验证对抗ML框架
adv = FRAMEWORKS_METADATA["adversarial_ml"]["frameworks"]
print(f"\n[OK] Adversarial ML: {len(adv)} frameworks")
for a in adv:
    print(f"    - {a['name']} ({a['org']}): {a['version']}")

# 验证多模态模型数量
mm = FRAMEWORKS_METADATA["multimodal"]["models"]
total_mm = sum(len(v) for v in mm.values())
print(f"\n[OK] Multimodal Models: {total_mm} models")
for cat, models in mm.items():
    print(f"    - {cat}: {len(models)} models")

# 验证AI基础设施
infra = FRAMEWORKS_METADATA["ai_infrastructure"]["platforms"]
print(f"\n[OK] AI Infrastructure: {len(infra)} platforms")
for i in infra:
    print(f"    - {i['name']}: {i.get('api_type', 'N/A')[:60]}")

# 验证方法论框架
meth = FRAMEWORKS_METADATA["methodology_frameworks"]["frameworks"]
print(f"\n[OK] Methodology: {len(meth)} frameworks")
for m in meth:
    print(f"    - {m['name']} v{m['version']}")

# 统计嵌入模型
emb = FRAMEWORKS_METADATA["embedding_models"]["categories"]
total_emb_models = sum(len(c["models"]) for c in emb)
print(f"\n[OK] Embedding Models: {len(emb)} providers, {total_emb_models} models")

# 统计 RAG 框架
rag = FRAMEWORKS_METADATA["rag_frameworks"]["frameworks"]
print(f"[OK] RAG Frameworks: {len(rag)} frameworks")

print(f"\n{'='*60}")
print(f"All metadata validations passed!")
print(f"Total metadata size: {len(json.dumps(FRAMEWORKS_METADATA)):,} chars")
