"""验证 AI-300 Frameworks 模块"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from llamafw.ai300_frameworks import FRAMEWORKS_MODULES

print(f"Loaded {len(FRAMEWORKS_MODULES)} framework modules:\n")
for m in FRAMEWORKS_MODULES:
    tasks = len(m.get("challenge", {}).get("tasks", []))
    print(f"  [{m['id']}] {m['title']}")
    print(f"       domain: {m['domain']} | tasks: {tasks} | route: {m['route']}")
    print(f"       flag: {m.get('flag', '(none)')}")
print(f"\nTotal: {len(FRAMEWORKS_MODULES)} modules")

# 验证所有 handler 可导入
from llamafw.ai300_frameworks import (
    handle_qdrant_collections, handle_qdrant_search, handle_qdrant_scroll,
    handle_faiss_info, handle_faiss_search,
    handle_pgvector_query,
    handle_milvus_collections, handle_weaviate_graphql,
    handle_emb_models, handle_emb_inversion,
    handle_llamaindex_pipelines, handle_haystack_query, handle_ragflow_datasets,
    handle_crewai_crews, handle_autogen_chat, handle_adk_agents, handle_sk_plugins,
    handle_dify_apps, handle_coze_bots, handle_metagpt_startup,
    handle_langgraph_graphs, handle_flowise_flows, handle_n8n_workflows,
    handle_mcp_ext_servers, handle_a2a_agent_card,
    handle_hf_models, handle_hf_scan_pickle, handle_mlflow_experiments, handle_mlflow_deploy, handle_pypi_scan,
    handle_adv_models, handle_adv_attack, handle_model_extraction,
    handle_multimodal_models, handle_image_injection, handle_pdf_injection, handle_audio_injection,
    handle_vllm_models, handle_vllm_metrics, handle_tgi_info, handle_triton_models,
    handle_bentoml_services, handle_ray_deployments, handle_kserve_services, handle_k8s_ai_resources,
    handle_methodology,
)
print("\nAll handlers imported successfully!")

# 测试几个关键函数
print("\n--- Testing Qdrant ---")
r = handle_qdrant_collections()
print(f"  Collections: {[c['name'] for c in r['result']['collections']]}")

r = handle_qdrant_search("enterprise_kb", q="flag")
print(f"  Search hits: {len(r['result'])}")

# 测试 Agent
print("\n--- Testing CrewAI ---")
r = handle_crewai_crews()
print(f"  Crews: {list(r['crews'].keys())}")

# 测试供应链
print("\n--- Testing Supply Chain ---")
r = handle_hf_scan_pickle("malicious-user/trojaned-gpt2")
print(f"  Pickle scan: risk={r['risk']}, flag={r.get('flag')}")

# 测试对抗 ML
print("\n--- Testing Adversarial ML ---")
r = handle_adv_models()
print(f"  Models: {list(r['models'].keys())}")
print(f"  Frameworks: {list(r['frameworks'].keys())}")

# 测试基础设施
print("\n--- Testing Infrastructure ---")
r = handle_vllm_models()
print(f"  vLLM models: {list(r['models'].keys())}")
r = handle_k8s_ai_resources()
print(f"  K8s flag: {r.get('flag')}")

print("\nAll tests passed!")
