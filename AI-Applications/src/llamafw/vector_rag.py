"""AISecLab 向量 RAG 模块：基于 ChromaDB + SentenceTransformer 的语义检索。

支持：
- 文档分块与向量索引
- 语义搜索（中文 + 英文）
- 混合检索（语义 + 关键词）
- 知识库管理
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from .config import VECTOR_DB_PATH, KNOWLEDGE_BASE_DIR

# ── ChromaDB 集合名 ──
COLLECTION_NAME = "aiseclab_knowledge_base"
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# 全局启用标志：设为 True 后才允许初始化 ChromaDB / 下载模型
_VECTOR_RAG_ENABLED = False


class VectorRAG:
    """基于 ChromaDB + SentenceTransformer 的向量检索。"""

    def __init__(self, persist_dir: str = "") -> None:
        self._persist_dir: str = persist_dir or str(VECTOR_DB_PATH)
        self._client: Any = None
        self._collection: Any = None
        self._embedding_model: Any = None
        self._initialized: bool = False

    def _ensure_initialized(self) -> bool:
        """初始化 ChromaDB 客户端和 embedding 模型。

        需要先调用 enable() 或设置全局标志后才实际初始化。
        """
        if self._initialized:
            return True
        if not _VECTOR_RAG_ENABLED:
            return False
        try:
            import chromadb
            from chromadb.config import Settings

            self._client = chromadb.PersistentClient(
                path=self._persist_dir,
                settings=Settings(anonymized_telemetry=False),
            )
            self._collection = self._client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            self._initialized = True
            return True
        except ImportError:
            return False
        except Exception:
            return False

    _model_download_attempted: bool = False

    def _get_embedding_model(self) -> Any:
        """延迟加载 embedding 模型。

        首次调用时自动跳过下载，避免 HuggingFace 不可达导致启动卡死。
        调用 download_model() 显式触发下载。
        """
        if self._embedding_model is not None:
            return self._embedding_model
        if not self._model_download_attempted:
            print("[VectorRAG] ℹ embedding 模型尚未下载，向量 RAG 功能暂不可用。"
                  " 调用 download_model() 下载模型，"
                  " 或设置 HF_ENDPOINT=https://hf-mirror.com 使用国内镜像加速。")
            self._model_download_attempted = True
        return None

    def download_model(self, timeout: int = 300) -> bool:
        """显式下载 embedding 模型。

        调用此方法触发模型下载。如果已有缓存则直接加载。
        国内用户建议提前设置: export HF_ENDPOINT=https://hf-mirror.com
        """
        if self._embedding_model is not None:
            print("[VectorRAG] ✅ 模型已加载，无需重复下载。")
            return True
        try:
            import threading
            from sentence_transformers import SentenceTransformer

            result: list[Any] = []
            error: list[Exception | None] = [None]

            print(f"[VectorRAG] ⏳ 正在下载/加载 embedding 模型 {EMBEDDING_MODEL_NAME} ...")

            def _load():
                try:
                    result.append(SentenceTransformer(EMBEDDING_MODEL_NAME))
                except Exception as e:
                    error[0] = e

            t = threading.Thread(target=_load, daemon=True)
            t.start()
            t.join(timeout=timeout)

            if t.is_alive():
                print(f"[VectorRAG] ⚠ 模型下载超时（{timeout}s），"
                      f" 可设置 HF_ENDPOINT=https://hf-mirror.com 使用镜像后重试。")
                return False

            if error[0]:
                print(f"[VectorRAG] ⚠ 模型加载失败: {error[0]}")
                return False

            if result:
                self._embedding_model = result[0]
                self._model_download_attempted = True
                print("[VectorRAG] ✅ 模型加载成功，向量 RAG 已就绪。")
                return True
            return False
        except Exception as e:
            print(f"[VectorRAG] ⚠ 模型加载异常: {e}")
            return False

    def _embed_texts(self, texts: list[str]) -> list[list[float]] | None:
        """将文本列表转为向量。"""
        model = self._get_embedding_model()
        if model is None:
            return None
        embeddings = model.encode(texts, show_progress_bar=False, normalize_embeddings=True)
        return [emb.tolist() for emb in embeddings]

    def _embed_query(self, query: str) -> list[float] | None:
        """将查询文本转为向量。"""
        emb = self._embed_texts([query])
        return emb[0] if emb else None

    # ═══════════════════════════════════════════════════════════
    #  索引管理
    # ═══════════════════════════════════════════════════════════

    def index_documents(self, documents: list[dict[str, Any]]) -> int:
        """将文档列表索引到 ChromaDB。

        Args:
            documents: [{"id": str, "title": str, "content": str, "metadata": dict}, ...]

        Returns:
            成功索引的文档数
        """
        if not self._ensure_initialized():
            return 0

        model = self._get_embedding_model()
        if model is None:
            return 0

        texts = []
        metadatas = []
        ids = []

        for doc in documents:
            doc_id = doc.get("id", hashlib.md5(doc["content"].encode()).hexdigest()[:16])
            title = doc.get("title", "")
            # 将 content 按段落分块
            paragraphs = self._split_text(doc.get("content", ""), max_chars=500)
            for i, para in enumerate(paragraphs):
                if not para.strip():
                    continue
                chunk_id = f"{doc_id}_{i}"
                texts.append(para)
                metadatas.append({
                    "doc_id": doc_id,
                    "title": title,
                    "chunk_index": i,
                    "category": doc.get("metadata", {}).get("category", ""),
                    "classification": doc.get("metadata", {}).get("classification", "public"),
                    **doc.get("metadata", {}),
                })
                ids.append(chunk_id)

        if not texts:
            return 0

        embeddings = model.encode(texts, show_progress_bar=False, normalize_embeddings=True)

        # 批量添加
        batch_size = 100
        total_added = 0
        for start in range(0, len(texts), batch_size):
            end = min(start + batch_size, len(texts))
            self._collection.add(
                ids=ids[start:end],
                embeddings=[emb.tolist() for emb in embeddings[start:end]],
                documents=texts[start:end],
                metadatas=metadatas[start:end],
            )
            total_added += (end - start)

        return total_added

    def _split_text(self, text: str, max_chars: int = 500) -> list[str]:
        """将文本按段落分块，确保每块不超过 max_chars。"""
        paragraphs = text.split("\n")
        chunks: list[str] = []
        current = ""

        for para in paragraphs:
            if len(current) + len(para) > max_chars and current:
                chunks.append(current.strip())
                current = para
            else:
                current = current + "\n" + para if current else para

        if current.strip():
            chunks.append(current.strip())

        return chunks if chunks else [text]

    # ═══════════════════════════════════════════════════════════
    #  检索
    # ═══════════════════════════════════════════════════════════

    def search(self, query: str, n_results: int = 5, classification_filter: str | None = None) -> list[dict[str, Any]]:
        """语义搜索。

        Args:
            query: 搜索查询文本
            n_results: 返回结果数
            classification_filter: 可选的分类过滤 (public/internal/confidential)

        Returns:
            [{doc_id, title, content, chunk_index, category, classification, distance}, ...]
        """
        if not self._ensure_initialized():
            return []

        query_embedding = self._embed_query(query)
        if query_embedding is None:
            return []

        where_filter = None
        if classification_filter:
            where_filter = {"classification": classification_filter}

        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=where_filter,
        )

        formatted: list[dict[str, Any]] = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                distance = results["distances"][0][i] if results.get("distances") else 0
                formatted.append({
                    "doc_id": metadata.get("doc_id", doc_id),
                    "title": metadata.get("title", ""),
                    "content": results["documents"][0][i] if results.get("documents") else "",
                    "chunk_index": metadata.get("chunk_index", 0),
                    "category": metadata.get("category", ""),
                    "classification": metadata.get("classification", "public"),
                    "distance": round(distance, 4),
                    "score": round(1.0 - min(distance, 1.0), 4),  # cosine distance → similarity
                })

        return formatted

    def hybrid_search(
        self, query: str, n_results: int = 5, keyword_weight: float = 0.3
    ) -> list[dict[str, Any]]:
        """混合检索：语义搜索 + 关键词匹配。

        Args:
            query: 搜索查询
            n_results: 返回结果数
            keyword_weight: 关键词权重 (0-1)，越高越偏向关键词匹配

        Returns:
            [{doc_id, title, content, score, ...}, ...]
        """
        semantic_results = self.search(query, n_results * 2)

        if not semantic_results:
            return []

        # 关键词匹配
        query_lower = query.lower()
        keywords = set(query_lower.split())

        for result in semantic_results:
            content_lower = result["content"].lower()
            keyword_matches = sum(1 for kw in keywords if kw in content_lower)
            keyword_score = min(keyword_matches / max(len(keywords), 1), 1.0)
            # 混合分数
            result["score"] = round(
                (1 - keyword_weight) * result["score"] + keyword_weight * keyword_score, 4
            )

        # 按混合分数排序
        semantic_results.sort(key=lambda x: x["score"], reverse=True)
        return semantic_results[:n_results]

    # ═══════════════════════════════════════════════════════════
    #  知识库管理
    # ═══════════════════════════════════════════════════════════

    def get_collection_stats(self) -> dict[str, Any]:
        """获取向量库统计信息。"""
        if not self._ensure_initialized():
            return {"initialized": False, "count": 0}

        count = self._collection.count()
        return {"initialized": True, "count": count, "name": COLLECTION_NAME}

    def clear_collection(self) -> int:
        """清空向量库（删除所有文档）。"""
        if not self._ensure_initialized():
            return 0

        count = self._collection.count()
        if count > 0:
            from chromadb.api.types import QueryResult
            # 获取所有 IDs 并删除
            try:
                all_ids = self._collection.get()["ids"]
                if all_ids:
                    self._collection.delete(ids=all_ids)
            except Exception:
                # Fallback: recreate collection
                self._client.delete_collection(COLLECTION_NAME)
                self._collection = self._client.create_collection(
                    name=COLLECTION_NAME,
                    metadata={"hnsw:space": "cosine"},
                )
            return count
        return 0


# ── 模块级单例 ──

_rag_instance: VectorRAG | None = None


def get_rag() -> VectorRAG:
    global _rag_instance
    if _rag_instance is None:
        _rag_instance = VectorRAG()
    return _rag_instance


def enable_rag() -> bool:
    """启用向量 RAG 并下载模型。

    Returns True 表示启用成功（含 ChromaDB 初始化 + embedding 模型下载）。
    国内用户建议提前设置: HF_ENDPOINT=https://hf-mirror.com
    """
    global _VECTOR_RAG_ENABLED
    _VECTOR_RAG_ENABLED = True
    rag = get_rag()
    if rag._ensure_initialized():
        return rag.download_model()
    print("[VectorRAG] ⚠ ChromaDB 初始化失败，向量 RAG 暂不可用。")
    return False


# ── 知识库内容 ──

def load_knowledge_base_files() -> list[dict[str, Any]]:
    """从 knowledge_base/ 目录加载 Markdown 知识库文件。"""
    documents: list[dict[str, Any]] = []

    if not KNOWLEDGE_BASE_DIR.exists():
        return documents

    for md_file in KNOWLEDGE_BASE_DIR.rglob("*.md"):
        try:
            content = md_file.read_text(encoding="utf-8")
            if not content.strip():
                continue

            # 从路径推断分类
            relative = md_file.relative_to(KNOWLEDGE_BASE_DIR)
            parts = relative.parts
            category = parts[0] if len(parts) > 1 else "general"
            subcategory = parts[1] if len(parts) > 2 else ""

            # 解析 Front Matter (简单实现)
            title = md_file.stem
            classification = "public"

            first_line = content.split("\n")[0] if content else ""
            if "---" in content.split("\n", 2)[0:2]:
                # 有 front matter
                sections = content.split("---", 2)
                if len(sections) >= 3:
                    fm = sections[1]
                    for line in fm.strip().split("\n"):
                        if ":" in line:
                            key, _, val = line.partition(":")
                            key = key.strip()
                            val = val.strip().strip('"').strip("'")
                            if key == "title":
                                title = val
                            elif key == "classification":
                                classification = val
                    content = sections[2]

            documents.append({
                "id": f"kb_{md_file.stem}",
                "title": title,
                "content": content.strip(),
                "metadata": {
                    "category": category,
                    "subcategory": subcategory,
                    "classification": classification,
                    "source": str(relative),
                    "document_type": "manual" if "manual" in str(relative).lower() else
                                     "policy" if "policy" in str(relative).lower() else
                                     "faq" if "faq" in str(relative).lower() else "article",
                },
            })
        except Exception:
            continue

    return documents


def index_knowledge_base(rag: VectorRAG | None = None) -> dict[str, Any]:
    """索引 knowledge_base/ 目录下的所有文档到向量库。

    Returns:
        {success: bool, indexed_count: int, total_documents: int, message: str}
    """
    if rag is None:
        rag = get_rag()

    documents = load_knowledge_base_files()
    if not documents:
        return {"success": False, "indexed_count": 0, "total_documents": 0, "message": "未找到知识库文件"}

    # 清空旧索引
    rag.clear_collection()

    # 索引新文档
    indexed = rag.index_documents(documents)
    return {
        "success": True,
        "indexed_count": indexed,
        "total_documents": len(documents),
        "message": f"成功索引 {indexed} 个文本块（来自 {len(documents)} 个文档）",
    }
