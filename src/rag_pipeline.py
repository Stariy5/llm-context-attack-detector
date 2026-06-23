from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import numpy as np


class LocalRagPipeline:
    """Small local RAG pipeline for demonstration.python --version

    It uses LangChain's RecursiveCharacterTextSplitter for chunking and
    sentence-transformers for local embeddings. FAISS is used when available;
    otherwise numpy cosine search is used as a fallback.
    """

    def __init__(self, knowledge_base_dir: str | Path, config: Dict[str, Any]) -> None:
        self.knowledge_base_dir = Path(knowledge_base_dir)
        self.config = config
        self.documents = self._load_documents()
        self.chunks = self._split_documents(self.documents)
        self.model = self._load_embedding_model()
        self.embeddings = self._embed([chunk["text"] for chunk in self.chunks]) if self.chunks else np.empty((0, 1))
        self.index = self._build_faiss_index()

    def _load_documents(self) -> List[dict]:
        docs = []
        for path in sorted(self.knowledge_base_dir.glob("*.txt")):
            docs.append({"source": path.name, "text": path.read_text(encoding="utf-8")})
        return docs

    def _split_documents(self, docs: List[dict]) -> List[dict]:
        try:
            from langchain_text_splitters import RecursiveCharacterTextSplitter
        except Exception as exc:
            raise RuntimeError(
                "langchain-text-splitters is required for the RAG demo. "
                "Install dependencies from requirements.txt."
            ) from exc

        splitter = RecursiveCharacterTextSplitter(
            chunk_size=int(self.config.get("rag", {}).get("chunk_size", 500)),
            chunk_overlap=int(self.config.get("rag", {}).get("chunk_overlap", 80)),
        )
        chunks: list[dict] = []
        for doc in docs:
            for i, chunk in enumerate(splitter.split_text(doc["text"])):
                chunks.append({"source": doc["source"], "chunk_id": i, "text": chunk})
        return chunks

    def _load_embedding_model(self):
        from sentence_transformers import SentenceTransformer

        return SentenceTransformer(self.config["model"]["embedding_model"])

    def _embed(self, texts: List[str]) -> np.ndarray:
        return self.model.encode(texts, convert_to_numpy=True, normalize_embeddings=True, show_progress_bar=False).astype("float32")

    def _build_faiss_index(self):
        try:
            import faiss

            index = faiss.IndexFlatIP(self.embeddings.shape[1])
            index.add(self.embeddings)
            return index
        except Exception:
            return None

    def retrieve(self, query: str, top_k: int | None = None) -> List[dict]:
        if not self.chunks:
            return []
        k = top_k or int(self.config.get("rag", {}).get("top_k_documents", 3))
        k = min(k, len(self.chunks))
        query_vector = self._embed([query])

        if self.index is not None:
            scores, indices = self.index.search(query_vector, k)
            return [
                {**self.chunks[int(idx)], "score": float(score)}
                for idx, score in zip(indices[0], scores[0])
                if idx >= 0
            ]

        scores = np.dot(self.embeddings, query_vector[0])
        top_indices = np.argsort(scores)[::-1][:k]
        return [{**self.chunks[int(idx)], "score": float(scores[idx])} for idx in top_indices]

    @staticmethod
    def join_context(chunks: List[dict]) -> str:
        parts = []
        for chunk in chunks:
            parts.append(f"[source={chunk['source']} chunk={chunk['chunk_id']} score={chunk['score']:.3f}]\n{chunk['text']}")
        return "\n\n".join(parts)
