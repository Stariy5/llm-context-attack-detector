from __future__ import annotations

from pathlib import Path
from typing import List, Tuple
import re

import numpy as np
import pandas as pd
from schemas import ScannerFinding


class SimilarityScanner:
    layer_name = "similarity_scanner"

    def __init__(
        self,
        attack_vault_path: str | Path,
        embedding_model_name: str,
        threshold: float = 0.58,
        top_k: int = 3,
    ) -> None:
        self.attack_vault_path = Path(attack_vault_path)
        self.embedding_model_name = embedding_model_name
        self.threshold = threshold
        self.top_k = top_k
        self.backend = "not_initialized"
        self.model = None
        self.index = None
        self.vault = self._load_vault()
        self.embeddings = self._build_embeddings()
        self._build_index()

    def _load_vault(self) -> pd.DataFrame:
        if not self.attack_vault_path.exists():
            raise FileNotFoundError(f"Attack vault not found: {self.attack_vault_path}")
        df = pd.read_csv(self.attack_vault_path)
        required = {"attack_class", "language", "text"}
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"Attack vault is missing columns: {missing}")
        return df.fillna("")

    def _build_embeddings(self) -> np.ndarray:
        try:
            from sentence_transformers import SentenceTransformer

            self.model = SentenceTransformer(self.embedding_model_name)
            vectors = self.model.encode(
                self.vault["text"].tolist(),
                convert_to_numpy=True,
                normalize_embeddings=True,
                show_progress_bar=False,
            )
            self.backend = "sentence_transformers"
            return vectors.astype("float32")
        except Exception as exc:
            # Fallback is intentionally simple: the project should still run even if
            # the embedding model cannot be downloaded during the first launch.
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.preprocessing import normalize

            self.model = TfidfVectorizer(ngram_range=(1, 2), lowercase=True)
            matrix = self.model.fit_transform(self.vault["text"].tolist())
            self.backend = f"tfidf_fallback: {type(exc).__name__}"
            return normalize(matrix).toarray().astype("float32")

    def _build_index(self) -> None:
        try:
            import faiss

            dim = self.embeddings.shape[1]
            self.index = faiss.IndexFlatIP(dim)
            self.index.add(self.embeddings)
            self.backend = f"{self.backend}+faiss"
        except Exception as exc:
            self.index = None
            self.backend = f"{self.backend}+numpy_fallback: {type(exc).__name__}"

    def _encode_query(self, text: str) -> np.ndarray:
        if "sentence_transformers" in self.backend:
            vector = self.model.encode(
                [text], convert_to_numpy=True, normalize_embeddings=True, show_progress_bar=False
            ).astype("float32")
            return vector

        from sklearn.preprocessing import normalize

        matrix = self.model.transform([text])
        return normalize(matrix).toarray().astype("float32")

    def _search(self, query_vector: np.ndarray) -> List[Tuple[int, float]]:
        k = min(self.top_k, len(self.vault))
        if self.index is not None:
            distances, indices = self.index.search(query_vector, k)
            return [(int(idx), float(score)) for idx, score in zip(indices[0], distances[0]) if idx >= 0]

        scores = np.dot(self.embeddings, query_vector[0])
        top_indices = np.argsort(scores)[::-1][:k]
        return [(int(idx), float(scores[idx])) for idx in top_indices]

    @staticmethod
    def _is_safe_educational_query(text: str, source: str) -> bool:
        if source != "user_query":
            return False

        lowered = text.lower()

        educational_patterns = [
            r"\bexplain\b",
            r"\bdefinition\b",
            r"\bacademic\b",
            r"\bwhy\b",
            r"\bwithout providing instructions\b",
            r"объясни",
            r"что такое",
            r"почему",
            r"составь список признаков",
            r"метод[аыов]* защиты",
            r"раздел отч[её]та",
            r"учебн",
            r"исследовательск",
        ]

        dangerous_imperatives = [
            r"\bignore\b",
            r"\bdisregard\b",
            r"\breveal\b",
            r"\bprint\b",
            r"\bshow\b",
            r"\bdisable\b",
            r"\bbypass\b",
            r"игнорируй",
            r"забудь",
            r"раскрой",
            r"покажи",
            r"выведи",
            r"отключи",
            r"обойди",
            r"проигнорируй",
        ]

        has_educational_intent = any(re.search(pattern, lowered) for pattern in educational_patterns)
        has_dangerous_imperative = any(re.search(pattern, lowered) for pattern in dangerous_imperatives)

        return has_educational_intent and not has_dangerous_imperative

    @staticmethod
    def _segments(text: str) -> list[str]:
        cleaned = text.strip()
        if not cleaned:
            return []

        parts = [cleaned]

        # Разбиение по строкам, HTML-комментариям и границам предложений.
        rough_parts = re.split(
            r"(\n+|<!--|-->|(?<=[.!?])\s+|(?<=[。！？])\s*)",
            cleaned,
            flags=re.IGNORECASE | re.UNICODE,
        )

        for part in rough_parts:
            part = part.strip()
            if 20 <= len(part) <= 600:
                parts.append(part)

        # Дополнительно берём короткие окна из соседних предложений.
        sentence_parts = [
            p.strip()
            for p in re.split(r"(?<=[.!?])\s+|\n+", cleaned)
            if p.strip()
        ]

        for i in range(len(sentence_parts) - 1):
            window = f"{sentence_parts[i]} {sentence_parts[i + 1]}".strip()
            if 20 <= len(window) <= 800:
                parts.append(window)

        # Удаление дублей с сохранением порядка.
        result = []
        seen = set()
        for part in parts:
            key = part.lower()
            if key not in seen:
                result.append(part)
                seen.add(key)

        return result

    @staticmethod
    def _is_safe_educational_query(text: str) -> bool:
        lowered = text.lower()

        educational_markers = [
            "explain", "define", "definition", "describe", "compare", "discuss",
            "report", "metrics", "detect", "detection", "defensive", "risks",
            "объясни", "опиши", "сравни", "определение", "отчёт", "отчет",
            "метрик", "обнаруж", "защит", "риски", "признаки",
        ]

        security_topics = [
            "prompt injection", "indirect prompt injection", "jailbreak",
            "system prompt", "retrieved context", "rag",
            "системный prompt", "системный промпт", "инъекц", "джейлбрейк",
            "внешний контекст", "retrieved context",
        ]

        dangerous_connectors = [
            " but ignore", " then ignore", " and ignore", " but reveal",
            " then reveal", " and reveal", " but bypass", " then bypass",
            " но игнорируй", " затем игнорируй", " и игнорируй",
            " но раскрой", " затем раскрой", " и раскрой",
        ]

        has_educational_marker = any(marker in lowered for marker in educational_markers)
        has_security_topic = any(topic in lowered for topic in security_topics)
        has_dangerous_connector = any(connector in lowered for connector in dangerous_connectors)

        return has_educational_marker and has_security_topic and not has_dangerous_connector

    def scan(self, text: str, source: str) -> List[ScannerFinding]:
        if not text or len(text.strip()) < 10:
            return []

        if source == "user_query" and self._is_safe_educational_query(text):
            return []

        findings: list[ScannerFinding] = []
        segments = self._segments(text)

        effective_threshold = self.threshold
        if source == "retrieved_context":
            # Внешний контекст в RAG-сценарии должен быть менее терпим к инструкциям,
            # адресованным модели, поэтому порог немного ниже.
            effective_threshold = max(0.52, self.threshold - 0.04)

        for segment in segments:
            query_vector = self._encode_query(segment)
            matches = self._search(query_vector)

            for idx, score in matches:
                if score < effective_threshold:
                    continue

                row = self.vault.iloc[idx]
                attack_class = str(row["attack_class"])

                if source == "retrieved_context" and attack_class in {"direct", "jailbreak"}:
                    attack_class = "indirect"

                findings.append(
                    ScannerFinding(
                        layer=self.layer_name,
                        is_attack=True,
                        attack_class=attack_class,
                        risk_score=min(0.99, max(0.0, score)),
                        source=source,
                        trigger=str(row["text"])[:200],
                        details={
                            "similarity": round(score, 4),
                            "matched_attack_class": str(row["attack_class"]),
                            "backend": self.backend,
                            "matched_segment": segment[:300],
                            "threshold": effective_threshold,
                        },
                    )
                )

        # Убираем дубли: если один и тот же класс сработал несколько раз,
        # оставляем самое сильное срабатывание.
        deduplicated: dict[tuple[str, str], ScannerFinding] = {}
        for finding in findings:
            key = (finding.attack_class, finding.source)
            existing = deduplicated.get(key)
            if existing is None or finding.risk_score > existing.risk_score:
                deduplicated[key] = finding

        return list(deduplicated.values())