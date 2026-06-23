from __future__ import annotations

from schemas import DetectionDecision


class MitigationHandler:
    """Applies a minimal action model for the PoC."""

    def apply(self, decision: DetectionDecision, user_query: str, retrieved_context: str) -> dict:
        if decision.action_taken == "deny":
            return {
                "allowed": False,
                "safe_user_query": "",
                "safe_context": "",
                "message": "Запрос заблокирован защитным слоем.",
            }
        if decision.action_taken in {"drop_context", "allow_without_context"}:
            return {
                "allowed": True,
                "safe_user_query": user_query,
                "safe_context": "",
                "message": "Подозрительный внешний контекст исключён из обработки.",
            }
        return {
            "allowed": True,
            "safe_user_query": user_query,
            "safe_context": retrieved_context,
            "message": "Запрос разрешён.",
        }
