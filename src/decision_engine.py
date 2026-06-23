from __future__ import annotations

from typing import Iterable, List

from schemas import DetectionDecision, ScannerFinding


class DecisionEngine:
    def __init__(self, min_attack_risk: float = 0.50) -> None:
        self.min_attack_risk = min_attack_risk

    def decide(self, findings: Iterable[ScannerFinding], original_context: str = "") -> DetectionDecision:
        finding_list = [f for f in findings if f.is_attack and f.risk_score >= self.min_attack_risk]
        if not finding_list:
            return DetectionDecision(
                predicted_label="benign",
                predicted_is_attack=0,
                verdict="allow",
                action_taken="allow",
                risk_score=0.0,
                trigger_layer="",
                trigger_source="",
                trigger_fragment="",
                sanitized_context=original_context,
                findings=[],
            )

        # Prioritize user-query attacks because they require full blocking.
        user_attacks = [f for f in finding_list if f.source == "user_query" and f.attack_class in {"direct", "jailbreak"}]
        context_attacks = [f for f in finding_list if f.source == "retrieved_context"]

        if user_attacks:
            top = max(user_attacks, key=lambda f: f.risk_score)
            return self._decision(top, "deny", "deny", "", finding_list)

        if context_attacks:
            top = max(context_attacks, key=lambda f: f.risk_score)
            return self._decision(top, "drop_context", "drop_context", "", finding_list)

        top = max(finding_list, key=lambda f: f.risk_score)
        if top.attack_class in {"direct", "jailbreak"}:
            return self._decision(top, "deny", "deny", "", finding_list)
        return self._decision(top, "drop_context", "drop_context", "", finding_list)

    @staticmethod
    def _decision(
        top: ScannerFinding,
        verdict: str,
        action_taken: str,
        sanitized_context: str,
        findings: List[ScannerFinding],
    ) -> DetectionDecision:
        return DetectionDecision(
            predicted_label=top.attack_class,
            predicted_is_attack=1,
            verdict=verdict,
            action_taken=action_taken,
            risk_score=top.risk_score,
            trigger_layer=top.layer,
            trigger_source=top.source,
            trigger_fragment=top.trigger,
            sanitized_context=sanitized_context,
            findings=findings,
        )
