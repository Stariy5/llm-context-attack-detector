from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from context_preprocessor import ContextPreprocessor
from decision_engine import DecisionEngine
from mitigation_handler import MitigationHandler
from scanners.heuristic_scanner import HeuristicScanner
from scanners.rule_scanner import RuleScanner
from scanners.similarity_scanner import SimilarityScanner
from schemas import DetectionDecision, ScannerFinding


class AttackDetector:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.preprocessor = ContextPreprocessor()
        self.rule_scanner = RuleScanner()
        self.heuristic_scanner = HeuristicScanner(
            risk_score=float(config.get("risk", {}).get("heuristic_risk", 0.72))
        )
        self.similarity_scanner = SimilarityScanner(
            attack_vault_path=Path(config["paths"]["attack_vault"]),
            embedding_model_name=config["model"]["embedding_model"],
            threshold=float(config["model"].get("similarity_threshold", 0.58)),
            top_k=int(config["model"].get("top_k_attack_matches", 3)),
        )
        self.decision_engine = DecisionEngine(
            min_attack_risk=float(config.get("risk", {}).get("min_attack_risk", 0.50))
        )
        self.mitigation_handler = MitigationHandler()

    def detect(self, user_query: str, retrieved_context: str = "") -> DetectionDecision:
        findings: list[ScannerFinding] = []
        targets = [
            ("user_query", user_query or ""),
            ("retrieved_context", retrieved_context or ""),
        ]
        for source, text in targets:
            prepared = self.preprocessor.prepare(text)
            normalized_text = prepared.normalized
            findings.extend(self.rule_scanner.scan(normalized_text, source))
            findings.extend(self.heuristic_scanner.scan(normalized_text, source))
            findings.extend(self.similarity_scanner.scan(normalized_text, source))

        return self.decision_engine.decide(findings, original_context=retrieved_context or "")

    def process(self, user_query: str, retrieved_context: str = "") -> dict:
        decision = self.detect(user_query, retrieved_context)
        mitigation = self.mitigation_handler.apply(decision, user_query, retrieved_context)
        return {
            "decision": decision,
            "mitigation": mitigation,
        }
