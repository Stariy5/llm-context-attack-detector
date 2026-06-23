from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


@dataclass
class ScannerFinding:
    layer: str
    is_attack: bool
    attack_class: str
    risk_score: float
    source: str
    trigger: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionDecision:
    predicted_label: str
    predicted_is_attack: int
    verdict: str
    action_taken: str
    risk_score: float
    trigger_layer: str
    trigger_source: str
    trigger_fragment: str
    sanitized_context: str
    findings: List[ScannerFinding] = field(default_factory=list)

    def to_result_dict(self) -> Dict[str, Any]:
        return {
            "predicted_label": self.predicted_label,
            "predicted_is_attack": self.predicted_is_attack,
            "verdict": self.verdict,
            "action_taken": self.action_taken,
            "risk_score": round(float(self.risk_score), 4),
            "trigger_layer": self.trigger_layer,
            "trigger_source": self.trigger_source,
            "trigger_fragment": self.trigger_fragment,
        }
