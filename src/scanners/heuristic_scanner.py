from __future__ import annotations

import re
from typing import List

from context_preprocessor import ContextPreprocessor
from schemas import ScannerFinding


SUSPICIOUS_WORDS = [
    "ignore", "disregard", "reveal", "system prompt", "developer", "hidden instruction",
    "instruction for generated answer", "model-facing", "assistant directive",
    "игнорируй", "раскрой", "системный промпт", "скрытая инструкция", "разработчика",
    "инструкция для ответа", "примечание для модели",
]

ROLE_MARKER_RE = re.compile(r"(^|\n)\s*(system|assistant|developer)\s*:\s*", re.IGNORECASE)

COMMAND_COUNT_RE = re.compile(
    r"\b(ignore|reveal|disregard|forget|bypass|pretend|act as|show|override|replace)\b|"
    r"\b(игнорируй|раскрой|забудь|обойди|покажи|представь|переопредели|замени)\b",
    re.IGNORECASE,
)

FEATURE_PATTERNS = [
    (
        "policy_override",
        r"(boundaries|constraints|restrictions|rules|policy).{0,50}(expired|obsolete|disabled|no longer apply|no longer active|not apply|replaced|waived)|"
        r"(границ|ограничен|правил|политик).{0,50}(устарел|отключен|не\s+действ|больше\s+не\s+примен|замен)",
        "мягкое переопределение политики или ограничений",
    ),
    (
        "fake_authorization",
        r"(approval|authorization|clearance|access).{0,60}(already|previously|pre[-\s]?approved|has already).{0,60}(granted|approved|authorized|allowed)|"
        r"(согласован|одобрен|разрешен|доступ).{0,60}(уже|предварительно).{0,60}(разреш|одобр|соглас|предостав)",
        "фиктивное разрешение или согласование доступа",
    ),
    (
        "internal_disclosure",
        r"(internal|hidden).{0,30}(configuration|settings|policy|instructions|details)|"
        r"(внутренн).{0,30}(настройк|конфигурац|правил|инструкц|детал)",
        "запрос на раскрытие внутренних настроек или скрытых инструкций",
    ),
    (
        "task_replacement",
        r"(replace|replacement).{0,50}(user('|’)?s request|user request|visible question|user query)|"
        r"(instead of|rather than).{0,50}(visible question|user('|’)?s request|user query)|"
        r"(замен|замещ).{0,50}(вопрос|запрос|видим)|"
        r"вместо.{0,50}(видим|пользовательск|вопрос|запрос)",
        "попытка заменить пользовательский запрос инструкцией из текста",
    ),
    (
        "model_targeted_instruction",
        r"(operational annotation|model-facing note|note to assistant|assistant directive|instruction for generated answer|generated response should|answer should)|"
        r"(рабочая\s+пометка|примечание\s+для\s+модели|для\s+языковой\s+модели|инструкция\s+для\s+ответа|ответ\s+должен)",
        "инструкция адресована модели или генерируемому ответу",
    ),
    (
        "hidden_task",
        r"hidden\s+(task|directive|instruction)|"
        r"скрыт.{0,20}(задач|команд|инструкц)",
        "скрытая задача или скрытая инструкция",
    ),
    (
        "alternative_persona",
        r"(alternate|alternative|second|internal|evaluation|hypothetical).{0,40}(assistant|persona|reviewer|version)|"
        r"(альтернативн|внутренн|оценочн|гипотетическ).{0,40}(ассистент|роль|верси|проверяющ)",
        "альтернативная роль или персона для обхода ограничений",
    ),
    (
        "unrestricted_mode",
        r"unrestricted\s+(assistant|mode|persona|answer|version)|"
        r"(роль|режим|верси).{0,40}без\s+ограничен",
        "неограниченный режим или роль",
    ),
]


class HeuristicScanner:
    layer_name = "heuristic_scanner"

    def __init__(self, risk_score: float = 0.72) -> None:
        self.risk_score = risk_score
        self.preprocessor = ContextPreprocessor()
        self._feature_patterns = [
            (name, re.compile(pattern, re.IGNORECASE | re.UNICODE), description)
            for name, pattern, description in FEATURE_PATTERNS
        ]

    def scan(self, text: str, source: str) -> List[ScannerFinding]:
        prepared = self.preprocessor.prepare(text)
        findings: list[ScannerFinding] = []
        if not prepared.normalized:
            return findings

        if prepared.has_invisible_chars:
            findings.append(self._finding("invisible unicode characters", source, "невидимые Unicode-символы"))

        for comment in prepared.html_comments:
            if any(word in comment.lower() for word in SUSPICIOUS_WORDS):
                findings.append(self._finding(comment[:200], source, "подозрительная инструкция в HTML-комментарии"))

        role_match = ROLE_MARKER_RE.search(prepared.normalized)
        if role_match:
            findings.append(self._finding(role_match.group(0).strip(), source, "служебная роль внутри текста"))

        command_count = len(COMMAND_COUNT_RE.findall(prepared.normalized))
        if command_count >= 3:
            findings.append(self._finding("multiple imperative commands", source, "избыточное число управляющих команд"))

        feature_hits = []
        for name, pattern, description in self._feature_patterns:
            match = pattern.search(prepared.normalized)
            if match:
                feature_hits.append((name, match.group(0)[:200], description))

        if feature_hits:
            findings.append(self._aggregate_feature_finding(feature_hits, source))

        return findings

    def _aggregate_feature_finding(self, feature_hits: list[tuple[str, str, str]], source: str) -> ScannerFinding:
        feature_names = {name for name, _, _ in feature_hits}
        trigger = " | ".join(trigger for _, trigger, _ in feature_hits[:3])
        descriptions = [description for _, _, description in feature_hits]

        if source == "retrieved_context":
            attack_class = "indirect"
        elif {"alternative_persona", "unrestricted_mode"} & feature_names:
            attack_class = "jailbreak"
        else:
            attack_class = "direct"

        # Несколько слабых признаков вместе дают более высокий риск.
        risk_score = 0.64 + 0.08 * len(feature_hits)

        # Некоторые пары признаков особенно характерны для prompt injection.
        strong_pairs = [
            {"policy_override", "internal_disclosure"},
            {"fake_authorization", "internal_disclosure"},
            {"model_targeted_instruction", "task_replacement"},
            {"model_targeted_instruction", "hidden_task"},
            {"alternative_persona", "unrestricted_mode"},
        ]

        if any(pair <= feature_names for pair in strong_pairs):
            risk_score += 0.12

        if source == "retrieved_context":
            risk_score += 0.05

        risk_score = min(0.95, risk_score)

        return ScannerFinding(
            layer=self.layer_name,
            is_attack=True,
            attack_class=attack_class,
            risk_score=risk_score,
            source=source,
            trigger=trigger,
            details={
                "description": "накопление эвристических признаков",
                "features": sorted(feature_names),
                "feature_descriptions": descriptions,
            },
        )

    def _finding(self, trigger: str, source: str, description: str) -> ScannerFinding:
        attack_class = "indirect" if source == "retrieved_context" else "jailbreak"
        return ScannerFinding(
            layer=self.layer_name,
            is_attack=True,
            attack_class=attack_class,
            risk_score=self.risk_score,
            source=source,
            trigger=trigger,
            details={"description": description},
        )