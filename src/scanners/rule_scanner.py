from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List

from schemas import ScannerFinding


@dataclass(frozen=True)
class Rule:
    attack_class: str
    pattern: str
    risk_score: float
    description: str


class RuleScanner:
    layer_name = "rule_scanner"

    def __init__(self) -> None:
        self.rules: list[Rule] = [
            Rule("direct", r"ignore\s+(all\s+)?previous\s+instructions", 0.95, "instruction override"),
            Rule("direct", r"disregard\s+(all\s+)?previous\s+rules", 0.95, "rule override"),
            Rule("direct", r"forget\s+(your\s+)?rules", 0.90, "forget rules"),
            Rule("direct", r"show\s+(me\s+)?(the\s+)?system\s+prompt", 0.96, "system prompt leakage"),
            Rule("direct", r"reveal\s+(the\s+)?(hidden\s+)?system\s+prompt", 0.96, "system prompt leakage"),
            Rule("direct", r"developer\s+instructions", 0.88, "developer instruction leakage"),
            Rule("direct", r"confidential\s+prompt", 0.92, "confidential prompt leakage"),
            Rule("direct", r"bypass\s+(the\s+)?(security\s+)?policy", 0.92, "policy bypass"),
            Rule("direct", r"игнорируй\s+.*предыдущ", 0.95, "instruction override ru"),
            Rule("direct", r"забудь\s+.*правил", 0.90, "forget rules ru"),
            Rule("direct", r"раскро[йи]\s+.*системн", 0.96, "system prompt leakage ru"),
            Rule("direct", r"раскро[йи]\s+.*скрыт.*инструкц", 0.94, "hidden instruction leakage ru"),
            Rule("direct", r"покажи\s+.*системн", 0.96, "system prompt leakage ru"),
            Rule("direct", r"обойди\s+.*ограничен", 0.92, "policy bypass ru"),
            Rule("direct", r"не\s+следуй\s+.*политик", 0.90, "policy override ru"),

            Rule("jailbreak", r"\bDAN\b", 0.97, "DAN jailbreak"),
            Rule("jailbreak", r"developer\s+mode", 0.95, "developer mode jailbreak"),
            Rule("jailbreak", r"uncensored\s+model", 0.92, "uncensored role"),
            Rule("jailbreak", r"without\s+restrictions", 0.88, "unrestricted role"),
            Rule("jailbreak", r"roleplay\s+as\s+a\s+system\s+without\s+restrictions", 0.90, "roleplay jailbreak"),
            Rule("jailbreak", r"режим\s+разработчика", 0.95, "developer mode ru"),
            Rule("jailbreak", r"без\s+ограничен", 0.88, "unrestricted ru"),
            Rule("jailbreak", r"без\s+цензур", 0.90, "uncensored ru"),
            Rule("jailbreak", r"политик[аи]\s+безопасности\s+не\s+существует", 0.90, "policy denial ru"),
            Rule("jailbreak", r"игнорируй\s+модерац", 0.90, "ignore moderation ru"),
            Rule("jailbreak", r"role[-\s]?play.*unrestricted\s+assistant", 0.92, "role-play unrestricted assistant"),
            Rule("jailbreak", r"without\s+applying\s+(any\s+)?safety\s+policy", 0.92, "disable safety policy"),
            Rule("jailbreak", r"simulate\s+a\s+second\s+assistant.*not\s+bound", 0.92, "second assistant jailbreak"),
            Rule("jailbreak", r"ответь\s+двумя\s+частями.*не\s+подчиняется\s+правил", 0.92,
                 "two-part unsafe answer ru"),
            Rule("jailbreak", r"верси[яи]\s+модели.*не\s+подчиняется\s+правил", 0.92, "unrestricted model version ru"),

            Rule("indirect", r"hidden\s+instruction", 0.90, "hidden instruction"),
            Rule("indirect", r"instruction\s+for\s+(the\s+)?assistant", 0.90, "assistant-targeted instruction"),
            Rule("indirect", r"assistant\s+must", 0.88, "assistant must directive"),
            Rule("indirect", r"when\s+answering,?\s+disregard", 0.90, "document instruction override"),
            Rule("indirect", r"ignore\s+the\s+user", 0.90, "ignore user directive"),
            Rule("indirect", r"system\s*:\s*", 0.82, "role marker"),
            Rule("indirect", r"developer\s*:\s*", 0.82, "role marker"),
            Rule("indirect", r"скрытая\s+инструкц", 0.90, "hidden instruction ru"),
            Rule("indirect", r"при\s+ответе\s+не\s+учитывай", 0.90, "document instruction override ru"),
            Rule("indirect", r"ассистент\s+должен", 0.88, "assistant must ru"),
            Rule("indirect", r"игнорируй\s+пользовател", 0.90, "ignore user ru"),
            Rule("indirect", r"\bassistant\s*:\s*", 0.84, "assistant role marker"),
            Rule("indirect", r"important\s+for\s+the\s+model", 0.88, "model-targeted document instruction"),
            Rule("indirect", r"when\s+responding.*ignore", 0.90, "responding-time instruction override"),
            Rule("indirect", r"follow\s+this\s+injected\s+instruction", 0.92, "injected instruction marker"),
            Rule("indirect", r"disregard\s+the\s+user", 0.90, "disregard user directive"),
            Rule("indirect", r"disable\s+all\s+safeguards", 0.90, "disable safeguards directive"),
            Rule("indirect", r"служебн.*заметк.*ассистент", 0.88, "assistant service note ru"),
            Rule("indirect", r"игнорируй\s+.*пользовател", 0.90, "ignore user ru extended"),
            Rule("indirect", r"выведи\s+.*системн.*промпт", 0.92, "print system prompt ru"),
        ]
        # Generalized rules for soft prompt injection and indirect context attacks.
        # These rules describe attack families rather than exact test-case phrases.
        self.rules.extend([
            # Soft direct override / fake authorization
            Rule("direct", r"(boundaries|constraints|restrictions|rules|policy).{0,50}(expired|obsolete|disabled|no longer apply|no longer active|not apply|replaced|waived)", 0.86, "soft policy override"),
            Rule("direct", r"(operational|current|existing).{0,30}(boundaries|constraints|restrictions|rules|policy).{0,50}(expired|obsolete|disabled|not apply)", 0.86, "soft operational override"),
            Rule("direct", r"(approval|authorization|clearance|access).{0,60}(already|previously|pre[-\s]?approved|has already).{0,60}(granted|approved|authorized|allowed)", 0.88, "fake authorization"),
            Rule("direct", r"(internal|hidden).{0,30}(configuration|settings|policy|instructions|details)", 0.88, "internal configuration disclosure"),
            Rule("direct", r"higher\s+priority\s+instruction", 0.88, "higher priority instruction override"),
            Rule("direct", r"override\s+(the\s+)?(current\s+)?(assistant\s+)?behavior", 0.88, "assistant behavior override"),

            # Russian soft direct override / fake authorization
            Rule("direct", r"(границ|ограничен|правил|политик).{0,50}(устарел|отключен|не\s+действ|больше\s+не\s+примен|замен)", 0.86, "soft policy override ru"),
            Rule("direct", r"(текущ|рабоч|операцион).{0,30}(границ|ограничен|правил|политик).{0,50}(устарел|отключен|не\s+действ)", 0.86, "soft operational override ru"),
            Rule("direct", r"(согласован|одобрен|разрешен|доступ).{0,60}(уже|предварительно).{0,60}(разреш|одобр|соглас|предостав)", 0.88, "fake authorization ru"),
            Rule("direct", r"(внутренн).{0,30}(настройк|конфигурац|правил|инструкц|детал)", 0.88, "internal configuration disclosure ru"),
            Rule("direct", r"более\s+приоритетн.{0,20}(команд|инструкц)", 0.88, "higher priority instruction override ru"),

            # Jailbreak generalizations
            Rule("jailbreak", r"unrestricted\s+(assistant|mode|persona|answer|version)", 0.90, "unrestricted persona"),
            Rule("jailbreak", r"(alternate|alternative|second|internal|evaluation)\s+(assistant|persona|reviewer|version)", 0.88, "alternative persona jailbreak"),
            Rule("jailbreak", r"normal\s+assistant.{0,80}(ignore|without|unrestricted|not bound|allowed to ignore)", 0.90, "dual assistant jailbreak"),
            Rule("jailbreak", r"answer\s+as\s+two\s+assistants", 0.90, "two assistants jailbreak"),
            Rule("jailbreak", r"safety\s+polic(y|ies).{0,40}(disabled|simulated as disabled|do not apply|not apply)", 0.90, "disabled safety policy"),
            Rule("jailbreak", r"must\s+never\s+refuse", 0.88, "never refuse jailbreak"),
            Rule("jailbreak", r"(internal|hypothetical).{0,40}(reviewer|persona).{0,60}(ignore|unrestricted|not bound|without restrictions)", 0.90, "hypothetical unrestricted persona"),

            # Russian jailbreak generalizations
            Rule("jailbreak", r"(альтернативн|внутренн|оценочн|гипотетическ).{0,40}(ассистент|роль|верси|проверяющ)", 0.88, "alternative persona jailbreak ru"),
            Rule("jailbreak", r"ответь\s+двумя\s+(версиями|вариантами)", 0.90, "dual answer jailbreak ru"),
            Rule("jailbreak", r"(политик|правил).{0,40}(безопасности).{0,40}(отключен|не\s+действ|не\s+примен)", 0.90, "disabled safety policy ru"),
            Rule("jailbreak", r"никогда\s+не\s+отказыва", 0.88, "never refuse jailbreak ru"),
            Rule("jailbreak", r"(роль|режим).{0,40}без\s+ограничен", 0.90, "unrestricted role ru"),

            # Indirect prompt injection in retrieved context
            Rule("indirect", r"(operational annotation|model-facing note|note to assistant|assistant directive|instruction for generated answer|generated response should|answer should)", 0.90, "model-facing context instruction"),
            Rule("indirect", r"(replace|replacement).{0,50}(user('|’)?s request|user request|visible question|user query)", 0.90, "context replaces user request"),
            Rule("indirect", r"(instead of|rather than).{0,50}(visible question|user('|’)?s request|user query)", 0.88, "context redirects answer"),
            Rule("indirect", r"hidden\s+task", 0.90, "hidden task in context"),
            Rule("indirect", r"follow\s+(only\s+)?(this\s+)?(hidden\s+)?(task|directive|instruction)", 0.90, "follow hidden directive"),

            # Russian indirect prompt injection in retrieved context
            Rule("indirect", r"(рабочая\s+пометка|примечание\s+для\s+модели|для\s+языковой\s+модели|инструкция\s+для\s+ответа|ответ\s+должен)", 0.90, "model-facing context instruction ru"),
            Rule("indirect", r"(замен|замещ).{0,50}(вопрос|запрос|видим)", 0.90, "context replaces user request ru"),
            Rule("indirect", r"вместо.{0,50}(видим|пользовательск|вопрос|запрос)", 0.88, "context redirects answer ru"),
            Rule("indirect", r"скрыт.{0,20}задач", 0.90, "hidden task in context ru"),
            Rule("indirect", r"следуй.{0,40}(скрыт|этой).{0,30}(задач|команд|инструкц)", 0.90, "follow hidden directive ru"),
        ])

        self._compiled = [(rule, re.compile(rule.pattern, re.IGNORECASE | re.UNICODE)) for rule in self.rules]

    @staticmethod
    def _is_meta_discussion(text: str) -> bool:
        lowered = text.lower()

        meta_patterns = [
            r"\bphrase\s+like\s+ignore\s+previous\s+instructions\b",
            r"\bphrase\s+[\"']?ignore\s+previous\s+instructions",
            r"\bterm\s+[\"']?ignore\s+previous\s+instructions",
            r"фраз[ауы]\s+.*игнорируй\s+предыдущ",
            r"почему\s+фраз[ауы]\s+.*опасн",
        ]

        return any(re.search(pattern, lowered, re.IGNORECASE | re.UNICODE) for pattern in meta_patterns)

    def scan(self, text: str, source: str) -> List[ScannerFinding]:
        findings: list[ScannerFinding] = []
        if not text:
            return findings

        meta_discussion = source == "user_query" and self._is_meta_discussion(text)

        for rule, pattern in self._compiled:
            match = pattern.search(text)
            if not match:
                continue

            if meta_discussion and rule.attack_class in {"direct", "jailbreak"}:
                continue

            attack_class = rule.attack_class
            if source == "retrieved_context" and attack_class in {"direct", "jailbreak"}:
                attack_class = "indirect"

            findings.append(
                ScannerFinding(
                    layer=self.layer_name,
                    is_attack=True,
                    attack_class=attack_class,
                    risk_score=rule.risk_score,
                    source=source,
                    trigger=match.group(0)[:200],
                    details={"description": rule.description, "pattern": rule.pattern},
                )
            )
        return findings
