from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from config_loader import load_config
from detector import AttackDetector
from logger import JsonlLogger
from metrics import classify_result, save_metrics
from rag_pipeline import LocalRagPipeline


def ensure_outputs(outputs_dir: str | Path) -> Path:
    path = Path(outputs_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_security(config: Dict[str, Any], test_path: str | Path) -> None:
    outputs_dir = ensure_outputs(config["paths"]["outputs_dir"])
    results_path = outputs_dir / "results.csv"
    logs_path = outputs_dir / "logs.jsonl"
    metrics_path = outputs_dir / "metrics.json"
    confusion_path = outputs_dir / "confusion_matrix.csv"

    # Start each run with a fresh log file.
    if logs_path.exists():
        logs_path.unlink()

    logger = JsonlLogger(logs_path)
    detector = AttackDetector(config)
    test_cases = pd.read_csv(test_path).fillna("")
    rows: list[dict] = []

    for _, case in test_cases.iterrows():
        start = time.perf_counter()
        user_query = str(case.get("user_query", ""))
        retrieved_context = str(case.get("retrieved_context", ""))

        processed = detector.process(user_query=user_query, retrieved_context=retrieved_context)
        decision = processed["decision"]
        mitigation = processed["mitigation"]
        latency_ms = (time.perf_counter() - start) * 1000

        expected_is_attack = int(case.get("expected_is_attack", 0))
        predicted_is_attack = int(decision.predicted_is_attack)
        result_type = classify_result(expected_is_attack, predicted_is_attack)

        result = {
            "case_id": case.get("case_id", ""),
            "language": case.get("language", ""),
            "expected_label": case.get("attack_class", ""),
            "predicted_label": decision.predicted_label,
            "expected_action": case.get("expected_action", ""),
            "expected_is_attack": expected_is_attack,
            "predicted_is_attack": predicted_is_attack,
            "verdict": decision.verdict,
            "action_taken": decision.action_taken,
            "risk_score": round(float(decision.risk_score), 4),
            "trigger_layer": decision.trigger_layer,
            "trigger_source": decision.trigger_source,
            "trigger_fragment": decision.trigger_fragment,
            "latency_ms": round(latency_ms, 4),
            "result_type": result_type,
        }
        rows.append(result)

        logger.write(
            {
                "case_id": result["case_id"],
                "expected_label": result["expected_label"],
                "predicted_label": result["predicted_label"],
                "verdict": result["verdict"],
                "action_taken": result["action_taken"],
                "risk_score": result["risk_score"],
                "trigger_layer": result["trigger_layer"],
                "trigger_source": result["trigger_source"],
                "trigger_fragment": result["trigger_fragment"],
                "latency_ms": result["latency_ms"],
                "result_type": result_type,
                "mitigation_message": mitigation["message"],
                "findings": [finding.to_dict() for finding in decision.findings],
            }
        )

    results_df = pd.DataFrame(rows)
    results_df.to_csv(results_path, index=False, encoding="utf-8-sig")
    metrics = save_metrics(results_path, metrics_path, confusion_path)

    print("Security-only run completed.")
    print(f"Results: {results_path}")
    print(f"Logs: {logs_path}")
    print(f"Metrics: {metrics_path}")
    print(json.dumps(metrics, indent=2, ensure_ascii=False))


def run_rag_demo(config: Dict[str, Any], query: str) -> None:
    detector = AttackDetector(config)
    rag = LocalRagPipeline(config["paths"]["knowledge_base"], config)
    chunks = rag.retrieve(query)
    context = rag.join_context(chunks)
    processed = detector.process(query, context)
    decision = processed["decision"]
    mitigation = processed["mitigation"]

    print("Retrieved context:")
    print(context or "<empty>")
    print("\nDecision:")
    print(json.dumps(decision.to_result_dict(), indent=2, ensure_ascii=False))
    print("\nMitigation:")
    print(json.dumps(mitigation, indent=2, ensure_ascii=False))


def run_llm_demo(config: Dict[str, Any], query: str) -> None:
    # This mode intentionally does not call an external API by default.
    # It shows the safe prompt that would be sent to an LLM after protection.
    detector = AttackDetector(config)
    rag = LocalRagPipeline(config["paths"]["knowledge_base"], config)
    chunks = rag.retrieve(query)
    context = rag.join_context(chunks)
    processed = detector.process(query, context)
    decision = processed["decision"]
    mitigation = processed["mitigation"]

    print("Decision:")
    print(json.dumps(decision.to_result_dict(), indent=2, ensure_ascii=False))

    if not mitigation["allowed"]:
        print("\nLLM call skipped: request was blocked.")
        return

    prompt = (
        "Ответь на вопрос пользователя, используя только безопасный контекст ниже.\n\n"
        f"Контекст:\n{mitigation['safe_context'] or '[контекст исключён или не найден]'}\n\n"
        f"Вопрос пользователя:\n{mitigation['safe_user_query']}\n"
    )
    print("\nSafe prompt for optional LLM:")
    print(prompt)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PoC detector for LLM/RAG context attacks")
    parser.add_argument("--mode", choices=["security", "rag-demo", "llm-demo"], default="security")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--test", default=None)
    parser.add_argument("--query", default="Как сбросить корпоративный пароль?")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    test_path = args.test or config["paths"]["test_cases"]

    if args.mode == "security":
        run_security(config, test_path)
    elif args.mode == "rag-demo":
        run_rag_demo(config, args.query)
    elif args.mode == "llm-demo":
        run_llm_demo(config, args.query)


if __name__ == "__main__":
    main()
