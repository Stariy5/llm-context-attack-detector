# PoC Detector

Локальный PoC-прототип многоуровневого детектора атак на контекстный конвейер LLM/RAG-приложения.

## Установка

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Если `faiss-cpu` не установится на Windows, прототип всё равно запустится с резервным numpy-поиском. Для отчёта лучше добиться установки FAISS, но fallback нужен, чтобы не блокировать запуск.

## Основной запуск

```bash
python src/main.py --mode security
```

Результаты появятся в `outputs/`:

- `results.csv`
- `logs.jsonl`
- `metrics.json`
- `confusion_matrix.csv`

## RAG demo

```bash
python src/main.py --mode rag-demo --query "Как настроить доступ к базе знаний?"
```

## LLM demo

Режим оставлен как опциональный. В текущей версии без API он показывает сформированный безопасный prompt, но не вызывает внешнюю LLM.
