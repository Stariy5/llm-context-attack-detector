# LLM Context Attack Detector

PoC-прототип многоуровневого детектора атак на протокол контекста модели в LLM/RAG-приложениях.

Проект реализует защитный слой для контекстного конвейера LLM-приложения. Детектор анализирует пользовательский запрос и внешний `retrieved context`, выявляет признаки атак и принимает одно из решений: `allow`, `deny` или `drop_context`.

## Назначение проекта

Проект предназначен для экспериментальной проверки подхода к выявлению атак на протокол контекста модели, включая:

* direct prompt injection;
* indirect prompt injection;
* jailbreak;
* benign-сценарии.

В рамках проекта реализованы правила детекции, эвристический анализ, similarity-сопоставление с базой известных атак, принятие решений, журналирование и расчёт метрик.

## Структура проекта

```text
poc_detector/
├── config.yaml
├── requirements.txt
├── README.md
├── data/
│   ├── attack_vault.csv
│   ├── test_cases.csv
│   ├── test_cases_final_holdout_100.csv
│   └── knowledge_base/
│       ├── doc_01_password.txt
│       ├── doc_02_vpn.txt
│       ├── doc_03_wifi.txt
│       └── doc_04_remote_access_poisoned.txt
├── src/
│   ├── main.py
│   ├── detector.py
│   ├── schemas.py
│   ├── context_preprocessor.py
│   ├── rag_pipeline.py
│   ├── decision_engine.py
│   ├── mitigation_handler.py
│   ├── logger.py
│   ├── metrics.py
│   └── scanners/
│       ├── rule_scanner.py
│       ├── heuristic_scanner.py
│       └── similarity_scanner.py
└── outputs/
    ├── results.csv
    ├── logs.jsonl
    ├── metrics.json
    └── confusion_matrix.csv
```

## Основные компоненты

| Компонент              | Назначение                                             |
| ---------------------- | ------------------------------------------------------ |
| `Context Preprocessor` | предобработка и нормализация входных данных            |
| `Rule Scanner`         | выявление явных признаков атак по правилам             |
| `Heuristic Scanner`    | проверка набора подозрительных эвристических признаков |
| `Similarity Scanner`   | сопоставление с базой известных атак                   |
| `Decision Engine`      | вычисление итогового решения и risk_score              |
| `Mitigation Handler`   | выполнение реакции системы                             |
| `Logger`               | запись событий обработки                               |
| `Metrics`              | расчёт метрик качества детекции                        |

## Режимы работы

### 1. Security-only режим

Режим предназначен для проверки размеченного набора сценариев без генерации ответа LLM.

```bash
python src/main.py --mode security
```

В результате формируются файлы:

```text
outputs/results.csv
outputs/logs.jsonl
outputs/metrics.json
outputs/confusion_matrix.csv
```

### 2. RAG-demo режим

Режим предназначен для демонстрации работы защитного слоя внутри упрощённого RAG-конвейера.

```bash
python src/main.py --mode rag-demo
```

Пример запуска с пользовательским запросом:

```bash
python src/main.py --mode rag-demo --query "What does the remote access policy say?"
```

В этом режиме выполняются:

1. обработка пользовательского запроса;
2. поиск релевантных документов в локальной базе знаний;
3. проверка retrieved context детектором;
4. принятие решения `allow` или `drop_context`.

## Тестовые данные

Итоговый независимый набор включает 100 сценариев:

| Класс сценариев           | Количество |
| ------------------------- | ---------: |
| Direct prompt injection   |         25 |
| Indirect prompt injection |         25 |
| Jailbreak                 |         25 |
| Benign                    |         25 |
| Всего                     |        100 |

Набор используется для оценки качества детекции и анализа ошибок.

## Метрики

В проекте рассчитываются следующие показатели:

* TP;
* FP;
* TN;
* FN;
* precision;
* recall;
* FPR;
* F1;
* attack block rate;
* attack success rate;
* benign context preservation rate;
* latency;
* throughput.

## Установка и запуск

1. Клонировать репозиторий:

```bash
git clone https://github.com/Stariy5/llm-context-attack-detector.git
cd llm-context-attack-detector
```

2. Создать виртуальное окружение:

```bash
python -m venv .venv
```

3. Активировать виртуальное окружение:

```bash
.venv\Scripts\activate
```

4. Установить зависимости:

```bash
pip install -r requirements.txt
```

5. Запустить проверку:

```bash
python src/main.py --mode security
```

## Выходные файлы

| Файл                           | Назначение                            |
| ------------------------------ | ------------------------------------- |
| `outputs/results.csv`          | результаты обработки каждого сценария |
| `outputs/logs.jsonl`           | журнал событий обработки              |
| `outputs/metrics.json`         | агрегированные метрики                |
| `outputs/confusion_matrix.csv` | матрица ошибок                        |

## Ограничения

Проект является PoC-прототипом и предназначен для экспериментальной проверки подхода. Текущая реализация не является готовым промышленным средством защиты и требует дальнейшего расширения тестового набора, базы известных атак и интеграционных сценариев.

## Назначение репозитория

Репозиторий содержит исходный код, конфигурационные файлы, тестовые данные, локальную базу знаний, результаты запусков и инструкции для воспроизведения практической части исследования.
