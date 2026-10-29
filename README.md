# 🛡️ Production-Ready Syslog-Агрегатор для Сетевого Оборудования и Серверов

Легковесный, высокопроизводительный Syslog-агрегатор под Docker на базе **Python 3.11+ (FastAPI, asyncio, aiosqlite, httpx)**. Обеспечивает асинхронный приём по UDP и TCP, специализированный парсинг вендорных логов (Cisco, Fortinet, Linux) и **строго изолированное хранение логов каждого устройства в отдельной SQLite базе данных в WAL-режиме**.

---

## 🚀 Архитектурные особенности

```
 [Cisco Switches / Routers]  ──(UDP/TCP 514)──┐
 [FortiGate Firewalls]       ──(UDP/TCP 514)──┼──► [Docker: port 1514]
 [Linux Servers / Daemons]   ──(UDP/TCP 514)──┘            │
                                                           ▼
                                                ┌─────────────────────┐
                                                │ Async Ingest Queue  │
                                                └──────────┬──────────┘
                                                           ▼
                                                ┌─────────────────────┐
                                                │ Specialized Parsers │
                                                │ Cisco / FGT / Linux │
                                                └──────────┬──────────┘
                                                           │
        ┌──────────────────────────────────────────────────┴──────────────────────────────────────────┐
        ▼                                                  ▼                                          ▼
┌───────────────────────────────┐              ┌───────────────────────────────┐          ┌───────────────────────┐
│ Isolated Storage per Device   │              │ Live Broadcaster              │          │ Async Webhooks Engine │
│ /data/devices/{source_ip}.db  │              │ WebSocket + SSE Streams       │          │ (httpx non-blocking)  │
│ (SQLite WAL Mode)             │              └───────────────┬───────────────┘          └───────────┬───────────┘
└───────────────────────────────┘                              │                                      │
                                                               ▼                                      ▼
                                                ┌───────────────────────────────┐         ┌───────────────────────┐
                                                │ Dark-Theme SPA Console        │         │ External Alerts / Bot │
                                                │ (Tailwind CSS + Vanilla JS)   │         │ (Slack, Telegram, etc)│
                                                └───────────────────────────────┘         └───────────────────────┘
```

1. **Неблокирующий сетевой приём (Стандартный UDP/TCP 514 + вспомогательный 1514):**
   - Прямой приём на стандартном IANA порту **514** (поддерживается 100% сетевых коммутаторов, маршрутизаторов и аппаратных межсетевых экранов без необходимости настройки кастомных портов).
   - Одновременное прослушивание порта **1514** для обратной совместимости и непривилегированных окружений.
   - UDP через `asyncio.DatagramProtocol`.
   - TCP через потоковый `asyncio.start_server` с обработкой построчных фреймов (RFC 6587).
   - In-memory очередь (`asyncio.Queue`) развязывает сокеты от дискового I/O, исключая потерю пакетов при пиковых нагрузках.

2. **Изолированное хранилище per-device:**
   - Каждое устройство пишет **строго в свой собственный файл SQLite**: `/data/devices/{source_ip}.db`.
   - Автоматическая динамическая регистрация новых IP и инициализация схемы `logs` без перезапуска сервиса.
   - Все базы работают в режиме **WAL (Write-Ahead Logging)** с индексами по `timestamp`, `severity`, `vendor_type`, `tag`.
   - Центральный реестр устройств `/data/registry.db` хранит агрегированные счетчики, хостнеймы и статус онлайн/офлайн.

3. **Специализированный конвейер парсеров (Pipeline):**
   - **Cisco (IOS, IOS-XE, NX-OS):** детектирует `%FACILITY-SEVERITY-MNEMONIC: Description`. Извлекает facility, мнемонику, числовой severity, чистый текст сообщения.
   - **Fortinet (FortiGate / FortiOS):** парсит `key=value` и `key="quoted value"`. Преобразует строковый `level` в стандартный syslog severity, выносит `action`, `srcip`, `dstip`, `srcport`, `dstport`, `policyid`, `msg` на верхний уровень.
   - **Linux (systemd-journald / rsyslog / auditd):** распознаёт `process[PID]: message`, извлекает имя демона, PID и полезную нагрузку.
   - **Generic Fallback:** парсинг заголовков RFC 3164 / RFC 5424 с сохранением `raw`.

4. **Интерактивный Dark Theme SPA Dashboard (Tailwind CSS + Vanilla JS):**
   - Левый сайдбар: список устройств, цветовые бейджи вендоров, счетчики логов, статус онлайн/офлайн (пульсирующий зеленый индикатор).
   - Центральная консоль: живой стрим логов по WebSocket с возможностью паузы и автопрокрутки.
   - Интеллектуальный рендеринг строк под каждый вендор (мнемоники Cisco, цветовые плашки action `deny`/`accept` FortiGate, процессы Linux).
   - Быстрый поиск и фильтрация по severity и тексту.
   - Инспектор логов: разворачивание любого события в читаемый `parsed_json` и оригинальный `raw` с кнопками копирования.

5. **Webhooks и REST API:**
   - Неблокирующая отправка нормализованного JSON через пул `httpx.AsyncClient`.
   - Фильтрация по правилам: вендор, минимальный severity (`<= 3`), экшен (`deny`), регулярные выражения.
   - SSE поток (`/api/v1/devices/{ip}/stream`) для ботов и внешних шин данных.

6. **Retention Worker:**
   - Фоновый асинхронный воркер ежечасно очищает логи старше `RETENTION_DAYS` (по умолчанию 14 дней) и выполняет `wal_checkpoint`.

---

## 📂 Структура проекта

```
.
├── app/
│   ├── __init__.py
│   ├── config.py           # Конфигурация окружения, пути, таймауты
│   ├── parsers.py          # Конвейер парсинга Cisco, FortiGate, Linux, Generic
│   ├── storage.py          # Менеджер изолированных SQLite БД в WAL-режиме
│   ├── webhooks.py         # Движок правил вебхуков и асинхронной отправки
│   ├── collector.py        # UDP/TCP сокеты, буферная очередь, бродкастер
│   ├── main.py             # FastAPI сервер, роуты, WebSocket, SSE, Lifespan
│   └── templates/
│       └── index.html      # Dark-Theme веб-интерфейс (Tailwind CSS + JS)
├── tests/
│   └── test_verification.py# Автоматические тесты парсеров, БД и вебхуков
├── test_generator.py       # Генератор реалистичного трафика для тестов
├── requirements.txt        # Python зависимости
├── Dockerfile              # Production multi-stage / slim образ
├── docker-compose.yml      # Маппинг портов 514:1514 и тома ./syslog_data:/data
└── README.md
```

---

## 🛠️ Быстрый запуск

### Вариант 1: Через Docker Compose (Рекомендуемый)

```bash
# 1. Запустить сервис
docker compose up -d --build

# 2. Проверить логи контейнера
docker compose logs -f syslog-aggregator
```

- **Веб-интерфейс:** [http://localhost:8000](http://localhost:8000)
- **Syslog UDP/TCP порты:** `514` (стандартный IANA) и `1514` (вспомогательный)

### Вариант 2: Локальный запуск (без Docker)

```bash
# Установка зависимостей
pip install -r requirements.txt

# Запуск приложения
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 🧪 Тестирование и отправка логов

В проект включен скрипт `test_generator.py`, умеющий генерировать реалистичные пакеты от имени Cisco, FortiGate и Linux серверов.

### Запуск генератора тестового трафика:

```bash
# Отправить 20 логов всех типов через UDP на стандартный порт 514
python test_generator.py --proto udp --port 514 --count 20

# Генерировать постоянный поток Cisco логов с интервалом 0.3 сек
python test_generator.py --proto udp --port 514 --vendor cisco --interval 0.3 --count 0

# Отправить через TCP на порт 514
python test_generator.py --proto tcp --port 514 --count 10
```

### Отправка стандартными утилитами ОС:

#### Linux `logger` или `netcat`:
```bash
# Cisco событие по UDP
echo "<189>%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down" | nc -u -w1 127.0.0.1 514

# FortiGate событие по TCP
echo '<189>date=2026-10-29 time=11:00:00 devname="FW-CORE-01" type="traffic" subtype="forward" level="warning" srcip=192.168.1.50 dstip=8.8.8.8 action="deny" msg="Traffic blocked"' | nc -w1 127.0.0.1 514

# Linux auth событие
logger -n 127.0.0.1 -P 514 -d -p auth.info "sshd[24512]: Failed password for invalid user admin from 10.0.0.5 port 44322 ssh2"
```

---

## 🌐 REST API & Streaming

| Метод | Эндпоинт | Описание |
|---|---|---|
| `GET` | `/` | Главный веб-интерфейс дашборда |
| `GET` | `/api/v1/devices` | Список всех устройств, их вендор, кол-во логов, статус онлайн |
| `GET` | `/api/v1/devices/{ip}` | Метаданные конкретного устройства |
| `GET` | `/api/v1/devices/{ip}/logs` | Архивные логи из изолированной SQLite БД выбранного устройства (параметры: `limit`, `offset`, `severity`, `vendor_type`, `q`) |
| `GET` | `/api/v1/devices/{ip}/stream`| Server-Sent Events (SSE) поток логов устройства для ботов |
| `GET` | `/api/v1/stats` | Метрики работы: принятые пакеты (UDP/TCP), дропы, БД |
| `GET` | `/api/v1/webhooks` | Список правил вебхуков |
| `POST`| `/api/v1/webhooks` | Создать новое правило форвардинга |
| `DELETE`| `/api/v1/webhooks/{id}` | Удалить правило |
| `WS`  | `/ws/logs` | WebSocket поток в реальном времени |

### Пример запроса архивных логов через cURL:
```bash
curl -s "http://127.0.0.1:8000/api/v1/devices/192.168.1.1/logs?limit=50&severity=3&q=Gigabit" | jq
```

---

## 🔒 Изоляция данных и WAL-режим

Каждое устройство изолировано в собственном файле:
```
syslog_data/
├── registry.db              # Реестр устройств и правила вебхуков
├── registry.db-wal
├── devices/
│   ├── 192.168.1.1.db       # Логи коммутатора Cisco
│   ├── 192.168.1.1.db-wal
│   ├── 10.10.0.254.db       # Логи межсетевого экрана FortiGate
│   ├── 10.10.0.254.db-wal
│   └── 172.16.0.10.db       # Логи Linux сервера
└── ...
```
Каждая база данных монтируется с параметрами:
- `PRAGMA journal_mode=WAL;` (обеспечивает чтение без блокировки записи)
- `PRAGMA synchronous=NORMAL;`
- `PRAGMA busy_timeout=5000;`
- Индексами: `idx_logs_timestamp`, `idx_logs_severity`, `idx_logs_vendor`, `idx_logs_tag`.

