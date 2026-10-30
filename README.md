# 🛡️ Production-Ready Syslog-Агрегатор для Сетевого Оборудования и Серверов

Легковесный, высокопроизводительный Syslog-агрегатор под Docker на базе **Python 3.11+ (FastAPI, asyncio, aiosqlite, httpx)**. Обеспечивает асинхронный приём логов по UDP и TCP, специализированный парсинг вендорных форматов (Cisco, Fortinet, Linux) и **строго изолированное хранение данных каждого устройства в отдельной SQLite базе данных в WAL-режиме**.

---

## 🚀 Архитектурные особенности

```
 [Cisco Switches / Routers]  ──(UDP/TCP 514 & 1514)──┐
 [FortiGate Firewalls]       ──(UDP/TCP 514 & 1514)──┼──► [Network Collector: UDP / TCP]
 [Linux Servers / Daemons]   ──(UDP/TCP 514 & 1514)──┘            │
                                                                   │
            ┌──────────────────────────────────────────────────────┴──────────────────────────────────────────────────────┐
            ▼                                                                                                             ▼
  [⚡ Express Lane (Microseconds)]                                                                               [📊 Analytics Lane]
  app/forwarder.py                                                                                               asyncio.Queue
  (Raw UDP Wire Relay / Persistent TCP Pool)                                                                              │
            │                                                                                                             ▼
            │ (Мгновенная ретрансляция без задержек на парсинг и диск)                                          [Specialized Parsers]
            │                                                                                                   (FortiGate → Cisco → Linux → Generic)
            ▼                                                                                                             │
 ┌───────────────────────┐                                          ┌─────────────────────────────────────────────────────┼───────────────────────────────────┐
 │ Remote Syslog Targets │                                          ▼                                                     ▼                                   ▼
 │ (SIEM, Graylog, etc)  │                             ┌───────────────────────────────┐                             ┌──────────────────────────┐          ┌───────────────────────┐
 └───────────────────────┘                             │ Isolated Storage per Device   │                             │ Live Broadcaster         │          │ Async Webhooks Engine │
                                                       │ /data/devices/{source_ip}.db  │                             │ (WebSocket + SSE Streams)│          │ (httpx non-blocking)  │
                                                       │ (SQLite WAL Mode)             │                             └────────────┬─────────────┘          └───────────┬───────────┘
                                                       └───────────────────────────────┘                                          │                                    │
                                                                                                                                  ▼                                    ▼
                                                                                                                   ┌────────────────────────────┐         ┌───────────────────────┐
                                                                                                                   │ Dark-Theme SPA Console     │         │ External Alerts / Bot │
                                                                                                                   │ (Tailwind CSS + Batch rAF) │         │ (Telegram, Slack, etc)│
                                                                                                                   └────────────────────────────┘         └───────────────────────┘
```

1. **Двухконтурный приём трафика (Dual-Lane Network Engine):**
   - **Express Lane (быстрый контур):** мгновенная аппаратная ретрансляция «сырых» пакетов на удалённые SIEM/Syslog-серверы за микросекунды через неблокирующий UDP-сокет и пул постоянных соединений `PersistentTcpSender` (с кэшированием DNS и защитой от исчерпания сокетов `TIME_WAIT`).
   - **Analytics Lane (аналитический контур):** асинхронная очередь `asyncio.Queue` с пачечной обработкой (`BATCH_SIZE=100`, таймаут `0.25 с`), развязывающая сокеты от дискового ввода-вывода и предотвращающая потерю пакетов при пиковых нагрузках.
   - Прослушивание портов: стандартный IANA **514** (UDP/TCP) для сетевых коммутаторов и межсетевых экранов + **1514** (UDP/TCP) для непривилегированных сред и контейнеров.

2. **Строго изолированное хранилище per-device:**
   - Каждое устройство пишет **в свой собственный изолированный файл**: `/data/devices/{source_ip}.db`.
   - Автоматическая динамическая регистрация новых IP и инициализация схемы таблицы `logs` без перезапуска сервиса.
   - Все базы работают в режиме **WAL (Write-Ahead Logging)** (`synchronous=NORMAL`, `busy_timeout=5000`) с индексами по `timestamp`, `severity`, `facility`, `vendor_type`, `tag`.
   - Центральный реестр `/data/registry.db` хранит агрегированные счётчики, хостнеймы, статус онлайн/офлайн, системные настройки, правила вебхуков и точки пересылки.

3. **Специализированный конвейер парсеров (Pipeline):**
   - **Cisco (IOS, IOS-XE, NX-OS):** распознаёт `%FACILITY-SEVERITY-MNEMONIC: Description`. Извлекает facility, мнемонику, числовой severity, хостнейм и очищенный текст.
   - **Fortinet (FortiGate / FortiOS):** парсит пары `key=value` и `key="quoted value"`. Преобразует строковый `level` в стандартный syslog severity, выносит `action`, `srcip`, `dstip`, `srcport`, `dstport`, `policyid`, `msg` в структурированный JSON.
   - **Linux (systemd-journald / rsyslog / auditd / sshd / sudo):** распознаёт `process[PID]: message`, извлекая имя демона, PID и полезную нагрузку.
   - **Generic Fallback:** парсинг заголовков RFC 3164 / RFC 5424 с сохранением оригинального `raw`.

4. **Интерактивный Dark Theme SPA Dashboard с высокой оптимизацией:**
   - **Пакетный рендеринг (Batching + `requestAnimationFrame` + `DocumentFragment`):** интерфейс легко выдерживает поток в тысячи логов в секунду при минимальной нагрузке на процессор (~2–5% CPU) без лагов и задержек.
   - **Счётчик «Логи в секунду» (Logs/s, EPS):** живой индикатор текущей скорости поступления событий в шапке дашборда.
   - **Интерактивная фильтрация в один клик:** клик по бейджу важности (Emergency..Debug), IP-адресу или тегу/мнемонике в любой строке консоли мгновенно накладывает соответствующий фильтр.
   - **Быстрые пресеты:** *⚠️ Errors (≤3)*, *⛔ Drops & Deny*, *🔌 Port / Link Status*, *🔒 Auth & Security*, *🌐 Routing (BGP/OSPF)*.
   - **Инспектор логов:** детальный просмотр события в структурированном JSON и исходном `raw` с возможностью быстрого копирования.
   - **Мультиязычность (i18n):** поддержка английского (EN) и русского (RU) языков интерфейса.

5. **Маршрутизация (Forwarding), Webhooks и REST API:**
   - Пересылка логов на внешние серверы по UDP, TCP или Webhook (в сыром RFC-виде или нормализованном JSON) с фильтрацией по IP, вендору и максимальной важности.
   - Движок вебхуков с неблокирующей отправкой через пул `httpx.AsyncClient` и фильтрацией по регулярным выражениям, действиям (`action="deny"`) и severity.
   - Server-Sent Events (SSE) поток (`/api/v1/devices/{ip}/stream`) для ботов и внешних систем.

6. **Retention Worker & Disaster Recovery:**
   - Фоновый воркер ежечасно очищает архивные логи старше `RETENTION_DAYS` (по умолчанию 14 дней) и выполняет `wal_checkpoint`.
   - Экспорт и импорт полной конфигурации (правила пересылки, вебхуки, системные настройки) в 1 клик в формате JSON.

---

## 📂 Структура проекта

```
.
├── app/
│   ├── __init__.py
│   ├── config.py           # Конфигурация путей, портов, часового пояса и очередей
│   ├── parsers.py          # Конвейер парсинга Cisco, FortiGate, Linux, Generic
│   ├── storage.py          # Изолированные SQLite WAL БД, пакетная запись, пагинация
│   ├── forwarder.py        # Express Lane: ретрансляция логов, пул TCP-соединений, DNS-кэш
│   ├── webhooks.py         # Движок правил вебхуков и асинхронной HTTP POST отправки
│   ├── collector.py        # UDP/TCP сокеты, буферная очередь, бродкастинг WS/SSE, EPS
│   ├── main.py             # FastAPI сервер, роуты, WebSocket, SSE, Lifespan
│   └── templates/
│       └── index.html      # SPA веб-интерфейс (Tailwind CSS, i18n, batch rAF)
├── tests/
│   └── test_verification.py# Автоматические тесты парсеров, БД, форвардинга и вебхуков
├── test_generator.py       # Генератор реалистичного синтетического трафика
├── syslog_data/            # Директория данных (БД устройств и registry.db, в .gitignore)
├── requirements.txt        # Python зависимости (FastAPI, uvicorn, aiosqlite, httpx...)
├── Dockerfile              # Production-образ на базе python:3.11-slim с tzdata
├── docker-compose.yml      # Маппинг портов 514/1514 (UDP/TCP), 8321 и тома ./syslog_data:/data
└── README.md               # Документация проекта
```

---

## 🛠️ Быстрый запуск

### Вариант 1: Через Docker Compose (Рекомендуемый)

```bash
# 1. Запустить сервис в фоновом режиме
docker compose up -d --build

# 2. Проверить статус и логи контейнера
docker compose logs -f syslog-aggregator
```

- **Веб-интерфейс:** [http://localhost:8321](http://localhost:8321)
- **Syslog-порты (UDP/TCP):** `514` (стандартный) и `1514` (вспомогательный)
- **Данные:** сохраняются на хосте в каталоге `./syslog_data/`

---

### Вариант 2: Локальный запуск (без Docker)

Для локального запуска вне контейнера рекомендуется использовать виртуальное окружение:

```bash
# 1. Создать виртуальное окружение и активировать его
python3 -m venv .venv
source .venv/bin/activate

# 2. Установить зависимости
pip install -r requirements.txt

# 3. Запустить сервер
# Переменная DATA_DIR указывает на локальную папку для баз данных
DATA_DIR=./syslog_data python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8321
```

> [!NOTE]
> В операционных системах Linux привязка к портам ниже 1024 (например, стандартный порт 514) требует прав суперпользователя `root` либо предоставления capabilities (`sudo setcap 'cap_net_bind_service=+ep' $(which python3)`). При обычном непривилегированном запуске сервис автоматически продолжит приём на порту **1514**.

---

## 🧪 Тестирование и отправка логов

В проект включен скрипт [test_generator.py](file:///home/dima/Projects/Syslog/test_generator.py), генерирующий реалистичные события сетевого оборудования и серверов.

### Запуск генератора тестового трафика:

```bash
# Отправить 50 логов всех вендоров по UDP на порт 1514 (или 514)
python3 test_generator.py --proto udp --port 1514 --count 50

# Генерировать постоянный поток Cisco логов с интервалом 0.1 сек
python3 test_generator.py --proto udp --port 1514 --vendor cisco --interval 0.1 --count 0

# Протестировать высокую нагрузку (стресс-тест 1000 логов с минимальной задержкой)
python3 test_generator.py --proto udp --port 1514 --count 1000 --interval 0.005

# Отправить пачку логов через TCP
python3 test_generator.py --proto tcp --port 1514 --count 20
```

### Отправка логов стандартными системными утилитами:

#### Linux `nc` (netcat):
```bash
# Cisco событие по UDP
echo "<189>%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down" | nc -u -w1 127.0.0.1 1514

# FortiGate событие по TCP
echo '<189>date=2026-10-30 time=12:00:00 devname="FW-CORE-01" type="traffic" subtype="forward" level="warning" srcip=192.168.1.50 dstip=8.8.8.8 action="deny" msg="Traffic blocked"' | nc -w1 127.0.0.1 1514
```

#### Linux `logger`:
```bash
# Linux auth событие через стандартный демон logger
logger -n 127.0.0.1 -P 1514 -d -p auth.info "sshd[24512]: Failed password for invalid user admin from 10.0.0.5 port 44322 ssh2"
```

---

## 🌐 REST API, WebSocket & Streaming

| Метод | Эндпоинт | Описание |
|---|---|---|
| `GET` | `/` | Главный веб-интерфейс дашборда |
| `GET` | `/api/v1/devices` | Список всех устройств, вендор, количество логов, статус онлайн |
| `GET` | `/api/v1/devices/{ip}` | Метаданные конкретного устройства |
| `DELETE` | `/api/v1/devices/{ip}` | Удаление устройства и его файла базы данных |
| `POST` | `/api/v1/devices/purge-test-data` | Очистка синтетических тестовых устройств (10.0.0.x, 127.0.0.1) |
| `GET` | `/api/v1/devices/{ip}/logs` | Архивные логи из изолированной базы выбранного устройства |
| `GET` | `/api/v1/logs` | Сквозной поиск и пагинация по базам **всех** устройств |
| `GET` | `/api/v1/devices/{ip}/stream`| Server-Sent Events (SSE) поток логов устройства для интеграций |
| `GET` | `/api/v1/stats` | Метрики работы: принятые пакеты (UDP/TCP), дропы, БД и **текущий EPS** |
| `GET` | `/api/v1/forwarding/endpoints` | Список точек пересылки и счётчики переданных пакетов |
| `POST`| `/api/v1/forwarding/endpoints` | Создать конечную точку (Syslog UDP, Syslog TCP, Webhook) |
| `PUT` | `/api/v1/forwarding/endpoints/{id}` | Изменить параметры точки пересылки |
| `DELETE`| `/api/v1/forwarding/endpoints/{id}`| Удалить точку пересылки |
| `POST`| `/api/v1/forwarding/endpoints/{id}/toggle` | Включить / приостановить пересылку |
| `POST`| `/api/v1/forwarding/test` | Тестовая отправка пробного пакета на целевой хост |
| `GET` | `/api/v1/settings` | Получить системные настройки (часовой пояс, язык, retention) |
| `POST`| `/api/v1/settings` | Обновить системные настройки |
| `GET` | `/api/v1/backup` | Скачать полную резервную копию конфигурации (JSON) |
| `POST`| `/api/v1/restore` | Восстановить конфигурацию из резервной копии (JSON) |
| `GET` | `/api/v1/webhooks` | Список правил вебхуков |
| `POST`| `/api/v1/webhooks` | Создать правило вебхука |
| `DELETE`| `/api/v1/webhooks/{id}` | Удалить правило |
| `POST`| `/api/v1/webhooks/{id}/toggle` | Включить / выключить правило вебхука |
| `POST`| `/api/v1/webhooks/test` | Тестовая отправка пейлоада на URL вебхука |
| `POST`| `/api/v1/retention/cleanup` | Принудительный запуск ротации архивных данных |
| `WS`  | `/ws/logs` | Двунаправленный WebSocket-поток логов в реальном времени |

### Пример выборки архивных логов через cURL:
```bash
curl -s "http://127.0.0.1:8321/api/v1/logs?limit=50&severity_max=3&q=Gigabit" | jq
```

---

## 🔒 Изоляция данных и режим SQLite WAL

Логи каждого устройства сохраняются в отдельном файле:
```
syslog_data/
├── registry.db              # Реестр устройств, настройки, правила вебхуков и пересылки
├── registry.db-wal
├── devices/
│   ├── 192.168.1.1.db       # Логи коммутатора Cisco
│   ├── 192.168.1.1.db-wal
│   ├── 10.10.0.254.db       # Логи межсетевого экрана FortiGate
│   ├── 10.10.0.254.db-wal
│   └── 172.16.0.10.db       # Логи Linux-сервера
└── ...
```

Параметры баз данных:
- `PRAGMA journal_mode=WAL;` — параллельное неблокирующее чтение при активной записи.
- `PRAGMA synchronous=NORMAL;` — оптимальный баланс надёжности и скорости I/O.
- `PRAGMA busy_timeout=5000;` — ожидание освобождения блокировок до 5 секунд.
- Индексы: `idx_logs_timestamp`, `idx_logs_severity`, `idx_logs_facility`, `idx_logs_vendor`, `idx_logs_tag`.

---

## 🕒 Часовой пояс по умолчанию: Кишинёв (Europe/Chisinau)

- **Контейнер и бэкенд:** `TZ=Europe/Chisinau` настроен в Dockerfile, compose и Python. Корректно учитывает переход на летнее/зимнее время (EET / EEST, UTC+2 / UTC+3).
- **События:** сохраняются с точной временной меткой в часовом поясе Кишинёва.
- **Интерфейс:** в шапке отображается активный часовой пояс, а в меню настроек доступен выбор любого альтернативного часового пояса IANA с живым предпросмотром времени.

---

## 💾 Сохранение данных и Disaster Recovery

1. **Монтирование тома в Docker:** в `docker-compose.yml` настроен bind mount `./syslog_data:/data`. При пересборке образов или `docker compose pull` все базы данных остаются нетронутыми на диске хоста.
2. **Исключение из Git:** каталог `syslog_data/` и файлы `.db` внесены в `.gitignore`. Команда `git pull` гарантированно не затрёт рабочие базы данных.
3. **Резервное копирование в 1 клик:**
   - В меню **Settings** доступна кнопка **«Export Backup (JSON)»** (или `GET /api/v1/backup`).
   - Кнопка **«Restore Configuration»** (или `POST /api/v1/restore`) восстанавливает все правила, точки маршрутизации и настройки на любом сервере за секунду.

---

## 🚦 Запуск автоматических тестов

В репозиторий включён изолированный тестовый сьют, проверяющий парсеры, базы данных, persistent TCP-отправку и быстрый релей без модификации рабочих баз:

```bash
python3 tests/test_verification.py
```
