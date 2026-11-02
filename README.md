# Sec-Bot — мониторинг новостей кибербезопасности

![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)
![DeepSeek](https://img.shields.io/badge/LLM-DeepSeek-4D6BFE)

Бот раз в 6 часов собирает новости по кибербезопасности из RSS-лент и из каталога
CISA KEV (Known Exploited Vulnerabilities), просит DeepSeek оценить критичность
каждой новости и присылает разбор в Telegram. Критичные новости (0-day, массовые
взломы) помечаются отдельным заголовком, остальные идут как дайджест.

---

## Что делает

1. Собирает до 20 записей с каждой из 6 RSS-лент за последние 24 часа —
   глубина сбора больше глубины доставки.
2. Пропускает то, что уже отправлял — дубли не попадают в канал.
3. Отправляет новость в DeepSeek с промптом на строгий формат ответа:

   ```
   [Критичность: 1-5] (5 — 0-day/массовый взлом, 1 — мнение)
   Суть: одно предложение.
   Детали: 2-3 предложения.
   ```

4. Публикует результат в Telegram: `🚨 КРИТИЧЕСКАЯ НОВОСТЬ` для оценок 4–5,
   `🛡 Security Дайджест` для остальных. В канал уходят только 2 новости
   с каждой ленты (`SEND_PER_FEED`), остальные собраны и ждут фазы 2.
5. Забирает CISA KEV — новые записи за последние 7 дней с NVD-ссылками.
   В фазе 1 они только логируются и в Telegram не отправляются.
6. Спит 6 часов и повторяет. Любой сбой сети, API или одного источника
   логируется, но не останавливает бота.

---

## Архитектура

```
        RSS-ленты (6 шт.)                  CISA KEV (JSON)
              │                                  │
              │ requests.get                     │ requests.get
              │ + браузерные заголовки           │ + браузерные заголовки
              │ + retry на 403/429/5xx           │ timeout 15 с
              ▼                                  ▼
     feedparser.parse()                 сортировка по dateAdded,
              │ до 20 записей/лента      окно 7 дней, NVD-ссылки
              │ за последние 24 ч                │
              └──────────────┬───────────────────┘
                             ▼
         дедупликация по seen_urls.json (ссылка уже была? пропустить)
                             │
              ┌──────────────┴───────────────┐
              ▼                              ▼
   в канал: 2 новости с ленты       в фазе 1: только лог
              │                     ([KEV] new: ...)
              ▼
   DeepSeek API  chat/completions (deepseek-chat)
              │  [Критичность: N] + Суть + Детали
              ▼
   классификация: 4–5 → 🚨, иначе → 🛡
              ▼
   Telegram Bot API  sendMessage (HTML, без превью ссылок)
```

| Этап | Модуль | Что происходит |
|---|---|---|
| Загрузка RSS | `requests` + `get_with_retry()` | GET с таймаутом 20 с и повтором при 403/429/5xx |
| Разбор RSS | `feedparser` | до `FETCH_DEPTH` (20) записей за `FETCH_WINDOW_HOURS` (24 ч) |
| CISA KEV | `requests` → JSON | сортировка по `dateAdded`, окно 7 дней, NVD-ссылки |
| Дедупликация | `seen_urls.json` | ссылка уже отправлялась → `continue` |
| Отбор на отправку | `SEND_PER_FEED` | из собранных — только 2 самые свежие с каждой ленты |
| Анализ | `openai` SDK → DeepSeek | `chat.completions.create`, `temperature=0.2` |
| Доставка | `requests` → Telegram API | `parse_mode="HTML"`, `disable_web_page_preview=True` |

---

## Структура проекта

```
sec-bot/
├── app.py              # вся логика: RSS + KEV → LLM → Telegram
├── requirements.txt    # feedparser, requests, openai
├── Dockerfile          # python:3.11-slim, запуск от непривилегированного bot
├── docker-compose.yml  # сервис sec-bot, restart: unless-stopped
├── seen_urls.json      # история отправленного (монтируется с хоста)
├── .env                # секреты, в git не попадает
└── README.md
```

---

## Быстрый старт

```bash
git clone <repo-url> sec-bot && cd sec-bot

cat > .env <<'EOF'
DEEPSEEK_API_KEY=sk-...
TELEGRAM_TOKEN=123456789:AA...
TELEGRAM_CHAT_ID=-1001234567890
EOF
chmod 600 .env

docker compose up -d --build
docker compose logs -f --tail=50
```

Остановить / перезапустить:

```bash
docker compose down                 # остановить
docker compose up -d --build        # пересобрать после правок кода
docker compose up -d --force-recreate   # применить новый .env
docker compose restart              # просто новый проход, без пересборки
```

> `docker compose restart` не перечитывает `.env` и не подхватывает изменения
> в коде — для этого нужен `up -d --build` / `--force-recreate`.

---

## Переменные окружения

Все секреты передаются через `.env` (см. `env_file` в `docker-compose.yml`).
Без них контейнер не стартует.

| Переменная | Обязательна | Назначение |
|---|---|---|
| `DEEPSEEK_API_KEY` | да | ключ DeepSeek, `https://api.deepseek.com` |
| `TELEGRAM_TOKEN` | да | токен бота от `@BotFather` |
| `TELEGRAM_CHAT_ID` | да | ID чата/канала, куда писать (число, у каналов с `-100…`) |

Пример `.env`:

```dotenv
DEEPSEEK_API_KEY=sk-...
TELEGRAM_TOKEN=123456789:AA...
TELEGRAM_CHAT_ID=-1001234567890
```

Узнать свой `chat_id` без сторонних ботов — напрямую у Telegram API.
Сначала напишите боту любое сообщение (например, `/start`), затем выполните:

```bash
read -rsp "Токен бота: " TOKEN; echo
curl -s "https://api.telegram.org/bot${TOKEN}/getUpdates"; echo
unset TOKEN
```

В ответе найдите `"chat": {"id": …}` — это и есть `TELEGRAM_CHAT_ID`.

Почему так безопасно: токен вводится скрыто (`-s`), не попадает в историю команд
и никуда не отправляется, кроме самого Telegram API; после запроса переменная
сразу удаляется (`unset TOKEN`). Сторонние сервисы не участвуют.

---

## Источники

### RSS-ленты

| Источник | URL | Комментарий |
|---|---|---|
| SecurityWeek | `https://www.securityweek.com/feed/` | индустрия, инциденты |
| The Hacker News | `https://thehackernews.com/feeds/posts/default` | оперативные новости |
| Krebs on Security | `https://krebsonsecurity.com/feed/` | расследования |
| BleepingComputer | `https://www.bleepingcomputer.com/feed/` | уязвимости, малварь |
| Zero Day Initiative | `https://www.zerodayinitiative.com/rss/published/` | 0-day advisory |
| Dark Reading | `https://www.darkreading.com/rss.xml` | аналитика и новости |

CISA (`/cybersecurity-advisories/all.xml`) убрана: их CDN (Akamai) отдаёт
`403` Python-клиенту — блокировка по TLS-отпечатку/IP, заголовками не лечится.
Если нужен именно CISA — добавить `curl_cffi` с `impersonate="chrome"`.

### CISA KEV (JSON, не RSS)

Отдельный поток:
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
Это каталог подтверждённых эксплуатаций, а не лента новостей, поэтому логика
другая:

- забираем записи за последние `KEV_WINDOW_DAYS` (7) дней, а не всю базу
  (в ней ~1766 записей);
- сортируем по `dateAdded` (свежие первыми), а не полагаемся на порядок массива;
- ключ статьи — NVD-ссылка `https://nvd.nist.gov/vuln/detail/CVE-…`;
- поля: `title = "CISA KEV: {vulnerabilityName} ({cveID})"`,
  `summary = "{shortDescription} Required action: {requiredAction}"`,
  `published` — `dateAdded` в ISO 8601, `is_kev = True`.

В фазе 1 KEV-статьи **только логируются** (`[KEV] new: ...`), в Telegram не
уходят — отправка появится в фазе 2. Именно этот поток вытащил Brotli2Shell
(CVE-2026-111497, `dateAdded 2026-10-27`), который RSS-ленты к тому моменту
уже вытеснили.

---

## Заметки: защита от дублей

История отправленного лежит в `seen_urls.json` — плоский JSON-массив ссылок:

```json
[
  "https://www.bleepingcomputer.com/news/security/...",
  "https://thehackernews.com/2026/10/..."
]
```

Как это работает:

- **Ключ дедупликации** — `link` новости; если ссылки нет, используется
  `title:<заголовок>`, чтобы записи без `link` не схлопывались в один пустой ключ.
- **KEV-статьи** используют NVD-ссылку (`https://nvd.nist.gov/vuln/detail/CVE-…`)
  как ключ — она уникальна и стабильна. Пока KEV не отправляется, его ссылки
  не попадают в `seen_urls.json`, поэтому в памяти процесса ведётся отдельный
  `_reported_kev`: первый цикл логирует 10 новых CVE, дальше — тишина, пока
  CISA не добавит новые. После рестарта контейнера они залогируются снова.
- **Проверка** стоит до обращения к LLM: дубль не тратит токены и время.
- **Запись** — только после успешной отправки в Telegram. Если Telegram или
  DeepSeek ответили ошибкой, новость остаётся «невиденной» и уйдёт в следующем
  цикле. Это осознанно: лучше повторить, чем потерять.
- **Сохранение сразу после каждой отправки**, а не в конце цикла — при падении
  процесса уже отправленное не потеряется.
- **Атомарная запись**: временный файл + `os.replace()`. В Docker
  `seen_urls.json` — bind-mount, а `rename()` поверх точки монтирования ядро
  запрещает (`EBUSY`), поэтому при такой ошибке код откатывается на прямую
  перезапись файла.
- **Битый JSON не убивает бота**: файл логируется как повреждённый и работа
  продолжается с пустой историей (ценой повторной отправки).

Полезные команды:

```bash
cat seen_urls.json                              # что уже отправлено
echo '[]' > seen_urls.json                      # сбросить историю
docker compose restart                          # и отправить всё заново
```

---

## Заметки: обработка ошибок

Три уровня изоляции — сбой одного шага не валит остальные:

1. **Одна лента** — `requests.RequestException` → `[WARN] Источник заблокирован
   или недоступен: <url>` и переход к следующей ленте.
2. **Одна новость** — ошибка LLM/Telegram логируется, остальные новости
   обрабатываются дальше.
3. **Весь цикл** — `log.exception(...)`, затем сон и новая попытка через 6 часов.

Ретраи (`get_with_retry`):

| Параметр | Значение |
|---|---|
| Повторяемые статусы | `403`, `429`, любые `5xx` |
| Всего попыток | 2 (первая + одна повторная) |
| Пауза между попытками | 2 секунды |
| `404` и прочие `4xx` | не ретраятся — сразу предупреждение |

Что ещё предусмотрено:

- HTTP-таймаут 20 с на каждый запрос — бот не зависает на «мёртвой» ленте.
- Ограничение длины сообщения 4096 символов (лимит Telegram).
- Экранирование HTML в заголовке, ссылке и ответе LLM — иначе `<`, `>`, `&`
  из RSS ломают разметку и Telegram отвечает `400`.
- Проверка обязательных переменных окружения на старте: понятная ошибка вместо
  падения в середине цикла.
- **CISA KEV**: 403/таймаут/битый JSON → `[WARN] CISA KEV fetch failed` и пустой
  список; остальной цикл продолжается. У KEV отдельный таймаут 15 с.
- Логгеры `httpx`/`httpx2` приглушены до `WARNING`, чтобы не сыпать строкой
  `HTTP Request: POST ...` на каждый вызов.

---

## Настройки

Все константы — в начале `app.py`:

| Константа | Значение | Смысл |
|---|---|---|
| `RSS_FEEDS` | 6 лент | источники |
| `FETCH_DEPTH` | `20` | максимум записей с ленты за цикл |
| `FETCH_WINDOW_HOURS` | `24` | окно свежести для RSS |
| `SEND_PER_FEED` | `2` | сколько из собранных уходит в Telegram |
| `MAX_MESSAGES_PER_CYCLE` | `12` | потолок сообщений (задел фазы 2) |
| `CHECK_INTERVAL_SECONDS` | `6 * 60 * 60` | период опроса |
| `HTTP_TIMEOUT` | `20` | таймаут запроса, сек |
| `FETCH_ATTEMPTS` | `2` | попыток на ленту |
| `RETRY_DELAY_SECONDS` | `2` | пауза перед повтором, сек |
| `TELEGRAM_MAX_LENGTH` | `4096` | лимит длины сообщения |
| `KEV_TIMEOUT` | `15` | таймаут запроса к CISA KEV |
| `KEV_LIMIT` | `10` | сколько новых KEV-записей за прогон |
| `KEV_WINDOW_DAYS` | `7` | окно свежести KEV |

---

## Пример лога

```
2026-11-02 15:09:26 [INFO] sec-bot: Старт. Лент: 6, сбор: до 20/лента за 24 ч, отправка: 2/лента, в истории: 26, интервал: 6 ч
2026-11-02 15:09:26 [INFO] sec-bot: Читаю ленту: https://www.securityweek.com/feed/
2026-11-02 15:09:27 [INFO] sec-bot: [RSS] https://www.securityweek.com/feed/: collected 3, sending 2
2026-11-02 15:09:28 [INFO] sec-bot: Отправлено (критично): PHP2Shell Attacks Root Palo Alto Firewalls...
2026-11-02 15:09:29 [INFO] sec-bot: Отправлено (дайджест): In Other News: Anthropic Breach Dispute...
2026-11-02 15:09:29 [INFO] sec-bot: Пропускаю дубль: Attackers Chain Three Ivanti Connect Secure Flaws...
2026-11-02 15:09:29 [WARNING] sec-bot: [WARN] Источник заблокирован или недоступен: https://example.com/feed/ (403 ...)
2026-11-02 15:09:29 [INFO] sec-bot: [KEV] Found 10 new exploits
2026-11-02 15:09:29 [INFO] sec-bot: [KEV] new: CISA KEV: Google Brotli Unchecked Return Value Vulnerability (CVE-2026-111497)
2026-11-02 15:09:29 [INFO] sec-bot: Collected 36 articles (26 from RSS, 10 from KEV)
2026-11-02 15:09:29 [INFO] sec-bot: Сплю 6 ч до следующей проверки
```

---

## Локальный запуск (без Docker)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

set -a; . ./.env; set +a      # экспортировать переменные из .env
python app.py
```

`app.py` читает секреты только из окружения — сам `.env` он не парсит.

---

## Если что-то не так

| Симптом | Причина | Решение |
|---|---|---|
| `401 ... api key is invalid` | ключ отозван/неверный | перевыпустить в кабинете DeepSeek, обновить `.env`, `up -d --force-recreate` |
| `402 Insufficient Balance` | нулевой баланс | пополнить счёт DeepSeek |
| `400 ... chat not found` | неверный `TELEGRAM_CHAT_ID` | получить настоящий ID через `getUpdates` |
| `403` на конкретной ленте | блокировка CDN/бот-защита | заменить источник или подключить `curl_cffi` |
| `[WARN] CISA KEV fetch failed` | CISA отдаёт 403 / таймаут / битый JSON | проверить доступность URL из контейнера; бот продолжит без KEV |
| `Не удалось сохранить seen_urls.json` | нет прав на файл | `sudo chown 10001:10001 seen_urls.json` |
| Контейнер сразу падает | не заданы переменные | проверить `.env`, затем `docker compose config` |

---

## Безопасность

- `.env` не коммитится; в Docker он передаётся через `env_file`, а не в образ.
- Контейнер работает не от root (`USER bot`, uid 10001).
- Токены, попавшие в переписку/логи, стоит перевыпустить: DeepSeek — в кабинете,
  Telegram — через `@BotFather` → `/revoke`.
- Если правите файлы на хосте под другим пользователем — держите общий доступ
  через группу, а не `chmod 777`.

---

## Идеи для развития

- **Фаза 2**: приоритизация P1/P2 и умная отправка — KEV и «критично» первыми,
  остальное одним дайджестом; `MAX_MESSAGES_PER_CYCLE` уже заведён под это.
- Хранить историю в SQLite вместо JSON — при росте числа лент и источников.
- Добавить второй канал (например, для «только критичного»).
- Кэшировать анализ по нормализованному заголовку, если ленты дублируют новость.
- Метрики/healthcheck-эндпоинт для мониторинга живости.
