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
3. Отправляет до 20 самых свежих статей за цикл в DeepSeek с промптом
   на строгий формат ответа:

   ```
   [Критичность: 1-5] (5 — 0-day/массовый взлом, 1 — мнение)
   Суть: одно предложение.
   Детали: 2-3 предложения.
   TITLE_RU: перевод заголовка на русский
   ```

4. Классифицирует результат: **5 → 🔴 алерты**, **4 → 🟡 контекст** (с `⚠️`),
   остальное и неанализированное — тоже в контекст (с `·`).
5. Публикует тремя потоками: `🆕 CISA KEV` (отдельно), `🔴 Алерты`
   (пачками по 5) и `🟡 Контекст` (строками). Оригинальный заголовок
   остаётся для поиска, перевод идёт следом через `·`
   (`Original · Перевод`). Каждое сообщение режется по границам
   новостей до 4000 символов — ничего не выбрасывается.
6. Забирает CISA KEV — новые записи за последние 7 дней с NVD-ссылками —
   и переводит их отдельным запросом (при сбое остаются оригиналы).
7. Спит 6 часов и повторяет. Любой сбой сети, API или одного источника
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
             дедупликация по seen_urls.json (ключ = ссылка)
                             ▼
          DeepSeek: до 20 самых свежих (KEV — отдельным запросом)
                             │  [Критичность: N] + Суть + Детали + TITLE_RU
                             ▼
     классификация: 5 → 🔴, 4 → 🟡⚠️, 1–3 → 🟡, без анализа → 🟡·
                             ▼
   pack_blocks(): разбивка по границам новостей, ≤ 4000 UTF-16 на сообщение
                             ▼
    🆕 KEV  →  🔴 Алерты (пачки по 5)  →  🟡 Контекст (строками)
                             ▼
    Telegram Bot API  sendMessage (HTML, без превью ссылок)
```

| Этап | Модуль | Что происходит |
|---|---|---|
| Загрузка RSS | `requests` + `get_with_retry()` | GET с таймаутом 20 с и повтором при 403/429/5xx |
| Разбор RSS | `feedparser` | до `FETCH_DEPTH` (20) записей за `FETCH_WINDOW_HOURS` (24 ч) |
| CISA KEV | `requests` → JSON | сортировка по `dateAdded`, окно 7 дней, NVD-ссылки |
| Перевод KEV | `openai` → DeepSeek | отдельный батч JSON; при ошибке — оригиналы |
| Дедупликация | `seen_urls.json` | уже отправленное и дубли внутри цикла |
| Анализ | `openai` SDK → DeepSeek | до `ANALYZE_PER_CYCLE` (20) самых свежих |
| Локализация | `extract_title_ru()` | `TITLE_RU` вырезается из разбора; fallback — оригинал |
| Классификация | `extract_criticality()` | 5 → 🔴, 4 → 🟡⚠️, 1–3 и без анализа → 🟡 |
| Разбивка | `pack_blocks()` | по границам новостей, ≤ `DIGEST_SPLIT_LIMIT` (4000) UTF-16 |
| Доставка | `requests` → Telegram API | KEV → алерты → контекст; `seen_urls` батчем после успеха |

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
  как ключ — она уникальна и стабильна. После успешной отправки KEV-сообщения
  ссылки попадают в `seen_urls.json` наравне с RSS. `_reported_kev` в памяти
  остаётся страховкой от повторного лога в рамках одного процесса.
- **Проверка** стоит до обращения к LLM: дубль не тратит токены и время.
- **Запись** — батчем, после успешной отправки конкретного сообщения: в историю
  попадают только ссылки из него. Если сообщение упало, его новости остаются
  «невиденными» и уйдут в следующем цикле. Лучше повторить, чем потерять.
- **Сохранение после каждого сообщения**, а не в конце цикла — при падении
  процесса уже доставленное не потеряется.
- **Обрезка истории**: при сохранении остаются последние `MAX_SEEN_URLS`
  (5000) записей в порядке добавления — файл не растёт бесконечно.
  При ~40 новых в сутки это ~4 месяца; если старая новость всплывёт позже,
  она уйдёт повторно.
- **Атомарная запись**: временный файл + `os.replace()`. В Docker
  `seen_urls.json` — bind-mount, а `rename()` поверх точки монтирования ядро
  запрещает (`EBUSY`), поэтому при такой ошибке код откатывается на прямую
  перезапись файла.
- **Битый файл**: непарсящийся JSON или не-список откладывается в
  `seen_urls.json.corrupt`, работа продолжается с пустой историей.
  Не-строки в массиве отбрасываются (`skipped N invalid entries`),
  корректные записи сохраняются.

Полезные команды:

```bash
cat seen_urls.json                              # что уже отправлено
echo '[]' > seen_urls.json                      # сбросить историю
docker compose restart                          # и отправить всё заново
```

---

## Заметки: обработка ошибок

Четыре уровня изоляции — сбой одного шага не валит остальные:

1. **Одна лента** — `requests.RequestException` → `[WARN] Источник заблокирован
   или недоступен: <url>` и переход к следующей ленте.
2. **Одна статья** — ошибка LLM логируется, остальные статьи обрабатываются.
3. **Одно сообщение** — ошибка отправки логируется, остальные пачки уходят;
   ссылки из упавшего сообщения не попадают в `seen_urls`.
4. **Весь цикл** — `log.exception(...)`, затем сон и новая попытка через 6 часов.

Ретраи (`get_with_retry`):

| Параметр | Значение |
|---|---|
| Повторяемые статусы | `403`, `429`, любые `5xx` |
| Всего попыток | 2 (первая + одна повторная) |
| Пауза между попытками | 2 секунды |
| `404` и прочие `4xx` | не ретраятся — сразу предупреждение |

Что ещё предусмотрено:

- HTTP-таймаут 20 с на каждый запрос — бот не зависает на «мёртвой» ленте.
- Разбивка сообщений по границам новостей до 4000 UTF-16 code units —
  ни одно сообщение не превышает лимит Telegram (4096).
- Экранирование HTML в заголовке, ссылке и ответе LLM — иначе `<`, `>`, `&`
  из RSS ломают разметку и Telegram отвечает `400`.
- Проверка обязательных переменных окружения на старте: понятная ошибка вместо
  падения в середине цикла.
- **CISA KEV**: 403/таймаут/битый JSON → `[WARN] CISA KEV fetch failed` и пустой
  список; остальной цикл продолжается. У KEV отдельный таймаут 15 с.
- **Перевод KEV**: ошибка/таймаут/битый JSON → `[WARN] KEV translation failed`,
  KEV-сообщение уходит с оригинальными названиями; цикл не прерывается.
- **Accounting** в конце цикла: `[cycle] collected=… analyzed=… alerts=… digest=…`
  и предупреждение `[WARN] accounting mismatch`, если что-то не сошлось.
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
| `ANALYZE_PER_CYCLE` | `20` | сколько статей за цикл уходит в LLM |
| `ALERTS_PER_MESSAGE` | `5` | алертов в одном сообщении (или лимит 4000) |
| `P1_MAX_MESSAGES` | `5` | максимум сообщений с алертами; излишек → дайджест |
| `DIGEST_SPLIT_LIMIT` | `4000` | символов на сообщение (UTF-16) |
| `MAX_MESSAGES_PER_CYCLE` | `12` | мягкий потолок сообщений (только лог) |
| `MESSAGE_PAUSE_SECONDS` | `1` | пауза между сообщениями |
| `MAX_SEEN_URLS` | `5000` | сколько последних ссылок хранить в истории |
| `CHECK_INTERVAL_SECONDS` | `6 * 60 * 60` | период опроса |
| `HTTP_TIMEOUT` | `20` | таймаут запроса, сек |
| `FETCH_ATTEMPTS` | `2` | попыток на ленту |
| `RETRY_DELAY_SECONDS` | `2` | пауза перед повтором, сек |
| `TELEGRAM_MAX_LENGTH` | `4096` | лимит длины сообщения |
| `KEV_TIMEOUT` | `15` | таймаут запроса к CISA KEV |
| `KEV_TRANSLATE_TIMEOUT` | `20` | таймаут запроса перевода KEV |
| `KEV_LIMIT` | `10` | сколько новых KEV-записей за прогон |
| `KEV_WINDOW_DAYS` | `7` | окно свежести KEV |
| `KEV_DESC_LIMIT` | `300` | обрезка описания KEV (по границе слова, с «…») |
| `DRY_RUN` | `0` | `1` — собрать и залогировать, но не отправлять |

---

## Пример лога

```
2026-11-04 13:35:12 [INFO] sec-bot: Старт. Лент: 6, сбор: до 20/лента за 24 ч, анализ: 20/цикл, в истории: 140, интервал: 6 ч, dry_run=False
2026-11-04 13:35:12 [INFO] sec-bot: Читаю ленту: https://www.securityweek.com/feed/
2026-11-04 13:35:12 [INFO] sec-bot: [RSS] https://www.securityweek.com/feed/: collected 9 of 10 in 24 h
2026-11-04 13:35:13 [INFO] sec-bot: [RSS] https://thehackernews.com/feeds/posts/default: collected 13 of 20 in 24 h
2026-11-04 13:35:21 [INFO] sec-bot: [cycle] collected=39 kev=0 rss_new=2 window_dropped=56 dup_seen=37 dup_cycle=0 analyzed=2 ru_missing=0 cve_total=2 cve_dupes=0 alerts=0 digest=2 messages=1 delivered=2 seen=142 dry_run=False
2026-11-04 13:35:21 [INFO] sec-bot: Сплю 6 ч до следующей проверки
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

## Разработка

```bash
pip install -r requirements.txt ruff mypy types-requests

ruff check .                      # линтер
mypy app.py                       # проверка типов
python -m unittest discover -s tests -v
```

То же самое прогоняется в CI (GitHub Actions) на каждый push и PR:
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). Конфиги — в
[`pyproject.toml`](pyproject.toml).

---

## Проверка без отправки (DRY_RUN)

```bash
DRY_RUN=1 docker compose up -d --force-recreate
docker compose logs -f --tail=50
```

Бот соберёт, проанализирует и разложит новости по сообщениям, но **не отправит**
их и **не изменит** `seen_urls.json`. Вместо отправки в лог пишется
`[DRY_RUN] сообщение (N новостей): …` — можно посмотреть формат, объём и
разбивку до боевого запуска:

```bash
docker compose up -d --force-recreate   # вернуть обычный режим
```

---

## Healthcheck

Бот пишет `/tmp/heartbeat` в конце каждого цикла, а `HEALTHCHECK` в Dockerfile
считает контейнер `healthy`, если метка обновлялась менее 8 часов назад
(6 ч сна плюс запас на длинный цикл).

```bash
docker compose ps       # STATUS: Up 5 minutes (healthy)
```

Важно: `restart: unless-stopped` **не** перезапускает контейнер по `unhealthy` —
healthcheck только показывает состояние. Для авторестарта нужен внешний
watchdog (например, `willfarrell/autoheal`).

---

## Если что-то не так

| Симптом | Причина | Решение |
|---|---|---|
| `401 ... api key is invalid` | ключ отозван/неверный | перевыпустить в кабинете DeepSeek, обновить `.env`, `up -d --force-recreate` |
| `402 Insufficient Balance` | нулевой баланс | пополнить счёт DeepSeek |
| `400 ... chat not found` | неверный `TELEGRAM_CHAT_ID` | получить настоящий ID через `getUpdates` |
| `403` на конкретной ленте | блокировка CDN/бот-защита | заменить источник или подключить `curl_cffi` |
| `[WARN] CISA KEV fetch failed` | CISA отдаёт 403 / таймаут / битый JSON | проверить доступность URL из контейнера; бот продолжит без KEV |
| `[WARN] KEV translation failed` | LLM вернул битый JSON / таймаут | KEV уйдут с оригинальными названиями; проверить ключ и баланс |
| `[RSS] … collected 0 of 20 in 24 h` | в ленте нет записей за сутки | это норма: лента жива, просто новости старше окна `FETCH_WINDOW_HOURS` |
| `Не удалось сохранить seen_urls.json` | нет прав на файл | `sudo chown 10001:10001 seen_urls.json` |
| `[WARN] accounting mismatch` | сбой в отборе/доставке | посмотреть `[cycle]`-строку цикла; сообщить разработчику |
| `unhealthy` в `docker compose ps` | цикл не завершался > 8 ч | проверить логи: завис LLM или Telegram |
| `seen_urls: skipped N invalid entries` | в истории были не-строки | ничего: мусор отброшен, валидные записи сохранены |
| `[budget] N messages > 12` | новостей больше, чем обычно | мягкий лимит: всё отправлено, просто больше сообщений |
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

- Хранить историю в SQLite вместо JSON — при росте числа лент и источников.
- Добавить второй канал (например, для «только критичного»).
- Кэшировать анализ по нормализованному заголовку, если ленты дублируют новость.
- Метрики/healthcheck-эндпоинт для мониторинга живости.
