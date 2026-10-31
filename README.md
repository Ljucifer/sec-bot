# Sec-Bot — мониторинг новостей кибербезопасности

![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)
![DeepSeek](https://img.shields.io/badge/LLM-DeepSeek-4D6BFE)

Бот раз в 6 часов читает RSS-ленты по кибербезопасности, просит DeepSeek оценить
критичность каждой новости и присылает разбор в Telegram. Критичные новости
(0-day, массовые взломы) помечаются отдельным заголовком, остальные идут как дайджест.

---

## Что делает

1. Опрашивает 6 RSS-лент и берёт по 2 самые свежие записи с каждой.
2. Пропускает то, что уже отправлял — дубли не попадают в канал.
3. Отправляет новость в DeepSeek с промптом на строгий формат ответа:

   ```
   [Критичность: 1-5] (5 — 0-day/массовый взлом, 1 — мнение)
   Суть: одно предложение.
   Детали: 2-3 предложения.
   ```

4. Публикует результат в Telegram: `🚨 КРИТИЧЕСКАЯ НОВОСТЬ` для оценок 4–5,
   `🛡 Security Дайджест` для остальных.
5. Спит 6 часов и повторяет. Любой сбой сети, API или одного источника
   логируется, но не останавливает бота.

---

## Архитектура

```
        RSS-ленты (6 шт.)
              │
              │  requests.get
              │  + браузерные заголовки
              │  + retry на 403 / 429 / 5xx
              ▼
     feedparser.parse()
              │  последние 2 записи
              ▼
   дедупликация по seen_urls.json ──► уже отправляли? пропустить
              │
              ▼
   DeepSeek API  chat/completions (deepseek-chat)
              │  [Критичность: N] + Суть + Детали
              ▼
   классификация: 4–5 → 🚨, иначе → 🛡
              │
              ▼
   Telegram Bot API  sendMessage (HTML, без превью ссылок)
```

| Этап | Модуль | Что происходит |
|---|---|---|
| Загрузка | `requests` + `get_with_retry()` | GET с таймаутом 20 с и повтором при 403/429/5xx |
| Разбор | `feedparser` | RSS/Atom → список записей, берём первые 2 |
| Дедупликация | `seen_urls.json` | ссылка уже отправлялась → `continue` |
| Анализ | `openai` SDK → DeepSeek | `chat.completions.create`, `temperature=0.2` |
| Доставка | `requests` → Telegram API | `parse_mode="HTML"`, `disable_web_page_preview=True` |

---

## Структура проекта

```
sec-bot/
├── app.py              # вся логика: RSS → LLM → Telegram
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

Узнать свой `chat_id`: написать боту сообщение и открыть
`https://api.telegram.org/bot<TOKEN>/getUpdates` → `message.chat.id`.

---

## RSS-ленты

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
- Логгеры `httpx`/`httpx2` приглушены до `WARNING`, чтобы не сыпать строкой
  `HTTP Request: POST ...` на каждый вызов.

---

## Настройки

Все константы — в начале `app.py`:

| Константа | Значение | Смысл |
|---|---|---|
| `RSS_FEEDS` | 6 лент | источники |
| `NEWS_PER_FEED` | `2` | новостей с каждой ленты за цикл |
| `CHECK_INTERVAL_SECONDS` | `6 * 60 * 60` | период опроса |
| `HTTP_TIMEOUT` | `20` | таймаут запроса, сек |
| `FETCH_ATTEMPTS` | `2` | попыток на ленту |
| `RETRY_DELAY_SECONDS` | `2` | пауза перед повтором, сек |
| `TELEGRAM_MAX_LENGTH` | `4096` | лимит длины сообщения |

---

## Пример лога

```
2026-10-31 09:40:00 [INFO] sec-bot: Старт. Лент: 6, новостей с каждой: 2, в истории: 0, интервал: 6 ч
2026-10-31 09:40:00 [INFO] sec-bot: Читаю ленту: https://www.securityweek.com/feed/
2026-10-31 09:40:02 [INFO] sec-bot: Отправлено (критично): PHP2Shell Attacks Root Palo Alto Firewalls...
2026-10-31 09:40:04 [INFO] sec-bot: Отправлено (дайджест): In Other News: Anthropic Breach Dispute...
2026-10-31 09:40:06 [INFO] sec-bot: Пропускаю дубль: Attackers Chain Three Ivanti Connect Secure Flaws...
2026-10-31 09:40:16 [WARNING] sec-bot: [WARN] Источник заблокирован или недоступен: https://example.com/feed/ (403 ...)
2026-10-31 09:40:16 [INFO] sec-bot: Сплю 6 ч до следующей проверки
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

- Хранить историю в SQLite вместо JSON — при росте числа лент.
- Добавить второй канал (например, для «только критичного»).
- Кэшировать анализ по нормализованному заголовку, если ленты дублируют новость.
- Метрики/healthcheck-эндпоинт для мониторинга живости.
