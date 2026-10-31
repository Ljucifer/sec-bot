#!/usr/bin/env python3
"""
Монитор новостей кибербезопасности.

Что делает скрипт:
  1. Раз в 6 часов забирает свежие записи из RSS-лент.
  2. Берёт по 2 самые свежие новости с каждой ленты.
  3. Пропускает новости, которые уже отправлял (файл seen_urls.json).
  4. Отправляет текст новости в DeepSeek (через официальный клиент openai).
  5. Публикует разбор в Telegram с пометкой «критично» / «дайджест».

Все секреты читаются из переменных окружения:
  DEEPSEEK_API_KEY, TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import sys
import time

import feedparser
import requests
from openai import OpenAI

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------

# RSS-ленты, которые опрашиваем.
RSS_FEEDS: list[str] = [
    "https://www.securityweek.com/feed/",
    "https://thehackernews.com/feeds/posts/default",
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.zerodayinitiative.com/rss/published/",
    "https://www.darkreading.com/rss.xml",
]

# DeepSeek API (совместим с OpenAI SDK).
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"

# Промпт для анализа новости. Требуем строгий формат ответа.
ANALYSIS_PROMPT = (
    "Проанализируй новость. Выдай ответ строго в формате: "
    "[Критичность: 1-5] (где 5 - это 0-day, массовый взлом; 1 - мнение). "
    "Суть: (одно предложение). Детали: (2-3 предложения)."
)

# Сколько новостей брать с каждой ленты (2 — для теста).
NEWS_PER_FEED = 2

# Интервал между проверками: 6 часов.
CHECK_INTERVAL_SECONDS = 6 * 60 * 60

# Таймаут HTTP-запросов (секунды).
HTTP_TIMEOUT = 20

# Лимит длины сообщения в Telegram.
TELEGRAM_MAX_LENGTH = 4096

# Обязательные переменные окружения.
REQUIRED_ENV_VARS = ("DEEPSEEK_API_KEY", "TELEGRAM_TOKEN", "TELEGRAM_CHAT_ID")

# Файл с уже отправленными новостями. Путь считаем от каталога скрипта,
# чтобы он совпадал с точкой монтирования в Docker (/app/seen_urls.json),
# независимо от того, откуда запущен процесс.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SEEN_URLS_FILE = os.path.join(BASE_DIR, "seen_urls.json")

# Заголовки для запросов к RSS: часть сайтов отдаёт 403 без User-Agent
# и без заголовков, которые присылает обычный браузер.
HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "application/rss+xml, application/xml, text/xml",
    "Accept-Language": "en-US,en;q=0.9",
}

# Ретраи для защиты от временных блокировок и сбоев на стороне источника.
FETCH_ATTEMPTS = 2          # всего попыток на одну ленту
RETRY_DELAY_SECONDS = 2     # пауза между попытками
RETRYABLE_STATUSES = {403, 429}  # 403/429 и любые 5xx имеет смысл повторить

log = logging.getLogger("sec-bot")

# Регулярка для «мягкого» определения критичности, если LLM слегка
# отклонился от формата (лишние пробелы внутри скобок и т.п.).
CRITICALITY_RE = re.compile(r"\[\s*Критичность\s*:\s*([1-5])\s*\]", re.IGNORECASE)

# HTML-теги в summary RSS — для промпта их нужно убрать.
HTML_TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# История отправленного (защита от дублей)
# ---------------------------------------------------------------------------


def load_seen_urls() -> set[str]:
    """Читает seen_urls.json и возвращает множество уже отправленных ссылок.

    Если файла нет (первый запуск) — возвращает пустое множество.
    Битый JSON не должен останавливать бота: логируем и стартуем с нуля.
    """
    try:
        with open(SEEN_URLS_FILE, encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        log.info("Файл %s не найден — начинаю с пустой историей", SEEN_URLS_FILE)
        return set()
    except (json.JSONDecodeError, OSError) as exc:
        log.warning(
            "Не удалось прочитать %s (%s) — начинаю с пустой историей",
            SEEN_URLS_FILE,
            exc,
        )
        return set()

    if not isinstance(data, list):
        log.warning("%s повреждён (ожидался список) — начинаю с нуля", SEEN_URLS_FILE)
        return set()

    # Отбрасываем всё, что не строка: в файле могли оказаться мусорные данные.
    return {item for item in data if isinstance(item, str)}


def save_seen_urls(seen: set[str]) -> None:
    """Сохраняет историю в seen_urls.json.

    Пытаемся писать атомарно: во временный файл + os.replace. Но
    seen_urls.json в Docker — это bind-mount (./seen_urls.json:/app/...),
    а rename() поверх точки монтирования ядро запрещает (EBUSY).
    Поэтому при такой ошибке откатываемся на прямую перезапись файла.
    """
    payload = json.dumps(sorted(seen), ensure_ascii=False, indent=2) + "\n"
    tmp_path = SEEN_URLS_FILE + ".tmp"

    try:
        with open(tmp_path, "w", encoding="utf-8") as file:
            file.write(payload)
        try:
            os.replace(tmp_path, SEEN_URLS_FILE)
            return
        except OSError:
            # EBUSY/EXDEV: файл смонтирован, подменить его нельзя.
            pass
    except OSError as exc:
        log.error("Не удалось записать %s: %s", tmp_path, exc)

    # Резервный путь: перезапись на месте (работает и для bind-mount).
    try:
        with open(SEEN_URLS_FILE, "w", encoding="utf-8") as file:
            file.write(payload)
    except OSError as exc:
        # Сбой записи не должен ломать рассылку уже отправленных новостей.
        log.error("Не удалось сохранить %s: %s", SEEN_URLS_FILE, exc)
        return

    # Временный файл мог остаться после неудачного rename — убираем.
    try:
        os.remove(tmp_path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------


def load_config() -> dict[str, str]:
    """Читает секреты из окружения и падает с понятной ошибкой, если их нет."""
    config: dict[str, str] = {}
    missing: list[str] = []

    for name in REQUIRED_ENV_VARS:
        value = os.getenv(name, "").strip()
        if not value:
            missing.append(name)
        config[name] = value

    if missing:
        raise RuntimeError(
            "Не заданы переменные окружения: " + ", ".join(missing)
        )

    return config


def clean_text(raw_text: str) -> str:
    """Убирает HTML-разметку из текста RSS и схлопывает пробелы."""
    without_tags = HTML_TAG_RE.sub(" ", raw_text or "")
    return WHITESPACE_RE.sub(" ", html.unescape(without_tags)).strip()


def get_with_retry(url: str) -> requests.Response:
    """GET с одной повторной попыткой при 403/429/5xx.

    Возвращает последний ответ (даже неуспешный) — решение о том, что
    делать с 403, принимает вызывающий код. Сетевые ошибки (таймаут,
    отсутствие DNS) пробрасываются наружу сразу.
    """
    response = requests.get(url, headers=HTTP_HEADERS, timeout=HTTP_TIMEOUT)

    for attempt in range(1, FETCH_ATTEMPTS + 1):
        status = response.status_code
        retryable = status in RETRYABLE_STATUSES or status >= 500

        if not retryable:
            return response

        log.warning(
            "HTTP %d от %s (попытка %d/%d)",
            status,
            url,
            attempt,
            FETCH_ATTEMPTS,
        )

        if attempt == FETCH_ATTEMPTS:
            break

        time.sleep(RETRY_DELAY_SECONDS)
        response = requests.get(url, headers=HTTP_HEADERS, timeout=HTTP_TIMEOUT)

    return response


def fetch_feed_news(feed_url: str, limit: int = NEWS_PER_FEED) -> list[dict[str, str]]:
    """Возвращает `limit` самых свежих новостей из одной RSS-ленты.

    Скачивание делаем через requests (чтобы контролировать таймаут),
    а разбор отдаём feedparser — он устойчив к разным версиям RSS/Atom.
    """
    response = get_with_retry(feed_url)
    response.raise_for_status()

    parsed = feedparser.parse(response.content)

    # Если лента битая, feedparser не бросает исключение — проверяем сами.
    if parsed.bozo and not parsed.entries:
        raise ValueError(f"Не удалось разобрать ленту: {feed_url}")

    news: list[dict[str, str]] = []
    for entry in parsed.entries[:limit]:
        # `entry.get(...) or ...` — страховка от None вместо строки.
        title = clean_text(entry.get("title") or "Без заголовка")
        link = entry.get("link") or ""
        summary = clean_text(entry.get("summary") or entry.get("description") or "")
        news.append({"title": title, "link": link, "summary": summary})

    return news


def news_key(item: dict[str, str]) -> str:
    """Ключ новости для дедупликации: ссылка, либо заголовок, если ссылки нет."""
    return item["link"] or f"title:{item['title']}"


def analyze_news(client: OpenAI, title: str, summary: str) -> str:
    """Отправляет новость в DeepSeek и возвращает текстовый разбор."""
    user_content = f"Заголовок: {title}\n\nТекст: {summary or 'Текст недоступен.'}"

    response = client.chat.completions.create(
        model=DEEPSEEK_MODEL,
        messages=[
            {"role": "system", "content": ANALYSIS_PROMPT},
            {"role": "user", "content": user_content},
        ],
        temperature=0.2,
        max_tokens=500,
    )

    return (response.choices[0].message.content or "").strip()


def is_critical(analysis: str) -> bool:
    """True, если LLM оценил новость на 4 или 5 (0-day, массовый взлом)."""
    # Основная проверка — ровно те маркеры, что просили в задании.
    if "[Критичность: 4]" in analysis or "[Критичность: 5]" in analysis:
        return True

    # Страховка от мелких отклонений в форматировании.
    match = CRITICALITY_RE.search(analysis)
    return bool(match) and int(match.group(1)) >= 4


def build_message(title: str, link: str, analysis: str, critical: bool) -> str:
    """Собирает HTML-сообщение для Telegram."""
    header = (
        "🚨 <b>КРИТИЧЕСКАЯ НОВОСТЬ</b> 🚨\n\n"
        if critical
        else "🛡 <b>Security Дайджест</b>\n\n"
    )

    # Экранируем всё, что пришло извне: LLM и RSS могут содержать <, >, &.
    safe_title = html.escape(title)
    safe_analysis = html.escape(analysis)

    if link:
        title_line = f'<b><a href="{html.escape(link, quote=True)}">{safe_title}</a></b>'
    else:
        title_line = f"<b>{safe_title}</b>"

    message = f"{header}{title_line}\n\n{safe_analysis}"

    # Telegram не примет сообщение длиннее 4096 символов.
    if len(message) > TELEGRAM_MAX_LENGTH:
        message = message[: TELEGRAM_MAX_LENGTH - 10] + "\n\n…"

    return message


def send_telegram_message(token: str, chat_id: str, text: str) -> None:
    """Отправляет сообщение в Telegram Bot API (sendMessage)."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    response = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)

    if not response.ok:
        # Тело ответа Telegram содержит описание ошибки — полезно в логах.
        raise RuntimeError(
            f"Telegram API вернул {response.status_code}: {response.text[:500]}"
        )


def process_all_feeds(
    client: OpenAI,
    token: str,
    chat_id: str,
    seen_urls: set[str],
) -> None:
    """Один полный проход по всем лентам.

    `seen_urls` изменяется на месте: после каждой успешной отправки
    ссылка добавляется туда и сразу сохраняется на диск.
    """
    for feed_url in RSS_FEEDS:
        log.info("Читаю ленту: %s", feed_url)

        # Сбой одной ленты не должен ломать весь цикл.
        try:
            news_items = fetch_feed_news(feed_url)
        except requests.RequestException as exc:
            # 403 после повторной попытки, таймаут, обрыв соединения и т.п.
            log.warning(
                "[WARN] Источник заблокирован или недоступен: %s (%s)",
                feed_url,
                exc,
            )
            continue
        except Exception as exc:  # noqa: BLE001 — намеренно ловим всё сетевое
            log.error("Не удалось получить %s: %s", feed_url, exc)
            continue

        if not news_items:
            log.warning("В ленте нет новостей: %s", feed_url)
            continue

        for item in news_items:
            key = news_key(item)

            # Дубль уже отправляли — пропускаем, не тратя запросы к LLM.
            if key in seen_urls:
                log.info("Пропускаю дубль: %s", item["title"])
                continue

            # И ошибка по одной новости тоже не должна останавливать остальные.
            try:
                analysis = analyze_news(client, item["title"], item["summary"])
                if not analysis:
                    log.warning("LLM вернул пустой ответ: %s", item["title"])
                    continue

                critical = is_critical(analysis)
                message = build_message(
                    item["title"], item["link"], analysis, critical
                )
                send_telegram_message(token, chat_id, message)

                # Отправка удалась — фиксируем факт сразу, до перехода
                # к следующей новости, чтобы не потерять его при падении.
                seen_urls.add(key)
                save_seen_urls(seen_urls)

                log.info(
                    "Отправлено (%s): %s",
                    "критично" if critical else "дайджест",
                    item["title"],
                )
            except Exception as exc:  # noqa: BLE001
                log.error("Ошибка обработки «%s»: %s", item["title"], exc)


def main() -> None:
    """Точка входа: настройка логов, клиента и бесконечный цикл."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # openai/httpx логируют каждый HTTP-запрос на уровне INFO — это шум.
    # Имя логгера зависит от версии клиента, поэтому глушим оба варианта.
    for noisy_logger in ("httpx", "httpx2"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

    try:
        config = load_config()
    except RuntimeError as exc:
        log.critical("%s", exc)
        sys.exit(1)

    client = OpenAI(
        api_key=config["DEEPSEEK_API_KEY"],
        base_url=DEEPSEEK_BASE_URL,
    )

    # Историю читаем один раз при старте, дальше держим в памяти и дописываем.
    seen_urls = load_seen_urls()

    log.info(
        "Старт. Лент: %d, новостей с каждой: %d, в истории: %d, интервал: %d ч",
        len(RSS_FEEDS),
        NEWS_PER_FEED,
        len(seen_urls),
        CHECK_INTERVAL_SECONDS // 3600,
    )

    try:
        while True:
            try:
                process_all_feeds(
                    client,
                    config["TELEGRAM_TOKEN"],
                    config["TELEGRAM_CHAT_ID"],
                    seen_urls,
                )
            except Exception:  # noqa: BLE001 — скрипт не должен падать
                log.exception("Сбой цикла проверки, продолжаю работу")

            log.info("Сплю %d ч до следующей проверки", CHECK_INTERVAL_SECONDS // 3600)
            time.sleep(CHECK_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        log.info("Остановка по Ctrl+C. Выход.")


if __name__ == "__main__":
    main()
