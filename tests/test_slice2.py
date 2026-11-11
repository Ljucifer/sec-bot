"""Тесты Среза 2: дедупликация, анализ, доставка и пайплайн.

Запуск: python -m unittest discover -s tests -v
"""

import json
import unittest
from types import SimpleNamespace

import app


def make_item(index: int, published: str | None = None) -> dict:
    return {
        "title": f"News #{index}",
        "link": f"https://example.com/news/{index}",
        "summary": f"summary {index}",
        "published": published or f"2026-11-02T{index % 24:02d}:00:00+00:00",
        "is_kev": False,
    }


def make_kev(index: int = 0) -> dict:
    link = f"https://nvd.nist.gov/vuln/detail/CVE-2026-{index}"
    return {
        "title": f"CISA KEV: Flaw {index} (CVE-2026-{index})",
        "name": f"Flaw {index}",
        "cve_id": f"CVE-2026-{index}",
        "link": link,
        "key": link,
        "summary": "description",
        "published": "2026-11-01T00:00:00+00:00",
        "is_kev": True,
    }


class _FakeCompletions:
    def __init__(self, content=None, error=None):
        self.content = content
        self.error = error
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=self.content))]
        )


class _FakeClient:
    def __init__(self, content=None, error=None):
        self.completions = _FakeCompletions(content, error)
        self.chat = SimpleNamespace(completions=self.completions)


class KevTranslationTests(unittest.TestCase):
    def test_empty_list_makes_no_request(self):
        client = _FakeClient(content="[]")
        self.assertEqual(app.translate_kev_articles([], client), {})
        self.assertEqual(client.completions.calls, 0)

    def test_valid_json(self):
        raw = json.dumps(
            [
                {
                    "cveID": "CVE-2026-1",
                    "title_ru": "Название",
                    "desc_ru": "Описание",
                }
            ],
            ensure_ascii=False,
        )
        result = app.translate_kev_articles([make_kev(1)], _FakeClient(content=raw))
        self.assertEqual(result["CVE-2026-1"]["title_ru"], "Название")
        self.assertEqual(result["CVE-2026-1"]["desc_ru"], "Описание")

    def test_fenced_json(self):
        raw = '```json\n[{"cveID": "CVE-2026-1", "title_ru": "Т", "desc_ru": "Д"}]\n```'
        result = app.translate_kev_articles([make_kev(1)], _FakeClient(content=raw))
        self.assertIn("CVE-2026-1", result)

    def test_partial_response(self):
        raw = '[{"cveID": "CVE-2026-1", "title_ru": "Т"}]'
        result = app.translate_kev_articles(
            [make_kev(1), make_kev(2)], _FakeClient(content=raw)
        )
        self.assertEqual(set(result), {"CVE-2026-1"})

    def test_broken_json(self):
        result = app.translate_kev_articles(
            [make_kev(1)], _FakeClient(content="not json")
        )
        self.assertEqual(result, {})

    def test_request_error(self):
        client = _FakeClient(error=RuntimeError("timeout"))
        self.assertEqual(app.translate_kev_articles([make_kev(1)], client), {})


class DedupeTests(unittest.TestCase):
    def test_filters_seen_and_cycle_duplicates(self):
        items = [make_item(1), make_item(2), make_item(1), make_item(3)]
        fresh, dup_seen, dup_cycle = app.dedupe_items(
            items, {"https://example.com/news/2"}
        )

        self.assertEqual([item["title"] for item in fresh], ["News #1", "News #3"])
        for item in fresh:
            self.assertIn("key", item)


class AnalyzeCandidatesTests(unittest.TestCase):
    def test_budget_and_order(self):
        items = [
            make_item(index, published=f"2026-11-01T{index:02d}:00:00+00:00")
            for index in range(30)
        ]
        calls: list[str] = []

        def fake_analyze(client, title, summary):
            calls.append(title)
            return "[Критичность: 3] Суть: тест."

        original = app.analyze_news
        original_batch = app.analyze_batch
        app.analyze_news = fake_analyze
        app.analyze_batch = lambda client, items: None
        try:
            analyzed, rest = app.analyze_candidates(items, object())
        finally:
            app.analyze_news = original
            app.analyze_batch = original_batch

        self.assertEqual(len(analyzed), app.ANALYZE_PER_CYCLE)
        self.assertEqual(len(rest), 30 - app.ANALYZE_PER_CYCLE)
        self.assertEqual(calls[0], "News #29")  # самые свежие первыми
        self.assertEqual(len(calls), app.ANALYZE_PER_CYCLE)


class MessageHeaderTests(unittest.TestCase):
    def test_headers_use_correct_plural_forms(self):
        self.assertEqual(app._digest_header(1), "🟡 <b>Контекст</b> — 1 новость")
        self.assertEqual(app._digest_header(5), "🟡 <b>Контекст</b> — 5 новостей")
        self.assertEqual(app._kev_header(1), "🆕 <b>CISA KEV</b> — 1 новая запись")
        self.assertEqual(app._alerts_header(2), "🔴 <b>Алерты</b> — 2 алерта")

    def test_split_messages_get_own_counts(self):
        items = [make_item(index) for index in range(6)]

        batches = app.build_batches(
            items,
            app.render_digest,
            app._digest_header,
            limit=80,
            separator="\n",
        )

        self.assertGreater(len(batches), 1)
        total = 0
        for text, group in batches:
            total += len(group)
            header = text.split("\n", 1)[0]
            self.assertIn(f"— {len(group)} ", header)
        self.assertEqual(total, 6)


class DeliverBatchesTests(unittest.TestCase):
    def setUp(self):
        self.original = {
            "send_telegram_message": app.send_telegram_message,
            "save_seen_urls": app.save_seen_urls,
            "DRY_RUN": app.DRY_RUN,
            "MESSAGE_PAUSE_SECONDS": app.MESSAGE_PAUSE_SECONDS,
        }
        app.save_seen_urls = lambda seen: None
        app.MESSAGE_PAUSE_SECONDS = 0

    def tearDown(self):
        for name, value in self.original.items():
            setattr(app, name, value)

    def test_seen_updated_only_after_success(self):
        app.send_telegram_message = lambda token, chat_id, text: None
        seen = set()

        messages, delivered = app.deliver_batches(
            [("ok", [{"key": "k1"}, {"key": "k2"}])], "t", "c", seen
        )

        self.assertEqual((messages, delivered), (1, 2))
        self.assertEqual(seen, {"k1", "k2"})

    def test_failed_message_not_recorded(self):
        def fake_send(token, chat_id, text):
            if text == "bad":
                raise RuntimeError("boom")

        app.send_telegram_message = fake_send
        seen = set()

        messages, delivered = app.deliver_batches(
            [("bad", [{"key": "k1"}]), ("good", [{"key": "k2"}])], "t", "c", seen
        )

        self.assertEqual((messages, delivered), (1, 1))
        self.assertEqual(seen, {"k2"})

    def test_dry_run_sends_nothing(self):
        app.DRY_RUN = True
        called = []
        app.send_telegram_message = lambda *args: called.append(args)
        seen = set()

        messages, delivered = app.deliver_batches(
            [("x", [{"key": "k1"}])], "t", "c", seen
        )

        self.assertEqual(called, [])
        self.assertEqual(seen, set())
        self.assertEqual((messages, delivered), (1, 0))


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.original = {
            "RSS_FEEDS": app.RSS_FEEDS,
            "fetch_feed_news": app.fetch_feed_news,
            "fetch_kev_articles": app.fetch_kev_articles,
            "translate_kev_articles": app.translate_kev_articles,
            "analyze_news": app.analyze_news,
            "send_telegram_message": app.send_telegram_message,
            "save_seen_urls": app.save_seen_urls,
            "DRY_RUN": app.DRY_RUN,
            "MESSAGE_PAUSE_SECONDS": app.MESSAGE_PAUSE_SECONDS,
        }
        app.RSS_FEEDS = ["https://feed.example/"]
        app.DRY_RUN = False
        app.MESSAGE_PAUSE_SECONDS = 0
        app.save_seen_urls = lambda seen: None
        app.translate_kev_articles = lambda articles, client: {}

    def tearDown(self):
        for name, value in self.original.items():
            setattr(app, name, value)

    def test_no_loss_and_kev_first(self):
        items = [make_item(index) for index in range(30)]

        def fake_analyze(client, title, summary):
            number = int(title.split("#")[1])
            score = 5 if number % 10 == 0 else 3
            return f"[Критичность: {score}] Суть: тест."

        app.fetch_feed_news = lambda feed_url: (items, len(items))
        app.fetch_kev_articles = lambda seen: [make_kev(1)]
        app.analyze_news = fake_analyze
        sent: list[str] = []
        app.send_telegram_message = lambda token, chat_id, text: sent.append(text)

        seen: set[str] = set()
        app.process_all_feeds(object(), "t", "c", seen)

        self.assertEqual(len(seen), 31)  # 30 RSS + 1 KEV
        self.assertTrue(sent)
        self.assertIn("CISA KEV", sent[0])
        self.assertIn("1 новая запись", sent[0])  # плюрализация заголовка
        alert_text = next(text for text in sent if "Алерты" in text)
        self.assertIn("2 алерта", alert_text)  # 20 и 10 попали в анализ
        self.assertTrue(any("🔴" in text for text in sent))
        self.assertTrue(any("🟡" in text for text in sent))

    def test_dry_run_keeps_history(self):
        app.DRY_RUN = True
        app.fetch_feed_news = lambda feed_url: ([make_item(1)], 1)
        app.fetch_kev_articles = lambda seen: []
        app.analyze_news = lambda client, title, summary: "[Критичность: 2] Суть: т."
        sent = []
        app.send_telegram_message = lambda *args: sent.append(args)

        seen: set[str] = set()
        app.process_all_feeds(object(), "t", "c", seen)

        self.assertEqual(sent, [])
        self.assertEqual(seen, set())

    def test_digest_uses_title_ru(self):
        app.fetch_feed_news = lambda feed_url: ([make_item(1)], 1)
        app.fetch_kev_articles = lambda seen: []
        app.analyze_news = lambda c, t, s: (
            "[Критичность: 3] Суть: т. TITLE_RU: Переведённый заголовок"
        )
        sent = []
        app.send_telegram_message = lambda *args: sent.append(args[2])

        seen: set[str] = set()
        app.process_all_feeds(object(), "t", "c", seen)

        digest = next(text for text in sent if "Контекст" in text)
        self.assertIn("Переведённый заголовок", digest)
        self.assertNotIn("TITLE_RU", digest)

    def test_alert_labels_and_title_ru_stripped(self):
        app.fetch_feed_news = lambda feed_url: ([make_item(1)], 1)
        app.fetch_kev_articles = lambda seen: []
        app.analyze_news = lambda c, t, s: (
            "[Критичность: 5] Суть: кратко. Детали: подробно. TITLE_RU: Перевод"
        )
        sent = []
        app.send_telegram_message = lambda *args: sent.append(args[2])

        seen: set[str] = set()
        app.process_all_feeds(object(), "t", "c", seen)

        alert = next(text for text in sent if "Алерты" in text)
        self.assertIn("<b>Суть:</b> кратко.", alert)
        self.assertIn("<b>Детали:</b> подробно.", alert)
        self.assertNotIn("TITLE_RU", alert)

    def test_kev_translation_applied(self):
        app.fetch_feed_news = lambda feed_url: ([], 0)
        app.fetch_kev_articles = lambda seen: [make_kev(1)]
        app.translate_kev_articles = lambda articles, client: {
            "CVE-2026-1": {
                "title_ru": "Перевод названия",
                "desc_ru": "Краткое описание",
            }
        }
        sent = []
        app.send_telegram_message = lambda *args: sent.append(args[2])

        seen: set[str] = set()
        app.process_all_feeds(object(), "t", "c", seen)

        self.assertEqual(len(sent), 1)
        self.assertIn("CVE-2026-1 (Flaw 1)", sent[0])
        self.assertIn(" · <b>Перевод названия</b>", sent[0])
        self.assertIn("Краткое описание", sent[0])

    def test_kev_translation_fallback(self):
        app.fetch_feed_news = lambda feed_url: ([], 0)
        app.fetch_kev_articles = lambda seen: [make_kev(1)]
        app.translate_kev_articles = lambda articles, client: {}
        sent = []
        app.send_telegram_message = lambda *args: sent.append(args[2])

        seen: set[str] = set()
        app.process_all_feeds(object(), "t", "c", seen)

        self.assertIn("CVE-2026-1 (Flaw 1)", sent[0])
        self.assertNotIn(" · <b>", sent[0])

    def test_alert_overflow_goes_to_digest(self):
        items = [make_item(index) for index in range(30)]
        app.fetch_feed_news = lambda feed_url: (items, len(items))
        app.fetch_kev_articles = lambda seen: []
        # Длинный разбор, чтобы 20 алертов не влезли в 5 сообщений.
        app.analyze_news = lambda client, title, summary: (
            "[Критичность: 5] Детали. " * 80
        )
        sent: list[str] = []
        app.send_telegram_message = lambda token, chat_id, text: sent.append(text)

        seen: set[str] = set()
        app.process_all_feeds(object(), "t", "c", seen)

        alert_messages = [text for text in sent if "🔴 <b>Алерты</b>" in text]
        digest_messages = [text for text in sent if "🟡 <b>Контекст</b>" in text]

        self.assertLessEqual(len(alert_messages), app.P1_MAX_MESSAGES)
        self.assertTrue(digest_messages)
        self.assertIn("🔴", digest_messages[0])  # overflow помечен
        self.assertEqual(len(seen), 30)


if __name__ == "__main__":
    unittest.main()
