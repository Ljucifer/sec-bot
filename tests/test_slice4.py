"""Тесты батч-анализа: парсер JSON, фолбэк и группировка дублей."""

import json
import unittest
from types import SimpleNamespace

import app


def make_item(index, published=None):
    return {
        "title": f"News #{index}",
        "link": f"https://e.com/{index}",
        "summary": f"Summary {index}",
        "published": published or f"2026-11-01T{index:02d}:00:00+00:00",
        "is_kev": False,
    }


def make_client(content, calls):
    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )

    return SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create))
    )


def entry(
    index,
    criticality=3,
    duplicate_of=None,
    title_ru=None,
    summary="S",
    details="D",
    overlap=None,
):
    if overlap is None:
        overlap = "full" if duplicate_of is not None else "none"
    return {
        "i": index,
        "criticality": criticality,
        "title_ru": title_ru if title_ru is not None else f"RU {index}",
        "summary_ru": summary,
        "details_ru": details,
        "duplicate_of": duplicate_of,
        "overlap": overlap,
    }


class BatchParseTests(unittest.TestCase):
    def test_valid_payload(self):
        raw = json.dumps({"items": [entry(0, 4), entry(1, 5, duplicate_of=0)]})
        parsed = app._parse_batch_response(raw, 2)

        self.assertEqual(parsed[0]["criticality"], 4)
        self.assertEqual(parsed[1]["duplicate_of"], 0)

    def test_code_fence_stripped(self):
        raw = "```json\n" + json.dumps({"items": [entry(0)]}) + "\n```"
        parsed = app._parse_batch_response(raw, 1)

        self.assertIsNotNone(parsed[0])

    def test_invalid_json(self):
        self.assertIsNone(app._parse_batch_response("не json", 2))

    def test_missing_items_key(self):
        self.assertIsNone(app._parse_batch_response('{"data": []}', 2))

    def test_out_of_range_and_missing_entries(self):
        raw = json.dumps({"items": [entry(0), entry(5), entry(1)]})
        parsed = app._parse_batch_response(raw, 3)

        self.assertIsNotNone(parsed[0])
        self.assertIsNotNone(parsed[1])
        self.assertIsNone(parsed[2])

    def test_criticality_clamped_and_rejects_non_int(self):
        raw = json.dumps(
            {
                "items": [
                    entry(0, criticality=9),
                    entry(1, criticality=0),
                    entry(2, criticality=True),
                    entry(3, criticality="5"),
                ]
            }
        )
        parsed = app._parse_batch_response(raw, 4)

        self.assertEqual(parsed[0]["criticality"], 5)
        self.assertEqual(parsed[1]["criticality"], 1)
        self.assertIsNone(parsed[2]["criticality"])
        self.assertIsNone(parsed[3]["criticality"])

    def test_duplicate_of_normalized(self):
        raw = json.dumps(
            {
                "items": [
                    entry(0, duplicate_of=0),
                    entry(1, duplicate_of=9),
                    entry(2, duplicate_of=0),
                ]
            }
        )
        parsed = app._parse_batch_response(raw, 3)

        self.assertIsNone(parsed[0]["duplicate_of"])
        self.assertIsNone(parsed[1]["duplicate_of"])
        self.assertEqual(parsed[2]["duplicate_of"], 0)

    def test_overlap_normalized(self):
        items = [
            dict(entry(0, duplicate_of=None)),
            dict(entry(1, duplicate_of=0, overlap="FULL")),
            dict(entry(2, duplicate_of=0, overlap="partial")),
            dict(entry(3, duplicate_of=0, overlap="junk")),
            {
                key: value
                for key, value in entry(4, duplicate_of=0).items()
                if key != "overlap"
            },
        ]

        parsed = app._parse_batch_response(json.dumps({"items": items}), 5)

        self.assertEqual(parsed[0]["overlap"], "none")
        self.assertEqual(parsed[1]["overlap"], "full")
        self.assertEqual(parsed[2]["overlap"], "partial")
        self.assertEqual(parsed[3]["overlap"], "partial")
        self.assertEqual(parsed[4]["overlap"], "partial")

    def test_non_dict_entries_ignored(self):
        raw = json.dumps({"items": ["мусор", entry(0)]})
        parsed = app._parse_batch_response(raw, 1)

        self.assertIsNotNone(parsed[0])


class AnalyzeBatchTests(unittest.TestCase):
    def test_numbers_items_in_prompt(self):
        calls = []
        payload = json.dumps({"items": [entry(0), entry(1)]})
        client = make_client(payload, calls)

        entries = app.analyze_batch(client, [make_item(0), make_item(1)])

        self.assertEqual(len(entries), 2)
        user = calls[0]["messages"][1]["content"]
        self.assertIn("[0] News #0", user)
        self.assertIn("[1] News #1", user)
        self.assertIn("duplicate_of", calls[0]["messages"][0]["content"])


class AnalyzeCandidatesBatchTests(unittest.TestCase):
    def test_uses_batch_and_keeps_duplicate_links(self):
        items = [make_item(index) for index in range(25)]
        chunks: list[int] = []

        def fake_batch(client, chunk):
            chunks.append(len(chunk))
            result = []
            for offset, _item in enumerate(chunk):
                result.append(
                    entry(
                        offset,
                        criticality=3,
                        duplicate_of=0 if offset == 1 else None,
                        title_ru=f"RU {offset}",
                    )
                )
            return result

        original = app.analyze_batch
        app.analyze_batch = fake_batch
        try:
            analyzed, rest = app.analyze_candidates(items, object())
        finally:
            app.analyze_batch = original

        self.assertEqual(len(analyzed), app.ANALYZE_PER_CYCLE)
        self.assertEqual(len(rest), 5)
        self.assertEqual(chunks, [10, 10])
        self.assertEqual(analyzed[0]["title_ru"], "RU 0")
        self.assertEqual(analyzed[1]["duplicate_of"], 0)
        self.assertEqual(analyzed[1]["overlap"], "full")
        self.assertEqual(analyzed[0]["criticality"], 3)

    def test_falls_back_to_single_calls(self):
        items = [make_item(index) for index in range(3)]
        calls: list[str] = []

        def fake_news(client, title, summary):
            calls.append(title)
            return "[Критичность: 4] TITLE_RU: RU\nСуть: суть.\nДетали: детали."

        original_batch = app.analyze_batch
        original_news = app.analyze_news
        app.analyze_batch = lambda client, items: None
        app.analyze_news = fake_news
        try:
            analyzed, _ = app.analyze_candidates(items, object())
        finally:
            app.analyze_batch = original_batch
            app.analyze_news = original_news

        self.assertEqual(len(analyzed), 3)
        self.assertEqual(len(calls), 3)
        self.assertEqual(analyzed[0]["criticality"], 4)
        self.assertEqual(analyzed[0]["title_ru"], "RU")
        self.assertIsNone(analyzed[0]["duplicate_of"])

    def test_batch_exception_triggers_fallback(self):
        items = [make_item(0)]
        calls: list[str] = []

        def fake_news(client, title, summary):
            calls.append(title)
            return "[Критичность: 3] Суть: суть."

        def broken_batch(client, chunk):
            raise RuntimeError("boom")

        original_batch = app.analyze_batch
        original_news = app.analyze_news
        app.analyze_batch = broken_batch
        app.analyze_news = fake_news
        try:
            analyzed, _ = app.analyze_candidates(items, object())
        finally:
            app.analyze_batch = original_batch
            app.analyze_news = original_news

        self.assertEqual(len(analyzed), 1)
        self.assertEqual(calls, ["News #0"])

    def test_auth_error_propagates(self):
        original = app.analyze_batch
        # У настоящего openai.AuthenticationError обязательны response и body,
        # поэтому создаём экземпляр без вызова конструктора.
        auth_error = app.AuthenticationError.__new__(app.AuthenticationError)

        def broken_batch(client, chunk):
            raise auth_error

        app.analyze_batch = broken_batch
        try:
            with self.assertRaises(app.AuthenticationError):
                app.analyze_candidates([make_item(0)], object())
        finally:
            app.analyze_batch = original


if __name__ == "__main__":
    unittest.main()
