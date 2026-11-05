"""Юнит-тесты Среза 1: чистые функции разбивки сообщений.

Запуск: python -m unittest discover -s tests -v
"""

import unittest

import app


class TelegramLengthTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(app.telegram_length(""), 0)

    def test_ascii(self):
        self.assertEqual(app.telegram_length("abc"), 3)

    def test_cyrillic(self):
        self.assertEqual(app.telegram_length("привет"), 6)

    def test_emoji_counts_as_two_units(self):
        self.assertEqual(app.telegram_length("🚨"), 2)
        self.assertEqual(app.telegram_length("a🚨b"), 4)

    def test_mixed(self):
        self.assertEqual(app.telegram_length("🔴 Критично"), 2 + 1 + 8)


class TruncateTests(unittest.TestCase):
    def test_short_text_untouched(self):
        self.assertEqual(app.truncate_escaped_html("abc", 10), "abc")

    def test_respects_utf16_limit(self):
        out = app.truncate_escaped_html("🚨" * 50, 21)
        self.assertLessEqual(app.telegram_length(out), 21)
        self.assertTrue(out.endswith("…"))

    def test_does_not_break_entity(self):
        text = "x" * 10 + "&amp;" + "y" * 10
        out = app.truncate_escaped_html(text, 12)
        body = out.rstrip("…")
        self.assertIsNone(app.ENTITY_TAIL_RE.search(body))


class ExtractCriticalityTests(unittest.TestCase):
    def test_all_levels(self):
        for level in range(1, 6):
            self.assertEqual(
                app.extract_criticality(f"[Критичность: {level}]"), level
            )

    def test_formats(self):
        self.assertEqual(app.extract_criticality("Критичность: 4"), 4)
        self.assertEqual(app.extract_criticality("[Критичность: 5/5]"), 5)
        self.assertEqual(app.extract_criticality("критичность = 3"), 3)

    def test_missing(self):
        self.assertIsNone(app.extract_criticality("Суть: без оценки"))

    def test_two_digit_rejected(self):
        self.assertIsNone(app.extract_criticality("Критичность: 12"))

    def test_is_critical_semantics(self):
        self.assertTrue(app.is_critical("[Критичность: 5]"))
        self.assertTrue(app.is_critical("[Критичность: 4]"))
        self.assertFalse(app.is_critical("[Критичность: 3]"))


class PackBlocksTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(app.pack_blocks([]), [])

    def test_single_oversized_block(self):
        messages = app.pack_blocks(["A" * 5000], header="H", limit=100)
        self.assertEqual(len(messages), 1)
        self.assertLessEqual(app.telegram_length(messages[0]), 100)
        self.assertTrue(messages[0].endswith("…"))

    def test_exactly_limit(self):
        messages = app.pack_blocks(["A" * 4000], header="", limit=4000)
        self.assertEqual(messages, ["A" * 4000])
        self.assertEqual(app.telegram_length(messages[0]), 4000)

    def test_entity_at_boundary(self):
        block = "x" * 95 + "&amp;" + "y" * 100
        messages = app.pack_blocks([block], header="", limit=98)
        body = messages[0].rstrip("…")
        self.assertIsNone(app.ENTITY_TAIL_RE.search(body))
        self.assertLessEqual(app.telegram_length(messages[0]), 98)

    def test_emoji_at_boundary(self):
        messages = app.pack_blocks(["🚨" * 100], header="📰", limit=51)
        for message in messages:
            self.assertLessEqual(app.telegram_length(message), 51)

    def test_splits_by_blocks_not_symbols(self):
        blocks = [f"{index}:" + "B" * 1500 for index in range(5)]
        messages = app.pack_blocks(blocks, header="H", limit=4000)
        self.assertGreater(len(messages), 1)
        for message in messages:
            self.assertLessEqual(app.telegram_length(message), 4000)
        for block in blocks:
            self.assertEqual(sum(m.count(block) for m in messages), 1)

    def test_header_and_separator(self):
        messages = app.pack_blocks(
            ["one", "two"], header="🟡", limit=4000, separator="\n"
        )
        self.assertEqual(messages, ["🟡\none\ntwo"])


class BuilderTests(unittest.TestCase):
    def test_alert_block_escapes_html(self):
        block = app.build_alert_block("A <b>&", "https://e.com/?a=1&b=2", "x < y")
        self.assertIn("&lt;b&gt;", block)
        self.assertIn("&amp;", block)
        self.assertNotIn("<b>&", block)
        self.assertTrue(block.startswith("🚨 "))

    def test_digest_markers(self):
        self.assertTrue(
            app.build_digest_line("t", "https://e.com", criticality=4).startswith("⚠️ ")
        )
        self.assertTrue(
            app.build_digest_line("t", "https://e.com", criticality=3).startswith("• ")
        )
        self.assertTrue(
            app.build_digest_line("t", "https://e.com", analyzed=False).startswith("· ")
        )


class PluralTests(unittest.TestCase):
    def test_russian_forms(self):
        cases = {
            0: "новостей",
            1: "новость",
            2: "новости",
            4: "новости",
            5: "новостей",
            10: "новостей",
            11: "новостей",
            12: "новостей",
            14: "новостей",
            21: "новость",
            22: "новости",
            25: "новостей",
            101: "новость",
            111: "новостей",
        }
        for count, expected in cases.items():
            self.assertEqual(
                app.plural(count, "новость", "новости", "новостей"), expected
            )


class AnalysisParsingTests(unittest.TestCase):
    def test_extract_title_ru(self):
        analysis = (
            "[Критичность: 5]\nСуть: кратко.\nДетали: подробно.\n"
            "TITLE_RU: Хакеры взломали сервер"
        )
        title_ru, cleaned = app.extract_title_ru(analysis)

        self.assertEqual(title_ru, "Хакеры взломали сервер")
        self.assertNotIn("TITLE_RU", cleaned)
        self.assertIn("Суть: кратко.", cleaned)

    def test_extract_title_ru_missing(self):
        title_ru, cleaned = app.extract_title_ru("Суть: без перевода.")
        self.assertIsNone(title_ru)
        self.assertEqual(cleaned, "Суть: без перевода.")

    def test_extract_title_ru_strips_quotes_and_bold(self):
        title_ru, _ = app.extract_title_ru('TITLE_RU: **"Перевод"**')
        self.assertEqual(title_ru, "Перевод")

    def test_split_analysis_full(self):
        parts = app.split_analysis("Суть: одно. Детали: два. Ещё детали.")
        self.assertEqual(parts, ("одно.", "два. Ещё детали."))

    def test_split_analysis_without_details(self):
        parts = app.split_analysis("Суть: только суть.")
        self.assertEqual(parts, ("только суть.", ""))

    def test_split_analysis_unknown_format(self):
        self.assertIsNone(app.split_analysis("просто текст без полей"))

    def test_split_analysis_markdown(self):
        parts = app.split_analysis("**Суть:** одно.\n**Детали:** два.")
        self.assertEqual(parts, ("одно.", "два."))


class LocalizationFormattingTests(unittest.TestCase):
    def test_alert_bolds_labels(self):
        block = app.build_alert_block(
            "Заголовок", "https://e.com", "Суть: кратко. Детали: подробнее."
        )
        self.assertIn("<b>Суть:</b> кратко.", block)
        self.assertIn("<b>Детали:</b> подробнее.", block)

    def test_alert_fallback_without_labels(self):
        block = app.build_alert_block("Заголовок", "", "просто текст")
        self.assertNotIn("<b>Суть:</b>", block)
        self.assertIn("просто текст", block)

    def test_alert_strips_title_ru_defensively(self):
        block = app.build_alert_block(
            "Заголовок", "", "Суть: кратко. Детали: подробно. TITLE_RU: Перевод"
        )
        self.assertNotIn("TITLE_RU", block)
        self.assertIn("<b>Детали:</b> подробно.", block)

    def test_digest_adds_translation(self):
        line = app.build_digest_line(
            "Original title", "https://e.com", criticality=3, title_ru="Перевод"
        )
        self.assertIn("Original title", line)
        self.assertIn(" · <b>Перевод</b>", line)

    def test_digest_skips_duplicate_translation(self):
        line = app.build_digest_line(
            "Original title", "https://e.com", criticality=3, title_ru="Original title"
        )
        self.assertNotIn("<b>", line)

    def test_kev_line_with_translation(self):
        line = app.build_kev_line(
            {
                "cve_id": "CVE-2026-1",
                "name": "Flaw Name",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
                "title_ru": "Название уязвимости",
                "desc_ru": "Краткое описание",
            }
        )
        self.assertIn("CVE-2026-1 (Flaw Name)", line)
        self.assertIn(" · <b>Название уязвимости</b>", line)
        self.assertIn("Краткое описание", line)

    def test_no_forbidden_telegram_tags(self):
        examples = [
            app.build_alert_block("T", "https://e.com", "Суть: a. Детали: b."),
            app.build_digest_line("T", "https://e.com", title_ru="Пер"),
            app.build_kev_line(
                {
                    "cve_id": "CVE-2026-1",
                    "name": "Name",
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
                    "title_ru": "Перевод",
                    "desc_ru": "Описание",
                }
            ),
        ]
        for text in examples:
            for tag in ("<ul>", "</ul>", "<li>", "</li>", "<br>"):
                self.assertNotIn(tag, text.lower())


class FixtureTests(unittest.TestCase):
    def _assert_no_loss(self, count):
        blocks = [
            app.build_digest_line(
                f"News item {index}", f"https://example.com/{index}", criticality=3
            )
            for index in range(count)
        ]
        messages = app.pack_blocks(
            blocks, header="🟡 <b>Контекст</b>", limit=4000, separator="\n"
        )
        self.assertTrue(messages)
        for message in messages:
            self.assertLessEqual(app.telegram_length(message), 4000)
        joined = "\n".join(messages)
        for block in blocks:
            self.assertEqual(joined.count(block), 1, block)

    def test_30_items(self):
        self._assert_no_loss(30)

    def test_50_items(self):
        self._assert_no_loss(50)

    def test_120_items(self):
        self._assert_no_loss(120)

    def test_alerts_fixture(self):
        blocks = [
            app.build_alert_block(
                f"Critical {index}",
                f"https://example.com/a/{index}",
                "Суть: тест. Детали: тест.",
            )
            for index in range(60)
        ]
        messages = app.pack_blocks(blocks, header="🔴 <b>Алерты</b>", limit=4000)
        self.assertGreater(len(messages), 1)
        for message in messages:
            self.assertLessEqual(app.telegram_length(message), 4000)
        joined = "\n\n".join(messages)
        for block in blocks:
            self.assertIn(block, joined)


class KevTruncationTests(unittest.TestCase):
    def test_truncate_at_word_boundary(self):
        text = "слово " * 40
        out = app.truncate_escaped_html(text, 40, at_word=True)

        self.assertTrue(out.endswith("…"))
        self.assertLessEqual(app.telegram_length(out), 40)
        body = out[:-1]
        self.assertEqual(body, body.rstrip())
        # Граница не должна приходиться на середину слова.
        self.assertTrue(text[len(body)].isspace())

    def test_long_desc_ends_with_ellipsis(self):
        line = app.build_kev_line(
            {
                "cve_id": "CVE-2024-27834",
                "name": "Apple Multiple Products Improper Authentication Vulnerability",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-27834",
                "title_ru": "Уязвимость неправильной аутентификации в продуктах Apple",
                "desc_ru": "Очень длинное описание уязвимости " * 40,
            }
        )

        desc = line.split("\n", 1)[1]
        self.assertTrue(desc.endswith("…"))
        self.assertLessEqual(app.telegram_length(desc), app.KEV_DESC_LIMIT)

    def test_short_desc_untouched(self):
        line = app.build_kev_line(
            {
                "cve_id": "CVE-2024-1",
                "name": "Name",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
                "desc_ru": "Коротко.",
            }
        )

        self.assertTrue(line.endswith("\nКоротко."))

    def test_long_name_truncated_with_ellipsis(self):
        line = app.build_kev_line(
            {
                "cve_id": "CVE-2024-1",
                "name": "Очень длинное название уязвимости " * 20,
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
            }
        )

        self.assertIn("…", line)

    def test_replacement_chars_removed(self):
        line = app.build_kev_line(
            {
                "cve_id": "CVE-2024-1",
                "name": "Name",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
                "desc_ru": "Текст\ufffd\ufffd уязвимости",
            }
        )

        self.assertNotIn("\ufffd", line)


if __name__ == "__main__":
    unittest.main()
