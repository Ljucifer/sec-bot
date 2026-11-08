"""Тесты состояния (SeenStore) и сухой статистики CVE.

Запуск: python -m unittest discover -s tests -v
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import app


class SeenStoreTests(unittest.TestCase):
    def test_add_keeps_order_and_dedupes(self):
        store = app.SeenStore()
        store.add("a")
        store.add("b")
        store.add("a")

        self.assertEqual(len(store), 2)
        self.assertIn("a", store)
        self.assertNotIn("c", store)
        self.assertEqual(store.order, ["a", "b"])

    def test_update_preserves_first_occurrence(self):
        store = app.SeenStore(["a", "b"])
        store.update(["c", "a", "d"])

        self.assertEqual(store.order, ["a", "b", "c", "d"])

    def test_trim_keeps_newest_and_syncs_set(self):
        store = app.SeenStore([f"u{index}" for index in range(10)])
        store.trim(4)

        self.assertEqual(store.order, ["u6", "u7", "u8", "u9"])
        self.assertNotIn("u0", store)
        self.assertIn("u9", store)


class SeenFileTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = os.path.join(self.tmpdir, "seen_urls.json")
        self._original_path = app.SEEN_URLS_FILE
        app.SEEN_URLS_FILE = self.path

    def tearDown(self):
        app.SEEN_URLS_FILE = self._original_path
        shutil.rmtree(self.tmpdir)

    def _write(self, payload):
        with open(self.path, "w", encoding="utf-8") as file:
            json.dump(payload, file)

    def _read(self):
        with open(self.path, encoding="utf-8") as file:
            return json.load(file)

    def test_missing_file_gives_empty_store(self):
        self.assertEqual(len(app.load_seen_urls()), 0)

    def test_old_format_list_is_loaded(self):
        self._write(["https://a", "https://b"])
        store = app.load_seen_urls()

        self.assertEqual(store.order, ["https://a", "https://b"])

    def test_duplicates_collapse_keeping_order(self):
        self._write(["https://a", "https://b", "https://a"])
        store = app.load_seen_urls()

        self.assertEqual(store.order, ["https://a", "https://b"])

    def test_mixed_types_keep_valid_entries(self):
        self._write(["https://a", 42, None, "https://b"])
        store = app.load_seen_urls()

        self.assertEqual(store.order, ["https://a", "https://b"])

    def test_non_list_starts_fresh_and_quarantines(self):
        self._write({"a": 1})
        store = app.load_seen_urls()

        self.assertEqual(len(store), 0)
        self.assertTrue(os.path.exists(self.path + ".corrupt"))

    def test_broken_json_starts_fresh_and_quarantines(self):
        with open(self.path, "w", encoding="utf-8") as file:
            file.write("{oops")
        store = app.load_seen_urls()

        self.assertEqual(len(store), 0)
        self.assertTrue(os.path.exists(self.path + ".corrupt"))

    def test_save_trims_to_limit(self):
        store = app.SeenStore([f"u{index}" for index in range(6000)])

        with mock.patch.object(app, "MAX_SEEN_URLS", 5000):
            app.save_seen_urls(store)

        data = self._read()
        self.assertEqual(len(data), 5000)
        self.assertEqual(data[0], "u1000")
        self.assertEqual(data[-1], "u5999")
        self.assertEqual(len(store), 5000)

    def test_save_falls_back_when_replace_fails(self):
        store = app.SeenStore(["https://a"])

        with mock.patch.object(app.os, "replace", side_effect=OSError(16, "busy")):
            app.save_seen_urls(store)

        self.assertEqual(self._read(), ["https://a"])
        self.assertFalse(os.path.exists(self.path + ".tmp"))


class CveExtractionTests(unittest.TestCase):
    def test_extracts_from_title_summary_and_link(self):
        item = {
            "title": "Patch for CVE-2026-111497",
            "summary": "also cve-2025-12345",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        }

        self.assertEqual(
            app.item_cves(item),
            {"CVE-2026-111497", "CVE-2025-12345", "CVE-2024-0001"},
        )

    def test_no_cves(self):
        self.assertEqual(app.extract_cves("no identifiers here"), set())

    def test_short_numbers_rejected(self):
        self.assertEqual(app.extract_cves("CVE-2026-1"), set())


class CveStatsTests(unittest.TestCase):
    def setUp(self):
        self._original = app._seen_cves
        app._seen_cves = set()

    def tearDown(self):
        app._seen_cves = self._original

    def test_duplicate_inside_pool(self):
        items = [
            {"title": "A CVE-2026-1111", "summary": "", "link": ""},
            {"title": "B CVE-2026-1111", "summary": "", "link": ""},
            {"title": "C", "summary": "", "link": ""},
        ]

        self.assertEqual(app.cve_stats(items, []), (1, 1))

    def test_kev_seeds_known_cves(self):
        kev = [{"cve_id": "CVE-2026-2222"}]
        items = [{"title": "x", "summary": "CVE-2026-2222", "link": ""}]

        self.assertEqual(app.cve_stats(items, kev), (1, 1))

    def test_remembers_across_calls(self):
        item = {"title": "CVE-2026-3333", "summary": "", "link": ""}

        self.assertEqual(app.cve_stats([item], []), (1, 0))
        self.assertEqual(app.cve_stats([item], []), (1, 1))


class StoryDedupTests(unittest.TestCase):
    def setUp(self):
        self._original = app._recent_stories
        app._recent_stories = []

    def tearDown(self):
        app._recent_stories = self._original

    @staticmethod
    def _item(title, link="https://e.com/1"):
        return {"title": title, "link": link, "summary": ""}

    def test_same_cve_is_duplicate(self):
        app.story_dupes_stats([self._item("A CVE-2026-1111")])
        duplicates, score = app.story_dupes_stats([self._item("B CVE-2026-1111")])

        self.assertEqual(duplicates, 1)
        self.assertEqual(score, 1.0)

    def test_similar_titles_are_duplicate(self):
        app.story_dupes_stats(
            [self._item("Zyxel GS1900 patch fails to block zero-day exploit")]
        )
        duplicates, score = app.story_dupes_stats(
            [self._item("Zyxel GS1900 patch fails to block zero-day attacks")]
        )

        self.assertEqual(duplicates, 1)
        self.assertGreaterEqual(score, app.STORY_SIMILARITY)

    def test_same_template_different_vendor_not_duplicate(self):
        app.story_dupes_stats([self._item("Cisco patch fails to block exploit")])
        duplicates, score = app.story_dupes_stats(
            [self._item("Zyxel patch fails to block exploit")]
        )

        self.assertEqual(duplicates, 0)
        self.assertLess(score, app.STORY_SIMILARITY)

    def test_different_stories_not_duplicate(self):
        app.story_dupes_stats([self._item("Apple fixes Safari bug")])
        duplicates, score = app.story_dupes_stats(
            [self._item("Cisco patches firewall")]
        )

        self.assertEqual(duplicates, 0)
        self.assertLess(score, app.STORY_NEAR_MISS)

    def test_near_miss_reported_below_threshold(self):
        app.story_dupes_stats(
            [self._item("Zyxel GS1900 patch fails to block zero-day exploit")]
        )
        duplicates, score = app.story_dupes_stats(
            [self._item("Zyxel patches GS1900 zero-day exploit")]
        )

        self.assertEqual(duplicates, 0)
        self.assertGreaterEqual(score, app.STORY_NEAR_MISS)
        self.assertLess(score, app.STORY_SIMILARITY)

    def test_best_match_returns_highest_score(self):
        app._recent_stories = []
        app.remember_story(self._item("Apple fixes Safari bug"))
        app.remember_story(self._item("Zyxel GS1900 zero-day exploit"))

        story, score = app.best_story_match(
            self._item("Zyxel GS1900 zero-day exploit details")
        )

        self.assertIsNotNone(story)
        self.assertGreaterEqual(score, app.STORY_NEAR_MISS)

    def test_zdi_advisories_not_duplicate(self):
        app.story_dupes_stats(
            [
                self._item(
                    "ZDI-26-884: OriginLab Origin Viewer OGWU File Parsing "
                    "Out-Of-Bounds Write Remote Code Execution Vulnerability"
                )
            ]
        )
        duplicates, score = app.story_dupes_stats(
            [
                self._item(
                    "ZDI-26-886: OriginLab Origin Viewer OPJU File Parsing "
                    "Out-Of-Bounds Write Remote Code Execution Vulnerability"
                )
            ]
        )

        self.assertEqual(duplicates, 0)
        self.assertEqual(score, 0.0)

    def test_different_cves_not_duplicate(self):
        app.story_dupes_stats(
            [self._item("Vendor X patch fixes CVE-2026-1111 in product")]
        )
        duplicates, score = app.story_dupes_stats(
            [self._item("Vendor X patch fixes CVE-2026-2222 in product")]
        )

        self.assertEqual(duplicates, 0)
        self.assertEqual(score, 0.0)

    def test_kev_covered_by_news(self):
        kev = [
            {
                "cve_id": "CVE-2026-19868",
                "title": "CISA KEV: SonicWall SonicOS SSLVPN ... (CVE-2026-19868)",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-19868",
            }
        ]
        news = [
            {
                "title": "SonicWall warns of new SSL-VPN MFA bypass flaw",
                "summary": "The vulnerability, tracked as CVE-2026-19868, ...",
                "link": "https://www.bleepingcomputer.com/news/security/sonicwall/",
            }
        ]

        self.assertEqual(app.kev_covered_by_news(kev, news), 1)

    def test_kev_not_covered(self):
        kev = [{"cve_id": "CVE-2026-19868", "title": "x", "link": "y"}]
        news = [
            {
                "title": "Unrelated story",
                "summary": "No identifiers here",
                "link": "https://example.com/1",
            }
        ]

        self.assertEqual(app.kev_covered_by_news(kev, news), 0)

    def test_ttl_expires(self):
        with mock.patch.object(app.time, "time", return_value=1000.0):
            app.remember_story(self._item("A CVE-2026-1111"))

        with mock.patch.object(
            app.time,
            "time",
            return_value=1000.0 + app.STORY_TTL_SECONDS + 1,
        ):
            self.assertIsNone(app.find_story_duplicate(self._item("B CVE-2026-1111")))


if __name__ == "__main__":
    unittest.main()
