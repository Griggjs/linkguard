# -*- coding: utf-8 -*-
"""存储层：名单增删、日志、统计。"""

import os
import tempfile
import unittest

from linkguard.store import Store


class TestStore(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.path)
        self.store = Store(self.path)

    def tearDown(self):
        self.store.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self.path + suffix)
            except OSError:
                pass

    def test_add_and_match(self):
        n = self.store.add_domains(["evil.top", "a.evil.top", "invalid"], "test")
        self.assertEqual(n, 2)          # invalid 没有点，被拒
        m = self.store.matcher()
        self.assertIsNotNone(m.match("x.evil.top"))
        self.assertEqual(self.store.domain_count(), 2)

    def test_add_is_idempotent(self):
        self.store.add_domains(["evil.top"], "a")
        n = self.store.add_domains(["evil.top"], "b")
        self.assertEqual(n, 0)

    def test_replace_source(self):
        self.store.add_domains(["old.top"], "src")
        added, removed = self.store.replace_source("src", ["new.top"])
        self.assertEqual((added, removed), (1, 1))
        self.assertIsNone(self.store.matcher().match("old.top"))
        self.assertIsNotNone(self.store.matcher().match("new.top"))

    def test_remove_domain(self):
        self.store.add_domains(["evil.top"], "t")
        self.assertTrue(self.store.remove_domain("evil.top"))
        self.assertFalse(self.store.remove_domain("evil.top"))

    def test_sources(self):
        self.store.add_domains(["a.top"], "s1")
        self.store.add_domains(["b.top", "c.top"], "s2")
        rows = {r["source"]: r["count"] for r in self.store.sources()}
        self.assertEqual(rows, {"s1": 1, "s2": 2})

    def test_matcher_cache_invalidated(self):
        self.store.add_domains(["a.top"], "t")
        self.assertIsNone(self.store.matcher().match("new.top"))
        self.store.add_domains(["new.top"], "t")
        self.assertIsNotNone(self.store.matcher().match("new.top"))

    def test_log_and_recent(self):
        from linkguard.analyzer import analyze

        r = analyze("http://icbc-login.top/x")
        rid = self.store.log_check(r, "1.2.3.4")
        self.assertGreater(rid, 0)
        rows = self.store.recent_checks(10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "block")
        self.assertEqual(rows[0]["client"], "1.2.3.4")
        self.assertTrue(rows[0]["signals"])

    def test_recent_filter_by_verdict(self):
        from linkguard.analyzer import analyze

        self.store.log_check(analyze("https://www.gov.cn/"), "x")
        self.store.log_check(analyze("http://x.top/a.apk"), "x")
        self.assertEqual(len(self.store.recent_checks(10, "block")), 1)
        self.assertEqual(len(self.store.recent_checks(10, "allow")), 1)

    def test_dns_log(self):
        self.store.log_dns("1.2.3.4", "evil.top", True, "evil.top")
        self.store.log_dns("1.2.3.4", "good.com", False)
        self.assertEqual(len(self.store.recent_dns(10)), 2)
        self.assertEqual(len(self.store.recent_dns(10, only_blocked=True)), 1)

    def test_stats(self):
        from linkguard.analyzer import analyze

        self.store.add_domains(["a.top"], "t")
        self.store.log_check(analyze("http://x.top/a.apk"), "x")
        s = self.store.stats()
        self.assertEqual(s["domains"], 1)
        self.assertEqual(s["checks"], 1)
        self.assertIn("block", s["by_verdict"])

    def test_reopen_keeps_data(self):
        self.store.add_domains(["persist.top"], "t")
        self.store.close()
        again = Store(self.path)
        try:
            self.assertIsNotNone(again.matcher().match("persist.top"))
        finally:
            again.close()


if __name__ == "__main__":
    unittest.main()
