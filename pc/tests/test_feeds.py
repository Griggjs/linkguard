# -*- coding: utf-8 -*-
"""名单解析：各种格式都要能归一成一堆域名，且不能把 IP、状态字段当成域名。"""

import unittest

from linkguard import feeds
from linkguard.matcher import DomainMatcher

HOSTS_TEXT = """# 这是注释
127.0.0.1 localhost
0.0.0.0 evil-c2.top
0.0.0.0 www.evil-c2.top
::1 tracker.example
"""
HOSTS_EXPECTED = ["evil-c2.top", "www.evil-c2.top", "tracker.example"]

ADBLOCK_TEXT = """! 注释
||bad1.top^
||bad2.com^$third-party
@@||good.com^
0.0.0.0 bad3.xyz
"""

CSV_TEXT = """"id","dateadded","url","url_status"
"1","2024-01-01 00:00:00","https://evil-payload.top/a.exe","online"
"2","2024-01-02 00:00:00","http://bad2.top/x","offline"
"""

JSON_TEXT = '{"domains":["a.evil.com","b.top","https://c.top/x"],"n":1}'


class TestExtractHosts(unittest.TestCase):
    def test_hosts_file(self):
        self.assertEqual(feeds.extract_hosts(HOSTS_TEXT), HOSTS_EXPECTED)

    def test_adblock(self):
        got = feeds.extract_hosts(ADBLOCK_TEXT)
        self.assertIn("bad1.top", got)
        self.assertIn("bad2.com", got)
        self.assertIn("bad3.xyz", got)
        self.assertNotIn("good.com", got)  # @@ 是白名单例外，不能进黑名单

    def test_csv(self):
        got = feeds.extract_hosts(CSV_TEXT)
        self.assertIn("evil-payload.top", got)
        self.assertIn("bad2.top", got)
        self.assertNotIn("online", got)

    def test_json(self):
        got = feeds.extract_hosts(JSON_TEXT)
        self.assertEqual(got, ["a.evil.com", "b.top", "c.top"])

    def test_rejects_noise(self):
        got = feeds.extract_hosts(
            "0.0.0.0 not-a-domain\n0.0.0.0 123.456.789.0\n# evil.com\n\x00\n"
        )
        # "123.456.789.0" 的数字后缀会被 TLD 规则拒掉
        for item in got:
            self.assertNotIn(item, ("not-a-domain", "123.456.789.0", "evil.com"))

    def test_inline_comment_is_not_a_domain(self):
        # 实际出现过的问题：hosts 行内注释中的 URL 被当成待拦域名，
        # 导致 github.com 被误拦。
        text = (
            "0.0.0.0 docs.pipenv.org # https://github.com/StevenBlack/hosts/issues/1635\n"
            "0.0.0.0 real-bad.top # see https://example.org/report\n"
        )
        got = feeds.extract_hosts(text)
        self.assertEqual(got, ["docs.pipenv.org", "real-bad.top"])
        self.assertNotIn("github.com", got)
        self.assertNotIn("example.org", got)

    def test_dedup_and_order(self):
        got = feeds.extract_hosts("a.com\nb.com\na.com\n")
        self.assertEqual(got, ["a.com", "b.com"])

    def test_parse_dispatches_by_kind(self):
        self.assertEqual(feeds.parse(HOSTS_TEXT, "hosts"), HOSTS_EXPECTED)
        self.assertEqual(len(feeds.parse(JSON_TEXT, "json")), 3)
        with self.assertRaises(ValueError):
            feeds.parse("x", "unknown-format")


class TestSourceUpdate(unittest.TestCase):
    def test_update_source_with_fake_fetcher(self):
        store = _make_store()
        try:
            src = feeds.Source("demo", "https://example.invalid/list.txt", "hosts")
            res = feeds.update_source(store, src, fetcher=lambda u: HOSTS_TEXT)
            self.assertTrue(res.ok)
            self.assertEqual(res.total, 3)
            self.assertEqual(store.domain_count(), 3)
            self.assertIn("evil-c2.top", store.matcher())
        finally:
            store.close()

    def test_update_is_idempotent(self):
        store = _make_store()
        try:
            src = feeds.Source("demo", "https://example.invalid/x", "hosts")
            feeds.update_source(store, src, fetcher=lambda u: HOSTS_TEXT)
            second = feeds.update_source(store, src, fetcher=lambda u: HOSTS_TEXT)
            self.assertTrue(second.ok)
            # 整源替换：先删后写，所以 added 仍是全量，但库里不会有重复
            self.assertEqual(second.removed, 3)
            self.assertEqual(store.domain_count(), 3)
        finally:
            store.close()

    def test_bad_source_does_not_raise(self):
        store = _make_store()
        try:
            def boom(url):
                raise OSError("DNS 挂了")

            src = feeds.Source("demo", "https://example.invalid/x", "hosts")
            res = feeds.update_source(store, src, fetcher=boom)
            self.assertFalse(res.ok)
            self.assertIn("DNS 挂了", res.error)
        finally:
            store.close()

    def test_parse_source_spec(self):
        s = feeds.parse_source_spec("mine=https://x/y.txt#adblock")
        self.assertEqual((s.name, s.url, s.kind), ("mine", "https://x/y.txt", "adblock"))
        with self.assertRaises(ValueError):
            feeds.parse_source_spec("nonsense")


def _make_store():
    import os
    import tempfile

    from linkguard.store import Store

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    return Store(path)


if __name__ == "__main__":
    unittest.main()
