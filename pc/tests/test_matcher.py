# -*- coding: utf-8 -*-
"""matcher 与域名工具函数。"""

import unittest

from linkguard.analyzer import (
    clean_input,
    ensure_scheme,
    is_ip_address,
    levenshtein,
    looks_random,
    registrable_domain,
)
from linkguard.matcher import DomainMatcher, host_suffixes


class TestDomainMatcher(unittest.TestCase):
    def test_exact_and_subdomain(self):
        m = DomainMatcher({"evil.com"})
        self.assertEqual(m.match("evil.com"), "evil.com")
        self.assertEqual(m.match("a.b.evil.com"), "evil.com")
        self.assertIsNone(m.match("notevil.com"))
        self.assertIsNone(m.match("evil.com.cn"))
        self.assertIsNone(m.match(""))

    def test_label_boundary(self):
        m = DomainMatcher({"evil.com"})
        self.assertIsNone(m.match("evil.company"))

    def test_case_and_dots(self):
        m = DomainMatcher({"Evil.COM."})
        self.assertEqual(m.match("A.Evil.Com."), "evil.com")

    def test_longest_match(self):
        m = DomainMatcher({"evil.com", "sub.evil.com"})
        self.assertEqual(m.match("x.sub.evil.com"), "sub.evil.com")

    def test_adblock_syntax(self):
        m = DomainMatcher(["||bad.top^", "*.wild.xyz", ".dot.kr"])
        self.assertIn("bad.top", m)
        self.assertIn("wild.xyz", m)
        self.assertIn("dot.kr", m)

    def test_rejects_invalid(self):
        m = DomainMatcher(["localhost", "", "no-dot", "  "])
        self.assertEqual(len(m), 0)

    def test_update_count(self):
        m = DomainMatcher()
        self.assertEqual(m.update(["a.com", "b.com"]), 2)
        self.assertEqual(m.update(["a.com"]), 0)
        self.assertEqual(len(m), 2)


class TestHelpers(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("a.b.evil.com.cn"), "evil.com.cn")
        self.assertEqual(registrable_domain("www.icbc.com.cn"), "icbc.com.cn")
        self.assertEqual(registrable_domain("deep.a.evil.com"), "evil.com")
        self.assertEqual(registrable_domain("1.2.3.4"), "1.2.3.4")

    def test_is_ip(self):
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("::1"))
        self.assertFalse(is_ip_address("example.com"))

    def test_levenshtein(self):
        self.assertEqual(levenshtein("icbc", "icbc"), 0)
        self.assertEqual(levenshtein("icbc", "1cbc"), 1)
        self.assertGreater(levenshtein("abc", "xyzxyz", cap=2), 2)

    def test_looks_random(self):
        self.assertTrue(looks_random("a8f3k2m9x"))
        self.assertTrue(looks_random("xkcdjfhg"))
        self.assertFalse(looks_random("microsoft"))
        self.assertFalse(looks_random("baidu"))
        self.assertFalse(looks_random("xn--80ak6aa92e"))

    def test_host_suffixes(self):
        self.assertEqual(list(host_suffixes("a.b.c")), ["a.b.c", "b.c", "c"])

    def test_clean_input(self):
        self.assertEqual(clean_input("  “www.qq.com”  "), "www.qq.com")
        self.assertEqual(clean_input("https://a.com/x\u200b"), "https://a.com/x")
        self.assertEqual(clean_input("全角：http：／／a.com"), "http://a.com")
        self.assertEqual(clean_input("【通知】请点击 https://x.top/a 查看"), "https://x.top/a")
        self.assertEqual(clean_input("https://a.com/x。）"), "https://a.com/x")

    def test_ensure_scheme(self):
        self.assertEqual(ensure_scheme("www.qq.com")[0], "http://www.qq.com")
        self.assertTrue(ensure_scheme("www.qq.com")[1])
        self.assertEqual(ensure_scheme("https://a.com")[0], "https://a.com")
        self.assertFalse(ensure_scheme("https://a.com")[1])


if __name__ == "__main__":
    unittest.main()
