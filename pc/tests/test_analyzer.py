# -*- coding: utf-8 -*-
"""判定引擎的行为测试。

原则：断言"该拦的一定拦得住"，对边界情况只断言"够可疑"，不锁死具体分数，
否则调规则时会不停地改测试。
"""

import unittest

from linkguard.analyzer import ALLOW, BLOCK, WARN, analyze
from linkguard.matcher import DomainMatcher


class TestHardBlocks(unittest.TestCase):
    """这些是"不需要犹豫"的，必须 BLOCK。"""

    def assertBlock(self, url, code=None, **kw):
        r = analyze(url, **kw)
        self.assertEqual(r.verdict, BLOCK, f"{url} -> {r.verdict} {r.codes}")
        if code:
            self.assertIn(code, r.codes, f"{url} 缺少 {code}，实际 {r.codes}")
        return r

    def test_install_package(self):
        self.assertBlock("http://cdn.example-update.top/app/update.apk", "DANGEROUS_FILE")
        self.assertBlock("https://x.top/a.jpg.exe", "DANGEROUS_FILE")
        self.assertBlock("http://x.top/ios.mobileconfig", "DANGEROUS_FILE")

    def test_pseudo_scheme(self):
        self.assertBlock("javascript:alert(document.cookie)", "DANGEROUS_SCHEME")
        self.assertBlock("data:text/html;base64,PHNjcmlwdD4=", "DANGEROUS_SCHEME")
        self.assertBlock("intent://scan/#Intent;scheme=zxing;end", "DANGEROUS_SCHEME")

    def test_userinfo_trick(self):
        self.assertBlock("http://www.icbc.com.cn@evil.top/login", "USERINFO_AT")

    def test_brand_in_subdomain(self):
        self.assertBlock("https://taobao.com.evil.top/pay", "BRAND_IMPERSONATION")
        self.assertBlock("http://icbc-login.top/verify?card=1", "BRAND_IMPERSONATION")

    def test_typosquat(self):
        self.assertBlock("http://1cbc.com.cn/login")
        self.assertBlock("http://www.icbc.com.cn.evil.top/")

    def test_ip_literal(self):
        self.assertBlock("http://192.168.1.1:8080/x", "IP_LITERAL")
        self.assertBlock("http://45.32.1.9/login")

    def test_punycode(self):
        self.assertBlock("http://xn--80ak6aa92e.com/login", "PUNYCODE")

    def test_blacklist(self):
        m = DomainMatcher({"evil-c2.top"})
        self.assertBlock("http://a.evil-c2.top/x", "BLOCKLIST", blocklist=m)

    def test_deep_nesting(self):
        self.assertBlock("http://login.verify.icbc.com.cn.secure.top/", None)


class TestNoFalsePositive(unittest.TestCase):
    """正规站点不能被误伤——误伤比漏报更容易让人弃用工具。"""

    def test_banks_and_gov(self):
        for url in (
            "https://www.icbc.com.cn/icbc/",
            "https://mail.icbc.com.cn/",
            "https://www.gov.cn/zhengce/",
            "https://www.12306.cn/index/",
            "https://www.tsinghua.edu.cn/",
            "https://www.ccb.com/cn/home/index.html",
        ):
            r = analyze(url)
            self.assertEqual(r.verdict, ALLOW, f"{url} -> {r.verdict} {[(s.code, s.weight) for s in r.signals]}")

    def test_big_tech(self):
        for url in (
            "https://weixin.qq.com/",
            "https://mail.qq.com/",
            "https://www.alipay.com/",
            "https://www.taobao.com/",
            "https://www.baidu.com/s?wd=%E4%BD%A0%E5%A5%BD",
            "https://github.com/python/cpython",
            "https://www.jd.com/",
        ):
            r = analyze(url)
            self.assertEqual(r.verdict, ALLOW, f"{url} -> {r.verdict} {[(s.code, s.weight) for s in r.signals]}")

    def test_plain_https_site(self):
        r = analyze("https://blog.example.org/post/2024/hello-world")
        self.assertEqual(r.verdict, ALLOW, r.codes)

    def test_allowlist_offsets_keywords(self):
        # 正规站的登录页 URL 里也有 login，不应该因此被拦
        r = analyze("https://www.alipay.com/login/index.htm")
        self.assertEqual(r.verdict, ALLOW, r.codes)


class TestWarnings(unittest.TestCase):
    def test_short_link_is_suspicious(self):
        r = analyze("https://t.cn/A6xyz")
        self.assertEqual(r.verdict, WARN, r.codes)
        self.assertIn("SHORTENER", r.codes)
        self.assertTrue(r.short_link)

    def test_http_with_scam_words(self):
        r = analyze("http://m.abc.com/verify?id=1")
        self.assertIn(r.verdict, (WARN, BLOCK))

    def test_nested_url(self):
        r = analyze("http://x.top/go?url=http://evil.top/pay")
        self.assertIn("NESTED_URL", r.codes)
        self.assertIn(r.verdict, (WARN, BLOCK))


class TestInputHandling(unittest.TestCase):
    def test_missing_scheme(self):
        r = analyze("www.icbc.com.cn")
        self.assertEqual(r.host, "www.icbc.com.cn")
        self.assertEqual(r.verdict, ALLOW, r.codes)

    def test_chat_text(self):
        r = analyze("【提醒】您有一笔退款，请点 https://x.top/refund 领取")
        self.assertTrue(r.url.startswith("https://x.top/refund"), r.url)

    def test_empty(self):
        r = analyze("")
        self.assertEqual(r.verdict, WARN)
        self.assertIn("EMPTY", r.codes)

    def test_uppercase_host(self):
        r = analyze("HTTPS://WWW.ICBC.COM.CN/")
        self.assertEqual(r.host, "www.icbc.com.cn")


class TestResolverHook(unittest.TestCase):
    def test_redirect_into_blacklist(self):
        m = DomainMatcher({"evil-c2.top"})
        fake = lambda url: [url, "http://evil-c2.top/dropper"]  # noqa: E731
        r = analyze("https://t.cn/abc", blocklist=m, resolver=fake,
                    analyse_redirects=True)
        self.assertEqual(r.verdict, BLOCK, r.codes)
        self.assertIn("REDIRECT_TO_BLACKLIST", r.codes)

    def test_redirect_to_good_site(self):
        fake = lambda url: [url, "https://www.gov.cn/"]  # noqa: E731
        r = analyze("https://t.cn/abc", resolver=fake, analyse_redirects=True)
        self.assertEqual(r.verdict, ALLOW, r.codes)
        self.assertIn("RESOLVED_SAFE", r.codes)

    def test_resolver_exception_is_swallowed(self):
        def boom(url):
            raise OSError("网络断了")

        r = analyze("https://t.cn/abc", resolver=boom, analyse_redirects=True)
        self.assertEqual(r.verdict, WARN, r.codes)


class TestReportShape(unittest.TestCase):
    def test_report_fields(self):
        r = analyze("http://icbc-login.top/login")
        self.assertTrue(r.elderly)
        self.assertTrue(r.category)
        self.assertTrue(r.advice)
        d = r.to_dict()
        for key in ("verdict", "label", "score", "elderly", "signals", "advice"):
            self.assertIn(key, d)
        self.assertIsInstance(d["signals"][0], dict)

    def test_elderly_text_is_plain(self):
        for url in ("https://www.gov.cn/", "https://t.cn/x", "http://a.top/a.apk"):
            r = analyze(url)
            self.assertLess(len(r.elderly), 80, r.elderly)


if __name__ == "__main__":
    unittest.main()
