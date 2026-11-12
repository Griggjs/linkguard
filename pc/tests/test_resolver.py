# -*- coding: utf-8 -*-
"""重定向链追踪：用本地 HTTP 服务模拟各种跳转，不碰外网。"""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from linkguard.resolver import (
    RedirectTracer,
    _is_public_ip,
    extract_urls,
)


class _RedirectHandler(BaseHTTPRequestHandler):
    routes = {
        "/r1": (302, "/r2"),
        "/r2": (302, "/final"),
        "/final": (200, None),
        "/loop-a": (302, "/loop-b"),
        "/loop-b": (302, "/loop-a"),
        "/to-app": (302, "intent://scan/#Intent;scheme=zxing;end"),
        "/to-http": (301, "/final"),
    }

    def do_HEAD(self):  # noqa: N802
        status, location = self.routes.get(self.path, (404, None))
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_HEAD

    def log_message(self, *args):
        pass


class TestExtractUrls(unittest.TestCase):
    def test_extracts_from_chat_text(self):
        text = "【通知】请点击 https://x.top/a 查看，或访问 www.example.com"
        self.assertEqual(extract_urls(text), ["https://x.top/a", "www.example.com"])

    def test_strips_trailing_punctuation(self):
        self.assertEqual(extract_urls("看这个 https://a.com/x。）"), ["https://a.com/x"])

    def test_empty(self):
        self.assertEqual(extract_urls(""), [])
        self.assertEqual(extract_urls("没有链接"), [])


class TestRedirectTracer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_follows_chain(self):
        tracer = RedirectTracer(allow_private=True, timeout=2.0)
        chain = tracer.trace(self.url("/r1"))
        self.assertEqual(len(chain), 3)
        self.assertTrue(chain[-1].endswith("/final"))

    def test_stops_at_app_scheme(self):
        tracer = RedirectTracer(allow_private=True, timeout=2.0)
        chain = tracer.trace(self.url("/to-app"))
        self.assertTrue(chain[-1].startswith("intent://"), chain)

    def test_loop_guard(self):
        tracer = RedirectTracer(allow_private=True, timeout=2.0, max_hops=8)
        chain = tracer.trace(self.url("/loop-a"))
        self.assertLessEqual(len(chain), 4, chain)

    def test_private_refused_by_default(self):
        tracer = RedirectTracer(timeout=1.0)  # allow_private=False
        self.assertEqual(tracer.trace(self.url("/r1")), [self.url("/r1")])

    def test_unreachable_host_is_quiet(self):
        tracer = RedirectTracer(allow_private=True, timeout=0.5)
        chain = tracer.trace("http://127.0.0.1:1/nothing")
        self.assertEqual(len(chain), 1)


class TestPublicIpCheck(unittest.TestCase):
    def test_classification(self):
        self.assertTrue(_is_public_ip("8.8.8.8"))
        self.assertFalse(_is_public_ip("127.0.0.1"))
        self.assertFalse(_is_public_ip("192.168.1.1"))
        self.assertFalse(_is_public_ip("10.0.0.1"))
        self.assertFalse(_is_public_ip("169.254.1.1"))
        self.assertFalse(_is_public_ip("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
