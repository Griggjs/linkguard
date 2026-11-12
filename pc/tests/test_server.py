# -*- coding: utf-8 -*-
"""HTTP 服务与网页渲染测试：真的起服务、真的发请求。"""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from linkguard import server
from linkguard.matcher import DomainMatcher
from linkguard.store import Store


def _temp_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    return path


class TestHttpServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = _temp_db()
        cls.store = Store(cls.db)
        cls.store.add_domains(["known-bad.top"], "test")
        cls.httpd = server.run(
            cls.store, host="127.0.0.1", port=0,
            blocklist=cls.store.matcher(), access_log=False, quiet=True,
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.store.close()
        try:
            os.unlink(cls.db)
        except OSError:
            pass

    def _get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=10) as r:
            return r.status, r.read().decode("utf-8")

    def _post(self, path, payload):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())

    # -- 健康检查 ---------------------------------------------------------
    def test_health(self):
        status, body = self._get("/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    # -- API --------------------------------------------------------------
    def test_api_check_block(self):
        status, body = self._get("/api/check?url=http%3A%2F%2Ficbc-login.top%2Fx")
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data["verdict"], "block")
        self.assertTrue(data["elderly"])
        self.assertTrue(data["signals"])

    def test_api_check_blacklist(self):
        status, body = self._get("/api/check?url=http%3A%2F%2Fa.known-bad.top%2Fx")
        data = json.loads(body)
        self.assertEqual(data["verdict"], "block")
        self.assertIn("BLOCKLIST", [s["code"] for s in data["signals"]])

    def test_api_check_allow(self):
        status, body = self._get("/api/check?url=https%3A%2F%2Fwww.gov.cn%2F")
        self.assertEqual(json.loads(body)["verdict"], "allow")

    def test_api_check_missing_param(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get("/api/check")
        self.assertEqual(ctx.exception.code, 400)

    def test_post_check(self):
        status, data = self._post("/api/check", {"url": "http://x.top/a.apk"})
        self.assertEqual(status, 200)
        self.assertEqual(data["verdict"], "block")

    def test_post_bad_json(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/check",
            data=b"not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 400)

    def test_recent_and_stats(self):
        self._get("/api/check?url=http%3A%2F%2Ficbc-login.top%2Fy")
        _, body = self._get("/api/recent?limit=5")
        self.assertIn("items", json.loads(body))
        _, body = self._get("/api/stats")
        self.assertGreaterEqual(json.loads(body)["checks"], 1)

    # -- 页面 -------------------------------------------------------------
    def test_page_without_url(self):
        status, html = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("链接体检", html)
        self.assertIn("<form", html)

    def test_page_with_blocked_url(self):
        _, html = self._get("/?u=http%3A%2F%2Ficbc-login.top%2Flogin")
        self.assertIn("危险，别点", html)
        self.assertIn("该怎么做", html)
        self.assertIn("给子女看的判定细节", html)

    def test_page_escapes_html(self):
        _, html = self._get("/?u=" + urllib.parse.quote(
            "http://x.top/<script>alert(1)</script>"))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_unknown_path_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get("/nope")
        self.assertEqual(ctx.exception.code, 404)

    def test_bookmarklet_uses_host_header(self):
        _, html = self._get("/")
        self.assertIn("javascript:location.href", html)


if __name__ == "__main__":
    unittest.main()
