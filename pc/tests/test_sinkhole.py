# -*- coding: utf-8 -*-
"""DNS 过滤服务器的端到端测试。

做法：起一个假的"上游 DNS"（本地 UDP 端口，对所有问题都回 1.2.3.4），
让被测服务器把上游指到它。这样测试完全离线，还能验证缓存是否真的生效。
"""

import socket
import struct
import threading
import unittest

from linkguard.matcher import DomainMatcher
from linkguard.sinkhole import (
    DNSParseError,
    DNSSinkhole,
    build_blocked,
    parse_question,
)
from tests.dnsutil import TYPE_A, TYPE_AAAA, answer_rdata, answers, build_query, rcode_of


class FakeUpstream(threading.Thread):
    """假上游：把问题段原样抄回去，附一条 1.2.3.4 的 A 记录。"""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.queries: list[bytes] = []
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            self.queries.append(data)
            pos = 12
            while data[pos] != 0:
                pos += 1 + data[pos]
            end = pos + 1 + 4
            header = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
            answer = b"\xc0\x0c" + struct.pack("!HHIH", TYPE_A, 1, 60, 4) + bytes([1, 2, 3, 4])
            self.sock.sendto(header + data[12:end] + answer, addr)

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


class TestPacketLayer(unittest.TestCase):
    def test_parse_question(self):
        q = parse_question(build_query("a.b.evil.top"))
        self.assertEqual(q.name, "a.b.evil.top")
        self.assertEqual(q.qtype, TYPE_A)
        self.assertEqual(q.qclass, 1)

    def test_parse_rejects_truncated(self):
        with self.assertRaises(DNSParseError):
            parse_question(b"\x00\x01")

    def test_parse_rejects_multi_question(self):
        raw = bytearray(build_query("a.com"))
        struct.pack_into("!H", raw, 4, 2)
        with self.assertRaises(DNSParseError):
            parse_question(bytes(raw))

    def test_build_blocked_zero(self):
        raw = build_query("evil.top", qid=0xABCD)
        q = parse_question(raw)
        resp = build_blocked(raw, q, "zero")
        self.assertEqual(resp[:2], b"\xab\xcd")     # 事务 ID 必须原样带回
        self.assertEqual(rcode_of(resp), 0)
        self.assertEqual(answers(resp), 1)
        self.assertEqual(answer_rdata(resp), b"\x00\x00\x00\x00")

    def test_build_blocked_aaaa(self):
        raw = build_query("evil.top", qtype=TYPE_AAAA)
        q = parse_question(raw)
        resp = build_blocked(raw, q, "zero")
        self.assertEqual(answers(resp), 1)
        self.assertEqual(answer_rdata(resp), b"\x00" * 16)

    def test_build_blocked_nxdomain(self):
        raw = build_query("evil.top")
        q = parse_question(raw)
        resp = build_blocked(raw, q, "nxdomain")
        self.assertEqual(rcode_of(resp), 3)
        self.assertEqual(answers(resp), 0)


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = FakeUpstream()
        cls.upstream.start()
        cls.matcher = DomainMatcher({"evil.top", "tracker.xyz"})
        cls.log: list[tuple] = []
        cls.server = DNSSinkhole(
            cls.matcher,
            upstreams=("127.0.0.1",),
            upstream_port=cls.upstream.port,
            host="127.0.0.1",
            port=0,
            timeout=1.5,
            on_query=lambda *a: cls.log.append(a),
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.upstream.stop()

    def _ask(self, name, qtype=TYPE_A, qid=0x4321):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(3.0)
        try:
            client.sendto(build_query(name, qtype, qid), ("127.0.0.1", self.server.port))
            resp, _ = client.recvfrom(4096)
            return resp
        finally:
            client.close()

    def test_blocked_is_sinkholed(self):
        resp = self._ask("evil.top")
        self.assertEqual(answer_rdata(resp), b"\x00\x00\x00\x00")
        self.assertEqual(rcode_of(resp), 0)

    def test_blocked_subdomain(self):
        resp = self._ask("deep.sub.evil.top")
        self.assertEqual(answer_rdata(resp), b"\x00\x00\x00\x00")

    def test_blocked_aaaa(self):
        resp = self._ask("evil.top", qtype=TYPE_AAAA)
        self.assertEqual(answer_rdata(resp), b"\x00" * 16)

    def test_allowed_is_forwarded(self):
        before = len(self.upstream.queries)
        resp = self._ask("www.allowed-example.com")
        self.assertEqual(answer_rdata(resp), bytes([1, 2, 3, 4]))
        self.assertGreater(len(self.upstream.queries), before)

    def test_cache_reuses_upstream(self):
        name = "cache-me-example.com"
        self._ask(name)
        n_after_first = len(self.upstream.queries)
        self._ask(name)
        self.assertEqual(len(self.upstream.queries), n_after_first,
                         "第二次查询应该命中缓存，不该再问上游")

    def test_query_id_is_preserved(self):
        resp = self._ask("evil.top", qid=0x7FFF)
        self.assertEqual(resp[:2], b"\x7f\xff")

    def test_callback_gets_client_and_match(self):
        self._ask("evil.top")
        hits = [entry for entry in self.log if entry[1] == "evil.top"]
        self.assertTrue(hits)
        client, qname, blocked, matched = hits[-1]
        self.assertEqual(client, "127.0.0.1")
        self.assertTrue(blocked)
        self.assertEqual(matched, "evil.top")

    def test_stats(self):
        stats = self.server.stats
        self.assertGreater(stats["queries"], 0)
        self.assertGreater(stats["blocked"], 0)


class TestNxdomainMode(unittest.TestCase):
    def test_nxdomain_end_to_end(self):
        upstream = FakeUpstream()
        upstream.start()
        server = DNSSinkhole(
            DomainMatcher({"evil.top"}),
            upstreams=("127.0.0.1",),
            upstream_port=upstream.port,
            host="127.0.0.1", port=0, block_mode="nxdomain", timeout=1.5,
        )
        server.start()
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(3.0)
            client.sendto(build_query("evil.top"), ("127.0.0.1", server.port))
            resp, _ = client.recvfrom(4096)
            client.close()
            self.assertEqual(rcode_of(resp), 3)
            self.assertEqual(answers(resp), 0)
        finally:
            server.stop()
            upstream.stop()


if __name__ == "__main__":
    unittest.main()
