# -*- coding: utf-8 -*-
"""本地 DNS 过滤服务器——真正"阻断"的那一层。

为什么选 DNS 层
--------------
在手机上调不动系统、也不想 root 的前提下，**DNS 是唯一能覆盖"所有 App"
的拦截点**：微信内置浏览器、抖音、短信里的链接、App 自己拉的后台接口，
全都要先解析域名。把恶意域名解析成 0.0.0.0，页面就打不开。
它的代价是：只认得"域名"，认不出"同一个域名下的某个具体链接"，
所以它和 analyzer（按链接判定）是互补的，不是替代关系。

实现要点
--------
- 纯标准库：手写 DNS 报文解析/合成，不依赖 dnslib。
- UDP + TCP 双协议（大响应会走 TCP）。
- 转发走上游，带超时和缓存；上游截断（TC 位）时自动改用 TCP 重查。
- 只解析问题段，不碰资源记录 —— 拦截时自己合成应答，转发时原样回传，
  所以不会被畸形报文里的压缩指针卡住。
- 所有查询（含放行的）都记日志，「老人手机到底在连什么」一目了然。

用法::

    python -m linkguard dns --port 53 --db data/linkguard.db
    # 然后把手机/路由器的 DNS 指向这台机器的局域网 IP
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from .matcher import DomainMatcher, normalize_host

# 国内公共 DNS，延迟低、支持 ECS，适合作为默认上游
DEFAULT_UPSTREAMS = ("223.5.5.5", "119.29.29.29", "180.76.76.76")

TYPE_A = 1
TYPE_AAAA = 28

RC_NOERROR = 0
RC_NXDOMAIN = 3

FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200
FLAG_RD = 0x0100
FLAG_RA = 0x0080


class DNSParseError(ValueError):
    pass


@dataclass
class Question:
    name: str
    qtype: int
    qclass: int
    end: int          # 问题段在原始报文中的结束偏移


def parse_question(data: bytes) -> Question:
    """只解析头部和第一个问题。qdcount != 1 时报错，交给调用方原样转发。"""
    if len(data) < 12:
        raise DNSParseError("报文短于 DNS 头")
    qdcount = struct.unpack_from("!H", data, 4)[0]
    if qdcount != 1:
        raise DNSParseError(f"qdcount={qdcount}，不做解析，直接转发")

    pos = 12
    labels: list[str] = []
    jumps = 0
    while True:
        if pos >= len(data):
            raise DNSParseError("域名越界")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DNSParseError("压缩指针越界")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            jumps += 1
            if jumps > 20:
                raise DNSParseError("压缩指针层数过多")
            pos = pointer
            continue
        if length > 63:
            raise DNSParseError(f"标签长度非法：{length}")
        if pos + 1 + length > len(data):
            raise DNSParseError("标签越界")
        labels.append(data[pos + 1:pos + 1 + length].decode("latin-1"))
        pos += 1 + length

    if pos + 4 > len(data):
        raise DNSParseError("缺少 qtype/qclass")
    qtype, qclass = struct.unpack_from("!HH", data, pos)
    return Question(normalize_host(".".join(labels)), qtype, qclass, pos + 4)


def build_query(name: str, qtype: int = TYPE_A, qid: int = 0x1234,
                rd: bool = True) -> bytes:
    """构造一个 DNS 查询报文。自检和调试用。"""
    flags = FLAG_RD if rd else 0
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    qname = b""
    for label in normalize_host(name).split("."):
        if not label:
            continue
        raw = label.encode("latin-1")
        if len(raw) > 63:
            raise ValueError(f"标签过长：{label!r}")
        qname += bytes([len(raw)]) + raw
    qname += b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def rcode_of(data: bytes) -> int:
    if len(data) < 4:
        return -1
    return struct.unpack_from("!H", data, 2)[0] & 0x000F


def answer_count(data: bytes) -> int:
    if len(data) < 8:
        return -1
    return struct.unpack_from("!H", data, 6)[0]


def build_blocked(data: bytes, q: Question, mode: str = "zero", ttl: int = 60) -> bytes:
    """合成一个"被拦"的应答：A/AAAA 返回 0.0.0.0 / ::，其它类型返回 NXDOMAIN。"""
    qid = data[:2]
    qflags = struct.unpack_from("!H", data, 2)[0]
    rd = qflags & FLAG_RD
    question = data[12:q.end]
    base = FLAG_QR | FLAG_AA | FLAG_RA | rd

    def nxdomain() -> bytes:
        flags = base | RC_NXDOMAIN
        return qid + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + question

    if mode == "nxdomain":
        return nxdomain()
    if q.qtype == TYPE_A:
        rdata = b"\x00\x00\x00\x00"
    elif q.qtype == TYPE_AAAA:
        rdata = b"\x00" * 16
    else:
        return nxdomain()

    header = qid + struct.pack("!HHHHH", base | RC_NOERROR, 1, 1, 0, 0)
    answer = (
        b"\xc0\x0c"                                  # 指向问题里的域名
        + struct.pack("!HH", q.qtype, 1)             # type, class IN
        + struct.pack("!IH", ttl, len(rdata))        # ttl, rdlength
        + rdata
    )
    return header + question + answer


class DNSSinkhole:
    """一个可嵌入的 DNS 过滤服务器。

    参数
    ----
    matcher : 黑名单匹配器（DomainMatcher 或实现了 match() 的对象）
    upstreams : 上游 DNS，按顺序尝试
    host / port : 监听地址。port=0 表示由系统挑一个空闲端口（测试用）
    block_mode : 'zero' 返回 0.0.0.0，'nxdomain' 返回"域名不存在"
    on_query : 回调 (client_ip, qname, blocked, matched)，用于落库
    """

    def __init__(
        self,
        matcher: DomainMatcher,
        upstreams: tuple[str, ...] | list[str] = DEFAULT_UPSTREAMS,
        host: str = "0.0.0.0",
        port: int = 5353,
        block_mode: str = "zero",
        on_query: Callable[[str, str, bool, str], None] | None = None,
        cache_ttl: float = 60.0,
        timeout: float = 3.0,
        workers: int = 32,
        upstream_port: int = 53,
    ):
        if block_mode not in ("zero", "nxdomain"):
            raise ValueError("block_mode 只能是 'zero' 或 'nxdomain'")
        self.matcher = matcher
        self.upstreams = tuple(upstreams) or DEFAULT_UPSTREAMS
        self.host = host
        self._want_port = port
        self.block_mode = block_mode
        self.on_query = on_query
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.upstream_port = upstream_port
        self._pool = ThreadPoolExecutor(max_workers=workers,
                                        thread_name_prefix="dns")
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self.port = port
        self._cache: dict[tuple[str, int], tuple[bytes, float]] = {}
        self._stats_lock = threading.Lock()
        self._stats = {
            "queries": 0, "blocked": 0, "forwarded": 0, "cache_hits": 0,
            "errors": 0, "tc_retries": 0,
        }

    # -- 生命周期 ---------------------------------------------------------
    def start(self) -> "DNSSinkhole":
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind((self.host, self._want_port))
        udp.settimeout(0.3)
        self._udp = udp
        self.port = udp.getsockname()[1]

        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            tcp.bind((self.host, self.port))
            tcp.listen(64)
            tcp.settimeout(0.3)
            self._tcp = tcp
        except OSError:
            # 端口被别的程序占着 TCP，退化成只做 UDP，不影响主流程
            tcp.close()
            self._tcp = None

        self._stop.clear()
        for target, name in ((self._udp_loop, "dns-udp"), (self._tcp_loop, "dns-tcp")):
            if target is self._tcp_loop and self._tcp is None:
                continue
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)
        return self

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads.clear()
        for sock in (self._udp, self._tcp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._udp = self._tcp = None
        self._pool.shutdown(wait=False, cancel_futures=True)

    def __enter__(self) -> "DNSSinkhole":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    def bump(self, key: str, n: int = 1) -> None:
        with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + n

    # -- 主循环 -----------------------------------------------------------
    def _udp_loop(self) -> None:
        assert self._udp is not None
        while not self._stop.is_set():
            try:
                data, addr = self._udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                continue
            self._pool.submit(self._serve_udp, data, addr)

    def _serve_udp(self, data: bytes, addr) -> None:
        resp = self.handle(data, addr[0])
        if resp and self._udp is not None:
            try:
                self._udp.sendto(resp, addr)
            except OSError:
                self.bump("errors")

    def _tcp_loop(self) -> None:
        assert self._tcp is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._pool.submit(self._serve_tcp, conn, addr)

    def _serve_tcp(self, conn: socket.socket, addr) -> None:
        try:
            conn.settimeout(self.timeout)
            head = self._recv_exact(conn, 2)
            if not head:
                return
            (length,) = struct.unpack("!H", head)
            if length == 0 or length > 4096:
                return
            body = self._recv_exact(conn, length)
            if not body:
                return
            resp = self.handle(body, addr[0])
            if resp:
                conn.sendall(struct.pack("!H", len(resp)) + resp)
        except (OSError, struct.error):
            self.bump("errors")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # -- 单个查询 ---------------------------------------------------------
    def handle(self, data: bytes, client: str = "") -> bytes | None:
        """处理一个 DNS 报文，返回应答字节；返回 None 表示放弃这个查询。"""
        self.bump("queries")
        try:
            q = parse_question(data)
        except DNSParseError:
            # 解析不了的（多问题、畸形），原样转发，不解析也不拦
            return self._forward_udp(data)

        matched = self.matcher.match(q.name) if q.name else None
        if matched:
            self.bump("blocked")
            self._notify(client, q.name, True, matched)
            return build_blocked(data, q, self.block_mode)

        self._notify(client, q.name, False, "")
        return self._resolve(data, q)

    def _notify(self, client: str, qname: str, blocked: bool, matched: str) -> None:
        if self.on_query is None:
            return
        try:
            self.on_query(client, qname, blocked, matched)
        except Exception:  # noqa: BLE001 - 记日志失败不能影响解析
            pass

    def _resolve(self, data: bytes, q: Question) -> bytes | None:
        key = (q.name.lower(), q.qtype)
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached is not None:
            payload, expires = cached
            if expires > now:
                self.bump("cache_hits")
                return data[:2] + payload[2:]

        resp = self._forward_udp(data)
        if resp is None:
            return self._servfail(data, q)

        flags = struct.unpack_from("!H", resp, 2)[0] if len(resp) >= 4 else 0
        if flags & FLAG_TC:
            self.bump("tc_retries")
            tcp_resp = self._forward_tcp(data)
            if tcp_resp:
                resp = tcp_resp

        self.bump("forwarded")
        if len(self._cache) > 5000:
            self._cache.clear()
        self._cache[key] = (resp, now + self.cache_ttl)
        return resp

    def _forward_udp(self, data: bytes) -> bytes | None:
        for upstream in self.upstreams:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(self.timeout)
                sock.sendto(data, (upstream, self.upstream_port))
                resp, _ = sock.recvfrom(4096)
                if resp:
                    return resp
            except (socket.timeout, OSError):
                continue
            finally:
                sock.close()
        self.bump("errors")
        return None

    def _forward_tcp(self, data: bytes) -> bytes | None:
        for upstream in self.upstreams:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(self.timeout)
                sock.connect((upstream, self.upstream_port))
                sock.sendall(struct.pack("!H", len(data)) + data)
                head = self._recv_exact(sock, 2)
                if not head:
                    continue
                (length,) = struct.unpack("!H", head)
                body = self._recv_exact(sock, length)
                if body:
                    return body
            except (socket.timeout, OSError, struct.error):
                continue
            finally:
                sock.close()
        return None

    @staticmethod
    def _servfail(data: bytes, q: Question) -> bytes:
        qid = data[:2]
        qflags = struct.unpack_from("!H", data, 2)[0]
        flags = FLAG_QR | FLAG_RA | (qflags & FLAG_RD) | 2  # rcode=2 SERVFAIL
        return qid + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + data[12:q.end]
