# -*- coding: utf-8 -*-
"""短链展开与重定向链追踪。

这是整条判定链上**唯一需要联网**的环节，所以：

- 完全可选。离线时 analyzer 照样能给出结论，只是"短链背后是什么"看不见。
- 有超时、有跳数上限、有环路保护。一个坏链接不能把服务卡死。
- 默认拒绝访问内网地址（SSRF 防护）。这个服务可能开在家里的电脑上，
  不能让任何人通过它去探测局域网里的路由器、NAS。
- `fetcher` 可注入，单元测试可以用本地 HTTP 服务模拟跳转，不依赖外网。

抓取只发 HEAD，服务器不支持时降级为 GET 且只读首部就断开，
不下载正文，避免不小心把恶意文件拉到本地。
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import urllib.error
from urllib.parse import urljoin, urlsplit

DEFAULT_TIMEOUT = 6.0
MAX_HOPS = 6
MAX_BODY_PROBE = 0  # 不读正文

# 真实的 URL 可能带各种尾随标点，从聊天文本里抽的时候要去掉
_URL_IN_TEXT_RE = re.compile(
    r"""(?xi)
    \b(?:
        https?://[^\s<>"'`\u3000-\u303f\uff01-\uff5e]+
      | www\.[^\s<>"'`\u3000-\u303f\uff01-\uff5e]+
    )
    """
)
_TRAILING = ".,;:!?)]}》，。、；：！？）】」』>"


def extract_urls(text: str) -> list[str]:
    """从一段聊天文本里抽出所有可能的网址（微信转发常带一堆说明文字）。"""
    if not text:
        return []
    found = []
    for m in _URL_IN_TEXT_RE.finditer(text):
        u = m.group(0).rstrip(_TRAILING)
        if u and u not in found:
            found.append(u)
    return found


class PrivateAddressRefused(Exception):
    """目标解析到内网/保留地址，出于 SSRF 防护拒绝访问。"""


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _assert_public_host(host: str) -> None:
    if not host:
        raise PrivateAddressRefused("空主机名")
    # 字面量 IP 直接判断
    try:
        if not _is_public_ip(host):
            raise PrivateAddressRefused(f"{host} 不是公网地址")
        return
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise PrivateAddressRefused(f"无法解析 {host}：{exc}") from exc
    for info in infos:
        ip = info[4][0]
        if not _is_public_ip(ip):
            raise PrivateAddressRefused(f"{host} 解析到非公网地址 {ip}")


def _request_once(url: str, timeout: float, *, want_body: bool = False) -> tuple[int, str | None]:
    """发一次请求，返回 (状态码, Location)。只读首部。"""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise urllib.error.URLError(f"不支持的协议 {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise urllib.error.URLError("URL 里没有主机名")

    port = parts.port
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13) LinkGuard/1.0",
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }

    if parts.scheme == "https":
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    try:
        method = "GET" if want_body else "HEAD"
        try:
            conn.request(method, path, headers=headers)
        except (http.client.HTTPException, OSError):
            # 某些服务器对 HEAD 直接断连，换 GET
            conn.close()
            conn = (
                http.client.HTTPSConnection(host, port, timeout=timeout,
                                            context=ssl.create_default_context())
                if parts.scheme == "https"
                else http.client.HTTPConnection(host, port, timeout=timeout)
            )
            conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        location = resp.getheader("Location")
        # 不读取响应体：正文可能包含不需要下载的内容
        return status, location
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


class RedirectTracer:
    """跟随跳转，记录完整链路。"""

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_hops: int = MAX_HOPS,
        allow_private: bool = False,
        fetcher=None,
    ):
        self.timeout = timeout
        self.max_hops = max_hops
        self.allow_private = allow_private
        self._fetcher = fetcher or (
            lambda url: _request_once(url, self.timeout, want_body=False)
        )

    def trace(self, url: str) -> list[str]:
        """返回 [起点, 第1跳, ..., 终点]。异常时不抛，返回已走过的部分。"""
        chain: list[str] = []
        current = url
        seen: set[str] = set()

        for _ in range(self.max_hops + 1):
            if not current or current in seen:
                break
            seen.add(current)
            chain.append(current)

            try:
                parts = urlsplit(current)
                if parts.scheme not in ("http", "https"):
                    break
                if not self.allow_private:
                    _assert_public_host(parts.hostname or "")
                status, location = self._fetcher(current)
            except (PrivateAddressRefused, urllib.error.URLError, OSError,
                    ssl.SSLError, http.client.HTTPException, ValueError):
                break

            if not location:
                break
            nxt = urljoin(current, location.strip())
            if urlsplit(nxt).scheme not in ("http", "https"):
                # 跳到了 intent:// 或 app 自定义协议，链路到此为止
                chain.append(nxt)
                break
            current = nxt

        return chain

    __call__ = trace


def default_tracer(allow_private: bool = False, timeout: float = DEFAULT_TIMEOUT) -> RedirectTracer:
    return RedirectTracer(timeout=timeout, allow_private=allow_private)
