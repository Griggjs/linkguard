# -*- coding: utf-8 -*-
"""域名后缀匹配器：判断 host 是否命中某个域名（含其所有子域）。

三处都要用同一套语义，所以单独抽出来：
- analyzer 判断黑名单命中
- sinkhole 判断要不要拦截这个 DNS 查询
- feeds 合并多份名单后去重

语义就是"域及其子域"：名单里有 evil.com，那么 evil.com 和 a.b.evil.com 都算命中，
但 notevil.com 不算（必须是标签边界对齐，不能做字符串后缀比较）。
"""

from __future__ import annotations

from typing import Iterable, Iterator


def normalize_host(host: str) -> str:
    """统一成小写、无首尾点、无首尾空白的形态。"""
    if not host:
        return ""
    host = host.strip().strip(".").lower()
    # 去掉 IPv6 方括号
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def host_suffixes(host: str) -> Iterator[str]:
    """依次产出 'a.b.c'、'b.c'、'c'，从长到短。"""
    host = normalize_host(host)
    if not host:
        return
    labels = host.split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


class DomainMatcher:
    """一组域名的后缀匹配器。

    用法::

        m = DomainMatcher({"evil.com", "bad.top"})
        m.match("a.evil.com")   # -> 'evil.com'
        m.match("notevil.com")  # -> None
    """

    __slots__ = ("_domains",)

    def __init__(self, domains: Iterable[str] = ()):
        self._domains: set[str] = set()
        for d in domains:
            self.add(d)

    def add(self, domain: str) -> bool:
        d = normalize_host(domain)
        if not d:
            return False
        # 直接吃 Adblock 语法，方便把现成的规则文件整份塞进来
        if d.startswith("@@"):        # 例外规则 = 白名单，不能进黑名单
            return False
        if d.startswith("||"):
            d = d[2:]
        if "^" in d:
            d = d.split("^", 1)[0]
        # 裸的通配写法 ||evil.com^ / *.evil.com / .evil.com 统一成 evil.com
        if d.startswith("*."):
            d = d[2:]
        d = normalize_host(d.lstrip("."))
        if not d or "." not in d:
            return False
        before = len(self._domains)
        self._domains.add(d)
        return len(self._domains) != before

    def update(self, domains: Iterable[str]) -> int:
        n = 0
        for d in domains:
            if self.add(d):
                n += 1
        return n

    def match(self, host: str) -> str | None:
        """返回命中的名单条目（最长匹配），未命中返回 None。"""
        h = normalize_host(host)
        if not h:
            return None
        for suffix in host_suffixes(h):
            if suffix in self._domains:
                return suffix
        return None

    def __contains__(self, host: object) -> bool:
        return isinstance(host, str) and self.match(host) is not None

    def __len__(self) -> int:
        return len(self._domains)

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._domains))

    def as_sorted_list(self) -> list[str]:
        return sorted(self._domains)
