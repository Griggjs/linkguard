# -*- coding: utf-8 -*-
"""恶意域名名单的抓取、解析、合并。

现实情况
--------
国内没有一个"官方开放 API"能查链接是不是诈骗，所以名单只能靠公开情报源拼。
不同源给的是不同格式：hosts 文件、纯域名列表、Adblock 规则、URLhaus CSV、JSON。
这个模块负责把它们都归一成"一堆域名"。

重要提醒
--------
内置源都是国外的公开情报（StevenBlack / URLhaus / Phishing Army），
**对中文诈骗站的覆盖率有限**。想真正好用，最有效的是两件事：
1. 家里人遇到可疑链接，随手 `linkguard feeds add-domain <域名>` 喂进来；
2. 接国内厂商的威胁情报 API（腾讯、阿里、微步），写好适配器挂上。

抓取失败不会中断整个更新流程，每个源单独报结果。
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlsplit

from .matcher import normalize_host

USER_AGENT = "LinkGuard/1.0 (+home-network-protection)"
DEFAULT_TIMEOUT = 20.0

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_COMMENT_PREFIXES = ("#", "!", "//", ";", "[")
_URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


@dataclass
class Source:
    name: str
    url: str
    kind: str = "auto"   # auto / hosts / domains / adblock / urlhaus / json


# 默认源：可以用 `--source name=url` 覆盖或追加
#
# 注意：这些源会失效、会改地址，是常态不是意外。
# 2026-11 实测：URLhaus 的所有 downloads/* 端点都返回 410 Gone，
# 所以直接用它的镜像（malware-filter 那个 Adblock 版）。
# 跑 `feeds --update` 时每个源单独报结果，挂了不影响别人。
DEFAULT_SOURCES: list[Source] = [
    Source("stevenblack",
           "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
           "hosts"),
    Source("phishing-army",
           "https://phishing.army/download/phishing_army_blocklist_extended.txt",
           "domains"),
    Source("phishdb",
           "https://raw.githubusercontent.com/MitchellKrogza/Phishing.Database/"
           "master/phishing-domains-ACTIVE.txt",
           "domains"),
    Source("openphish",
           "https://openphish.com/feed.txt",
           "domains"),
    Source("urlhaus-adblock",
           "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt",
           "adblock"),
]


def _is_valid_domain(token: str) -> bool:
    if not token or len(token) > 253:
        return False
    if token.startswith("-") or token.endswith("-") or ".." in token:
        return False
    if _IPV4_RE.match(token):
        return False
    return bool(_DOMAIN_RE.match(token))


def _clean_token(token: str) -> str:
    t = token.strip().strip("\"'`()[]<>,;")
    if t.startswith("||"):          # Adblock: ||evil.com^
        t = t[2:]
    if t.startswith("@@"):          # Adblock 例外规则，是白名单，不能进黑名单
        return ""
    if "^" in t:
        t = t.split("^", 1)[0]
    if "/" in t:
        t = t.split("/", 1)[0]
    if ":" in t:
        t = t.split(":", 1)[0]
    if t.startswith("*."):
        t = t[2:]
    if t.startswith("."):
        t = t[1:]
    return normalize_host(t)


def extract_hosts(text: str) -> list[str]:
    """从任意文本里抽出域名，保持出现顺序并去重。

    这是所有格式的公共底座：先把"像 URL 的 token"交给 urlsplit，
    剩下的裸 token 再按域名规则校验。这样 hosts 文件里的 IP、
    CSV 里的状态字段、注释里的英文单词都不会被误收。
    """
    if not text:
        return []
    if text.lstrip()[:1] in "[{":
        # JSON 数组/对象，走结构化解析更可靠
        try:
            return _walk_json(json.loads(text))
        except (json.JSONDecodeError, ValueError):
            pass

    out: list[str] = []
    seen: set[str] = set()

    def push(candidate: str) -> None:
        c = _clean_token(candidate)
        if c and c not in seen and _is_valid_domain(c):
            seen.add(c)
            out.append(c)

    for line in text.splitlines():
        # 行内注释必须切掉：hosts 文件里常写成
        #   0.0.0.0 docs.pipenv.org # https://github.com/StevenBlack/hosts/issues/1635
        # 不切除的话，注释中的 github.com 会被当成待拦域名（曾实际发生）。
        # 域名里不可能有 #，URL 的 # 后面是锚点、对取域名没意义，所以直接切到底。
        s = line.split("#", 1)[0].strip()
        if not s or s.startswith(_COMMENT_PREFIXES):
            continue
        # 逗号也要当分隔符：CSV 格式的一行里没有空格，不切分就一个 token 都提不出来
        for token in re.split(r"[,\s]+", s):
            token = token.strip("\"'`()[],;")
            if not token:
                continue
            if _URL_SCHEME_RE.match(token) or "://" in token:
                try:
                    host = urlsplit(token).hostname
                except ValueError:
                    host = None
                if host:
                    push(host)
                continue
            push(token)
    return out


def _walk_json(node) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def push(value: str) -> None:
        v = normalize_host(str(value))
        if v and v not in seen and _is_valid_domain(v):
            seen.add(v)
            out.append(v)

    def walk(n) -> None:
        if isinstance(n, str):
            if "://" in n:
                try:
                    host = urlsplit(n).hostname
                except ValueError:
                    host = None
                if host:
                    push(host)
            else:
                push(n)
        elif isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
        elif isinstance(n, dict):
            for value in n.values():
                walk(value)

    walk(node)
    return out


def parse_hosts(text: str) -> list[str]:
    return extract_hosts(text)


def parse_domain_lines(text: str) -> list[str]:
    return extract_hosts(text)


def parse_adblock(text: str) -> list[str]:
    return extract_hosts(text)


def parse_urlhaus_csv(text: str) -> list[str]:
    """URLhaus 的 CSV：id, dateadded, url, url_status, ... 抽出 URL 的 host。"""
    return extract_hosts(text)


PARSERS: dict[str, Callable[[str], list[str]]] = {
    "hosts": parse_hosts,
    "domains": parse_domain_lines,
    "adblock": parse_adblock,
    "urlhaus": parse_urlhaus_csv,
    "json": lambda t: _walk_json(json.loads(t)),
    "auto": extract_hosts,
}


def parse(text: str, kind: str = "auto") -> list[str]:
    parser = PARSERS.get(kind)
    if parser is None:
        raise ValueError(f"未知的名单格式：{kind!r}，可选 {sorted(PARSERS)}")
    return parser(text)


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """下载一份名单文本。file:// 也可以，方便离线导入。"""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        raw = resp.read()
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


@dataclass
class UpdateResult:
    name: str
    ok: bool
    added: int = 0
    removed: int = 0
    total: int = 0
    error: str = ""

    def __str__(self) -> str:
        if not self.ok:
            return f"[失败] {self.name}: {self.error}"
        return (f"[成功] {self.name}: 解析 {self.total} 条，"
                f"新增 {self.added}（其余与已有名单重复），移除 {self.removed}")


def update_source(
    store,
    source: Source,
    *,
    fetcher: Callable[[str], str] = fetch,
) -> UpdateResult:
    try:
        text = fetcher(source.url)
    except Exception as exc:  # noqa: BLE001 - 单源失败不能影响别的源
        return UpdateResult(source.name, False, error=str(exc))

    try:
        domains = parse(text, source.kind)
    except Exception as exc:  # noqa: BLE001
        return UpdateResult(source.name, False, error=f"解析失败：{exc}")

    if not domains:
        return UpdateResult(source.name, False, error="解析结果为空，可能源已失效")

    added, removed = store.replace_source(source.name, domains)
    return UpdateResult(source.name, True, added, removed, len(domains))


def update_all(
    store,
    sources: Iterable[Source] = (),
    *,
    fetcher: Callable[[str], str] = fetch,
) -> list[UpdateResult]:
    srcs = list(sources) or DEFAULT_SOURCES
    return [update_source(store, s, fetcher=fetcher) for s in srcs]


def parse_source_spec(spec: str) -> Source:
    """解析 'name=url' 或 'name=url#kind' 命令行语法。"""
    if "=" not in spec:
        raise ValueError(f"源格式应为 name=url，收到 {spec!r}")
    name, rest = spec.split("=", 1)
    kind = "auto"
    if "#" in rest:
        rest, kind = rest.rsplit("#", 1)
    return Source(name.strip(), rest.strip(), kind.strip() or "auto")
