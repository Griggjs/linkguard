# -*- coding: utf-8 -*-
"""核心判定引擎：给一个网址打分，并翻译成老人能看懂的一句话。

设计原则
--------
1. **纯离线可判**。不联网也能给出结论，这样断网、没信号、机场WiFi 都能用。
2. **硬拦截优先**。安装包直链、`javascript:` 伪协议、黑名单命中这类
   不需要看总分，直接判死。
3. **白名单只减分，不免死**。避免把银行官网自己判成钓鱼站。
4. **理由必须能讲给老人听**。每条信号都带 `plain` 字段，是大白话。

调用方式::

    from linkguard.analyzer import analyze
    r = analyze("http://icbc-login.top/verify?card=1")
    r.verdict      # 'block' / 'warn' / 'allow'
    r.elderly      # '别点！这个链接很危险……'
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

from . import rules
from .matcher import DomainMatcher, normalize_host

# 结论常量
BLOCK = "block"
WARN = "warn"
ALLOW = "allow"

VERDICT_LABELS = {BLOCK: "危险，别点", WARN: "可疑，要小心", ALLOW: "看着正常"}

# 零宽字符、全角标点等，老人从微信复制链接时经常带上
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\ufeff"), None)
_FULLWIDTH = str.maketrans({
    "：": ":", "／": "/", "．": ".", "？": "?", "＃": "#", "＆": "&",
    "＝": "=", "％": "%", "＠": "@", "，": ",", "；": ";", "～": "~",
    "＿": "_", "－": "-", "＋": "+",
})
# 从微信/短信里粘出来的常见包裹符
_WRAPPERS = "\"'`“”‘’《》<>【】[]（）() \t\r\n"

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")
# 夹在一大段中文里的链接，例如「【通知】请点击 https://x.top/a 查看」
_EMBEDDED_URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'`\u3000-\u303f\uff01-\uff5e]+",
    re.IGNORECASE,
)
# 链接尾部经常粘着的中英文标点
_TRAILING_JUNK = ".,;:!?)]}》」，。、；：！？）】」』"
_EXT_RE = re.compile(r"\.([a-z0-9]{2,14})(?=[/?#&;\s]|$)", re.IGNORECASE)
_NESTED_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_RANDOM_CONSONANTS_RE = re.compile(r"[bcdfghjklmnpqrstvwxz]{5,}")
_LONG_DIGITS_RE = re.compile(r"\d{5,}")

# 重定向参数名，出现即说明这个链接只是"中转站"
_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "target", "goto", "to", "link",
    "u", "r", "next", "dest", "destination", "return", "returnurl",
    "jump", "jumpurl", "out", "outurl", "forward",
}

# 同形字归一：把常见的"看起来一样"的字符折叠成同一个
_CONFUSABLE = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g",
    "7": "t", "8": "b", "9": "g", "i": "l", "j": "i", "q": "g",
})


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Signal:
    """一条判定证据。"""

    code: str
    weight: int
    detail: str          # 技术说明，给年轻人看
    plain: str           # 大白话，给老人看
    hard: bool = False   # True 表示这一条单独就足以拦截


@dataclass
class Report:
    raw: str
    url: str
    host: str
    registrable: str
    scheme: str
    verdict: str
    score: int
    signals: list[Signal] = field(default_factory=list)
    chain: list[str] = field(default_factory=list)
    short_link: bool = False
    elderly: str = ""
    advice: list[str] = field(default_factory=list)
    category: str = ""

    @property
    def label(self) -> str:
        return VERDICT_LABELS.get(self.verdict, self.verdict)

    @property
    def codes(self) -> list[str]:
        return [s.code for s in self.signals]

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "url": self.url,
            "host": self.host,
            "registrable": self.registrable,
            "scheme": self.scheme,
            "verdict": self.verdict,
            "label": self.label,
            "score": self.score,
            "elderly": self.elderly,
            "advice": self.advice,
            "category": self.category,
            "short_link": self.short_link,
            "chain": self.chain,
            "signals": [
                {
                    "code": s.code,
                    "weight": s.weight,
                    "detail": s.detail,
                    "plain": s.plain,
                    "hard": s.hard,
                }
                for s in self.signals
            ],
        }


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def clean_input(raw: str) -> str:
    """清理从微信/短信里粘出来的链接：去包裹符、零宽字符、全角标点。"""
    if not raw:
        return ""
    text = str(raw).translate(_ZERO_WIDTH)
    text = text.strip(_WRAPPERS)
    text = text.translate(_FULLWIDTH)
    # 微信/短信里常见「某某通知：请点击 https://… 查看」这种整句话
    m = _EMBEDDED_URL_RE.search(text)
    if m and m.start() > 0:
        text = m.group(0)
    elif " " in text or "\n" in text:
        for token in text.split():
            if "://" in token or token.startswith("www.") or "." in token:
                text = token.strip(_WRAPPERS)
                break
    return text.rstrip(_TRAILING_JUNK).strip(_WRAPPERS)


def ensure_scheme(text: str) -> tuple[str, bool]:
    """补全缺失的协议。返回 (完整URL, 是否原本就没写协议)。"""
    if not text:
        return "", False
    m = _SCHEME_RE.match(text)
    if m:
        return text, False
    if text.startswith("//"):
        return "http:" + text, True
    return "http://" + text, True


def is_ip_address(host: str) -> bool:
    h = normalize_host(host)
    if not h:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def split_labels(host: str) -> list[str]:
    return [x for x in normalize_host(host).split(".") if x]


def registrable_domain(host: str) -> str:
    """取"可注册域"，例如 a.b.evil.com.cn -> evil.com.cn。

    不是完整的公共后缀列表实现，只覆盖国内最常见的多段后缀，
    对"这个域名到底注册在谁名下"这个判断已经够用。
    """
    h = normalize_host(host)
    if not h or is_ip_address(h):
        return h
    labels = split_labels(h)
    if len(labels) < 2:
        return h
    if len(labels) >= 3 and ".".join(labels[-2:]) in rules.MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def sld(domain: str) -> str:
    """取注册域里那段"名字"，icbc.com.cn -> icbc。"""
    labels = split_labels(domain)
    if not labels:
        return ""
    if len(labels) >= 3 and ".".join(labels[-2:]) in rules.MULTI_PART_SUFFIXES:
        return labels[-3]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0]


def is_under(host: str, domain: str) -> bool:
    """host 是否等于 domain 或它的子域（标签边界对齐）。"""
    h, d = normalize_host(host), normalize_host(domain)
    if not h or not d:
        return False
    return h == d or h.endswith("." + d)


def levenshtein(a: str, b: str, cap: int = 3) -> int:
    """带提前退出的编辑距离，超过 cap 直接返回 cap+1。"""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    import math

    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def looks_random(label: str) -> bool:
    """判断一段域名标签是不是机器生成的随机串。"""
    if len(label) < 8 or label.startswith("xn--"):
        return False
    digits = sum(ch.isdigit() for ch in label)
    letters = sum(ch.isalpha() for ch in label)
    if digits >= 5 and letters >= 2:
        return True
    if _RANDOM_CONSONANTS_RE.search(label):
        return True
    if _LONG_DIGITS_RE.search(label):
        return True
    # 大小写字母数字混排、且明显没有语义的短串（k3j9x2q8 这类）
    if digits >= 3 and letters >= 3 and len(label) >= 8 and _shannon_entropy(label) >= 3.0:
        return True
    if len(label) >= 12 and digits >= 3 and letters >= 3 and _shannon_entropy(label) >= 3.4:
        return True
    return False


def _decode_fully(text: str, rounds: int = 3) -> str:
    """反复百分号解码，防止 %252e 这类双重编码绕过关键词检测。"""
    out = text
    for _ in range(rounds):
        new = unquote(out)
        if new == out:
            break
        out = new
    return out


def _confusable_fold(text: str) -> str:
    return text.translate(_CONFUSABLE)


def _blocklist_hit(blocklist, host: str) -> str | None:
    """兼容 set / list / DomainMatcher / 实现了 match() 的对象。"""
    if blocklist is None:
        return None
    if hasattr(blocklist, "match"):
        return blocklist.match(host)
    return DomainMatcher(blocklist).match(host)


# ---------------------------------------------------------------------------
# 主分析函数
# ---------------------------------------------------------------------------
def analyze(
    raw_url: str,
    *,
    blocklist=None,
    allowlist=None,
    resolver=None,
    analyse_redirects: bool = False,
) -> Report:
    """分析一个网址。

    参数
    ----
    raw_url : 用户输入的原始文本，可以是 "www.xxx.com/a" 这种没写协议的。
    blocklist : 黑名单（DomainMatcher / set / list）。
    allowlist : 白名单，默认用 rules.ALLOWLIST_DOMAINS。
    resolver : 可选的 (url) -> list[str]，用于展开短链和重定向链。
    analyse_redirects : 是否真的去联网追踪。默认关，保证离线可用。
    """
    raw = str(raw_url or "")
    signals: list[Signal] = []
    chain: list[str] = []

    text = clean_input(raw)
    if not text:
        return Report(
            raw=raw, url="", host="", registrable="", scheme="", verdict=WARN,
            score=0,
            signals=[Signal("EMPTY", 30, "输入为空", "没看懂这个链接")],
            elderly="没看懂这个链接，别点",
            advice=["让发链接的人重新发一次，或者让家里人看看"],
            category="无法识别",
        )

    url, had_scheme = ensure_scheme(text)
    try:
        parsed = urlsplit(url)
    except ValueError:
        return Report(
            raw=raw, url=url, host="", registrable="", scheme="", verdict=BLOCK,
            score=100,
            signals=[Signal("PARSE_ERROR", 100, "URL 结构非法，无法解析", "这个链接是坏的", True)],
            elderly="这个链接是坏的，别点",
            advice=["直接删掉，不要点"],
            category="畸形链接",
        )

    scheme = (parsed.scheme or "").lower()
    host = normalize_host(parsed.hostname or "")
    reg = registrable_domain(host)
    path = parsed.path or ""
    query = parsed.query or ""
    decoded = _decode_fully(path + ("?" + query if query else ""))
    decoded_lower = decoded.lower()

    # ---- 协议 ----
    if scheme in rules.DANGEROUS_SCHEMES:
        w = rules.DANGEROUS_SCHEMES[scheme]
        signals.append(Signal(
            "DANGEROUS_SCHEME", w,
            f"使用了 {scheme}: 伪协议，可直接触发本机行为，绕过浏览器沙箱",
            "这不是普通网页，会直接操控手机", True,
        ))
    elif scheme not in rules.ANALYZABLE_SCHEMES:
        signals.append(Signal(
            "UNKNOWN_SCHEME", 40,
            f"非 http/https 协议：{scheme!r}，通常是 App 自定义跳转",
            "这个链接会直接叫起某个 App", False,
        ))

    # ---- 主机存在性 ----
    if not host:
        signals.append(Signal(
            "NO_HOST", 45, "URL 中没有可解析的主机名",
            "这个链接没有网址，不正常",
        ))

    # ---- 用户名/@ 混淆 ----
    netloc = parsed.netloc or ""
    if "@" in netloc or "%40" in netloc.lower():
        # http://www.icbc.com.cn@evil.top/ 这种做法，host 其实是 evil.top
        signals.append(Signal(
            "USERINFO_AT", 42,
            "URL 的 authority 段含 @，真实主机是 @ 之后的部分，前面的域名是伪装",
            "这个链接把别的网站名字套在前面骗人", True,
        ))

    # ---- 端口 ----
    port = None
    if parsed.port:
        port = parsed.port
    if port and port not in rules.COMMON_PORTS:
        signals.append(Signal(
            "ODD_PORT", 20,
            f"使用了非常用端口 {port}（{rules.PORT_NAMES.get(port, '未知服务')}）",
            "这个链接走的通道不正常",
        ))

    # ---- 黑名单 ----
    hit = _blocklist_hit(blocklist, host)
    if hit:
        signals.append(Signal(
            "BLOCKLIST", 100,
            f"命中恶意域名黑名单：{hit}",
            "这个网站已经被很多人举报过了", True,
        ))

    # ---- 白名单 ----
    white = rules.ALLOWLIST_DOMAINS if allowlist is None else allowlist
    white_hit = _blocklist_hit(white, host) if white is not None else None
    if white_hit:
        signals.append(Signal(
            "ALLOWLIST", -55,
            f"属于已知正规站点：{white_hit}",
            "这是正经网站", False,
        ))

    # ---- IP 直连 ----
    if host and is_ip_address(host):
        signals.append(Signal(
            "IP_LITERAL", 35,
            f"直接用 IP 地址 {host} 访问，没有域名，常见于临时架设的钓鱼页",
            "这个链接没写网站名字，只用了一串数字", True,
        ))

    # ---- IDN / punycode ----
    if "xn--" in host:
        signals.append(Signal(
            "PUNYCODE", 32,
            "主机名含 punycode（xn--），可显示成与真实域名几乎一样的字符",
            "这个网站的字母是伪装的，看着像其实不是", True,
        ))
    if host and any(ord(ch) > 127 for ch in host):
        signals.append(Signal(
            "NON_ASCII_HOST", 18,
            "主机名含非 ASCII 字符",
            "这个网站的字母不常见",
        ))

    # ---- 后缀风险 ----
    labels = split_labels(host)
    if labels:
        tld = labels[-1]
        if tld in rules.SUSPICIOUS_TLDS:
            signals.append(Signal(
                "SUSPICIOUS_TLD", rules.SUSPICIOUS_TLDS[tld],
                f"顶级域 .{tld} 是钓鱼站高发后缀（注册便宜、批量注册）",
                "这个网站的后缀不太正经",
            ))

    # ---- 结构异常 ----
    if len(labels) >= 5:
        signals.append(Signal(
            "DEEP_SUBDOMAIN", 20,
            f"域名嵌套 {len(labels)} 层，常用于把官方域名塞进子域里骗人",
            "这个网站名字套了好几层，在装样子",
        ))
    elif len(labels) == 4:
        signals.append(Signal(
            "DEEP_SUBDOMAIN", 10,
            f"域名嵌套 {len(labels)} 层",
            "这个网站名字有点长",
        ))
    if len(host) > 40:
        signals.append(Signal(
            "LONG_HOST", 12, f"主机名长度 {len(host)}，超出正常范围",
            "这个网站名字特别长，不正常",
        ))
    hyphens = host.count("-")
    if hyphens >= 3:
        signals.append(Signal(
            "MANY_HYPHENS", 16,
            f"主机名含 {hyphens} 个连字符，典型的关键词堆砌型钓鱼域",
            "这个网址里横杠太多，是编出来的",
        ))
    for label in labels[:-1]:
        if looks_random(label):
            signals.append(Signal(
                "RANDOM_LABEL", 22,
                f"域名标签 {label!r} 像机器生成的随机串",
                "这个网址是一串乱码",
            ))
            break

    # ---- 危险文件类型 ----
    for m in _EXT_RE.finditer(decoded):
        ext = m.group(1).lower()
        if ext in rules.DANGEROUS_EXTENSIONS:
            signals.append(Signal(
                "DANGEROUS_FILE", rules.DANGEROUS_EXTENSIONS[ext],
                f"链接指向 .{ext} 文件，下载安装后会获得手机控制权",
                "点开就会往手机里装东西，装完手机就被别人管了",
                ext in ("apk", "apks", "xapk", "exe", "mobileconfig", "mobileprovision"),
            ))
            break

    # ---- 短链 ----
    short = bool(reg and (reg in rules.SHORTENER_DOMAINS or host in rules.SHORTENER_DOMAINS))
    if short:
        signals.append(Signal(
            "SHORTENER", 30,
            "使用了短链服务，真实去向被隐藏，必须展开后再判断",
            "这个链接把真实地址藏起来了",
        ))

    # ---- 嵌套 URL / 开放重定向 ----
    nested = _NESTED_URL_RE.findall(decoded)
    if nested:
        signals.append(Signal(
            "NESTED_URL", 28,
            f"参数里又套了一个网址：{nested[0][:80]}，典型的跳转洗白",
            "这个链接里面还藏着另一个链接",
        ))
    try:
        qs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        qs = []
    for key, value in qs:
        if key.lower() in _REDIRECT_PARAMS and ("http" in value.lower() or "//" in value):
            signals.append(Signal(
                "OPEN_REDIRECT", 22,
                f"参数 {key}= 里带着目标地址，这是一个中转跳转链接",
                "这个链接会把你转到别的地方去",
            ))
            break

    # ---- 编码异常 ----
    if path.count("%") + query.count("%") >= 8:
        signals.append(Signal(
            "HEAVY_ENCODING", 18,
            "百分号编码比例异常高，常用于绕过关键词检测",
            "这个网址被故意搅乱了",
        ))

    # ---- 诈骗话术 ----
    kw_score = 0
    kw_hits: list[str] = []
    for kw, w in rules.SCAM_KEYWORDS.items():
        if kw in decoded_lower:
            kw_score += w
            kw_hits.append(kw)
            if len(kw_hits) >= 4:
                break
    if kw_hits:
        kw_score = min(kw_score, 34)
        signals.append(Signal(
            "SCAM_KEYWORDS", kw_score,
            f"路径/参数含诱导性关键词：{'、'.join(kw_hits)}",
            "这个链接在催你办一件事（转账、认证、领奖）",
        ))

    # ---- 未加密 ----
    if scheme == "http":
        signals.append(Signal(
            "NO_HTTPS", 18 if kw_hits else 8,
            "使用明文 HTTP，内容可被中间人篡改，正规站点早已强制 HTTPS",
            "这个链接没有加密，容易被坏人改动",
        ))

    # ---- 品牌仿冒 ----
    if host:
        brand_sig = _check_brand(host, reg, labels, decoded_lower)
        if brand_sig:
            signals.extend(brand_sig)

    # ---- 重定向链（可选联网）----
    if analyse_redirects and resolver and scheme in rules.ANALYZABLE_SCHEMES and host:
        try:
            chain = list(resolver(url) or [])
        except Exception:  # noqa: BLE001 - 联网失败不能影响主判定
            chain = []
        if chain:
            sig = _check_chain(url, chain, blocklist)
            if sig:
                signals.extend(sig)
            # 展开后落在正规站上，可以把短链的怀疑抵消掉
            try:
                final_host = normalize_host(urlsplit(chain[-1]).hostname or "")
            except ValueError:
                final_host = ""
            if final_host and white is not None:
                f_w = _blocklist_hit(white, final_host)
                if f_w:
                    signals.append(Signal(
                        "RESOLVED_SAFE", -35,
                        f"短链展开后最终落在已知正规站点：{f_w}",
                        "这个短链打开后是正经网站",
                    ))

    # ---- 计分 ----
    score = max(0, sum(s.weight for s in signals))
    hard = any(s.hard for s in signals)
    if hard:
        verdict = BLOCK
    elif white_hit:
        # 正规站点的软性疑点不构成拦截理由
        verdict = ALLOW
    elif score >= rules.VERDICT_BLOCK_AT:
        verdict = BLOCK
    elif score >= rules.VERDICT_WARN_AT:
        verdict = WARN
    else:
        verdict = ALLOW

    report = Report(
        raw=raw, url=url, host=host, registrable=reg, scheme=scheme,
        verdict=verdict, score=score, signals=signals, chain=chain,
        short_link=short,
    )
    report.category = _category(signals)
    report.elderly = _elderly_text(report)
    report.advice = _advice(report)
    return report


# ---------------------------------------------------------------------------
# 品牌仿冒判定
# ---------------------------------------------------------------------------
def _check_brand(host: str, reg: str, labels: list[str], decoded_lower: str) -> list[Signal]:
    out: list[Signal] = []
    host_flat = host.replace("-", "").replace(".", "")

    for brand, officials in rules.BRANDS.items():
        official_hit = any(is_under(host, o) for o in officials)
        if official_hit:
            continue

        if len(brand) >= rules.BRAND_MIN_SUBSTRING_LEN:
            present = brand in host_flat
        else:
            present = brand in labels
        if not present:
            continue

        out.append(Signal(
            "BRAND_IMPERSONATION", 58,
            f"域名里带品牌词 {brand!r}，但官方域是 {'/'.join(sorted(officials))}，这不是官方站",
            "这个网站冒充了银行或大公司，是假的", True,
        ))
        break

    # 形近域名：1~2 个字符之差（含 0/o、1/l 这类同形替换）
    reg_sld = sld(reg)
    folded = _confusable_fold(reg_sld) if reg_sld else ""
    for officials in rules.BRANDS.values():
        for official in officials:
            o_sld = sld(official)
            if len(o_sld) < 4:
                continue
            official_reg = registrable_domain(official)
            # 名字一样，但后缀不是官方的：icbc.com vs icbc.com.cn
            if reg_sld == o_sld:
                if reg != official_reg:
                    out.append(Signal(
                        "WRONG_TLD", 42,
                        f"注册域 {reg!r} 用了品牌名，但后缀不是官方后缀 {official!r}",
                        "网址名字对，但结尾不对，是假的",
                    ))
                    return out
                continue
            if not folded:
                continue
            o_folded = _confusable_fold(o_sld)
            if o_folded == folded:
                out.append(Signal(
                    "TYPO_CONFUSABLE", 62,
                    f"注册域 {reg!r} 与官方 {official!r} 只差同形字符（0/o、1/l 一类）",
                    "这个网址把字母换了个样子，是冒充的", True,
                ))
                return out
            d = levenshtein(folded, o_folded, cap=2)
            if 0 < d <= 2 and min(len(o_sld), len(folded)) >= 5:
                out.append(Signal(
                    "TYPO_SQUAT", 55 if d == 1 else 45,
                    f"注册域 {reg!r} 与官方 {official!r} 编辑距离 {d}，是抢注的近似域名",
                    "这个网址和正经网站只差一两个字，是假的",
                ))
                return out

    # 中文品牌词被塞进路径里（仿冒页常见 /工商银行/ 这种路径）
    for kw, w in (("工商银行", 30), ("建设银行", 30), ("农业银行", 30),
                  ("中国银行", 30), ("支付宝", 30), ("微信", 24),
                  ("国家反诈", 30), ("银联", 30)):
        if kw in decoded_lower:
            out.append(Signal(
                "BRAND_IN_PATH", w,
                f"URL 路径里出现品牌名 {kw!r}，常被仿冒页用来伪装",
                "这个网址在冒充官方",
            ))
            break
    return out


# ---------------------------------------------------------------------------
# 重定向链判定
# ---------------------------------------------------------------------------
def _check_chain(start: str, chain: list[str], blocklist) -> list[Signal]:
    out: list[Signal] = []
    if len(chain) >= 4:
        out.append(Signal(
            "LONG_REDIRECT", 25,
            f"跳转 {len(chain)} 次才到最终页面，正常链接很少这样",
            "这个链接要转好几道弯才到地方",
        ))
    final = chain[-1]
    try:
        f_host = normalize_host(urlsplit(final).hostname or "")
    except ValueError:
        return out
    if start.startswith("https://") and final.startswith("http://"):
        out.append(Signal(
            "HTTPS_DOWNGRADE", 30,
            "从 HTTPS 降级到 HTTP，内容可被中间人替换",
            "这个链接中途把加密关掉了", True,
        ))
    if f_host and blocklist is not None:
        hit = _blocklist_hit(blocklist, f_host)
        if hit:
            out.append(Signal(
                "REDIRECT_TO_BLACKLIST", 100,
                f"短链最终跳到了黑名单域名：{hit}",
                "这个链接最后会把你带到骗子网站", True,
            ))
    return out


# ---------------------------------------------------------------------------
# 人话生成
# ---------------------------------------------------------------------------
def _category(signals: list[Signal]) -> str:
    codes = {s.code for s in signals}
    if "DANGEROUS_FILE" in codes:
        return "安装包下载"
    if "DANGEROUS_SCHEME" in codes:
        return "伪协议跳转"
    if "BRAND_IMPERSONATION" in codes or "TYPO_SQUAT" in codes or "TYPO_CONFUSABLE" in codes:
        return "冒充官方"
    if "BLOCKLIST" in codes or "REDIRECT_TO_BLACKLIST" in codes:
        return "已举报的恶意站"
    if "SHORTENER" in codes:
        return "短链跳转"
    if "NESTED_URL" in codes or "OPEN_REDIRECT" in codes:
        return "中转跳转"
    if "PUNYCODE" in codes or "NON_ASCII_HOST" in codes or "USERINFO_AT" in codes:
        return "伪装域名"
    if "IP_LITERAL" in codes:
        return "临时搭的站"
    if "SCAM_KEYWORDS" in codes:
        return "催办诈骗"
    return "普通链接"


def _elderly_text(r: Report) -> str:
    if r.verdict == ALLOW:
        # 放行时不要把减分项的解释（比如"名字有点长"）说出来，只会让老人困惑
        if "ALLOWLIST" in set(r.codes):
            return "这个链接看着正常。这是正经网站"
        if "RESOLVED_SAFE" in set(r.codes):
            return "这个链接看着正常。短链打开后是正经网站"
        return "这个链接看着正常"

    top = sorted((s for s in r.signals if s.hard), key=lambda s: -s.weight)
    if not top:
        top = sorted(
            (s for s in r.signals if s.weight > 0), key=lambda s: -s.weight
        )
    reason = top[0].plain if top else ""
    head = "别点！这个链接很危险" if r.verdict == BLOCK else "小心！这个链接有点可疑"
    return f"{head}。{reason}" if reason else head


def _advice(r: Report) -> list[str]:
    codes = set(r.codes)
    out: list[str] = []
    if r.verdict == BLOCK:
        out.append("直接删掉这条消息，不要点，也不要转发给朋友")
        if "DANGEROUS_FILE" in codes:
            out.append("如果已经下载了安装包，立刻在「设置 → 应用」里卸载，并关掉「允许安装未知应用」")
        if {"BRAND_IMPERSONATION", "TYPO_SQUAT", "TYPO_CONFUSABLE", "BRAND_IN_PATH"} & codes:
            out.append("银行、支付、政务不会用短信发链接让你登录，要办业务请自己在应用商店打开官方 App")
        if "SHORTENER" in codes:
            out.append("短链接背后是什么看不见，别人发的短链一律不要点")
        out.append("让家里人帮忙确认一下，或者打官方客服电话核实")
    elif r.verdict == WARN:
        out.append("先别急着点，把这条链接发给家里人看一眼")
        out.append("如果页面让你填密码、验证码、银行卡号，一律不填")
        out.append("如果是熟人发的，打电话问一句是不是他本人发的")
    else:
        out.append("看起来没问题，但页面上一旦让你填银行卡、验证码，仍然不要填")
        out.append("不要在陌生页面上扫码付款")
    return out
