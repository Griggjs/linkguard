# -*- coding: utf-8 -*-
"""手机浏览器直接可用的大字版「链接体检」页面 + JSON API。

为什么要一个网页
----------------
手机上没有"脚本"的落脚点，但每个手机都有浏览器。让老人（或帮他的人）
连着家里 WiFi，打开这台电脑上的一个地址，把可疑链接粘进去，就能看到
大字结论——这是全流程里最容易被真正用起来的一环。

设计取舍
--------
- **服务端渲染，不依赖 JavaScript**。老人手机可能是老旧机型、可能关了 JS、
  可能装了拦截插件。表单直接 GET 提交，结果由服务器拼好 HTML 返回。
- **零外部资源**。不引 CDN、不引字体、不引统计脚本。断网也能用，也不会
  因为某个 CDN 慢而转半天。
- 字号按老人可读的尺寸定（正文 20px 起，结论 40px 起），高对比配色。

路由
----
    GET  /                 体检页（?u=<链接> 直接出结果）
    GET  /api/check?url=   JSON 结果（给书签小工具和脚本用）
    POST /api/check        JSON 结果（body: {"url": "..."}）
    GET  /api/recent       最近的检测记录（子女回看）
    GET  /api/stats        统计
    GET  /api/health       健康检查
"""

from __future__ import annotations

import html
import json
import socket
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import rules
from .analyzer import ALLOW, BLOCK, WARN, Report, analyze
from .store import Store

MAX_BODY = 64 * 1024
COLORS = {BLOCK: "#c62828", WARN: "#e65100", ALLOW: "#2e7d32"}
TINTS = {BLOCK: "#ffebee", WARN: "#fff3e0", ALLOW: "#e8f5e9"}
ICONS = {BLOCK: "✕", WARN: "!", ALLOW: "✓"}

_CSS = """
*{box-sizing:border-box;-webkit-text-size-adjust:100%}
body{margin:0;padding:16px 16px 48px;font-family:-apple-system,BlinkMacSystemFont,
"PingFang SC","Microsoft YaHei","Helvetica Neue",sans-serif;
font-size:20px;line-height:1.65;color:#1a1a1a;background:#f5f6f8}
h1{font-size:26px;margin:8px 0 16px;text-align:center;color:#1b3a63}
h2{font-size:22px;margin:24px 0 12px;color:#1b3a63}
.card{background:#fff;border-radius:16px;padding:20px;margin:0 0 20px;
box-shadow:0 2px 10px rgba(0,0,0,.08)}
form{display:flex;flex-direction:column;gap:12px}
input[type=text]{width:100%;font-size:20px;padding:16px;border:2px solid #c7ccd6;
border-radius:12px;background:#fff;color:#111}
input[type=text]:focus{outline:none;border-color:#1b6fd6}
button{font-size:22px;font-weight:600;padding:18px;border:0;border-radius:12px;
background:#1b6fd6;color:#fff;cursor:pointer}
button:active{background:#1559ad}
.verdict{border-radius:16px;padding:24px 20px;margin:0 0 20px;text-align:center}
.verdict .icon{font-size:64px;line-height:1;font-weight:700}
.verdict .label{font-size:34px;font-weight:700;margin:6px 0 12px}
.verdict .elderly{font-size:24px;line-height:1.5}
ol.advice{margin:0;padding-left:26px;font-size:20px}
ol.advice li{margin:10px 0}
.meta{font-size:17px;color:#5a6472;word-break:break-all}
.meta b{color:#1a1a1a}
table{width:100%;border-collapse:collapse;font-size:17px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #e6e8ec;vertical-align:top}
th{color:#5a6472;font-weight:600}
details summary{font-size:20px;font-weight:600;cursor:pointer;padding:8px 0;color:#1b3a63}
.tag{display:inline-block;font-size:15px;padding:2px 8px;border-radius:999px;
background:#eceff1;color:#37474f;margin:2px 4px 2px 0}
.hard{background:#ffcdd2;color:#b71c1c}
footer{font-size:16px;color:#78828f;text-align:center;margin-top:32px;line-height:1.7}
a{color:#1b6fd6}
code{background:#eceff1;padding:1px 6px;border-radius:6px;font-size:16px;word-break:break-all}
"""


# ---------------------------------------------------------------------------
# 页面渲染
# ---------------------------------------------------------------------------
def _render_result(report: Report) -> str:
    color = COLORS.get(report.verdict, "#455a64")
    tint = TINTS.get(report.verdict, "#eceff1")
    icon = ICONS.get(report.verdict, "?")
    advice = "".join(f"<li>{html.escape(a)}</li>" for a in report.advice)
    advice_block = f"<h2>该怎么做</h2><ol class='advice'>{advice}</ol>" if advice else ""

    rows = []
    for s in sorted(report.signals, key=lambda x: -x.weight):
        if s.weight == 0:
            continue
        cls = "tag hard" if s.hard else "tag"
        rows.append(
            "<tr><td><span class='{}'>{}</span></td><td>{}</td></tr>".format(
                cls,
                html.escape(s.code),
                html.escape(s.detail),
            )
        )
    detail_table = (
        "<table><tr><th>判定依据</th><th>说明</th></tr>{}</table>".format("".join(rows))
        if rows else "<p class='meta'>没有发现异常特征。</p>"
    )

    chain_html = ""
    if report.chain:
        items = "".join(
            f"<li><code>{html.escape(u)}</code></li>" for u in report.chain
        )
        chain_html = f"<h2>跳转路径</h2><ol class='meta'>{items}</ol>"

    return f"""
<div class="verdict" style="background:{tint};color:{color}">
  <div class="icon">{icon}</div>
  <div class="label">{html.escape(report.label)}</div>
  <div class="elderly">{html.escape(report.elderly)}</div>
</div>
<div class="card">
  {advice_block}
  <h2>这个链接的底细</h2>
  <p class="meta">
    <b>网址</b>：{html.escape(report.url)}<br>
    <b>网站名</b>：{html.escape(report.registrable or report.host or "（无）")}<br>
    <b>类型</b>：{html.escape(report.category)}<br>
    <b>风险分</b>：{report.score}
    （{rules.VERDICT_WARN_AT} 分以上可疑，{rules.VERDICT_BLOCK_AT} 分以上拦下）
  </p>
  {chain_html}
  <details>
    <summary>给子女看的判定细节</summary>
    {detail_table}
  </details>
</div>
"""


def _render_page(
    *, query: str = "", report: Report | None = None, bookmarklet_href: str = "",
    notice: str = "", recent: list[dict] | None = None,
) -> str:
    form = f"""
<form method="get" action="/">
  <input type="text" name="u" value="{html.escape(query)}"
         placeholder="把可疑链接粘贴到这里" autocomplete="off"
         autocapitalize="off" spellcheck="false" inputmode="text">
  <button type="submit">查一查</button>
</form>
"""
    body = form
    if notice:
        body += f"<div class='card'><p>{html.escape(notice)}</p></div>"
    if report is not None:
        body += _render_result(report)

    bookmark = ""
    if bookmarklet_href:
        bookmark = f"""
<div class="card">
  <details>
    <summary>在手机浏览器里加一个「一键查当前网页」按钮</summary>
    <p class="meta">把这个地址存成书签（长按下面的链接 → 添加到书签）。
    以后在任何网页上点这个书签，就会跳到这里告诉你这页安不安全。</p>
    <p class="meta"><code>{html.escape(bookmarklet_href)}</code></p>
  </details>
</div>
"""

    recent_html = ""
    if recent:
        items = "".join(
            "<tr><td style='color:{}'><b>{}</b></td>"
            "<td class='meta' style='word-break:break-all'>{}</td>"
            "<td class='meta'>{}</td></tr>".format(
                COLORS.get(r.get("verdict", ""), "#455a64"),
                html.escape({"block": "危险", "warn": "可疑", "allow": "正常"}.get(
                    r.get("verdict", ""), "?")),
                html.escape((r.get("url") or "")[:120]),
                html.escape((r.get("ts") or "")[:16].replace("T", " ")),
            )
            for r in recent
        )
        recent_html = f"""
<div class="card">
  <details>
    <summary>最近查过的链接（{len(recent)} 条）</summary>
    <table><tr><th>结论</th><th>链接</th><th>时间</th></tr>{items}</table>
  </details>
</div>
"""

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="format-detection" content="telephone=no">
<meta name="robots" content="noindex,nofollow">
<title>护链 · 链接体检</title>
<style>{_CSS}</style>
</head>
<body>
<h1>护链 · 链接体检</h1>
<div class="card">{body}</div>
{bookmark}
{recent_html}
<footer>
  这个页面只在你家路由器内部可用，数据不出门。<br>
  它只能"看出"链接有问题，不能替你保证没问题的链接一定安全。<br>
  凡是要你填银行卡、验证码、身份证的页面，一律关掉。
</footer>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP 处理
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "LinkGuard"
    protocol_version = "HTTP/1.1"

    # -- 由 run() 注入 --
    store: Store | None = None
    blocklist = None
    resolver = None
    analyse_redirects = False
    access_log = True

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        if self.access_log:
            super().log_message(fmt, *args)

    # -- 工具 -------------------------------------------------------------
    def _send(self, status: int, body: str | bytes, ctype: str = "text/html; charset=utf-8",
              extra: dict[str, str] | None = None) -> None:
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _json(self, obj: Any, status: int = 200) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _check(self, url: str) -> Report:
        return analyze(
            url,
            blocklist=self.blocklist,
            resolver=self.resolver,
            analyse_redirects=self.analyse_redirects,
        )

    def _remember(self, report: Report) -> None:
        if self.store is None:
            return
        try:
            self.store.log_check(report, self.client_address[0] if self.client_address else "")
        except Exception:  # noqa: BLE001 - 落库失败不能挡住用户看结果
            pass

    def _bookmarklet(self) -> str:
        host = self.headers.get("Host") or f"127.0.0.1:{self.server.server_port}"
        return "javascript:location.href='http://{}/?u='+encodeURIComponent(location.href)".format(host)

    # -- 路由 -------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if path == "/api/health":
            self._json({"ok": True, "service": "linkguard", "version": "1.0.0"})
            return

        if path == "/api/check":
            url = (params.get("url") or params.get("u") or [""])[0]
            if not url.strip():
                self._json({"error": "缺少 url 参数"}, 400)
                return
            report = self._check(url)
            self._remember(report)
            self._json(report.to_dict())
            return

        if path == "/api/recent":
            try:
                limit = max(1, min(200, int((params.get("limit") or ["30"])[0])))
            except ValueError:
                limit = 30
            verdict = (params.get("verdict") or [""])[0] or None
            rows = self.store.recent_checks(limit, verdict) if self.store else []
            self._json({"items": rows})
            return

        if path == "/api/stats":
            self._json(self.store.stats() if self.store else {})
            return

        if path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return

        if path == "/":
            url = (params.get("u") or params.get("url") or [""])[0].strip()
            report = None
            notice = ""
            if url:
                report = self._check(url)
                self._remember(report)
            try:
                recent = self.store.recent_checks(8) if self.store else []
            except Exception:  # noqa: BLE001
                recent = []
            page = _render_page(
                query=url, report=report, notice=notice,
                bookmarklet_href=self._bookmarklet(), recent=recent,
            )
            self._send(200, page)
            return

        self._send(404, "<h1>404</h1><p>没有这个页面。<a href='/'>回到体检页</a></p>")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path.rstrip("/") != "/api/check":
            self._send(404, "not found", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._json({"error": "请求体为空或过大"}, 400)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json({"error": "请求体不是合法 JSON"}, 400)
            return
        url = str(payload.get("url") or payload.get("u") or "")
        if not url.strip():
            self._json({"error": "缺少 url 字段"}, 400)
            return
        report = self._check(url)
        self._remember(report)
        self._json(report.to_dict())


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------
def lan_ip() -> str:
    """猜本机在局域网里的地址（不会真的发包）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("223.5.5.5", 53))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        sock.close()


def run(
    store: Store,
    host: str = "0.0.0.0",
    port: int = 8088,
    *,
    blocklist=None,
    resolver=None,
    analyse_redirects: bool = False,
    access_log: bool = True,
    quiet: bool = False,
) -> ThreadingHTTPServer:
    """启动服务并返回 server 对象（调用方决定 shutdown 时机）。"""
    Handler.store = store
    Handler.blocklist = blocklist if blocklist is not None else store.matcher()
    Handler.resolver = resolver
    Handler.analyse_redirects = analyse_redirects
    Handler.access_log = access_log

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    actual = httpd.server_address[1]
    if quiet:
        return httpd
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print("=" * 62)
    print(f"护链 链接体检服务已启动  {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"  本机打开： http://{shown}:{actual}/")
    if host in ("0.0.0.0", "::"):
        print(f"  手机打开： http://{lan_ip()}:{actual}/   （要连同一个 WiFi）")
    print(f"  黑名单：   {len(Handler.blocklist) if Handler.blocklist is not None else 0} 个域名")
    print(f"  联网展开短链：{'开' if analyse_redirects else '关'}")
    print("  按 Ctrl+C 停止")
    print("=" * 62)
    return httpd
