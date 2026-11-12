# -*- coding: utf-8 -*-
"""命令行入口。

    python -m linkguard check <链接>          查一个链接
    python -m linkguard serve                 开网页版（手机用这个）
    python -m linkguard dns                   开 DNS 过滤（整台手机被保护）
    python -m linkguard feeds --update        更新恶意名单
    python -m linkguard feeds --add-file x.txt 导入自己的名单
    python -m linkguard export --format hosts 导出成 hosts / dnsmasq / AdGuard
    python -m linkguard log                   看检测记录
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

from . import __version__, feeds, server, sinkhole
from .analyzer import ALLOW, BLOCK, WARN, analyze
from .matcher import DomainMatcher
from .resolver import RedirectTracer, extract_urls
from .store import Store

DEFAULT_DB = os.path.join("data", "linkguard.db")
VERDICT_CN = {BLOCK: "危险，别点", WARN: "可疑，要小心", ALLOW: "看着正常"}


# ---------------------------------------------------------------------------
def _open_store(args) -> Store:
    return Store(getattr(args, "db", DEFAULT_DB) or DEFAULT_DB)


def _print_report(report, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return
    print()
    print(f"  结论：{VERDICT_CN.get(report.verdict, report.verdict)}   （风险分 {report.score}）")
    print(f"  {report.elderly}")
    print()
    print(f"  链接：{report.url}")
    print(f"  网站：{report.registrable or report.host or '（无）'}")
    print(f"  类型：{report.category}")
    if report.chain:
        print("  跳转：")
        for i, hop in enumerate(report.chain):
            print(f"        {i}. {hop}")
    print()
    print("  判定依据：")
    shown = 0
    for s in sorted(report.signals, key=lambda x: -x.weight):
        if s.weight == 0:
            continue
        flag = "硬拦" if s.hard else "可疑"
        print(f"   [{flag}] {s.weight:>4} 分  {s.code:<20} {s.detail}")
        shown += 1
    if not shown:
        print("        （无异常特征）")
    print()
    print("  该怎么做：")
    for i, tip in enumerate(report.advice, 1):
        print(f"    {i}. {tip}")
    print()


# ---------------------------------------------------------------------------
def cmd_check(args) -> int:
    url = args.url
    if not url and args.from_text:
        found = extract_urls(args.from_text)
        if not found:
            print("这段文字里没有找到网址。", file=sys.stderr)
            return 2
        url = found[0]
        print(f"从文字里提取到：{url}")
    if not url:
        print("请给出要检查的链接。", file=sys.stderr)
        return 2

    store = _open_store(args)
    try:
        matcher = store.matcher() if store.domain_count() else DomainMatcher()
        tracer = RedirectTracer(allow_private=args.allow_private) if args.resolve else None
        report = analyze(
            url,
            blocklist=matcher,
            resolver=tracer,
            analyse_redirects=args.resolve,
        )
        store.log_check(report, "cli")
        _print_report(report, args.json)
        # 有危险就返回非零，方便别的脚本据此做动作
        return 0 if report.verdict == ALLOW else 1
    finally:
        store.close()


def cmd_serve(args) -> int:
    store = _open_store(args)
    tracer = RedirectTracer(allow_private=args.allow_private)
    httpd = server.run(
        store,
        host=args.host,
        port=args.port,
        resolver=tracer,
        analyse_redirects=args.resolve,
        access_log=args.verbose,
    )
    try:
        httpd.serve_forever(poll_interval=0.4)
    except KeyboardInterrupt:
        print("\n正在停止……")
    finally:
        httpd.shutdown()
        httpd.server_close()
        store.close()
    return 0


def cmd_dns(args) -> int:
    store = _open_store(args)
    matcher = store.matcher()
    print(f"已加载黑名单 {len(matcher)} 个域名")

    def on_query(client: str, qname: str, blocked: bool, matched: str) -> None:
        if blocked:
            print(f"  [拦截] {client:<15} {qname}  ← {matched}", flush=True)
        elif args.log_all:
            print(f"  [放行] {client:<15} {qname}", flush=True)
        if blocked or args.log_all:
            try:
                store.log_dns(client, qname, blocked, matched)
            except Exception:  # noqa: BLE001
                pass

    upstreams = tuple(args.upstream) if args.upstream else sinkhole.DEFAULT_UPSTREAMS
    srv = sinkhole.DNSSinkhole(
        matcher,
        upstreams=upstreams,
        host=args.host,
        port=args.port,
        block_mode=args.mode,
        on_query=on_query,
        timeout=args.timeout,
    )
    srv.start()
    print("=" * 62)
    print(f"DNS 过滤服务已启动  监听 {args.host}:{srv.port}  模式={args.mode}")
    print(f"  上游 DNS： {'，'.join(upstreams)}")
    print(f"  把手机/路由器的 DNS 改成这台机器的地址：{server.lan_ip()}")
    print("  按 Ctrl+C 停止")
    print("=" * 62, flush=True)
    try:
        while True:
            import time

            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n正在停止……")
    finally:
        srv.stop()
        print("统计：", json.dumps(srv.stats, ensure_ascii=False))
        store.close()
    return 0


def cmd_feeds(args) -> int:
    store = _open_store(args)
    try:
        if args.list:
            rows = store.sources()
            if not rows:
                print("名单为空。先运行：python -m linkguard feeds --update")
            for r in rows:
                print(f"  {r['count']:>8}  {r['source'] or '(未标注来源)'}")
            print(f"  {store.domain_count():>8}  合计")
            return 0

        if args.add_domain:
            n = store.add_domains(args.add_domain, "manual")
            print(f"新增 {n} 个域名（来源 manual）")
            return 0

        if args.add_file:
            text = open(args.add_file, encoding="utf-8", errors="replace").read()
            domains = feeds.parse(text, args.kind)
            name = args.source_name or os.path.basename(args.add_file)
            added, removed = store.replace_source(name, domains)
            print(f"从 {args.add_file} 解析出 {len(domains)} 个域名，新增 {added}，移除 {removed}")
            return 0

        if args.update or not (args.list or args.add_file or args.add_domain):
            sources = list(feeds.DEFAULT_SOURCES)
            for spec in args.source or []:
                try:
                    sources.append(feeds.parse_source_spec(spec))
                except ValueError as exc:
                    print(f"源参数有误：{exc}", file=sys.stderr)
                    return 2
            print(f"开始更新 {len(sources)} 个名单源……")
            results = feeds.update_all(store, sources)
            for r in results:
                print("  " + str(r))
            print(f"名单总量：{store.domain_count()} 个域名")

            # 更新后立即体检：名单由第三方维护，误拦正规站是常见问题
            conflicts = _audit_conflicts(store)
            if conflicts:
                print()
                print(f"注意：有 {len(conflicts)} 个正规站点被新名单误拦了：")
                for domain, hit in conflicts[:10]:
                    tail = "" if hit == domain else f"（被上级域 {hit} 连带）"
                    print(f"  - {domain}{tail}")
                if len(conflicts) > 10:
                    print(f"  ……还有 {len(conflicts) - 10} 个")
                print("执行 `linkguard audit --fix` 移除，否则这些网站会打不开。")
            return 0 if any(r.ok for r in results) else 1
    finally:
        store.close()
    return 0


EXPORTERS = {
    "hosts": lambda d: f"0.0.0.0 {d}",
    "dnsmasq": lambda d: f"address=/{d}/0.0.0.0",
    "adguard": lambda d: f"||{d}^",
    "plain": lambda d: d,
}


def cmd_export(args) -> int:
    store = _open_store(args)
    try:
        fmt = args.format
        if fmt not in EXPORTERS:
            print(f"未知格式 {fmt!r}，可选：{', '.join(EXPORTERS)}", file=sys.stderr)
            return 2
        fn = EXPORTERS[fmt]
        count = 0
        lines = []
        if args.source:
            domains = list(store.iter_domains(args.source))
        else:
            domains = list(store.iter_domains())
        header = [
            f"# 护链 LinkGuard 导出 {datetime.now():%Y-%m-%d %H:%M:%S}",
            f"# 格式：{fmt}   条目：{len(domains)}",
            "# 用途：路由器 / Pi-hole / AdGuard Home / 安卓 hosts（需 root）",
        ]
        for d in domains:
            lines.append(fn(d))
            count += 1
        text = "\n".join(header + lines) + "\n"
        if args.out:
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            print(f"已写入 {args.out}（{count} 条）")
        else:
            sys.stdout.write(text)
        return 0
    finally:
        store.close()


def cmd_log(args) -> int:
    store = _open_store(args)
    try:
        if args.dns:
            rows = store.recent_dns(args.limit, only_blocked=args.blocked)
            if not rows:
                print("没有 DNS 记录。")
            for r in rows:
                mark = "拦截" if r["blocked"] else "放行"
                print(f"  {r['ts'][:19]}  {mark}  {r['client']:<15} {r['qname']}"
                      + (f"  ← {r['matched']}" if r["matched"] else ""))
            return 0
        rows = store.recent_checks(args.limit, verdict=args.verdict or None)
        if not rows:
            print("还没有检测记录。")
        for r in rows:
            print(f"  {r['ts'][:19]}  {VERDICT_CN.get(r['verdict'], r['verdict']):<8} "
                  f"{r['score']:>4}  {r['category']:<8} {r['url'][:90]}")
            if args.verbose:
                print(f"        {r['elderly']}")
        return 0
    finally:
        store.close()


def cmd_stats(args) -> int:
    store = _open_store(args)
    try:
        print(json.dumps(store.stats(), ensure_ascii=False, indent=2))
        return 0
    finally:
        store.close()


def _audit_conflicts(store) -> list[tuple[str, str]]:
    """返回 [(正规站点, 命中的黑名单条目), ...]。"""
    from . import rules

    matcher = store.matcher()
    out = []
    for domain in sorted(rules.ALLOWLIST_DOMAINS):
        hit = matcher.match(domain)
        if hit:
            out.append((domain, hit))
    return out


def cmd_audit(args) -> int:
    """名单体检：确认没有把正规站点误加进黑名单。

    为什么要这个命令：名单是别人维护的，出错的方式五花八门。
    真踩过的坑——hosts 文件某行的行内注释里有一个 github.com 的链接，
    结果 github.com 被当成恶意域名拦掉了。这种错误不会报错，只会让全家上不了网。
    """
    from . import rules

    store = _open_store(args)
    try:
        matcher = store.matcher()
        total = len(matcher)
        print(f"名单总量：{total} 个域名")
        if total == 0:
            print("名单是空的。先跑：python -m linkguard feeds --update")
            return 0

        conflicts = _audit_conflicts(store)

        if not conflicts:
            print(f"体检通过：{len(rules.ALLOWLIST_DOMAINS)} 个正规站点没有一条被误拦。")
            return 0

        print()
        print(f"发现问题：{len(conflicts)} 个正规站点被黑名单拦住了")
        origins = {(r["domain"], r["source"]) for r in
                   store.lookup({hit for _, hit in conflicts})}
        source_of = {d: s for d, s in origins}
        for domain, hit in conflicts:
            extra = f"（来自 {source_of[hit]}）" if hit in source_of else ""
            if hit == domain:
                print(f"  - {domain}{extra}")
            else:
                print(f"  - {domain}  ← 被上级域 {hit} 连带拦截{extra}")

        if not args.fix:
            print()
            print("这会让你打不开这些网站。执行 `linkguard audit --fix` 把它们从黑名单里删掉。")
            return 1

        removed = 0
        for _, hit in conflicts:
            if store.remove_domain(hit):
                removed += 1
                print(f"  已从黑名单移除：{hit}")
        print(f"共移除 {removed} 条。再次体检：linkguard audit")
        return 0
    finally:
        store.close()


def cmd_selftest(args) -> int:
    """一键自检：不联网的前提下，把关键链路都跑一遍。

    部署完先跑这个。它回答的是「我装对了吗」，不是「我的名单全不全」。
    """
    import socket
    import tempfile

    from .matcher import DomainMatcher as _DM

    passed = 0
    failed = 0

    def check(name, fn):
        nonlocal passed, failed
        try:
            detail = fn()
            print(f"  [通过] {name}" + (f"  {detail}" if detail else ""))
            passed += 1
        except Exception as exc:  # noqa: BLE001 - 自检要把所有问题都报出来
            print(f"  [失败] {name}  {exc}")
            failed += 1

    print("护链自检")
    print("=" * 62)

    def _py():
        if sys.version_info < (3, 9):
            raise RuntimeError(f"需要 Python 3.9+，当前 {sys.version.split()[0]}")
        return sys.version.split()[0]

    check("Python 版本", _py)

    def _store():
        tmp = os.path.join(tempfile.gettempdir(), f"linkguard-selftest-{os.getpid()}.db")
        st = Store(tmp)
        st.add_domains(["selftest-blocked.example"], "selftest")
        if st.matcher().match("a.selftest-blocked.example") != "selftest-blocked.example":
            raise RuntimeError("名单匹配不正常")
        st.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp + suffix)
            except OSError:
                pass
        return "数据库读写与名单匹配正常"

    check("数据库与名单", _store)

    def _engine():
        cases = [
            ("http://icbc-login.top/verify?card=1", BLOCK),
            ("http://x.top/a.apk", BLOCK),
            ("http://www.icbc.com.cn@evil.top/", BLOCK),
            ("javascript:alert(1)", BLOCK),
            ("https://www.icbc.com.cn/", ALLOW),
            ("https://www.gov.cn/", ALLOW),
            ("https://weixin.qq.com/", ALLOW),
        ]
        bad = []
        for url, want in cases:
            got = analyze(url).verdict
            if got != want:
                bad.append(f"{url} 期望 {want} 实际 {got}")
        if bad:
            raise RuntimeError("；".join(bad))
        return f"{len(cases)} 个样本判定正确"

    check("判定引擎", _engine)

    def _dns():
        matcher = _DM({"selftest-blocked.example"})
        srv = sinkhole.DNSSinkhole(
            matcher, host="127.0.0.1", port=0, timeout=0.5, cache_ttl=5,
        )
        srv.start()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            try:
                sock.sendto(sinkhole.build_query("selftest-blocked.example"),
                            ("127.0.0.1", srv.port))
                resp, _ = sock.recvfrom(4096)
            finally:
                sock.close()
            if sinkhole.rcode_of(resp) != 0:
                raise RuntimeError(f"应答 rcode={sinkhole.rcode_of(resp)}")
            if sinkhole.answer_count(resp) != 1:
                raise RuntimeError(f"应答条数={sinkhole.answer_count(resp)}")
            if resp[-4:] != b"\x00\x00\x00\x00":
                raise RuntimeError("拦截应答不是 0.0.0.0")
            return f"UDP 监听与拦截正常（测试端口 {srv.port}）"
        finally:
            srv.stop()

    check("DNS 过滤（离线）", _dns)

    def _upstream():
        upstreams = tuple(args.upstream) if args.upstream else sinkhole.DEFAULT_UPSTREAMS
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            for up in upstreams:
                try:
                    sock.sendto(sinkhole.build_query("www.baidu.com"), (up, 53))
                    resp, _ = sock.recvfrom(4096)
                    if sinkhole.rcode_of(resp) == 0:
                        return f"{up} 可用"
                except (socket.timeout, OSError):
                    continue
        finally:
            sock.close()
        raise RuntimeError("所有上游 DNS 都没有应答——请检查这台电脑能不能上网")

    check("上游 DNS 连通性（需要联网）", _upstream)

    print("=" * 62)
    print(f"通过 {passed} 项，失败 {failed} 项")
    if failed:
        print("有失败项。先解决上面标 [失败] 的那几条，再部署。")
        return 1
    print("自检全部通过。下一步：")
    print("  1) 跑  .\\scripts\\run.ps1 dns     然后把手机/路由器的 DNS 指到本机")
    print("  2) 跑  .\\scripts\\run.ps1 serve   手机浏览器打开打印出来的地址")
    return 0


# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linkguard",
        description="护链：识别并阻断手机上来源不明的链接",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version", version=f"linkguard {__version__}")
    p.add_argument("--db", default=DEFAULT_DB, help=f"数据库路径（默认 {DEFAULT_DB}）")
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("check", help="检查一个链接")
    c.add_argument("url", nargs="?", default="", help="要检查的链接")
    c.add_argument("--from-text", default="", help="从一段聊天文字里自动提取链接")
    c.add_argument("--json", action="store_true", help="输出 JSON")
    c.add_argument("--resolve", action="store_true", help="联网展开短链和跳转（唯一需要联网的步骤）")
    c.add_argument("--allow-private", action="store_true", help="允许访问内网地址（仅调试用）")
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("serve", help="启动手机可访问的网页版")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8088)
    s.add_argument("--resolve", action="store_true", help="联网展开短链")
    s.add_argument("--allow-private", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true", help="打印每个请求")
    s.set_defaults(func=cmd_serve)

    d = sub.add_parser("dns", help="启动本地 DNS 过滤（真正的全局阻断）")
    d.add_argument("--host", default="0.0.0.0")
    d.add_argument("--port", type=int, default=53)
    d.add_argument("--upstream", action="append", help="上游 DNS，可重复指定")
    d.add_argument("--mode", choices=["zero", "nxdomain"], default="zero",
                   help="拦截方式：返回 0.0.0.0 或 域名不存在")
    d.add_argument("--timeout", type=float, default=3.0)
    d.add_argument("--log-all", action="store_true", help="把所有查询都写日志（默认只记拦截）")
    d.set_defaults(func=cmd_dns)

    f = sub.add_parser("feeds", help="管理恶意域名名单")
    f.add_argument("--update", action="store_true", help="从内置源更新")
    f.add_argument("--source", action="append", help="额外源，name=url[#kind]")
    f.add_argument("--add-file", default="", help="从本地文件导入")
    f.add_argument("--kind", default="auto",
                   choices=sorted(feeds.PARSERS), help="导入文件的格式")
    f.add_argument("--source-name", default="", help="导入时记录的来源名")
    f.add_argument("--add-domain", action="append", help="手工加一个域名")
    f.add_argument("--list", action="store_true", help="按来源列出统计")
    f.set_defaults(func=cmd_feeds)

    e = sub.add_parser("export", help="导出名单为 hosts / dnsmasq / AdGuard 格式")
    e.add_argument("--format", default="hosts", choices=sorted(EXPORTERS))
    e.add_argument("--out", default="", help="输出文件，不写则打到标准输出")
    e.add_argument("--source", default="", help="只导出某个来源")
    e.set_defaults(func=cmd_export)

    g = sub.add_parser("log", help="查看检测记录")
    g.add_argument("--limit", type=int, default=30)
    g.add_argument("--verdict", default="", choices=["", BLOCK, WARN, ALLOW])
    g.add_argument("--dns", action="store_true", help="看 DNS 查询日志")
    g.add_argument("--blocked", action="store_true", help="配合 --dns，只看被拦截的")
    g.add_argument("-v", "--verbose", action="store_true")
    g.set_defaults(func=cmd_log)

    st = sub.add_parser("stats", help="统计信息")
    st.set_defaults(func=cmd_stats)

    sf = sub.add_parser("selftest", help="一键自检，部署完先跑这个")
    sf.add_argument("--upstream", action="append", help="指定要测试的上游 DNS")
    sf.set_defaults(func=cmd_selftest)

    au = sub.add_parser("audit", help="名单体检：确认没有误拦正规站点")
    au.add_argument("--fix", action="store_true", help="把误拦的条目从黑名单删掉")
    au.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中断。")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
