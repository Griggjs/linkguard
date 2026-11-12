# -*- coding: utf-8 -*-
"""SQLite 存储：恶意名单 + 检测日志。

为什么要有日志
--------------
老人被骗之后，子女最想知道的是"他到底点过什么、连过哪些域名"。
所以每次体检、每次 DNS 查询都落库，可以回看。这是事后止损的关键证据。

只用标准库 sqlite3，多线程安全（服务端是多线程的，这里加锁复用一条连接）。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Iterable, Iterator

from .matcher import DomainMatcher, normalize_host

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    domain    TEXT PRIMARY KEY,
    source    TEXT NOT NULL DEFAULT '',
    added_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domains_source ON domains(source);

CREATE TABLE IF NOT EXISTS checks (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    client    TEXT NOT NULL DEFAULT '',
    url       TEXT NOT NULL,
    host      TEXT NOT NULL DEFAULT '',
    verdict   TEXT NOT NULL,
    score     INTEGER NOT NULL DEFAULT 0,
    category  TEXT NOT NULL DEFAULT '',
    elderly   TEXT NOT NULL DEFAULT '',
    detail    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts DESC);
CREATE INDEX IF NOT EXISTS idx_checks_verdict ON checks(verdict);

CREATE TABLE IF NOT EXISTS dns_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    client    TEXT NOT NULL DEFAULT '',
    qname     TEXT NOT NULL,
    blocked   INTEGER NOT NULL DEFAULT 0,
    matched   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_blocked ON dns_log(blocked);

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=15)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.commit()
        self._matcher: DomainMatcher | None = None

    # -- 名单 -------------------------------------------------------------
    def add_domains(self, domains: Iterable[str], source: str = "") -> int:
        rows = []
        for d in domains:
            nd = normalize_host(d)
            if nd and "." in nd:
                rows.append((nd, source, _now()))
        if not rows:
            return 0
        added = 0
        with self._lock:
            before = self._conn.total_changes
            self._conn.executemany(
                "INSERT OR IGNORE INTO domains(domain, source, added_at) VALUES(?,?,?)",
                rows,
            )
            added = self._conn.total_changes - before
            self._conn.commit()
        if added:
            self._matcher = None
        return added

    def replace_source(self, source: str, domains: Iterable[str]) -> tuple[int, int]:
        """整源替换：先删该源旧数据再写入，避免名单越滚越大。返回(新增, 删除)。"""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM domains WHERE source=?", (source,)
            )
            removed = cur.rowcount
            self._conn.commit()
        self._matcher = None
        added = self.add_domains(domains, source)
        return added, removed

    def remove_domain(self, domain: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM domains WHERE domain=?", (normalize_host(domain),)
            )
            self._conn.commit()
        if cur.rowcount:
            self._matcher = None
        return bool(cur.rowcount)

    def matcher(self) -> DomainMatcher:
        """返回黑名单匹配器（进程内缓存，名单变动后自动重建）。"""
        if self._matcher is None:
            with self._lock:
                rows = self._conn.execute("SELECT domain FROM domains").fetchall()
            self._matcher = DomainMatcher(r[0] for r in rows)
        return self._matcher

    def domain_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]

    def sources(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT source, COUNT(*) AS n FROM domains GROUP BY source ORDER BY n DESC"
            ).fetchall()
        return [{"source": r["source"], "count": r["n"]} for r in rows]

    def iter_domains(self, source: str | None = None) -> Iterator[str]:
        sql = "SELECT domain FROM domains"
        args: tuple = ()
        if source is not None:
            sql += " WHERE source=?"
            args = (source,)
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY domain", args).fetchall()
        for r in rows:
            yield r[0]

    def lookup(self, domains: Iterable[str]) -> list[dict]:
        """按域名查它是从哪个源进来的（用于排查误拦）。"""
        names = [normalize_host(d) for d in domains]
        if not names:
            return []
        marks = ",".join("?" * len(names))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT domain, source, added_at FROM domains WHERE domain IN ({marks})",
                names,
            ).fetchall()
        return [dict(r) for r in rows]

    # -- 检测日志 ---------------------------------------------------------
    def log_check(self, report, client: str = "") -> int:
        """把一次 analyzer.Report 记下来。"""
        data = report.to_dict() if hasattr(report, "to_dict") else dict(report)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO checks(ts, client, url, host, verdict, score, category, elderly, detail)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    _now(), client, data.get("url", ""), data.get("host", ""),
                    data.get("verdict", ""), int(data.get("score", 0)),
                    data.get("category", ""), data.get("elderly", ""),
                    json.dumps(data.get("signals", []), ensure_ascii=False),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def recent_checks(self, limit: int = 50, verdict: str | None = None) -> list[dict]:
        sql = "SELECT * FROM checks"
        args: list = []
        if verdict:
            sql += " WHERE verdict=?"
            args.append(verdict)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["signals"] = json.loads(d.pop("detail") or "[]")
            except json.JSONDecodeError:
                d["signals"] = []
            out.append(d)
        return out

    # -- DNS 日志 ---------------------------------------------------------
    def log_dns(self, client: str, qname: str, blocked: bool, matched: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO dns_log(ts, client, qname, blocked, matched) VALUES(?,?,?,?,?)",
                (_now(), client, qname, 1 if blocked else 0, matched),
            )
            self._conn.commit()

    def recent_dns(self, limit: int = 100, only_blocked: bool = False) -> list[dict]:
        sql = "SELECT * FROM dns_log"
        if only_blocked:
            sql += " WHERE blocked=1"
        sql += " ORDER BY id DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, (int(limit),)).fetchall()
        return [dict(r) for r in rows]

    # -- 统计 -------------------------------------------------------------
    def stats(self) -> dict:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
            by_verdict = {
                r[0]: r[1]
                for r in self._conn.execute(
                    "SELECT verdict, COUNT(*) FROM checks GROUP BY verdict"
                ).fetchall()
            }
            dns_total = self._conn.execute("SELECT COUNT(*) FROM dns_log").fetchone()[0]
            dns_blocked = self._conn.execute(
                "SELECT COUNT(*) FROM dns_log WHERE blocked=1"
            ).fetchone()[0]
        return {
            "domains": self.domain_count(),
            "checks": total,
            "by_verdict": by_verdict,
            "dns_queries": dns_total,
            "dns_blocked": dns_blocked,
            "db": self.path,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
