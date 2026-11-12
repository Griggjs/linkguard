# -*- coding: utf-8 -*-
"""护链 LinkGuard —— 中老年人手机链接防护工具包。

分层设计（每一层的真实能力见 docs/04-能力边界.md）：

    analyzer  判定引擎：给网址打分，输出「拦截 / 警告 / 放行」+ 大白话理由
    resolver  短链与重定向链展开（唯一需要联网的判定环节，可关）
    sinkhole  本地 DNS 过滤服务：整台手机在 DNS 层被挡住，不依赖浏览器配合
    feeds     恶意域名名单的抓取、解析、合并
    store     SQLite：名单缓存 + 检测日志（子女可以回看老人点过什么）
    server    手机浏览器直接打开的大字版体检页面 + JSON API + 书签小工具
    cli       命令行入口
"""

from .analyzer import ALLOW, BLOCK, WARN, Report, Signal, analyze

__all__ = ["analyze", "Report", "Signal", "BLOCK", "WARN", "ALLOW"]
__version__ = "1.0.0"
