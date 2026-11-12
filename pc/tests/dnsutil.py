# -*- coding: utf-8 -*-
"""测试用的 DNS 报文小工具（只为测试服务，产品代码里不需要）。"""

from __future__ import annotations

import struct

TYPE_A = 1
TYPE_AAAA = 28


def build_query(name: str, qtype: int = TYPE_A, qid: int = 0x1234) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    qname = b""
    for label in name.split("."):
        if not label:
            continue
        qname += bytes([len(label)]) + label.encode("latin-1")
    qname += b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def flags_of(resp: bytes) -> int:
    return struct.unpack_from("!H", resp, 2)[0]


def rcode_of(resp: bytes) -> int:
    return flags_of(resp) & 0x000F


def answers(resp: bytes) -> int:
    return struct.unpack_from("!H", resp, 6)[0]


def _skip_question(resp: bytes) -> int:
    pos = 12
    while resp[pos] != 0:
        pos += 1 + resp[pos]
    return pos + 1 + 4  # 结束符 + qtype + qclass


def answer_rdata(resp: bytes) -> bytes:
    """取第一条应答记录的 rdata。只适用于我们自己合成的应答。"""
    pos = _skip_question(resp)
    if resp[pos] & 0xC0 == 0xC0:
        pos += 2
    else:  # pragma: no cover - 合成应答永远是压缩指针
        while resp[pos] != 0:
            pos += 1 + resp[pos]
        pos += 1
    rdlength = struct.unpack_from("!H", resp, pos + 8)[0]
    return resp[pos + 10:pos + 10 + rdlength]
