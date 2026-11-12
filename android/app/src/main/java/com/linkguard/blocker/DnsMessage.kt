package com.linkguard.blocker

/**
 * DNS 报文的解析与构造。只处理"问题段"，不碰资源记录。
 *
 * 为什么只做问题段：
 * - 判断一个域名要不要放行，只需要问题段的域名和类型；
 * - 拦截时由本地合成 NXDOMAIN，不需要解析上游应答；
 * - 放行时把上游应答原样回传，也不需要解析。
 *
 * 从而避免压缩指针与各类 RR 解析引发的问题。纯 JVM 代码，可单测。
 */
class DnsQuestion(
    val name: String,
    val qtype: Int,
    val qclass: Int,
    /** 问题段在原报文里的结束偏移（含 qtype/qclass）。 */
    val endOffset: Int
)

object DnsMessage {

    const val TYPE_A = 1
    const val TYPE_AAAA = 28

    const val RCODE_NOERROR = 0
    const val RCODE_SERVFAIL = 2
    const val RCODE_NXDOMAIN = 3

    private const val FLAG_QR = 0x8000
    private const val FLAG_AA = 0x0400
    private const val FLAG_RD = 0x0100
    private const val FLAG_RA = 0x0080

    /** 解析头部 + 第一个问题。有问题返回 null（调用方选择丢弃或原样转发）。 */
    fun parseQuestion(buf: ByteArray, length: Int = buf.size): DnsQuestion? {
        if (length < 12) return null
        val qdCount = ((buf[4].toInt() and 0xFF) shl 8) or (buf[5].toInt() and 0xFF)
        if (qdCount != 1) return null

        val labels = ArrayList<String>(8)
        var pos = 12
        while (true) {
            if (pos >= length) return null
            val len = buf[pos].toInt() and 0xFF
            if (len == 0) { pos += 1; break }
            // 问题段理论上不该出现压缩指针；遇到了就放弃解析，交给调用方丢包
            if (len and 0xC0 == 0xC0) return null
            if (len > 63) return null
            if (pos + 1 + len > length) return null
            labels.add(String(buf, pos + 1, len, Charsets.ISO_8859_1))
            pos += 1 + len
        }
        if (pos + 4 > length) return null
        val qtype = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
        val qclass = ((buf[pos + 2].toInt() and 0xFF) shl 8) or (buf[pos + 3].toInt() and 0xFF)
        return DnsQuestion(DomainName.normalize(labels.joinToString(".")), qtype, qclass, pos + 4)
    }

    /** 合成一个 NXDOMAIN 应答：域名不存在。这是白名单模式下的标准拒绝方式。 */
    fun buildNxdomain(query: ByteArray, q: DnsQuestion): ByteArray =
        buildReply(query, q, RCODE_NXDOMAIN, answer = null)

    /** 构造一个 DNS 查询报文（诊断/自测用）。 */
    fun buildQuery(name: String, qtype: Int = TYPE_A, qid: Int = 0x1234): ByteArray {
        val labels = name.split('.').filter { it.isNotEmpty() }
        val size = 12 + labels.sumOf { it.length + 1 } + 1 + 4
        val out = ByteArray(size)
        out[0] = ((qid shr 8) and 0xFF).toByte()
        out[1] = (qid and 0xFF).toByte()
        out[2] = 0x01                              // RD
        out[5] = 0x01                              // qdcount = 1
        var p = 12
        for (label in labels) {
            out[p] = label.length.toByte()
            val bytes = label.toByteArray(Charsets.ISO_8859_1)
            System.arraycopy(bytes, 0, out, p + 1, bytes.size)
            p += 1 + bytes.size
        }
        out[p] = 0                                 // 结束符
        p += 1
        putU16(out, p, qtype); p += 2
        putU16(out, p, 1)                          // class IN
        return out
    }

    /** 解析应答的 rcode（诊断用）。 */
    fun rcodeOf(resp: ByteArray): Int =
        if (resp.size < 4) -1 else resp[3].toInt() and 0x0F

    /** 解析应答里的 answer 条数（诊断用）。 */
    fun answerCountOf(resp: ByteArray): Int =
        if (resp.size < 8) -1
        else ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF)

    /** 合成一个 SERVFAIL 应答：上游查不到时用，客户端会当成解析失败。 */
    fun buildServfail(query: ByteArray, q: DnsQuestion): ByteArray =
        buildReply(query, q, RCODE_SERVFAIL, answer = null)

    /** 直接把查询变成 A=0.0.0.0 / AAAA=:: 的应答（备用模式，当前未启用）。 */
    fun buildZeroAddress(query: ByteArray, q: DnsQuestion, ttlSec: Int = 60): ByteArray {
        val rdata: ByteArray = when (q.qtype) {
            TYPE_A -> byteArrayOf(0, 0, 0, 0)
            TYPE_AAAA -> ByteArray(16)
            else -> return buildNxdomain(query, q)
        }
        return buildReply(query, q, RCODE_NOERROR, answerType = q.qtype, answer = rdata, ttl = ttlSec)
    }

    private fun buildReply(
        query: ByteArray,
        q: DnsQuestion,
        rcode: Int,
        answerType: Int = 0,
        answer: ByteArray? = null,
        ttl: Int = 60
    ): ByteArray {
        val questionLen = q.endOffset - 12
        val answerLen = if (answer != null) 12 + answer.size else 0
        val out = ByteArray(12 + questionLen + answerLen)

        out[0] = query[0]
        out[1] = query[1]

        val qFlags = ((query[2].toInt() and 0xFF) shl 8) or (query[3].toInt() and 0xFF)
        val rd = qFlags and FLAG_RD
        val flags = FLAG_QR or FLAG_AA or FLAG_RA or rd or (rcode and 0x0F)
        out[2] = ((flags shr 8) and 0xFF).toByte()
        out[3] = (flags and 0xFF).toByte()

        putU16(out, 4, 1)                                    // qdcount
        putU16(out, 6, if (answer != null) 1 else 0)          // ancount
        putU16(out, 8, 0)
        putU16(out, 10, 0)

        System.arraycopy(query, 12, out, 12, questionLen)

        if (answer != null) {
            var p = 12 + questionLen
            out[p] = 0xC0.toByte(); out[p + 1] = 0x0C          // 指向问题里的域名
            p += 2
            putU16(out, p, answerType); p += 2
            putU16(out, p, 1); p += 2                          // class IN
            putU32(out, p, ttl.toLong()); p += 4
            putU16(out, p, answer.size); p += 2
            System.arraycopy(answer, 0, out, p, answer.size)
        }
        return out
    }

    /**
     * 把应答裁到能塞进一个 UDP 包的大小。
     *
     * 为什么需要：上游完整应答可能有 2–3KB（多条 A 记录 + OPT），而隧道 MTU 只有 1500，
     * 整包写进 tun 会被内核以 EMSGSIZE 拒绝，客户端什么都收不到 —— 表现就是
     * "页面能开、图片和接口全加载不出来"。
     *
     * 做法：保留 question 和尽可能多的完整 A 记录，丢掉 authority/additional，
     * 并清除 TC 位（由服务端保证客户端用 UDP 即可拿到完整答案，无需改走 TCP）。
     */
    fun fitUdp(response: ByteArray, budget: Int = 1400): ByteArray {
        if (response.size <= budget || response.size < 12) return response

        val qd = u16(response, 4)
        val an = u16(response, 6)

        var pos = 12
        for (i in 0 until qd) pos = skipName(response, pos)
        pos += 4

        var keep = 0
        var p = pos
        while (keep < an) {
            val nameEnd = skipName(response, p)
            if (nameEnd + 10 > response.size) break
            val rdlen = u16(response, nameEnd + 8)
            val rrEnd = nameEnd + 10 + rdlen
            if (rrEnd > response.size) break
            if (rrEnd > budget) break            // 这一条放不下就到这儿
            keep++
            p = rrEnd
        }

        val out = response.copyOf(p)
        putU16(out, 6, keep)                     // ancount
        putU16(out, 8, 0)                        // nscount
        putU16(out, 10, 0)                       // arcount
        val flags = u16(out, 2) and 0xFFFFFDFF.toInt()   // 清 TC 位
        putU16(out, 2, flags)
        return out
    }

    /** 判断一个应答是否被上游截断（TC 位）。 */
    fun isTruncated(response: ByteArray): Boolean =
        response.size >= 4 && (u16(response, 2) and 0x0200) != 0


    private fun putU16(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v shr 8) and 0xFF).toByte()
        b[off + 1] = (v and 0xFF).toByte()
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    /** 跳过压缩指针，返回该名字结束后的偏移。 */
    private fun skipName(buf: ByteArray, start: Int): Int {
        var pos = start
        while (true) {
            if (pos >= buf.size) return buf.size
            val len = buf[pos].toInt() and 0xFF
            if (len == 0) return pos + 1
            if (len and 0xC0 == 0xC0) return pos + 2          // 指针后名字结束
            pos += 1 + len
        }
    }

    /**
     * 把查询里的 EDNS0 OPT 记录的 UDP 载荷上限改小。
     *
     * 为什么必须做：如果客户端声明能收 4096 字节，上游就真会回大包，
     * 而隧道 MTU 只有 1500，大包会被丢弃——客户端等不到应答，表现就是
     * "页面能打开但图片/视频加载失败"。钳到 1232 之后上游就不会超。
     *
     * 只改 2 个字节（OPT 的 class 字段），不影响其它部分；没有 EDNS 的查询原样返回。
     */
    fun clampEdnsUdpSize(query: ByteArray, max: Int = 1232): ByteArray {
        val out = query.copyOf()
        if (out.size < 12) return out
        val qd = u16(out, 4)
        val an = u16(out, 6)
        val ns = u16(out, 8)
        val ar = u16(out, 10)
        if (qd != 1 || ar == 0) return out

        var pos = 12
        for (i in 0 until qd) pos = skipName(out, pos)
        pos += 4                                             // qtype + qclass

        // 跳过 answer 和 authority（查询里一般没有，但格式上要处理）
        for (i in 0 until an + ns) {
            pos = skipName(out, pos)
            if (pos + 10 > out.size) return out
            pos += 10 + u16(out, pos + 8)
        }

        for (i in 0 until ar) {
            if (pos >= out.size) return out
            pos = skipName(out, pos)
            // 名字后还要 type(2)+class(2)+ttl(4)+rdlength(2) = 10 字节
            if (pos + 10 > out.size) return out
            val type = u16(out, pos)
            if (type == 41) {                                // OPT
                putU16(out, pos + 2, max)                    // class = UDP payload size
                return out
            }
            pos += 10 + u16(out, pos + 8)
        }
        return out
    }

    private fun putU32(b: ByteArray, off: Int, v: Long) {
        b[off] = ((v shr 24) and 0xFF).toByte()
        b[off + 1] = ((v shr 16) and 0xFF).toByte()
        b[off + 2] = ((v shr 8) and 0xFF).toByte()
        b[off + 3] = (v and 0xFF).toByte()
    }
}
