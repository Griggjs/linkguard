package com.linkguard.blocker

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsMessageTest {

    // ------------------------------------------------------------ 基本解析

    @Test
    fun parsesQuestion() {
        val raw = DnsTestUtil.query("a.b.evil.top")
        val q = DnsMessage.parseQuestion(raw)
        assertNotNull(q)
        assertEquals("a.b.evil.top", q!!.name)
        assertEquals(DnsMessage.TYPE_A, q.qtype)
        assertEquals(1, q.qclass)
        assertEquals(raw.size, q.endOffset)
    }

    @Test
    fun rejectsTooShort() {
        assertNull(DnsMessage.parseQuestion(ByteArray(8)))
    }

    @Test
    fun rejectsMultipleQuestions() {
        val raw = DnsTestUtil.query("a.com")
        raw[4] = 0; raw[5] = 2
        assertNull(DnsMessage.parseQuestion(raw))
    }

    @Test
    fun rejectsTruncatedName() {
        val raw = DnsTestUtil.query("a-very-long-label.example.com")
        assertNull(DnsMessage.parseQuestion(raw, raw.size - 10))
    }

    @Test
    fun nameIsLowercased() {
        val raw = DnsTestUtil.query("Evil.EXAMPLE.com")
        val q = DnsMessage.parseQuestion(raw)!!
        assertEquals("evil.example.com", q.name)
    }

    // ------------------------------------------------------------ 合成应答

    @Test
    fun nxdomainKeepsIdAndQuestion() {
        val raw = DnsTestUtil.query("blocked.example", qid = 0xBEEF)
        val q = DnsMessage.parseQuestion(raw)!!
        val resp = DnsMessage.buildNxdomain(raw, q)

        assertEquals(0xBEEF, DnsTestUtil.id(resp))
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsTestUtil.rcode(resp))
        assertEquals(0, DnsTestUtil.answerCount(resp))
        assertArrayEquals(DnsTestUtil.questionBytes(raw, q), DnsTestUtil.questionBytes(resp, q))
    }

    @Test
    fun nxdomainSetsQrBit() {
        val raw = DnsTestUtil.query("x.example")
        val q = DnsMessage.parseQuestion(raw)!!
        val resp = DnsMessage.buildNxdomain(raw, q)
        assertTrue((resp[2].toInt() and 0x80) != 0)
    }

    @Test
    fun zeroAddressForA() {
        val raw = DnsTestUtil.query("blocked.example")
        val q = DnsMessage.parseQuestion(raw)!!
        val resp = DnsMessage.buildZeroAddress(raw, q)
        assertEquals(DnsMessage.RCODE_NOERROR, DnsTestUtil.rcode(resp))
        assertEquals(1, DnsTestUtil.answerCount(resp))
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), resp.copyOfRange(resp.size - 4, resp.size))
    }

    @Test
    fun zeroAddressForAaaaIsAllZero() {
        val raw = DnsTestUtil.query("blocked.example", qtype = DnsMessage.TYPE_AAAA)
        val q = DnsMessage.parseQuestion(raw)!!
        val resp = DnsMessage.buildZeroAddress(raw, q)
        assertEquals(1, DnsTestUtil.answerCount(resp))
        assertArrayEquals(ByteArray(16), resp.copyOfRange(resp.size - 16, resp.size))
    }

    @Test
    fun zeroAddressFallsBackToNxdomainForOtherTypes() {
        val raw = DnsTestUtil.query("blocked.example", qtype = 16)
        val q = DnsMessage.parseQuestion(raw)!!
        val resp = DnsMessage.buildZeroAddress(raw, q)
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsTestUtil.rcode(resp))
    }

    @Test
    fun servfailRcode() {
        val raw = DnsTestUtil.query("x.example")
        val q = DnsMessage.parseQuestion(raw)!!
        val resp = DnsMessage.buildServfail(raw, q)
        assertEquals(DnsMessage.RCODE_SERVFAIL, DnsTestUtil.rcode(resp))
        assertEquals(0, DnsTestUtil.answerCount(resp))
    }

    @Test
    fun buildQueryAndReplyHelpers() {
        val q = DnsMessage.buildQuery("www.baidu.com", qid = 0x5151)
        assertEquals(0x5151, DnsTestUtil.id(q))
        val parsed = DnsMessage.parseQuestion(q)
        assertNotNull(parsed)
        assertEquals("www.baidu.com", parsed!!.name)
        assertEquals(q.size, parsed.endOffset)

        val nx = DnsMessage.buildNxdomain(q, parsed)
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsMessage.rcodeOf(nx))
        assertEquals(0, DnsMessage.answerCountOf(nx))

        val zero = DnsMessage.buildZeroAddress(q, parsed)
        assertEquals(DnsMessage.RCODE_NOERROR, DnsMessage.rcodeOf(zero))
        assertEquals(1, DnsMessage.answerCountOf(zero))
    }

    // ------------------------------------------------------------ 测试辅助

    /** 手工拼一个带 EDNS0 OPT 的查询。 */
    private fun queryWithEdns(size: Int, qid: Int = 0x7777): ByteArray {
        val q = DnsMessage.buildQuery("img.example.com", qid = qid)
        val opt = ByteArray(11)
        opt[0] = 0                                    // 名字 = 根（1 字节）
        opt[1] = 0; opt[2] = 41                       // type = OPT（2 字节）
        opt[3] = ((size shr 8) and 0xFF).toByte()      // class = UDP payload size（2 字节）
        opt[4] = (size and 0xFF).toByte()
        val out = ByteArray(q.size + opt.size)
        System.arraycopy(q, 0, out, 0, q.size)
        System.arraycopy(opt, 0, out, q.size, opt.size)
        out[10] = 0x01                                // arcount = 1
        return out
    }

    /** 拼一个带 count 条 A 记录的应答。每条 16 字节。 */
    private fun multiAnswerResponse(
        name: String,
        count: Int,
        tc: Boolean = false,
        ttl: Int = 60
    ): ByteArray {
        val q = DnsMessage.buildQuery(name, qid = 0x1234)
        val question = q.copyOfRange(12, q.size)
        val out = ByteArray(12 + question.size + count * 16)
        out[0] = 0x12; out[1] = 0x34
        out[2] = (if (tc) 0x83 else 0x81).toByte()     // QR + RD (+TC)；TC 在第一个 flags 字节
        out[3] = 0x80.toByte()                         // RA
        out[5] = 0x01                                  // qdcount = 1
        out[7] = count.toByte()                        // ancount
        System.arraycopy(question, 0, out, 12, question.size)
        var p = 12 + question.size
        repeat(count) {
            out[p] = 0xC0.toByte(); out[p + 1] = 0x0C  // 名字指针
            out[p + 2] = 0; out[p + 3] = 1             // type A
            out[p + 4] = 0; out[p + 5] = 1             // class IN
            out[p + 6] = ((ttl shr 24) and 0xFF).toByte()
            out[p + 7] = ((ttl shr 16) and 0xFF).toByte()
            out[p + 8] = ((ttl shr 8) and 0xFF).toByte()
            out[p + 9] = (ttl and 0xFF).toByte()
            out[p + 10] = 0; out[p + 11] = 4           // rdlength = 4
            out[p + 12] = 1; out[p + 13] = 2; out[p + 14] = 3; out[p + 15] = 4
            p += 16
        }
        return out
    }

    // ------------------------------------------------------------ EDNS 钳制

    @Test
    fun clampEdnsShrinksPayloadSize() {
        val raw = queryWithEdns(4096)
        val clamped = DnsMessage.clampEdnsUdpSize(raw)
        val pos = raw.size - 8
        val newSize = ((clamped[pos].toInt() and 0xFF) shl 8) or (clamped[pos + 1].toInt() and 0xFF)
        assertEquals(1232, newSize)
        var diff = 0
        for (i in clamped.indices) if (clamped[i] != raw[i]) diff++
        assertEquals(2, diff)
    }

    @Test
    fun clampEdnsLeavesNonEdnsQueriesAlone() {
        val raw = DnsTestUtil.query("img.example.com")
        assertArrayEquals(raw, DnsMessage.clampEdnsUdpSize(raw))
    }

    @Test
    fun clampEdnsKeepsIdAndQuestion() {
        val raw = queryWithEdns(4096, qid = 0x4242)
        val clamped = DnsMessage.clampEdnsUdpSize(raw)
        assertEquals(0x4242, DnsTestUtil.id(clamped))
        // 问题段长度 = "img.example.com"(13 字符 + 3 长度字节 + 1 零 = 17) + 4
        assertArrayEquals(
            raw.copyOfRange(12, 12 + 17 + 4),
            clamped.copyOfRange(12, 12 + 17 + 4)
        )
    }

    // ------------------------------------------------------------ 应答裁剪

    @Test
    fun fitUdpDropsExtraAnswersToFitMtu() {
        val resp = multiAnswerResponse("img.example.com", 120)
        assertTrue(resp.size > 1400)

        val fitted = DnsMessage.fitUdp(resp, 1400)
        assertTrue(fitted.size <= 1400)

        val an = DnsMessage.answerCountOf(fitted)
        assertTrue("保留条数应在 1..119，实际 $an", an in 1..119)
        val questionSize = DnsMessage.buildQuery("img.example.com").size
        assertEquals(questionSize + an * 16, fitted.size)
        assertFalse(DnsMessage.isTruncated(fitted))
    }

    @Test
    fun fitUdpLeavesSmallResponsesAlone() {
        val resp = multiAnswerResponse("img.example.com", 2)
        assertArrayEquals(resp, DnsMessage.fitUdp(resp, 1400))
    }

    @Test
    fun detectsTruncatedFlag() {
        assertTrue(DnsMessage.isTruncated(multiAnswerResponse("a.example", 1, tc = true)))
        assertFalse(DnsMessage.isTruncated(multiAnswerResponse("a.example", 1, tc = false)))
        assertFalse(DnsMessage.isTruncated(ByteArray(2)))
    }
}
