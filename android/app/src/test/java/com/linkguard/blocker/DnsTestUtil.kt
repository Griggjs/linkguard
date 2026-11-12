package com.linkguard.blocker

import java.io.ByteArrayOutputStream

/** 测试用的 DNS 查询构造器（产品代码里不需要）。 */
object DnsTestUtil {

    fun query(name: String, qtype: Int = DnsMessage.TYPE_A, qid: Int = 0x1234): ByteArray {
        val o = ByteArrayOutputStream()
        o.write((qid shr 8) and 0xFF)
        o.write(qid and 0xFF)
        o.write(0x01); o.write(0x00)          // flags: RD
        o.write(0x00); o.write(0x01)          // qdcount = 1
        repeat(6) { o.write(0x00) }           // an / ns / ar
        for (label in name.split('.')) {
            if (label.isEmpty()) continue
            val b = label.toByteArray(Charsets.ISO_8859_1)
            o.write(b.size)
            o.write(b)
        }
        o.write(0x00)
        o.write((qtype shr 8) and 0xFF); o.write(qtype and 0xFF)
        o.write(0x00); o.write(0x01)          // class IN
        return o.toByteArray()
    }

    fun rcode(resp: ByteArray): Int = resp[3].toInt() and 0x0F

    fun answerCount(resp: ByteArray): Int =
        ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF)

    fun id(resp: ByteArray): Int =
        ((resp[0].toInt() and 0xFF) shl 8) or (resp[1].toInt() and 0xFF)

    /** 取问题段结束偏移，用来断言"问题段原样回显"。 */
    fun questionBytes(resp: ByteArray, q: DnsQuestion): ByteArray =
        resp.copyOfRange(12, q.endOffset)
}
