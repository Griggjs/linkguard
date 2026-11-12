package com.linkguard.blocker

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Ipv4Test {

    private val myIp = byteArrayOf(10, 111, 111, 1)
    private val phoneIp = byteArrayOf(10, 111, 111, 2)
    private val payload = byteArrayOf(1, 2, 3, 4, 5, 6, 7)

    @Test
    fun roundTrip() {
        // 手机 -> 我（DNS 查询）
        val packet = Ipv4.buildUdp(
            srcIp = phoneIp, srcPort = 40000,
            dstIp = myIp, dstPort = 53,
            payload = payload
        )
        val d = Ipv4.parseUdp(packet)
        assertNotNull(d)
        assertArrayEquals(phoneIp, d!!.srcIp)
        assertArrayEquals(myIp, d.dstIp)
        assertEquals(40000, d.srcPort)
        assertEquals(53, d.dstPort)
        assertEquals(payload.size, d.payloadLength)
        assertArrayEquals(payload, d.buffer.copyOfRange(d.payloadOffset, d.payloadOffset + d.payloadLength))
    }

    @Test
    fun headerChecksumIsValid() {
        val packet = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, payload)
        assertTrue(Ipv4.verifyHeaderChecksum(packet))
    }

    @Test
    fun headerChecksumDetectsCorruption() {
        val packet = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, payload)
        packet[12] = 99                       // 改源地址
        assertFalse(Ipv4.verifyHeaderChecksum(packet))
    }

    @Test
    fun totalLengthMatchesBuffer() {
        val packet = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, payload)
        assertEquals(packet.size, Ipv4.u16(packet, 2))
        assertEquals(Ipv4.IP_HEADER_LEN + Ipv4.UDP_HEADER_LEN + payload.size, packet.size)
    }

    @Test
    fun rejectsNonUdp() {
        val packet = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, payload)
        packet[9] = 6                          // 改成 TCP
        assertNull(Ipv4.parseUdp(packet))
    }

    @Test
    fun rejectsFragments() {
        val packet = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, payload)
        Ipv4.putU16(packet, 6, 0x2000)         // MF 置位
        assertNull(Ipv4.parseUdp(packet))
    }

    @Test
    fun rejectsShortBuffer() {
        assertNull(Ipv4.parseUdp(ByteArray(10)))
    }

    @Test
    fun rejectsBadIhl() {
        val packet = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, payload)
        packet[0] = 0x43                       // IHL=3（12 字节头，非法）
        assertNull(Ipv4.parseUdp(packet))
    }

    @Test
    fun checksumIsDeterministic() {
        val a = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, payload)
        val b = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, payload)
        assertArrayEquals(a, b)
    }

    @Test
    fun oddLengthPayloadComputesChecksum() {
        val odd = byteArrayOf(1, 2, 3)
        val packet = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, odd)
        val d = Ipv4.parseUdp(packet)
        assertNotNull(d)
        assertEquals(3, d!!.payloadLength)
    }

    // ---------------------------------------------------------------- 校验和正确性
    // 这一组是"彻查"的核心：如果校验和算错，内核会静默丢弃本服务构造的每一个应答，
    // 表现就是"放行也没用、什么都加载不出来"，而且完全看不到错误。
    //
    // 判定依据（独立于产品代码的算法）：把校验和字段一起做 16 位求和并折叠，
    // 结果必须是 0xFFFF。

    /** 独立实现：16 位求和 + 折叠，不取反。 */
    private fun foldSum(bytes: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += ((bytes[i].toInt() and 0xFF) shl 8) or (bytes[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += ((bytes[i].toInt() and 0xFF) shl 8)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum
    }

    @Test
    fun ipHeaderChecksumValidIncludingItself() {
        val packet = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, payload)
        // 头部（含校验和字段）加起来折叠后必须是 0xFFFF
        assertEquals(0xFFFF, foldSum(packet, 0, Ipv4.IP_HEADER_LEN))
    }

    @Test
    fun udpChecksumValidIncludingItself() {
        val packet = Ipv4.buildUdp(phoneIp, 1234, myIp, 53, payload)
        val udpLen = packet.size - Ipv4.IP_HEADER_LEN

        var sum = 0
        sum += foldSum(packet.copyOfRange(12, 16), 0, 4)   // 源 IP
        sum += foldSum(packet.copyOfRange(16, 20), 0, 4)   // 目的 IP
        sum += Ipv4.PROTO_UDP
        sum += udpLen
        sum += foldSum(packet, Ipv4.IP_HEADER_LEN, udpLen) // UDP 段（含校验和字段）
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)

        assertEquals(0xFFFF, sum)
    }

    @Test
    fun udpChecksumValidForOddPayload() {
        val packet = Ipv4.buildUdp(phoneIp, 40000, myIp, 53, byteArrayOf(1, 2, 3))
        val udpLen = packet.size - Ipv4.IP_HEADER_LEN
        var sum = foldSum(packet.copyOfRange(12, 16), 0, 4) +
            foldSum(packet.copyOfRange(16, 20), 0, 4) +
            Ipv4.PROTO_UDP + udpLen +
            foldSum(packet, Ipv4.IP_HEADER_LEN, udpLen)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum)
    }

    @Test
    fun realDnsPayloadProducesValidPacket() {
        // 用一条真实的 DNS 应答载荷再验一次，覆盖更长的偶数/奇数长度
        val dnsAnswer = ByteArray(64) { (it * 7 + 3).toByte() }
        val packet = Ipv4.buildUdp(myIp, 53, phoneIp, 33333, dnsAnswer)
        assertEquals(0xFFFF, foldSum(packet, 0, Ipv4.IP_HEADER_LEN))

        val udpLen = packet.size - Ipv4.IP_HEADER_LEN
        var sum = foldSum(packet.copyOfRange(12, 16), 0, 4) +
            foldSum(packet.copyOfRange(16, 20), 0, 4) +
            Ipv4.PROTO_UDP + udpLen +
            foldSum(packet, Ipv4.IP_HEADER_LEN, udpLen)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum)
    }
}
