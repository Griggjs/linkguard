package com.linkguard.blocker

/**
 * IPv4 + UDP 的解析与构造。
 *
 * 为什么需要这个：VpnService 只能把"IP 包"交给你（tun 是一个网卡）。
 * 要把手机的 DNS 查询截下来，就得自己拆开 IP 头和 UDP 头拿到 DNS 载荷；
 * 要把应答送回去，就得自己拼出 IP/UDP 包并算对校验和——校验和算错，
 * 系统的 DNS 解析器会静默丢弃你的应答，表现为网络可用但速度明显变慢。
 *
 * 纯 JVM 代码，可以单测（校验和、往返解析都有测试覆盖）。
 */
class UdpDatagram(
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val buffer: ByteArray,
    val payloadOffset: Int,
    val payloadLength: Int
)

object Ipv4 {

    const val PROTO_UDP = 17
    const val IP_HEADER_LEN = 20
    const val UDP_HEADER_LEN = 8

    /** 拆一个 IPv4/UDP 包。不是完整、未分片的 UDP 包则返回 null。 */
    fun parseUdp(packet: ByteArray, length: Int = packet.size): UdpDatagram? {
        if (length < IP_HEADER_LEN + UDP_HEADER_LEN) return null
        if ((packet[0].toInt() and 0xFF) shr 4 != 4) return null

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < IP_HEADER_LEN || ihl > length) return null

        val totalLen = u16(packet, 2)
        if (totalLen < ihl + UDP_HEADER_LEN) return null
        val end = minOf(totalLen, length)

        // 分片包一律不处理（DNS 查询极少分片）
        if ((u16(packet, 6) and 0x3FFF) != 0) return null
        if ((packet[9].toInt() and 0xFF) != PROTO_UDP) return null

        val srcPort = u16(packet, ihl)
        val dstPort = u16(packet, ihl + 2)
        val udpLen = u16(packet, ihl + 4)
        if (udpLen < UDP_HEADER_LEN) return null

        val payloadOff = ihl + UDP_HEADER_LEN
        val payloadLen = minOf(udpLen - UDP_HEADER_LEN, end - payloadOff)
        if (payloadLen < 0) return null

        return UdpDatagram(
            srcIp = packet.copyOfRange(12, 16),
            dstIp = packet.copyOfRange(16, 20),
            srcPort = srcPort,
            dstPort = dstPort,
            buffer = packet,
            payloadOffset = payloadOff,
            payloadLength = payloadLen
        )
    }

    /** 构造一个 IPv4/UDP 包（校验和全部算好）。 */
    fun buildUdp(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size
    ): ByteArray {
        require(srcIp.size == 4 && dstIp.size == 4) { "只支持 IPv4" }
        val udpLen = UDP_HEADER_LEN + payloadLength
        val totalLen = IP_HEADER_LEN + udpLen
        val out = ByteArray(totalLen)

        out[0] = 0x45                                   // IPv4, IHL=5
        out[1] = 0
        putU16(out, 2, totalLen)
        putU16(out, 4, 0)                               // id
        putU16(out, 6, 0x4000)                          // DF
        out[8] = 64                                     // TTL
        out[9] = PROTO_UDP.toByte()
        System.arraycopy(srcIp, 0, out, 12, 4)
        System.arraycopy(dstIp, 0, out, 16, 4)
        putU16(out, 10, headerChecksum(out))

        putU16(out, IP_HEADER_LEN, srcPort)
        putU16(out, IP_HEADER_LEN + 2, dstPort)
        putU16(out, IP_HEADER_LEN + 4, udpLen)
        // 先把校验和字段留 0，算完再写回
        System.arraycopy(payload, payloadOffset, out, IP_HEADER_LEN + UDP_HEADER_LEN, payloadLength)
        val ck = udpChecksum(out, IP_HEADER_LEN, udpLen, srcIp, dstIp)
        putU16(out, IP_HEADER_LEN + 6, if (ck == 0) 0xFFFF else ck)

        return out
    }

    /** IP 头校验和（对 20 字节头做反码和）。 */
    fun headerChecksum(header: ByteArray, offset: Int = 0): Int {
        var sum = 0
        var i = offset
        val end = offset + IP_HEADER_LEN
        while (i < end) {
            sum += ((header[i].toInt() and 0xFF) shl 8) or (header[i + 1].toInt() and 0xFF)
            i += 2
        }
        while ((sum shr 16) != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    /** 校验一个 IPv4 包的头部是否完整（测试与调试用）。 */
    fun verifyHeaderChecksum(packet: ByteArray): Boolean {
        if (packet.size < IP_HEADER_LEN) return false
        val stored = u16(packet, 10)
        val copy = packet.copyOf(IP_HEADER_LEN)
        putU16(copy, 10, 0)
        return headerChecksum(copy) == stored
    }

    /** UDP 校验和（含伪头部）。 */
    fun udpChecksum(
        packet: ByteArray,
        udpOffset: Int,
        udpLength: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ): Int {
        var sum = 0L
        sum += ipWords(srcIp)
        sum += ipWords(dstIp)
        sum += PROTO_UDP.toLong()
        sum += udpLength.toLong()

        var i = udpOffset
        val end = udpOffset + udpLength
        while (i + 1 < end) {
            sum += (((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < end) {                                  // 奇数长度补 0
            sum += ((packet[i].toInt() and 0xFF) shl 8).toLong()
        }

        while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun ipWords(ip: ByteArray): Long {
        var v = 0L
        for (b in ip) v = (v shl 8) or (b.toLong() and 0xFF)
        // 当成两个 16 位字相加
        return ((v shr 16) and 0xFFFF) + (v and 0xFFFF)
    }

    fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    fun putU16(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v shr 8) and 0xFF).toByte()
        b[off + 1] = (v and 0xFF).toByte()
    }
}
