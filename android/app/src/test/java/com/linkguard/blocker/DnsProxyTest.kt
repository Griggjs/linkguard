package com.linkguard.blocker

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * 这一组测试专门防止 v2.8 那个致命 bug 复发：
 * 应答包的目的地址必须是**请求方**，而非本机地址。
 *
 * 当时的现象极具迷惑性——内部统计（收到/处理/上游/写回）全部正常，
 * 但设备上任何域名均无法解析，原因是应答被回传至隧道自身并被丢弃。
 */
class DnsProxyTest {

    private val clientIp = byteArrayOf(10, 111, 111, 2)      // 手机在隧道里的地址
    private val ourDnsIp = byteArrayOf(10, 111, 111, 1)      // 护链的虚拟 DNS
    private val payload = byteArrayOf(1, 2, 3, 4, 5)

    @Test
    fun replyGoesToTheClientNotToOurself() {
        val request = Ipv4.buildUdp(clientIp, 40000, ourDnsIp, DnsProxy.DNS_PORT, payload)
        val parsedRequest = Ipv4.parseUdp(request)
        assertNotNull(parsedRequest)

        val answer = byteArrayOf(9, 9, 9)
        val reply = DnsProxy.buildReply(parsedRequest!!, ourDnsIp, answer)
        val parsedReply = Ipv4.parseUdp(reply)
        assertNotNull(parsedReply)

        // 目的 = 客户端
        assertArrayEquals(clientIp, parsedReply!!.dstIp)
        assertEquals(40000, parsedReply.dstPort)
        // 源 = 服务端 DNS 地址和端口
        assertArrayEquals(ourDnsIp, parsedReply.srcIp)
        assertEquals(DnsProxy.DNS_PORT, parsedReply.srcPort)
        // 绝不能是"发给自己"
        assertFalse(parsedReply.dstIp.contentEquals(ourDnsIp))
        // 载荷要原样带上
        assertArrayEquals(
            answer,
            parsedReply.buffer.copyOfRange(
                parsedReply.payloadOffset,
                parsedReply.payloadOffset + parsedReply.payloadLength
            )
        )
    }

    @Test
    fun worksWithDifferentClientPorts() {
        for (port in listOf(1024, 5353, 65535)) {
            val request = Ipv4.buildUdp(clientIp, port, ourDnsIp, DnsProxy.DNS_PORT, payload)
            val parsed = Ipv4.parseUdp(request)!!
            val reply = Ipv4.parseUdp(DnsProxy.buildReply(parsed, ourDnsIp, byteArrayOf(1)))!!
            assertEquals(port, reply.dstPort)
            assertEquals(DnsProxy.DNS_PORT, reply.srcPort)
        }
    }

    @Test
    fun replyPacketIsValid() {
        val request = Ipv4.buildUdp(clientIp, 40000, ourDnsIp, DnsProxy.DNS_PORT, payload)
        val parsed = Ipv4.parseUdp(request)!!
        val reply = DnsProxy.buildReply(parsed, ourDnsIp, ByteArray(40))
        // 校验和必须合法，否则内核会静默丢弃
        org.junit.Assert.assertTrue(Ipv4.verifyHeaderChecksum(reply))
    }
}
