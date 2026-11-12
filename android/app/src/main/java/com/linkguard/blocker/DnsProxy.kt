package com.linkguard.blocker

/**
 * 构造回给客户端的应答包。
 *
 * 抽成独立的纯函数是有原因的：v2.8 及以前，应答包的**目的地址写错成了自己**
 * （用了请求包的 dstIp 而不是 srcIp），导致每个应答都被回传至隧道自身并丢弃。
 * 表现是：内部统计一切正常（收到、处理、写回都成功），但手机上一个域名都解析不出来，
 * 所有 App 都加载失败，且与白名单、工作模式完全无关。
 *
 * 这个错误用"泛泛地测 Ipv4.buildUdp"是测不出来的（那个函数本身没错，
 * 错的是调用时传了哪个参数），所以把"地址怎么对调"这件事单独抽出来，让它可被测试。
 */
object DnsProxy {

    const val DNS_PORT = 53

    /**
     * 把 [request] 变成一个应答包：
     *   源 = 服务端 DNS 地址:53
     *   目的 = **请求方的地址**和端口（也就是 request.srcIp / request.srcPort）
     */
    fun buildReply(request: UdpDatagram, ourDnsIp: ByteArray, payload: ByteArray): ByteArray =
        Ipv4.buildUdp(
            srcIp = ourDnsIp,
            srcPort = DNS_PORT,
            dstIp = request.srcIp,          // ← 必须是请求的**源**地址
            dstPort = request.srcPort,
            payload = payload
        )
}
