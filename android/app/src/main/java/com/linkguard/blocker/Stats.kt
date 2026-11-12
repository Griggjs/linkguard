package com.linkguard.blocker

import java.util.concurrent.atomic.AtomicLong

/**
 * 内部运行统计。
 *
 * 为什么需要它：之前整条 DNS 链路有三处"静默失败"——报文不匹配就 return、
 * 上游超时即切换下一个、写回失败则忽略异常。表现为应用无法正常访问，
 * 无法定位失败环节，导致此前的排查方向长期偏离。
 *
 * 这些计数器把每一步都暴露出来，一眼就能看出是"没收到"、"解析不了"、
 * "上游失败"还是"写回失败"。
 */
object Stats {

    /** 从隧道读到的 IP 包总数。 */
    val packets = AtomicLong()

    /** 非目标 DNS 查询（如 TCP 或其它端口）。 */
    val notDns = AtomicLong()

    /** 其中属于 DNS over TCP 的（服务不处理 TCP，只能丢弃）。 */
    val tcpDns = AtomicLong()

    /** 是 DNS 但解析不了问题段。 */
    val unparsable = AtomicLong()

    /** 判定为拦截。 */
    val blocked = AtomicLong()

    /** 判定为放行。 */
    val allowed = AtomicLong()

    /** 上游（UDP）全部失败。 */
    val forwardFail = AtomicLong()

    /** UDP 被截断后走 TCP 重查。 */
    val tcpRetry = AtomicLong()

    /** 写回隧道失败（通常是包超过 MTU）。 */
    val writeErr = AtomicLong()

    /** 看门狗重启次数。 */
    val restarts = AtomicLong()

    fun reset() {
        packets.set(0); notDns.set(0); tcpDns.set(0); unparsable.set(0); blocked.set(0)
        allowed.set(0); forwardFail.set(0); tcpRetry.set(0); writeErr.set(0)
        restarts.set(0)
    }

    /** 给界面看的一行摘要。 */
    fun summary(): String =
        "收 ${packets.get()} · 答 ${allowed.get() + blocked.get()} · " +
            "非DNS ${notDns.get()}（其中TCP ${tcpDns.get()}）· 解析失败 ${unparsable.get()} · " +
            "上游失败 ${forwardFail.get()} · 写回失败 ${writeErr.get()} · " +
            "TCP回退 ${tcpRetry.get()} · 重启 ${restarts.get()}"

    /** 是否有明显异常（用于把摘要染红）。 */
    fun looksBroken(): Boolean =
        forwardFail.get() > 0 || writeErr.get() > 0 ||
            (packets.get() > 0 && allowed.get() + blocked.get() == 0L)
}
