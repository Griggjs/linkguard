package com.linkguard.blocker

import java.util.concurrent.ConcurrentHashMap

/**
 * 「学习」期间记录的、被放行的域名。
 *
 * 用途：严格模式下某个正常软件打不开时，用户点一下「学习」，
 * 程序临时切到智能模式并记录这段时间里放行了哪些域名；
 * 用户用完后，把这些域名一次性加入白名单，之后在严格模式下也能正常使用。
 *
 * 只在学习期间记录，平时零开销。数量有上限，避免长时间开启导致膨胀。
 */
object LearnedLog {

    private const val MAX_ENTRIES = 500

    private val counts = ConcurrentHashMap<String, Int>()

    @Volatile
    private var active = false

    fun isActive(): Boolean = active

    fun start() {
        counts.clear()
        active = true
    }

    fun stop() {
        active = false
    }

    fun clear() {
        counts.clear()
        active = false
    }

    /** DNS 处理线程会频繁调用；非学习状态下立即返回。 */
    fun record(host: String) {
        if (!active || host.isEmpty()) return
        if (counts.size >= MAX_ENTRIES && !counts.containsKey(host)) return
        counts.merge(host, 1) { a, b -> a + b }
    }

    /** 按访问次数从多到少返回。 */
    fun snapshot(): List<Pair<String, Int>> =
        counts.entries
            .sortedByDescending { it.value }
            .map { it.key to it.value }
}
