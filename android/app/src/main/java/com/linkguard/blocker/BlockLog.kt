package com.linkguard.blocker

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

/**
 * 拦截日志：白名单模式的"自我修复"手段。
 *
 * 白名单一定不全，某个正常网站打不开时，子女需要知道"刚才拦了哪个域名"，
 * 才能把它加进允许名单。这就是这个类的全部职责。
 *
 * 实现注意：
 * - DNS 处理线程每条查询都会调 record()，不能每次都写磁盘（会卡住解析）。
 *   所以计数放内存，最多每 5 秒落盘一次。
 * - 有些 App 会查随机域名，日志会膨胀，所以要限量。
 */
object BlockLog {

    private const val MAX_ENTRIES = 800
    private const val FLUSH_INTERVAL_MS = 5_000L

    private val counts = ConcurrentHashMap<String, Int>()

    @Volatile private var loaded = false
    @Volatile private var lastFlush = 0L
    private var pendingTotal = 0L
    private val lock = Any()

    private fun ensureLoaded(ctx: Context) {
        if (loaded) return
        synchronized(lock) {
            if (loaded) return
            counts.putAll(Prefs.loadBlockLog(ctx))
            loaded = true
        }
    }

    fun record(ctx: Context, host: String) {
        if (host.isEmpty()) return
        ensureLoaded(ctx)
        counts.merge(host, 1) { a, b -> a + b }
        pendingTotal++
        val now = System.currentTimeMillis()
        if (now - lastFlush >= FLUSH_INTERVAL_MS) {
            lastFlush = now
            flush(ctx)
        }
    }

    fun totalBlocked(ctx: Context): Long {
        ensureLoaded(ctx)
        return Prefs.totalBlocked(ctx) + pendingTotal
    }

    fun snapshot(ctx: Context): List<Pair<String, Int>> {
        ensureLoaded(ctx)
        return counts.entries
            .sortedByDescending { it.value }
            .map { it.key to it.value }
    }

    fun flush(ctx: Context) {
        if (!loaded) return
        val copy = HashMap(counts)
        trim(copy)
        Prefs.saveBlockLog(ctx, copy)
        val delta = pendingTotal
        if (delta > 0) {
            pendingTotal = 0
            Prefs.addTotalBlocked(ctx, delta)
        }
    }

    fun clear(ctx: Context) {
        synchronized(lock) {
            counts.clear()
            loaded = true
            Prefs.clearBlockLog(ctx)
        }
    }

    fun remove(ctx: Context, host: String) {
        ensureLoaded(ctx)
        counts.remove(host)
        flush(ctx)
    }

    /** 超过上限时，先把只出现过一次的丢掉（那些通常是 App 查的随机域名）。 */
    private fun trim(map: HashMap<String, Int>) {
        if (map.size <= MAX_ENTRIES) return
        val singles = map.filterValues { it <= 1 }.keys
        singles.forEach { map.remove(it) }
    }
}
