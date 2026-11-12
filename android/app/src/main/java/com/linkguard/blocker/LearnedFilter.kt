package com.linkguard.blocker

/**
 * 学习结束后，把记录到的域名整理成"适合加入白名单"的一组。
 *
 * 用户看到的是"已收录 N 个网站"，不需要做任何挑选，所以这里的清洗必须够狠：
 *   1. 已经能访问的（白名单内）不再重复添加；
 *   2. 广告 / 追踪域名不加（否则等于给自己开广告）；
 *   3. 子域名折叠到父域：同时出现 img.jd.com 与 jd.com 时只保留 jd.com，
 *      因为白名单本来就是"域及其子域"语义，收父域等于收全部；
 *   4. 数量封顶，避免用户误开一小时学习把整机流量都收进来。
 *
 * 纯 JVM，无 Android 依赖，可单测。
 */
object LearnedFilter {

    /** 一次最多收录多少条。 */
    const val MAX_RESULT = 60

    /**
     * @param hosts 学习期间被放行的域名（顺序不重要）
     * @param isAlreadyAllowed 该域名是否已在白名单里
     * @param isDenied 该域名是否属于广告/追踪等应排除的域名
     */
    fun prepare(
        hosts: Collection<String>,
        isAlreadyAllowed: (String) -> Boolean,
        isDenied: (String) -> Boolean
    ): List<String> {
        // 去重 + 规范化
        val unique = LinkedHashSet<String>()
        for (raw in hosts) {
            val h = DomainName.normalize(raw)
            if (h.isEmpty() || !h.contains('.')) continue
            unique.add(h)
        }

        // 标签少的排前面：父域先被保留，子域随后被折叠掉
        val sorted = unique.sortedWith(compareBy({ it.count { c -> c == '.' } }, { it.length }))

        val kept = ArrayList<String>(sorted.size)
        for (host in sorted) {
            if (isAlreadyAllowed(host)) continue
            if (isDenied(host)) continue
            // 已被更短的父域覆盖则跳过
            if (kept.any { host == it || host.endsWith(".$it") }) continue
            kept.add(host)
            if (kept.size >= MAX_RESULT) break
        }
        return kept
    }
}
