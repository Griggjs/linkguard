package com.linkguard.blocker

/**
 * 域名白名单/黑名单。
 *
 * 语义是"域及其所有子域"：
 *   entries 里有 "qq.com" 时，qq.com 和 mp.weixin.qq.com 都算命中，
 *   但 "notqq.com" 不算（必须按标签边界对齐，不能做字符串后缀比较）。
 *
 * 本类刻意不依赖任何 Android API，因此可在 JVM 上直接用 JUnit 测试。
 */
object DomainName {
    /** 统一成小写、去首尾空白、去结尾点。 */
    fun normalize(host: String?): String {
        if (host == null) return ""
        var h = host.trim().trimEnd('.').lowercase()
        if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length - 1)
        return h
    }

    /**
     * 把用户手输的东西变成域名。
     *
     * 老人/子女很可能直接粘一整条链接进来（`https://www.example.com/a/b?c=1`），
     * 也可能带端口、带前后空格。这里把这些都切掉，只留域名。
     */
    fun fromUserInput(raw: String?): String {
        if (raw.isNullOrBlank()) return ""
        var s = raw.trim().lowercase()
        // 去掉协议
        val idx = s.indexOf("://")
        if (idx >= 0) s = s.substring(idx + 3)
        // 去掉路径 / 查询 / 锚点
        s = s.substringBefore('/').substringBefore('?').substringBefore('#')
        // 去掉端口（IPv6 的 [::1]:53 这种在这里本来也不会通过校验）
        s = s.substringBefore(':')
        // 去掉 "www." 之外的装饰性前后缀
        s = s.trim().trimStart('.').trimEnd('.')
        return normalize(s)
    }

    /** 粗略校验：是不是一个看起来合法的域名。 */
    fun isPlausibleDomain(raw: String?): Boolean {
        val h = normalize(raw)
        if (h.isEmpty() || h.length > 253) return false
        if (!h.contains('.')) return false
        if (h.startsWith(".") || h.endsWith(".") || h.contains("..")) return false
        if (h.any { !(it.isLetterOrDigit() || it == '.' || it == '-') }) return false
        // 必须有字母后缀（排除 192.168.1.1 这类纯 IP）
        val tld = h.substringAfterLast('.')
        if (tld.length < 2 || tld.all { it.isDigit() }) return false
        return true
    }
}

class DomainSet(entries: Collection<String> = emptyList()) {

    private val domains = HashSet<String>()

    init {
        entries.forEach { add(it) }
    }

    /**
     * 加一条。能直接吃 Adblock 写法（||evil.com^）和通配写法（*.evil.com）。
     * 返回是否真的新增了。
     */
    fun add(raw: String): Boolean {
        var d = DomainName.normalize(raw)
        if (d.isEmpty()) return false
        if (d.startsWith("@@")) return false        // 例外规则，是白名单，不能进黑名单
        if (d.startsWith("||")) d = d.substring(2)
        d = d.substringBefore('^').substringBefore('/')
        if (d.startsWith("*.")) d = d.substring(2)
        d = DomainName.normalize(d.trimStart('.'))
        if (d.isEmpty() || !d.contains('.')) return false
        return domains.add(d)
    }

    /** 命中的最长条目；没命中返回 null。 */
    fun match(host: String): String? {
        val h = DomainName.normalize(host)
        if (h.isEmpty()) return null
        var idx = 0
        while (true) {
            if (domains.contains(h.substring(idx))) return h.substring(idx)
            val dot = h.indexOf('.', idx)
            if (dot < 0) return null
            idx = dot + 1
        }
    }

    fun contains(host: String): Boolean = match(host) != null

    fun size(): Int = domains.size

    fun toSortedList(): List<String> = domains.sorted()

    fun remove(domain: String): Boolean = domains.remove(DomainName.normalize(domain))
}
