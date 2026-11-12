package com.linkguard.blocker

/** 判定结果的原因，用于区分提示文案和日志统计。 */
enum class VerdictReason {
    /** 放行。 */
    ALLOWED,
    /** 严格模式下：不在允许名单里 —— 需要子女确认，不是"危险"。 */
    NOT_IN_ALLOWLIST,
    /** 明确拦下：广告域、黑名单、或智能模式命中了可疑特征。 */
    HARD_BLOCKED,
    /** 报文里没有合法域名。 */
    BAD_REQUEST
}

/** 三种工作模式。 */
enum class GuardMode {
    /** 默认拒绝：只有允许名单里的能过。最安全，但名单永远补不全。 */
    STRICT,

    /** 默认放行 + 按域名特征拦截：不影响正常应用可用性，仍可拦截高风险域名。 */
    SMART,

    /**
     * 全放行，只记录。**排障专用**。
     *
     * 用途：如果这个模式下 App 还是受限，那问题根本不在 DNS 过滤器上
     * （可能是 VPN 本身、可能是 App 自己的问题），不用再补域名了。
     */
    OBSERVE
}

data class Verdict(
    val allowed: Boolean,
    val matched: String?,
    val host: String,
    val reason: VerdictReason,
    /** 拦下的具体原因（智能模式下的 tld / punycode / brand 等）。 */
    val detail: String? = null
)

/**
 * 判定引擎。
 *
 * 两种模式的顺序都是**黑名单先判**（广告/已知恶意），再按模式分流：
 *
 *   STRICT：允许名单命中 → 放行；否则拒绝
 *   SMART ：允许名单命中 → 放行（用于豁免官方域）；
 *           否则查 [SuspiciousRules]，可疑 → 拦，不可疑 → 放行
 *
 * 纯 JVM，无 Android 依赖，可单测。
 */
class GuardEngine(
    private val allow: DomainSet,
    private val deny: DomainSet = DomainSet(),
    private val mode: GuardMode = GuardMode.STRICT
) {

    fun decide(rawHost: String): Verdict {
        val host = DomainName.normalize(rawHost)
        if (host.isEmpty() || !host.contains('.')) {
            return Verdict(false, null, host, VerdictReason.BAD_REQUEST)
        }

        // 观察模式：不拦截，仅记录。用于判断"问题是否由本组件引起"。
        if (mode == GuardMode.OBSERVE) {
            return Verdict(true, null, host, VerdictReason.ALLOWED, "observe")
        }

        // 黑名单优先：广告/已知恶意，即使被误加进允许名单也拦
        deny.match(host)?.let {
            return Verdict(false, it, host, VerdictReason.HARD_BLOCKED, "deny")
        }

        // 允许名单命中：两种拦截模式都放行
        allow.match(host)?.let {
            return Verdict(true, it, host, VerdictReason.ALLOWED)
        }

        return when (mode) {
            GuardMode.STRICT -> Verdict(false, null, host, VerdictReason.NOT_IN_ALLOWLIST)

            GuardMode.SMART -> {
                val suspicious = SuspiciousRules.check(host)
                if (suspicious == null) {
                    Verdict(true, null, host, VerdictReason.ALLOWED)
                } else {
                    Verdict(false, suspicious, host, VerdictReason.HARD_BLOCKED, suspicious)
                }
            }

            // 上面已经提前返回了
            GuardMode.OBSERVE -> Verdict(true, null, host, VerdictReason.ALLOWED, "observe")
        }
    }

    fun allowListSize(): Int = allow.size()

    fun denyListSize(): Int = deny.size()

    fun currentMode(): GuardMode = mode

    fun snapshotAllowList(): List<String> = allow.toSortedList()
}
