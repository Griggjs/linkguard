package com.linkguard.blocker

/**
 * 「智能模式」使用的域名特征判断。
 *
 * 设计背景：严格白名单在通用手机上无法收敛——单个应用会访问十几个 CDN / 第三方域名，
 * 白名单扩充至数百条仍不完整，且缺失项多为基础设施域名，而非高风险域名。
 *
 * 因此提供另一种模式：**默认放行，仅按域名特征拦截**。高风险域名具有较强的一致性特征：
 *   - 使用 punycode（xn--）伪装成正规域名
 *   - 使用批量注册成本低的顶级域（.top / .xyz / .icu 等）
 *   - 域名中包含品牌词但不在官方域下
 *   - 域名由多个敏感词拼接而成（如 secure-login-verify）
 *   - 域名含过多连字符（人工堆砌关键词的典型形态）
 *
 * 能力边界：本类只能判断**域名形态**，无法判断页面内容。域名正常、
 * 内容为仿冒页的情况不在覆盖范围内。
 *
 * 纯 JVM，无 Android 依赖，可单测。
 */
object SuspiciousRules {

    /** 批量注册成本低、滥用率高的顶级域。 */
    private val BAD_TLDS: Set<String> = setOf(
        "top", "xyz", "icu", "cyou", "buzz", "sbs", "cfd", "monster",
        "tk", "gq", "ml", "cf", "ga", "work", "link", "click", "rest",
        "quest", "lol", "bond", "boats", "cam", "best", "win", "bid",
        "loan", "date", "racing", "stream", "download", "review",
        "trade", "party", "science", "men", "space", "website", "site"
    )

    /**
     * 品牌词 -> 官方域。
     *
     * 匹配策略：
     *   - 长度 >= 4 的品牌词，在"去掉点和连字符"的域名里做包含匹配；
     *   - 更短的品牌词，要求与某个域名标签（或连字符切分后的片段）完全相等，
     *     避免误拦随机字符串。
     */
    private val BRANDS: Map<String, Set<String>> = mapOf(
        // 银行
        "icbc" to setOf("icbc.com.cn"),
        "abchina" to setOf("abchina.com"),
        "bankcomm" to setOf("bankcomm.com"),
        "cmbchina" to setOf("cmbchina.com"),
        "citicbank" to setOf("citicbank.com"),
        "cebbank" to setOf("cebbank.com"),
        "spdb" to setOf("spdb.com.cn"),
        "psbc" to setOf("psbc.com"),
        "ccb" to setOf("ccb.com"),
        "boc" to setOf("boc.cn"),
        "cib" to setOf("cib.com.cn"),
        "hxb" to setOf("hxb.com.cn"),
        "cmbc" to setOf("cmbc.com.cn"),
        "95588" to setOf("icbc.com.cn"),
        "95533" to setOf("ccb.com"),
        "95566" to setOf("boc.cn"),
        "95599" to setOf("abchina.com"),
        // 支付 / 电商 / 社交
        "unionpay" to setOf("unionpay.com"),
        "alipay" to setOf("alipay.com"),
        "tenpay" to setOf("tenpay.com"),
        "wechatpay" to setOf("wechatpay.cn"),
        "taobao" to setOf("taobao.com"),
        "tmall" to setOf("tmall.com"),
        "pinduoduo" to setOf("pinduoduo.com"),
        "jd" to setOf("jd.com"),
        "weixin" to setOf("weixin.qq.com", "weixin.com"),
        "wechat" to setOf("wechat.com"),
        "douyin" to setOf("douyin.com"),
        "kuaishou" to setOf("kuaishou.com"),
        // 出行 / 票务
        "12306" to setOf("12306.cn"),
        "ctrip" to setOf("ctrip.com", "c-ctrip.com"),
        // 运营商
        "10086" to setOf("10086.cn"),
        "chinatelecom" to setOf("189.cn", "chinatelecom.com.cn"),
        "chinaunicom" to setOf("10010.com", "chinaunicom.com.cn"),
        // 大厂（仅用于抓仿冒，官方域以国内可访问者为准）
        "microsoft" to setOf("microsoft.com", "microsoftonline.com"),
        "apple" to setOf("apple.com", "apple.com.cn"),
        "huawei" to setOf("huawei.com"),
        "xiaomi" to setOf("xiaomi.com", "mi.com"),
        "alibaba" to setOf("alibaba.com"),
        "tencent" to setOf("tencent.com"),
        "baidu" to setOf("baidu.com")
    )

    /** 诱导性词汇。域名里出现两个以上，通常意味着这是一个仿冒页面。 */
    private val RISKY_TOKENS: Set<String> = setOf(
        "login", "signin", "verify", "verification", "secure", "security",
        "account", "update", "confirm", "unlock", "activate", "reset",
        "password", "pwd", "auth", "wallet", "payment", "pay", "bank",
        "card", "idcard", "otp", "sms", "code", "bind", "realname",
        "kyc", "appeal", "service", "center", "vip"
    )

    /** 连字符超过该数量视为人工堆砌关键词。 */
    private const val MAX_REASONABLE_HYPHENS = 4

    /**
     * 检查一个域名是否可疑。
     *
     * @return 命中的原因（用于日志与提示）；不可疑返回 null。
     */
    fun check(rawHost: String): String? {
        val host = DomainName.normalize(rawHost)
        if (host.isEmpty() || !host.contains('.')) return null

        // 1. punycode：可以显示成与正规域名完全一致的字符
        if (host.startsWith("xn--") || host.contains(".xn--")) return "punycode"

        // 2. 高风险顶级域
        val tld = host.substringAfterLast('.')
        if (tld in BAD_TLDS) return "tld:$tld"

        val labels = host.split('.')
        val body = labels.dropLast(1).joinToString(".")   // 去掉 TLD
        val flat = host.replace("-", "").replace(".", "")

        // 3. 冒充品牌
        for ((brand, officials) in BRANDS) {
            val present = if (brand.length >= 4) {
                flat.contains(brand)
            } else {
                labels.any { it == brand } ||
                    labels.any { label -> label.split('-').any { it == brand } }
            }
            if (!present) continue
            if (officials.any { host == it || host.endsWith(".$it") }) continue
            return "brand:$brand"
        }

        // 4. 敏感词堆砌：出现两个以上诱导性词汇
        val hitTokens = RISKY_TOKENS.filter { body.contains(it) }
        if (hitTokens.size >= 2) return "tokens:${hitTokens.take(2).joinToString("+")}"

        // 5. 连字符过多
        if (host.count { it == '-' } > MAX_REASONABLE_HYPHENS) return "hyphens"

        return null
    }
}
