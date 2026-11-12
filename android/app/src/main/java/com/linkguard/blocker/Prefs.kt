package com.linkguard.blocker

import android.content.Context
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * 本地存储：PIN、额外允许的域名、拦截计数。
 *
 * 全部存在 App 私有目录（SharedPreferences），不上传、不需要联网权限之外的东西。
 * 没有数据库：这几种数据都小，用 SharedPreferences 足够，也少一层出错的可能。
 */
object Prefs {

    private const val FILE = "linkguard"

    private const val KEY_PIN_HASH = "pin_hash"
    private const val KEY_PIN_SALT = "pin_salt"
    private const val KEY_EXTRA_ALLOW = "extra_allow"
    private const val KEY_BLOCK_LOG = "block_log"
    private const val KEY_TOTAL_BLOCKED = "total_blocked"
    private const val KEY_ENABLED = "protection_enabled"

    // ------------------------------------------------------------ 开关状态

    /** 记录"上一次是不是开着"，供开机自启判断。 */
    fun setEnabled(ctx: Context, enabled: Boolean) {
        sp(ctx).edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    fun wasEnabled(ctx: Context): Boolean = sp(ctx).getBoolean(KEY_ENABLED, false)

    private fun sp(ctx: Context) = ctx.applicationContext
        .getSharedPreferences(FILE, Context.MODE_PRIVATE)

    // ---------------------------------------------------------------- PIN

    fun hasPin(ctx: Context): Boolean =
        sp(ctx).getString(KEY_PIN_HASH, null)?.isNotEmpty() == true

    fun setPin(ctx: Context, pin: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val saltHex = salt.toHex()
        sp(ctx).edit()
            .putString(KEY_PIN_SALT, saltHex)
            .putString(KEY_PIN_HASH, hashPin(pin, salt))
            .apply()
    }

    fun checkPin(ctx: Context, pin: String): Boolean {
        val stored = sp(ctx).getString(KEY_PIN_HASH, null) ?: return false
        val saltHex = sp(ctx).getString(KEY_PIN_SALT, null) ?: return false
        val salt = saltHex.fromHex() ?: return false
        return constantTimeEquals(stored, hashPin(pin, salt))
    }

    // ------------------------------------------------------- PIN 失败次数
    // 没有这个计数的话，4 位数字（1 万种）可以在一分钟内被逐个试完。

    private const val KEY_PIN_FAILS = "pin_fails"

    fun pinFailures(ctx: Context): Int = sp(ctx).getInt(KEY_PIN_FAILS, 0)

    fun notePinFailure(ctx: Context): Int {
        val n = pinFailures(ctx) + 1
        sp(ctx).edit().putInt(KEY_PIN_FAILS, n).apply()
        return n
    }

    fun clearPinFailures(ctx: Context) {
        sp(ctx).edit().putInt(KEY_PIN_FAILS, 0).apply()
    }

    private fun hashPin(pin: String, salt: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(salt)
        md.update(pin.toByteArray(Charsets.UTF_8))
        // 多迭代几次，让离线暴力破解变慢（本地工具，够用）
        var digest = md.digest()
        repeat(20_000) {
            md.reset()
            md.update(digest)
            md.update(salt)
            digest = md.digest()
        }
        return digest.toHex()
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var r = 0
        for (i in a.indices) r = r or (a[i].code xor b[i].code)
        return r == 0
    }

    // -------------------------------------------------------- 额外允许名单

    fun extraAllow(ctx: Context): Set<String> =
        sp(ctx).getStringSet(KEY_EXTRA_ALLOW, emptySet())?.toSet() ?: emptySet()

    fun addAllow(ctx: Context, domain: String) {
        val d = DomainName.normalize(domain)
        if (d.isEmpty()) return
        val next = HashSet(extraAllow(ctx)).apply { add(d) }
        sp(ctx).edit().putStringSet(KEY_EXTRA_ALLOW, next).apply()
    }

    fun removeAllow(ctx: Context, domain: String) {
        val d = DomainName.normalize(domain)
        val next = HashSet(extraAllow(ctx)).apply { remove(d) }
        sp(ctx).edit().putStringSet(KEY_EXTRA_ALLOW, next).apply()
    }

    /** 清空所有手动添加的域名（恢复出厂白名单）。 */
    fun clearExtraAllow(ctx: Context) {
        sp(ctx).edit().remove(KEY_EXTRA_ALLOW).apply()
    }

    fun buildEngine(ctx: Context): GuardEngine {
        val m = mode(ctx)
        // 智能/观察模式的宗旨是"不打扰 App"：广告黑名单只在严格模式下生效。
        // 智能模式下拦截 umeng / mob / cnzz 等 SDK 域名会影响登录、短信验证与推送。
        val includeAds = m == GuardMode.STRICT && isAdBlockEnabled(ctx)
        return GuardEngine(
            BuiltinRules.buildAllowSet(extraAllow(ctx)),
            BuiltinRules.buildDenySet(includeAds = includeAds),
            m
        )
    }

    // ------------------------------------------------------------ 工作模式

    private const val KEY_MODE = "guard_mode"

    /** 默认严格白名单（用户最初的要求）。设备被拦截过多、影响使用时切到 SMART / OBSERVE。 */
    fun mode(ctx: Context): GuardMode =
        when (sp(ctx).getString(KEY_MODE, "strict")) {
            "smart" -> GuardMode.SMART
            "observe" -> GuardMode.OBSERVE
            else -> GuardMode.STRICT
        }

    fun setMode(ctx: Context, mode: GuardMode) {
        val v = when (mode) {
            GuardMode.SMART -> "smart"
            GuardMode.OBSERVE -> "observe"
            GuardMode.STRICT -> "strict"
        }
        sp(ctx).edit().putString(KEY_MODE, v).apply()
    }

    // -------------------------------------------------------------- 学习状态

    private const val KEY_LEARNING_START = "learning_start"
    private const val KEY_LEARNING_PREV = "learning_prev_mode"

    /** 是否处于「学习」流程中。 */
    fun isLearning(ctx: Context): Boolean = sp(ctx).getLong(KEY_LEARNING_START, 0L) > 0L

    fun learningStartedAt(ctx: Context): Long = sp(ctx).getLong(KEY_LEARNING_START, 0L)

    /** 进入学习：临时切到宽松模式，并记住原来的模式，结束后恢复。 */
    fun startLearning(ctx: Context) {
        val prev = when (mode(ctx)) {
            GuardMode.SMART -> "smart"
            GuardMode.OBSERVE -> "observe"
            GuardMode.STRICT -> "strict"
        }
        sp(ctx).edit()
            .putLong(KEY_LEARNING_START, System.currentTimeMillis())
            .putString(KEY_LEARNING_PREV, prev)
            .apply()
    }

    fun stopLearning(ctx: Context) {
        sp(ctx).edit().remove(KEY_LEARNING_START).apply()
    }

    /** 学习开始之前的模式，用于还原。 */
    fun modeBeforeLearning(ctx: Context): GuardMode =
        when (sp(ctx).getString(KEY_LEARNING_PREV, "strict")) {
            "smart" -> GuardMode.SMART
            "observe" -> GuardMode.OBSERVE
            else -> GuardMode.STRICT
        }

    // -------------------------------------------------------- 广告拦截开关

    private const val KEY_AD_BLOCK = "ad_block"

    /** 默认开启。某个 App 因为少了广告接口而打不开时，关掉它。 */
    fun isAdBlockEnabled(ctx: Context): Boolean = sp(ctx).getBoolean(KEY_AD_BLOCK, true)

    fun setAdBlockEnabled(ctx: Context, enabled: Boolean) {
        sp(ctx).edit().putBoolean(KEY_AD_BLOCK, enabled).apply()
    }

    // ------------------------------------------------------------ 拦截计数

    /**
     * 累计拦截次数。注意：只在 BlockLog 每 5 秒落盘时调用一次，
     * 不能在每条 DNS 查询里调 —— 那会让解析卡在磁盘 IO 上。
     */
    fun addTotalBlocked(ctx: Context, delta: Long) {
        if (delta <= 0) return
        val cur = sp(ctx).getLong(KEY_TOTAL_BLOCKED, 0L)
        sp(ctx).edit().putLong(KEY_TOTAL_BLOCKED, cur + delta).apply()
    }

    fun totalBlocked(ctx: Context): Long = sp(ctx).getLong(KEY_TOTAL_BLOCKED, 0L)

    fun loadBlockLog(ctx: Context): MutableMap<String, Int> {
        val raw = sp(ctx).getString(KEY_BLOCK_LOG, "") ?: ""
        val map = LinkedHashMap<String, Int>()
        for (line in raw.lineSequence()) {
            if (line.isBlank()) continue
            val parts = line.split('\t')
            if (parts.size != 2) continue
            val n = parts[1].toIntOrNull() ?: continue
            map[parts[0]] = n
        }
        return map
    }

    fun saveBlockLog(ctx: Context, map: Map<String, Int>) {
        val sb = StringBuilder()
        for ((k, v) in map) sb.append(k).append('\t').append(v).append('\n')
        sp(ctx).edit().putString(KEY_BLOCK_LOG, sb.toString()).apply()
    }

    fun clearBlockLog(ctx: Context) {
        sp(ctx).edit().remove(KEY_BLOCK_LOG).apply()
    }
}

// ---------------------------------------------------------------- 十六进制

internal fun ByteArray.toHex(): String {
    val sb = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        sb.append("0123456789abcdef"[v shr 4])
        sb.append("0123456789abcdef"[v and 0x0F])
    }
    return sb.toString()
}

internal fun String.fromHex(): ByteArray? {
    if (length % 2 != 0) return null
    val out = ByteArray(length / 2)
    for (i in out.indices) {
        val hi = "0123456789abcdef".indexOf(this[i * 2].lowercaseChar())
        val lo = "0123456789abcdef".indexOf(this[i * 2 + 1].lowercaseChar())
        if (hi < 0 || lo < 0) return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}
