package com.linkguard.blocker

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GuardEngineTest {

    private fun engine(vararg allow: String) =
        GuardEngine(DomainSet(allow.toList()), DomainSet(listOf("evil-c2.top")))

    @Test
    fun allowedDomainPasses() {
        val v = engine("qq.com").decide("mp.weixin.qq.com")
        assertTrue(v.allowed)
        assertEquals(VerdictReason.ALLOWED, v.reason)
        assertEquals("qq.com", v.matched)
    }

    @Test
    fun unlistedDomainIsBlockedByDefault() {
        val v = engine("qq.com").decide("icbc-login.top")
        assertFalse(v.allowed)
        assertEquals(VerdictReason.NOT_IN_ALLOWLIST, v.reason)
        assertNull(v.matched)
    }

    @Test
    fun denyBeatsAllow() {
        // 即使误把黑名单域名加进允许名单，也要拦
        val v = engine("qq.com", "evil-c2.top").decide("a.evil-c2.top")
        assertFalse(v.allowed)
        assertEquals(VerdictReason.HARD_BLOCKED, v.reason)
        assertEquals("evil-c2.top", v.matched)
    }

    @Test
    fun hostIsNormalizedBeforeDecision() {
        val v = engine("qq.com").decide("  MP.Weixin.QQ.com.  ")
        assertTrue(v.allowed)
        assertEquals("mp.weixin.qq.com", v.host)
    }

    @Test
    fun singleLabelIsBadRequest() {
        val v = engine("qq.com").decide("localhost")
        assertFalse(v.allowed)
        assertEquals(VerdictReason.BAD_REQUEST, v.reason)
    }

    @Test
    fun emptyHostIsBadRequest() {
        assertEquals(VerdictReason.BAD_REQUEST, engine("qq.com").decide("").reason)
    }

    @Test
    fun adNetworksBlockedEvenUnderAllowedParent() {
        // 这些域名都挂在已放行的大域名下（qq.com / jd.com / taobao.com），
        // 但作为广告域名必须被拦 —— 这是"区分 App 内部混进来的不明链接"的关键。
        val e = GuardEngine(BuiltinRules.buildAllowSet(), BuiltinRules.buildDenySet(includeAds = true))
        assertEquals(VerdictReason.HARD_BLOCKED, e.decide("e.qq.com").reason)
        assertEquals(VerdictReason.HARD_BLOCKED, e.decide("union.jd.com").reason)
        assertEquals(VerdictReason.HARD_BLOCKED, e.decide("simba.taobao.com").reason)
        // 同一批父域下的正常子域不受影响
        assertTrue(e.decide("api.m.jd.com").allowed)
        assertTrue(e.decide("mp.weixin.qq.com").allowed)
    }

    @Test
    fun adBlockCanBeTurnedOff() {
        val withAds = GuardEngine(BuiltinRules.buildAllowSet(), BuiltinRules.buildDenySet(true))
        val without = GuardEngine(BuiltinRules.buildAllowSet(), BuiltinRules.buildDenySet(false))
        assertEquals(VerdictReason.HARD_BLOCKED, withAds.decide("e.qq.com").reason)
        // 关掉广告拦截后，靠父域 qq.com 放行
        assertTrue(without.decide("e.qq.com").allowed)
    }

    @Test
    fun builtinRulesCoverWechatAndSystem() {
        val e = GuardEngine(BuiltinRules.buildAllowSet(), BuiltinRules.buildDenySet())
        // 系统必需
        assertTrue(e.decide("connectivitycheck.gstatic.com").allowed)
        assertTrue(e.decide("conn.pangu.miui.com").allowed)
        // 微信
        assertTrue(e.decide("mp.weixin.qq.com").allowed)
        assertTrue(e.decide("res.wx.qq.com").allowed)
        // 银行 / 政务 / 12306
        assertTrue(e.decide("www.icbc.com.cn").allowed)
        assertTrue(e.decide("www.12306.cn").allowed)
        assertTrue(e.decide("www.gov.cn").allowed)
        // 短视频（用户选的 B）
        assertTrue(e.decide("www.douyin.com").allowed)
        assertTrue(e.decide("www.kuaishou.com").allowed)
        // 电商 / 生活服务（v1.1 加入：老人实际在用，误拦会直接影响日常使用）
        assertTrue(e.decide("www.taobao.com").allowed)
        assertTrue(e.decide("img.alicdn.com").allowed)
        assertTrue(e.decide("api.m.jd.com").allowed)
        assertTrue(e.decide("www.meituan.com").allowed)
        assertTrue(e.decide("www.qunar.com").allowed)
        assertTrue(e.decide("www.kfc.com.cn").allowed)
        assertTrue(e.decide("www.youdao.com").allowed)
        // 不在名单里的，一律拒绝
        assertFalse(e.decide("icbc-login.top").allowed)
        assertFalse(e.decide("some-random-shop.example").allowed)
    }
}
