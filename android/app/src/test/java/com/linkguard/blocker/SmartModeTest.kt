package com.linkguard.blocker

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 智能拦截模式：默认放行，只拦按域名特征可疑的。
 *
 * 用于严格白名单无法收敛时的替代方案：保持应用可用性，同时拦截高风险域名。
 */
class SmartModeTest {

    private fun smart(deny: DomainSet = DomainSet()) =
        GuardEngine(BuiltinRules.buildAllowSet(), deny, GuardMode.SMART)

    private fun strict() =
        GuardEngine(BuiltinRules.buildAllowSet(), BuiltinRules.buildDenySet(), GuardMode.STRICT)

    @Test
    fun ordinarySiteAllowedInSmart() {
        assertTrue(smart().decide("www.example.com").allowed)
        assertTrue(smart().decide("some-hospital.com.cn").allowed)
        assertTrue(smart().decide("img.alicdn.com").allowed)
        assertTrue(smart().decide("pull-p1.wxlivecdn.com").allowed)
    }

    @Test
    fun ordinarySiteStillBlockedInStrict() {
        // 严格模式下没进名单就打不开 —— 是就是收敛不了的原因
        assertFalse(strict().decide("www.example.com").allowed)
    }

    @Test
    fun cheapTldBlocked() {
        val v = smart().decide("abc.top")
        assertFalse(v.allowed)
        assertNotNull(v.detail)
        assertEquals("tld:top", v.detail)
        assertFalse(smart().decide("promo.xyz").allowed)
        assertFalse(smart().decide("x.cyou").allowed)
    }

    @Test
    fun punycodeBlocked() {
        val v = smart().decide("xn--80ak6aa92e.com")
        assertFalse(v.allowed)
        assertEquals("punycode", v.detail)
    }

    @Test
    fun brandImpersonationBlocked() {
        val v = smart().decide("icbc-login.com")
        assertFalse(v.allowed)
        assertEquals("brand:icbc", v.detail)
        assertFalse(smart().decide("alipay-verify.net").allowed)
        assertFalse(smart().decide("12306-ticket.com").allowed)
        // v3.4 扩表后新增的银行 / 运营商 / 大厂
        assertFalse(smart().decide("ccb-verify.com").allowed)
        assertFalse(smart().decide("psbc-service.net").allowed)
        assertFalse(smart().decide("10086-chongzhi.com").allowed)
        assertFalse(smart().decide("apple-id-unlock.com").allowed)
    }

    @Test
    fun riskyTokenCombinationBlocked() {
        // 域名由多个诱导性词汇拼接而成 —— 仿冒页最常见的形态
        val v = smart().decide("secure-login-verify.com")
        assertFalse(v.allowed)
        assertNotNull(v.detail)
        assertTrue("detail 应说明命中敏感词，实际 $($v.detail)", v.detail!!.startsWith("tokens:"))
        assertFalse(smart().decide("account-update-confirm.net").allowed)
        assertFalse(smart().decide("bank-card-bind.com").allowed)
    }

    @Test
    fun excessiveHyphensBlocked() {
        assertFalse(smart().decide("a-b-c-d-e-f.com").allowed)
        // 正常域名不应被误拦
        assertTrue(smart().decide("example-domain.com").allowed)
    }

    @Test
    fun singleRiskyTokenIsTolerated() {
        // 只出现一个诱导性词（如 login.xxx.com）不应拦截，否则误拦范围过大
        assertTrue(smart().decide("login.example.com").allowed)
        assertTrue(smart().decide("account.example.com").allowed)
    }

    @Test
    fun officialBrandNotFlagged() {
        assertTrue(smart().decide("www.icbc.com.cn").allowed)
        assertTrue(smart().decide("mail.icbc.com.cn").allowed)
        assertTrue(smart().decide("www.12306.cn").allowed)
        assertTrue(smart().decide("m.alipay.com").allowed)
        // 官方域的国内变体不应误拦
        assertTrue(smart().decide("www.apple.com.cn").allowed)
        assertTrue(smart().decide("login.microsoftonline.com").allowed)
        assertTrue(smart().decide("sso.jd.com").allowed)
    }

    @Test
    fun adNetworksStillBlockedInSmartMode() {
        val e = smart(BuiltinRules.buildDenySet())
        assertFalse(e.decide("e.qq.com").allowed)
        assertFalse(e.decide("union.jd.com").allowed)
    }

    @Test
    fun modeIsReportedCorrectly() {
        assertEquals(GuardMode.SMART, smart().currentMode())
        assertEquals(GuardMode.STRICT, strict().currentMode())
    }

    @Test
    fun emptyOrSingleLabelIsBadRequest() {
        assertEquals(VerdictReason.BAD_REQUEST, smart().decide("").reason)
        assertEquals(VerdictReason.BAD_REQUEST, smart().decide("localhost").reason)
    }
}
