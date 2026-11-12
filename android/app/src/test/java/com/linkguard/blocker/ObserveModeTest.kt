package com.linkguard.blocker

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 观察模式：什么都不拦，只让上层记录。
 *
 * 这是排障用的关键工具——如果观察模式下 App 还是受限，
 * 说明问题不在 DNS 过滤器上，再补域名也没用。
 */
class ObserveModeTest {

    private fun observe() = GuardEngine(
        BuiltinRules.buildAllowSet(),
        BuiltinRules.buildDenySet(includeAds = true),
        GuardMode.OBSERVE
    )

    @Test
    fun blocksNothing() {
        val e = observe()
        assertTrue(e.decide("www.example.com").allowed)
        assertTrue(e.decide("abc.top").allowed)
        assertTrue(e.decide("xn--80ak6aa92e.com").allowed)
        assertTrue(e.decide("icbc-login.com").allowed)
        // 连广告域名也放行 —— 观察模式必须是"零拦截"，否则无法做对照实验
        assertTrue(e.decide("e.qq.com").allowed)
        assertTrue(e.decide("umeng.com").allowed)
    }

    @Test
    fun stillRejectsGarbage() {
        assertEquals(VerdictReason.BAD_REQUEST, observe().decide("").reason)
        assertEquals(VerdictReason.BAD_REQUEST, observe().decide("localhost").reason)
    }

    @Test
    fun modeIsReported() {
        assertEquals(GuardMode.OBSERVE, observe().currentMode())
    }

    @Test
    fun smartStillBlocksWhatObserveAllows() {
        val smart = GuardEngine(
            BuiltinRules.buildAllowSet(),
            BuiltinRules.buildDenySet(includeAds = true),
            GuardMode.SMART
        )
        assertFalse(smart.decide("abc.top").allowed)
        assertTrue(observe().decide("abc.top").allowed)
    }
}
