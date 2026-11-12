package com.linkguard.blocker

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 学习结果的整理逻辑。这里的取舍直接决定"用户要不要自己挑域名"，
 * 所以每个清洗规则都要有测试盯着。
 */
class LearnedFilterTest {

    private fun prepare(
        hosts: List<String>,
        allowed: Set<String> = emptySet(),
        denied: Set<String> = emptySet()
    ): List<String> = LearnedFilter.prepare(
        hosts,
        isAlreadyAllowed = { allowed.any { a -> it == a || it.endsWith(".$a") } },
        isDenied = { denied.any { d -> it == d || it.endsWith(".$d") } }
    )

    @Test
    fun collapsesSubdomainsToParent() {
        val result = prepare(
            listOf("img.jd.com", "api.jd.com", "jd.com", "p1.meituan.net", "meituan.net")
        )
        assertTrue(result.contains("jd.com"))
        assertTrue(result.contains("meituan.net"))
        // 子域被父域覆盖，不应重复收录
        assertFalse(result.contains("img.jd.com"))
        assertFalse(result.contains("api.jd.com"))
        assertFalse(result.contains("p1.meituan.net"))
        assertEquals(2, result.size)
    }

    @Test
    fun skipsAlreadyAllowedDomains() {
        val result = prepare(
            listOf("mp.weixin.qq.com", "new-shop.com"),
            allowed = setOf("qq.com")
        )
        assertEquals(listOf("new-shop.com"), result)
    }

    @Test
    fun skipsAdAndTrackingDomains() {
        val result = prepare(
            listOf("cnlogs.umeng.com", "analytics.oceanengine.com", "new-shop.com"),
            denied = setOf("umeng.com", "oceanengine.com")
        )
        assertEquals(listOf("new-shop.com"), result)
    }

    @Test
    fun normalizesAndDropsInvalid() {
        val result = prepare(listOf("Example.COM.", "  ", "localhost", "a.b.com"))
        assertTrue(result.contains("example.com"))
        assertFalse(result.contains("localhost"))
    }

    @Test
    fun capsResultSize() {
        val many = (1..200).map { "site$it.com" }
        val result = prepare(many)
        assertEquals(LearnedFilter.MAX_RESULT, result.size)
    }

    @Test
    fun keepsDistinctDomains() {
        val result = prepare(listOf("a-shop.com", "b-shop.com", "c.cn"))
        assertEquals(3, result.size)
    }
}
