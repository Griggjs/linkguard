package com.linkguard.blocker

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainSetTest {

    @Test
    fun exactAndSubdomain() {
        val s = DomainSet(listOf("qq.com"))
        assertEquals("qq.com", s.match("qq.com"))
        assertEquals("qq.com", s.match("mp.weixin.qq.com"))
        assertEquals("qq.com", s.match("A.Qq.Com."))
    }

    @Test
    fun labelBoundaryNotRawSuffix() {
        val s = DomainSet(listOf("qq.com"))
        assertNull(s.match("notqq.com"))
        assertNull(s.match("qq.com.cn"))
        assertNull(s.match("evil.com"))
    }

    @Test
    fun longestMatchWins() {
        val s = DomainSet(listOf("qq.com", "mp.weixin.qq.com"))
        assertEquals("mp.weixin.qq.com", s.match("x.mp.weixin.qq.com"))
    }

    @Test
    fun adblockSyntaxAccepted() {
        val s = DomainSet(listOf("||bad.top^", "*.wild.xyz", ".dot.kr", "@@||good.com^"))
        assertTrue(s.contains("bad.top"))
        assertTrue(s.contains("wild.xyz"))
        assertTrue(s.contains("dot.kr"))
        assertFalse(s.contains("good.com"))   // @@ 是白名单例外，不能进黑名单
    }

    @Test
    fun rejectsSingleLabelAndEmpty() {
        val s = DomainSet()
        assertFalse(s.add("localhost"))
        assertFalse(s.add(""))
        assertFalse(s.add("   "))
        assertEquals(0, s.size())
    }

    @Test
    fun dedupAndRemove() {
        val s = DomainSet(listOf("a.com", "a.com"))
        assertEquals(1, s.size())
        assertTrue(s.remove("a.com"))
        assertFalse(s.contains("a.com"))
    }

    @Test
    fun userInputStripsSchemePathAndPort() {
        assertEquals("example.com", DomainName.fromUserInput("https://example.com/a/b?c=1"))
        assertEquals("www.example.com", DomainName.fromUserInput("  HTTPS://WWW.Example.COM:8080/x  "))
        assertEquals("example.com", DomainName.fromUserInput("example.com"))
        assertEquals("example.com", DomainName.fromUserInput("example.com."))
        assertEquals("", DomainName.fromUserInput("   "))
        assertEquals("", DomainName.fromUserInput(null))
    }

    @Test
    fun plausibleDomainValidation() {
        assertTrue(DomainName.isPlausibleDomain("example.com"))
        assertTrue(DomainName.isPlausibleDomain("mp.weixin.qq.com"))
        assertTrue(DomainName.isPlausibleDomain("x.top"))
        // 纯 IP 不算域名
        assertFalse(DomainName.isPlausibleDomain("192.168.1.1"))
        // 单标签、空、带协议、带斜杠都不行
        assertFalse(DomainName.isPlausibleDomain("localhost"))
        assertFalse(DomainName.isPlausibleDomain(""))
        assertFalse(DomainName.isPlausibleDomain("http://a.com"))
        assertFalse(DomainName.isPlausibleDomain("a..b"))
    }

    @Test
    fun manualDomainBecomesMatchable() {
        val set = DomainSet()
        set.add(DomainName.fromUserInput("https://example.com/path"))
        assertTrue(set.contains("api.example.com"))
    }
}
