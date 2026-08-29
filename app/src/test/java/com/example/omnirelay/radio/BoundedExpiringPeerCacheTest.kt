package com.example.omnirelay.radio

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BoundedExpiringPeerCacheTest {
    @Test
    fun cacheEvictsLeastRecentlyUsedEntryAtStrictBound() {
        var now = 1_000L
        val cache = BoundedExpiringPeerCache<String, Int>(2, 10_000L) { now }
        cache.put("first", 1)
        cache.put("second", 2)
        assertEquals(2, cache.snapshot().size)

        now++
        cache.put("third", 3)
        val keys = cache.snapshot().map { it.first }.toSet()
        assertEquals(2, keys.size)
        assertFalse("first" in keys)
        assertTrue("second" in keys)
        assertTrue("third" in keys)
    }

    @Test
    fun cacheExpiresEntriesAndHandlesClockRollback() {
        var now = 500L
        val cache = BoundedExpiringPeerCache<String, Int>(4, 100L) { now }
        cache.put("peer", 7)
        now = 599L
        assertEquals(1, cache.size())
        now = 600L
        assertEquals(0, cache.size())

        cache.put("rollback", 8)
        now = 1L
        assertEquals(0, cache.size())
    }

    @Test
    fun putIfAbsentRejectsReplayUntilEntryExpires() {
        var now = 10L
        val cache = BoundedExpiringPeerCache<String, Unit>(4, 100L) { now }
        assertTrue(cache.putIfAbsent("control-id", Unit))
        assertFalse(cache.putIfAbsent("control-id", Unit))
        now = 110L
        assertTrue(cache.putIfAbsent("control-id", Unit))
    }

    @Test
    fun getOrPutReusesAndRefreshesBoundedPeerState() {
        var now = 0L
        var created = 0
        val cache = BoundedExpiringPeerCache<String, Int>(2, 100L) { now }
        assertEquals(1, cache.getOrPut("peer") { ++created })
        now = 90L
        assertEquals(1, cache.getOrPut("peer") { ++created })
        now = 150L
        assertEquals(1, cache.size())
        assertEquals(1, created)
    }

    @Test
    fun permitBudgetAcquiresWholeFragmentSetOrNothing() {
        var now = 0L
        val budget = FixedWindowPermitBudget(10, 1_000L) { now }
        assertTrue(budget.tryAcquire(7))
        assertFalse(budget.tryAcquire(4))
        assertEquals(7, budget.usedPermits())
        assertTrue(budget.tryAcquire(3))
        assertEquals(10, budget.usedPermits())

        now = 1_000L
        assertTrue(budget.tryAcquire(10))
        assertEquals(10, budget.usedPermits())
    }

    @Test
    fun retryBackoffIsExponentialBoundedAndResettable() {
        val backoff = BoundedRetryBackoff(1_000L, 30_000L)
        assertEquals(1_000L, backoff.nextDelayMillis())
        assertEquals(2_000L, backoff.nextDelayMillis())
        assertEquals(4_000L, backoff.nextDelayMillis())
        assertEquals(8_000L, backoff.nextDelayMillis())
        assertEquals(16_000L, backoff.nextDelayMillis())
        assertEquals(30_000L, backoff.nextDelayMillis())
        assertEquals(30_000L, backoff.nextDelayMillis())
        backoff.reset()
        assertEquals(1_000L, backoff.nextDelayMillis())
    }
}
