package com.example.omnirelay.routing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class HourlyByteBudgetTest {
    @Test
    fun enforcesLimitAndResetsAfterAnHour() {
        var now = 1_000L
        val budget = HourlyByteBudget { now }

        assertTrue(budget.tryConsume(60, 100))
        assertFalse(budget.tryConsume(41, 100))
        assertEquals(60, budget.usedBytes())

        now += 60 * 60 * 1_000L
        assertTrue(budget.tryConsume(100, 100))
        assertEquals(100, budget.usedBytes())
    }

    @Test
    fun disabledAndInvalidBudgetsFailSafely() {
        val budget = HourlyByteBudget { 0L }
        assertFalse(budget.tryConsume(1, 0))
        assertThrows(IllegalArgumentException::class.java) { budget.tryConsume(-1, 10) }
    }

    @Test
    fun packetRateLimitStopsBurstsAndResets() {
        var now = 0L
        val limiter = FixedWindowRateLimit(60_000) { now }
        assertTrue(limiter.tryAcquire(2))
        assertTrue(limiter.tryAcquire(2))
        assertFalse(limiter.tryAcquire(2))
        now = 60_000
        assertTrue(limiter.tryAcquire(2))
    }
}
