package com.example.omnirelay.network

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OutboundRetryPolicyTest {
    @Test
    fun messagesRemainDurableWithoutCallState() {
        assertTrue(OutboundRetryPolicy.shouldAttempt("message", null, null, 0L, Long.MAX_VALUE))
    }

    @Test
    fun callRetryRequiresTheCurrentlyActiveCall() {
        assertTrue(OutboundRetryPolicy.shouldAttempt("call", "call-a", "call-a", 1_000L, 1_500L))
        assertFalse(OutboundRetryPolicy.shouldAttempt("call", "call-a", null, 1_000L, 1_500L))
        assertFalse(OutboundRetryPolicy.shouldAttempt("call", "call-a", "call-b", 1_000L, 1_500L))
        assertFalse(OutboundRetryPolicy.shouldAttempt("call", null, null, 1_000L, 1_500L))
    }

    @Test
    fun staleOrClockInvalidCallSignalsAreRejected() {
        assertFalse(OutboundRetryPolicy.shouldAttempt(
            "call",
            "call-a",
            "call-a",
            1_000L,
            1_000L + OutboundRetryPolicy.MAX_CALL_SIGNAL_AGE_MS
        ))
        assertFalse(OutboundRetryPolicy.shouldAttempt("call", "call-a", "call-a", 2_000L, 1_999L))
        assertFalse(OutboundRetryPolicy.shouldAttempt("call", "call-a", "call-a", -1L, 0L))
    }
}
