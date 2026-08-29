package com.example.omnirelay.protocol

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayReplayTrackerTest {
    private val pairKey = ByteArray(32) { (it * 11 + 7).toByte() }
    private val recipientA = ByteArray(32) { (it + 1).toByte() }
    private val recipientB = ByteArray(32) { (it + 2).toByte() }

    @Test
    fun authenticatedDeliveryCannotBePoisonedAcrossRecipients() {
        val tracker = RelayReplayTracker(8)
        val capsule = RelayCapsule.seal(ByteArray(OmniFrame.HEADER_SIZE) { it.toByte() }, pairKey, 3)

        assertTrue(tracker.markAuthenticatedDelivery(recipientA, capsule))
        assertFalse(tracker.markAuthenticatedDelivery(recipientA, capsule))
        assertTrue(tracker.markAuthenticatedDelivery(recipientB, capsule))
    }

    @Test
    fun lowerHopCopyCannotSuppressLaterHigherHopCopy() {
        val tracker = RelayReplayTracker(8)
        val original = RelayCapsule.seal(ByteArray(OmniFrame.HEADER_SIZE) { it.toByte() }, pairKey, 3)
        val lowered = original.copy(remainingHops = 1)

        assertTrue(tracker.markForwardProgress(lowered))
        assertTrue(tracker.markForwardProgress(original))
        assertFalse(tracker.markForwardProgress(original.copy(remainingHops = 2)))
        assertFalse(tracker.markForwardProgress(original))
    }
}
