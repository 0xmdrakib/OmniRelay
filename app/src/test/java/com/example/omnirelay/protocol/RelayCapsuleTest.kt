package com.example.omnirelay.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

class RelayCapsuleTest {
    private val sharedKey = ByteArray(32) { (it * 7 + 3).toByte() }
    private val innerFrame = OmniFrame(
        payloadType = OmniFrame.PAYLOAD_TYPE_TEXT,
        ephemeralPublicKey = ByteArray(32) { it.toByte() },
        encryptedPayload = "opaque-message".toByteArray()
    ).pack()

    @Test
    fun capsuleRoundTripHidesAndRestoresCompleteFrame() {
        val capsule = RelayCapsule.seal(innerFrame, sharedKey)
        val packed = capsule.pack()

        assertTrue(RelayCapsule.isCapsule(packed))
        assertFalse(packed.containsSubsequence(innerFrame))
        val unpacked = RelayCapsule.unpack(packed)
        assertNotNull(unpacked)
        assertArrayEquals(innerFrame, unpacked!!.tryOpen(sharedKey))
    }

    @Test
    fun wrongKeyAndTamperingCannotOpenCapsule() {
        val packed = RelayCapsule.seal(innerFrame, sharedKey).pack()
        val capsule = RelayCapsule.unpack(packed)
        assertNotNull(capsule)
        assertNull(capsule!!.tryOpen(ByteArray(32) { 9 }))

        packed[packed.lastIndex] = (packed.last() + 1).toByte()
        assertNull(RelayCapsule.unpack(packed)?.tryOpen(sharedKey))
    }

    @Test
    fun forwardingOnlyChangesBoundedHopCounter() {
        val original = RelayCapsule.seal(innerFrame, sharedKey, maxHops = 2)
        val first = original.forwarded()
        assertNotNull(first)
        val second = first!!.forwarded()
        assertNotNull(second)

        assertEquals(1, first.remainingHops)
        assertEquals(0, second!!.remainingHops)
        assertNull(second.forwarded())
        assertArrayEquals(innerFrame, second.tryOpen(sharedKey))
    }

    @Test
    fun paddingUsesFixedBuckets() {
        val short = RelayCapsule.seal(innerFrame, sharedKey).pack().size
        val slightlyLonger = RelayCapsule.seal(innerFrame + ByteArray(20), sharedKey).pack().size
        assertEquals(short, slightlyLonger)
    }

    @Test
    fun malformedInputsNeverThrowOrParse() {
        val random = Random(0x0C25)
        repeat(1_000) {
            val bytes = ByteArray(random.nextInt(600)).also(random::nextBytes)
            assertNull(RelayCapsule.unpack(bytes))
        }
        val valid = RelayCapsule.seal(innerFrame, sharedKey).pack()
        for (length in 0 until minOf(valid.size, 100)) {
            assertNull(RelayCapsule.unpack(valid.copyOf(length)))
        }
    }

    private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > size) return false
        return (0..size - needle.size).any { offset ->
            needle.indices.all { index -> this[offset + index] == needle[index] }
        }
    }
}
