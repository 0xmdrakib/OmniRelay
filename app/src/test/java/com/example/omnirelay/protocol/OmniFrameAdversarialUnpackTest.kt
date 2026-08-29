package com.example.omnirelay.protocol

import java.util.Random
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

class OmniFrameAdversarialUnpackTest {
    @Test
    fun inputsShorterThanCompactFrameAreRejected() {
        for (size in 0 until OmniFrame.COMPACT_FRAME_SIZE) {
            assertNull("size=$size", OmniFrame.unpack(ByteArray(size) { 0x5A }))
        }
    }

    @Test
    fun onlyExactCompactLengthIsAcceptedBelowFullHeaderLength() {
        val compact = deterministicFrame(payloadSize = 0).packCompact()
        assertNotNull(OmniFrame.unpack(compact))

        val acceptedAmbiguousLengths =
            ((OmniFrame.COMPACT_FRAME_SIZE + 1) until OmniFrame.HEADER_SIZE)
                .filter { size -> OmniFrame.unpack(compact.copyOf(size)) != null }
        assertEquals(
            "ambiguous packet lengths must not be interpreted as compact",
            emptyList<Int>(),
            acceptedAmbiguousLengths
        )
    }

    @Test
    fun everyTruncatedFullPayloadIsRejected() {
        val packed = deterministicFrame(payloadSize = 257).pack()

        for (size in OmniFrame.HEADER_SIZE until packed.size) {
            assertNull("truncated full frame size=$size", OmniFrame.unpack(packed.copyOf(size)))
        }
        assertArrayEquals(
            deterministicPayload(257),
            OmniFrame.unpack(packed)?.encryptedPayload
        )
    }

    @Test
    fun fullFrameMustMatchItsDeclaredLengthExactly() {
        val packed = deterministicFrame(payloadSize = 32).pack()
        assertNotNull(OmniFrame.unpack(packed))

        assertNull(
            "trailing bytes must not be silently ignored",
            OmniFrame.unpack(packed + byteArrayOf(0x55))
        )
    }

    @Test
    fun oversizedDeclaredPayloadLengthsAreRejectedWithoutAllocationFailure() {
        val declaredLengths = intArrayOf(1, 255, 32_768, 65_535)

        for (declaredLength in declaredLengths) {
            val header = deterministicFrame(payloadSize = 0).pack()
            header[60] = (declaredLength ushr 8).toByte()
            header[61] = declaredLength.toByte()
            assertNull("declaredLength=$declaredLength", OmniFrame.unpack(header))
        }
    }

    @Test
    fun unknownPayloadTypesAreRejectedForCompactAndFullFrames() {
        val unknownTypes = byteArrayOf(0x00, 0x09, 0x7F, 0xFF.toByte())

        val acceptedCompact = unknownTypes.filter { payloadType ->
            val bytes = deterministicFrame(4).packCompact()
            bytes[19] = payloadType
            OmniFrame.unpack(bytes) != null
        }.map { it.toInt() and 0xFF }
        val acceptedFull = unknownTypes.filter { payloadType ->
            val bytes = deterministicFrame(4).pack()
            bytes[62] = payloadType
            OmniFrame.unpack(bytes) != null
        }.map { it.toInt() and 0xFF }

        assertEquals(
            "unknown types accepted: compact=$acceptedCompact full=$acceptedFull",
            emptyList<Int>() to emptyList<Int>(),
            acceptedCompact to acceptedFull
        )
    }

    @Test
    fun compactReservedByteMustBeZero() {
        val compact = deterministicFrame(0).packCompact()
        compact[18] = 1
        assertNull(OmniFrame.unpack(compact))
    }

    @Test(timeout = 3_000L)
    fun arbitraryByteArraysNeverCrashUnpack() {
        val random = Random(0x4F4D4E4952454C41L)

        repeat(4_096) { iteration ->
            val bytes = ByteArray(random.nextInt(1_025))
            random.nextBytes(bytes)
            try {
                OmniFrame.unpack(bytes)
            } catch (throwable: Throwable) {
                fail(
                    "unpack crashed at iteration=$iteration size=${bytes.size}: " +
                        "${throwable::class.java.name}: ${throwable.message}"
                )
            }
        }
    }

    @Test
    fun exactMaximumWirePayloadRoundTrips() {
        val frame = deterministicFrame(payloadSize = 65_535)
        val packed = frame.pack()
        val unpacked = OmniFrame.unpack(packed)

        assertNotNull(unpacked)
        assertEquals(OmniFrame.HEADER_SIZE + 65_535, packed.size)
        assertArrayEquals(frame.encryptedPayload, unpacked?.encryptedPayload)
    }

    private fun deterministicFrame(
        payloadSize: Int,
        payloadType: Byte = OmniFrame.PAYLOAD_TYPE_TEXT
    ): OmniFrame = OmniFrame(
        version = OmniFrame.CURRENT_VERSION,
        flags = OmniFrame.FLAG_E2EE,
        pathVectorMap = 1,
        priorityToken = 1,
        sequenceNumber = 0x10203040,
        timestampMs = 0x50607080,
        ephemeralPublicKey = ByteArray(32) { (it * 3 + 1).toByte() },
        macTag = ByteArray(16) { (it * 5 + 2).toByte() },
        payloadType = payloadType,
        encryptedPayload = deterministicPayload(payloadSize)
    )

    private fun deterministicPayload(size: Int): ByteArray =
        ByteArray(size) { ((it * 31 + 17) and 0xFF).toByte() }
}
