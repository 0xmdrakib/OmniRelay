package com.example.omnirelay.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class OmniFrameCipherTest {
    private val alice = CryptoEngine.generateX25519KeyPair()
    private val bob = CryptoEngine.generateX25519KeyPair()
    private val aliceShared = CryptoEngine.deriveSharedSecret(alice.privateKey, bob.publicKey)
    private val bobShared = CryptoEngine.deriveSharedSecret(bob.privateKey, alice.publicKey)

    @Test
    fun directionalRoundTripAuthenticatesAllImmutableMetadata() {
        val plaintext = "direction-bound".toByteArray()
        val metadata = OmniFrame(
            flags = OmniFrame.FLAG_E2EE,
            pathVectorMap = 3,
            priorityToken = 17,
            sequenceNumber = 1234,
            timestampMs = 5678,
            ephemeralPublicKey = alice.publicKey,
            payloadType = OmniFrame.PAYLOAD_TYPE_TEXT
        )
        val sealed = OmniFrameCipher.seal(metadata, plaintext, aliceShared, alice.publicKey, bob.publicKey)

        assertArrayEquals(plaintext, OmniFrameCipher.open(sealed, bobShared, bob.publicKey))
        assertNull(OmniFrameCipher.open(sealed.copy(sequenceNumber = 1235), bobShared, bob.publicKey))
        assertNull(OmniFrameCipher.open(sealed.copy(flags = OmniFrame.FLAG_E2EE orByte OmniFrame.FLAG_RELAY_ALLOWED), bobShared, bob.publicKey))
    }

    @Test
    fun reflectedCiphertextCannotAuthenticateAsTheOtherDirection() {
        val plaintext = "do not reflect me".toByteArray()
        val original = OmniFrameCipher.seal(
            OmniFrame(ephemeralPublicKey = alice.publicKey, payloadType = OmniFrame.PAYLOAD_TYPE_TEXT),
            plaintext,
            aliceShared,
            alice.publicKey,
            bob.publicKey
        )
        val reflectedPayload = alice.publicKey.copyOf(OmniFrameCipher.RECIPIENT_PREFIX_BYTES) +
            original.encryptedPayload.copyOfRange(
                OmniFrameCipher.RECIPIENT_PREFIX_BYTES,
                original.encryptedPayload.size
            )
        val reflected = original.copy(
            ephemeralPublicKey = bob.publicKey,
            encryptedPayload = reflectedPayload
        )

        assertFalse(aliceShared.contentEquals(ByteArray(aliceShared.size)))
        assertNull(OmniFrameCipher.open(reflected, aliceShared, alice.publicKey))
    }

    @Test
    fun authenticatedLow32TimestampHasWrapSafeShortFreshness() {
        val modulus = 1L shl 32
        val now = modulus + 1_000L
        val fresh = OmniFrame(timestampMs = (now - 500L).toInt())
        val stale = OmniFrame(timestampMs = (now - 60_000L).toInt())
        val future = OmniFrame(timestampMs = (now + 15_001L).toInt())

        assertEquals(59_500L, fresh.remainingLifetimeMillis(60_000L, 15_000L, now))
        assertNull(stale.remainingLifetimeMillis(60_000L, 15_000L, now))
        assertNull(future.remainingLifetimeMillis(60_000L, 15_000L, now))
    }

    private infix fun Byte.orByte(other: Byte): Byte = (toInt() or other.toInt()).toByte()
}
