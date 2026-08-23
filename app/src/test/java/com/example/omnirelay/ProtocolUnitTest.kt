package com.example.omnirelay

import com.example.omnirelay.media.AdpcmCodec
import com.example.omnirelay.protocol.CryptoEngine
import com.example.omnirelay.protocol.FecEngine
import com.example.omnirelay.protocol.OmniFragment
import com.example.omnirelay.protocol.OmniFrame
import org.junit.Assert.*
import org.junit.Test

class ProtocolUnitTest {

    @Test
    fun testOmniFramePackAndUnpack() {
        val originalPayload = "Hello OmniRelay Zero-Data Mesh!".toByteArray()
        val senderKey = ByteArray(32) { (it + 10).toByte() }
        val originalFrame = OmniFrame(
            sequenceNumber = 42,
            payloadType = OmniFrame.PAYLOAD_TYPE_CALL_RING,
            ephemeralPublicKey = senderKey,
            encryptedPayload = originalPayload
        )

        val packedBytes = originalFrame.pack()
        assertEquals(OmniFrame.HEADER_SIZE + originalPayload.size, packedBytes.size)

        val unpackedFrame = OmniFrame.unpack(packedBytes)
        assertNotNull(unpackedFrame)
        assertEquals(42, unpackedFrame!!.sequenceNumber)
        assertEquals(OmniFrame.PAYLOAD_TYPE_CALL_RING, unpackedFrame.payloadType)
        assertArrayEquals(senderKey, unpackedFrame.ephemeralPublicKey)
        assertArrayEquals(originalPayload, unpackedFrame.encryptedPayload)
    }

    @Test
    fun testCompactFrameContainsPresenceMetadataButNoPayload() {
        val senderKey = ByteArray(32) { (it + 1).toByte() }
        val compact = OmniFrame(
            sequenceNumber = 77,
            payloadType = OmniFrame.PAYLOAD_TYPE_PRESENCE,
            ephemeralPublicKey = senderKey,
            encryptedPayload = "must-not-be-advertised".toByteArray()
        ).packCompact()

        assertEquals(20, compact.size)
        val unpacked = OmniFrame.unpack(compact)!!
        assertEquals(77, unpacked.sequenceNumber)
        assertEquals(OmniFrame.PAYLOAD_TYPE_PRESENCE, unpacked.payloadType)
        assertArrayEquals(
            senderKey.copyOfRange(0, OmniFrame.COMPACT_KEY_PREFIX_SIZE),
            unpacked.ephemeralPublicKey.copyOfRange(0, OmniFrame.COMPACT_KEY_PREFIX_SIZE)
        )
        assertTrue(unpacked.encryptedPayload.isEmpty())
    }

    @Test
    fun testCallSignalingFrame() {
        val ringFrame = OmniFrame(
            payloadType = OmniFrame.PAYLOAD_TYPE_CALL_RING,
            sequenceNumber = 101,
            encryptedPayload = "omni://node-8f3a92".toByteArray()
        )
        val packed = ringFrame.pack()
        val unpacked = OmniFrame.unpack(packed)

        assertNotNull(unpacked)
        assertEquals(OmniFrame.PAYLOAD_TYPE_CALL_RING, unpacked!!.payloadType)
        assertEquals("omni://node-8f3a92", String(unpacked.encryptedPayload))
    }

    @Test
    fun testAdpcmCodecIntelligibility() {
        val pcm = ByteArray(640)
        for (i in 0 until 320) {
            val sample = (Math.sin(2.0 * Math.PI * 440.0 * i / 16000) * 10000).toInt().toShort()
            pcm[i * 2] = (sample.toInt() and 0xFF).toByte()
            pcm[i * 2 + 1] = ((sample.toInt() shr 8) and 0xFF).toByte()
        }

        val state = AdpcmCodec.State()
        val adpcm = AdpcmCodec.encode(pcm, state)
        assertEquals(160, adpcm.size) // 4:1 compression

        val decodedPcm = AdpcmCodec.decode(adpcm, AdpcmCodec.State())
        assertEquals(640, decodedPcm.size)
    }

    @Test
    fun testOmniFragmentPackAndUnpack() {
        val fragData = "FragmentData".toByteArray()
        val fragment = OmniFragment(
            flowId = 1001,
            fragmentIndex = 1,
            totalFragments = 3,
            pathIdTag = 0x01,
            fecBlockId = 0x0A,
            symbolIndex = 0,
            fragmentData = fragData
        )

        val packed = fragment.pack()
        assertEquals(OmniFragment.FRAGMENT_HEADER_SIZE + fragData.size, packed.size)

        val unpacked = OmniFragment.unpack(packed)
        assertNotNull(unpacked)
        assertEquals(1001, unpacked!!.flowId)
        assertEquals(1.toShort(), unpacked.fragmentIndex)
        assertArrayEquals(fragData, unpacked.fragmentData)
    }

    @Test
    fun testCryptoEngineEncryptionDecryption() {
        val masterKey = ByteArray(32) { (it + 1).toByte() }
        val plainText = "Secret E2EE Audio Payload Data".toByteArray()

        val encrypted = CryptoEngine.encryptPayload(plainText, masterKey)
        assertNotNull(encrypted)
        assertEquals(16, encrypted.macTag.size)
        assertEquals(12, encrypted.iv.size)

        val decrypted = CryptoEngine.decryptPayload(encrypted, masterKey)
        assertNotNull(decrypted)
        assertArrayEquals(plainText, decrypted)
    }

    @Test
    fun testX25519AgreementEncryptsAcrossTwoDifferentDevices() {
        val alice = CryptoEngine.generateX25519KeyPair()
        val bob = CryptoEngine.generateX25519KeyPair()
        val aliceShared = CryptoEngine.deriveSharedSecret(alice.privateKey, bob.publicKey)
        val bobShared = CryptoEngine.deriveSharedSecret(bob.privateKey, alice.publicKey)
        assertArrayEquals(aliceShared, bobShared)

        val encrypted = CryptoEngine.encryptPayload("hello bob".toByteArray(), aliceShared)
        assertEquals("hello bob", String(CryptoEngine.decryptPayload(encrypted, bobShared)!!))
    }

    @Test
    fun testCallMediaKeyIsSharedAndBoundToCallId() {
        val alice = CryptoEngine.generateX25519KeyPair()
        val bob = CryptoEngine.generateX25519KeyPair()
        val aliceKey = CryptoEngine.deriveCallMediaKey(alice.privateKey, bob.publicKey, "call-one")
        val bobKey = CryptoEngine.deriveCallMediaKey(bob.privateKey, alice.publicKey, "call-one")
        val nextCallKey = CryptoEngine.deriveCallMediaKey(alice.privateKey, bob.publicKey, "call-two")
        assertArrayEquals(aliceKey, bobKey)
        assertFalse(aliceKey.contentEquals(nextCallKey))
    }

    @Test
    fun testFecLossRecovery() {
        val packet1 = "VoiceChunk1".toByteArray()
        val packet2 = "VoiceChunk2".toByteArray()
        val sourcePackets = listOf(packet1, packet2)

        val symbols = FecEngine.encodeFecBlock(sourcePackets, parityCount = 1, blockId = 0x01)
        assertEquals(3, symbols.size)

        val incompleteReceived = listOf(symbols[0], symbols[2])
        val reconstructed = FecEngine.decodeFecBlock(incompleteReceived, totalSourceCount = 2)

        assertNotNull(reconstructed)
        assertEquals(2, reconstructed!!.size)
        assertArrayEquals(packet1, reconstructed[0])
        assertArrayEquals(packet2, reconstructed[1])
    }
}
