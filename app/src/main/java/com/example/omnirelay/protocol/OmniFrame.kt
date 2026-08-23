package com.example.omnirelay.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * OmniFrame: Fixed 64-byte Protocol Header + Variable Encrypted Payload.
 * Supports compact 20-byte BLE Advertising frames for zero-data beaconing & signaling.
 *
 * Wire Layout (64-byte header):
 * [0.0 - 0.3]: Version (4 bits)
 * [0.4 - 0.7]: Flags (4 bits: E2EE, FEC, Voice, Relay)
 * [1.0 - 1.7]: Path Vector Map (8 bits: Mesh, Cell Control, LEO Sat)
 * [2.0 - 3.7]: Priority Token (16 bits)
 * [4.0 - 7.7]: Sequence Number (32 bits)
 * [8.0 - 11.7]: Timestamp (32 bits / ms epoch)
 * [12.0 - 43.7]: Ephemeral Public Key (32 bytes / X25519)
 * [44.0 - 59.7]: MAC Tag (16 bytes / Poly1305)
 * [60.0 - 61.7]: Payload Length (16 bits)
 * [62.0 - 62.7]: Payload Type (8 bits: 0x01 Text, 0x02 Voice, 0x03 Handshake)
 * [63.0 - 63.7]: Reserved Alignment (8 bits)
 */
data class OmniFrame(
    val version: Byte = 0x01,
    val flags: Byte = 0x0F, // Default: E2EE | FEC | Voice | Relay
    val pathVectorMap: Byte = 0x07, // Bitmask: Mesh | Cell | LEO
    val priorityToken: Short = 0x03E8.toShort(), // Sponsored 3x Queue Class
    val sequenceNumber: Int = (1..999999).random(),
    val timestampMs: Int = (System.currentTimeMillis() and 0xFFFFFFFFL).toInt(),
    val ephemeralPublicKey: ByteArray = ByteArray(32),
    val macTag: ByteArray = ByteArray(16),
    val payloadType: Byte = PAYLOAD_TYPE_TEXT,
    val encryptedPayload: ByteArray = ByteArray(0)
) {
    companion object {
        const val HEADER_SIZE = 64
        const val COMPACT_FRAME_SIZE = 20
        const val COMPACT_KEY_PREFIX_SIZE = 7

        const val PAYLOAD_TYPE_TEXT: Byte = 0x01
        const val PAYLOAD_TYPE_VOICE: Byte = 0x02
        const val PAYLOAD_TYPE_HANDSHAKE: Byte = 0x03
        const val PAYLOAD_TYPE_CALL_RING: Byte = 0x04
        const val PAYLOAD_TYPE_CALL_ACCEPT: Byte = 0x05
        const val PAYLOAD_TYPE_CALL_DECLINE: Byte = 0x06
        const val PAYLOAD_TYPE_CALL_END: Byte = 0x07
        const val PAYLOAD_TYPE_PRESENCE: Byte = 0x08

        const val FLAG_E2EE: Byte = 0x01
        const val FLAG_FEC_ENCODED: Byte = 0x02
        const val FLAG_VOICE_STREAM: Byte = 0x04
        const val FLAG_RELAY_ALLOWED: Byte = 0x08

        fun unpack(bytes: ByteArray): OmniFrame? {
            if (bytes.size < COMPACT_FRAME_SIZE) return null

            if (bytes.size < HEADER_SIZE) {
                // Compact advertisements contain discovery metadata only. Actual
                // payloads are transferred over GATT or Wi-Fi Aware.
                val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
                val verAndFlags = buffer.get().toInt() and 0xFF
                val version = ((verAndFlags shr 4) and 0x0F).toByte()
                val flags = (verAndFlags and 0x0F).toByte()

                val pathVectorMap = buffer.get()
                val priorityToken = buffer.short
                val sequenceNumber = buffer.int
                val timestampMs = buffer.int

                val ephemeralPubKey = ByteArray(CryptoEngine.X25519_KEY_SIZE)
                buffer.get(ephemeralPubKey, 0, COMPACT_KEY_PREFIX_SIZE)
                val pType = buffer.get()

                return OmniFrame(
                    version = version,
                    flags = flags,
                    pathVectorMap = pathVectorMap,
                    priorityToken = priorityToken,
                    sequenceNumber = sequenceNumber,
                    timestampMs = timestampMs,
                    ephemeralPublicKey = ephemeralPubKey,
                    macTag = ByteArray(16),
                    payloadType = pType,
                    encryptedPayload = ByteArray(0)
                )
            }

            // Parse Full 64-byte Packet
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            val verAndFlags = buffer.get().toInt() and 0xFF
            val version = ((verAndFlags shr 4) and 0x0F).toByte()
            val flags = (verAndFlags and 0x0F).toByte()

            val pathVectorMap = buffer.get()
            val priorityToken = buffer.short
            val sequenceNumber = buffer.int
            val timestampMs = buffer.int

            val ephemeralPubKey = ByteArray(32)
            buffer.get(ephemeralPubKey)

            val macTag = ByteArray(16)
            buffer.get(macTag)

            val payloadLength = buffer.short.toInt() and 0xFFFF
            val payloadType = buffer.get()
            val reserved = buffer.get()

            if (bytes.size < HEADER_SIZE + payloadLength) return null

            val encryptedPayload = ByteArray(payloadLength)
            buffer.get(encryptedPayload)

            return OmniFrame(
                version = version,
                flags = flags,
                pathVectorMap = pathVectorMap,
                priorityToken = priorityToken,
                sequenceNumber = sequenceNumber,
                timestampMs = timestampMs,
                ephemeralPublicKey = ephemeralPubKey,
                macTag = macTag,
                payloadType = payloadType,
                encryptedPayload = encryptedPayload
            )
        }
    }

    fun pack(): ByteArray {
        val payloadLen = encryptedPayload.size
        require(payloadLen <= 0xFFFF) { "OmniFrame payload exceeds the 16-bit wire limit" }
        val totalSize = HEADER_SIZE + payloadLen
        val buffer = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN)

        val verAndFlags = (((version.toInt() and 0x0F) shl 4) or (flags.toInt() and 0x0F)).toByte()
        buffer.put(verAndFlags)
        buffer.put(pathVectorMap)
        buffer.putShort(priorityToken)
        buffer.putInt(sequenceNumber)
        buffer.putInt(timestampMs)

        val pubKeyPadded = ByteArray(32)
        System.arraycopy(ephemeralPublicKey, 0, pubKeyPadded, 0, minOf(32, ephemeralPublicKey.size))
        buffer.put(pubKeyPadded)

        val macPadded = ByteArray(16)
        System.arraycopy(macTag, 0, macPadded, 0, minOf(16, macTag.size))
        buffer.put(macPadded)

        buffer.putShort(payloadLen.toShort())
        buffer.put(payloadType)
        buffer.put(0x00.toByte()) // Reserved

        buffer.put(encryptedPayload)
        return buffer.array()
    }

    /** Packs metadata for a legacy-size BLE manufacturer advertisement. */
    fun packCompact(): ByteArray {
        val buffer = ByteBuffer.allocate(COMPACT_FRAME_SIZE).order(ByteOrder.BIG_ENDIAN)
        val verAndFlags = (((version.toInt() and 0x0F) shl 4) or (flags.toInt() and 0x0F)).toByte()
        buffer.put(verAndFlags)
        buffer.put(pathVectorMap)
        buffer.putShort(priorityToken)
        buffer.putInt(sequenceNumber)
        buffer.putInt(timestampMs)

        val normalizedKey = CryptoEngine.normalizePublicKey(ephemeralPublicKey)
        buffer.put(normalizedKey, 0, COMPACT_KEY_PREFIX_SIZE)
        buffer.put(payloadType)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as OmniFrame
        return sequenceNumber == other.sequenceNumber &&
                version == other.version &&
                encryptedPayload.contentEquals(other.encryptedPayload)
    }

    override fun hashCode(): Int {
        var result = sequenceNumber
        result = 31 * result + encryptedPayload.contentHashCode()
        return result
    }
}
