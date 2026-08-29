package com.example.omnirelay.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Privacy envelope for immediate opportunistic forwarding over untrusted nearby phones.
 *
 * The complete OmniFrame is encrypted again and padded before a relay sees it.
 * Relays can decrement the unauthenticated hop counter, but cannot identify the
 * sender or recipient, inspect the inner header, or alter the protected frame.
 */
data class RelayCapsule(
    val remainingHops: Int,
    val capsuleId: ByteArray,
    val routeTag: ByteArray,
    val iv: ByteArray,
    val macTag: ByteArray,
    val cipherText: ByteArray
) {
    init {
        require(remainingHops in 0..MAX_HOPS) { "Invalid relay hop count" }
        require(capsuleId.size == ID_BYTES) { "Invalid capsule ID" }
        require(routeTag.size == ROUTE_TAG_BYTES) { "Invalid route tag" }
        require(iv.size == CryptoEngine.IV_LENGTH_BYTES) { "Invalid relay IV" }
        require(macTag.size == CryptoEngine.MAC_TAG_LENGTH_BYTES) { "Invalid relay tag" }
        require(cipherText.size in MIN_CIPHER_TEXT_BYTES..MAX_CIPHER_TEXT_BYTES) {
            "Invalid relay ciphertext length"
        }
    }

    val canForward: Boolean get() = remainingHops > 0

    fun forwarded(): RelayCapsule? = if (canForward) {
        copy(
            remainingHops = remainingHops - 1,
            capsuleId = capsuleId.copyOf(),
            routeTag = routeTag.copyOf(),
            iv = iv.copyOf(),
            macTag = macTag.copyOf(),
            cipherText = cipherText.copyOf()
        )
    } else null

    fun pack(): ByteArray = ByteBuffer.allocate(FIXED_HEADER_BYTES + cipherText.size)
        .order(ByteOrder.BIG_ENDIAN)
        .apply {
            put(MAGIC)
            put(VERSION)
            put(remainingHops.toByte())
            putShort(0)
            putInt(cipherText.size)
            put(capsuleId)
            put(routeTag)
            put(iv)
            put(macTag)
            put(cipherText)
        }
        .array()

    /** Returns the protected OmniFrame only when this shared key owns the route tag. */
    fun tryOpen(sharedKey: ByteArray): ByteArray? {
        if (!MessageDigest.isEqual(routeTag, routeTagFor(sharedKey, capsuleId))) return null
        val contentKey = contextKey(sharedKey, CONTENT_LABEL, capsuleId)
        val plain = CryptoEngine.decryptPayload(
            CryptoEngine.EncryptedResult(cipherText, iv, macTag),
            contentKey,
            authenticatedData(capsuleId, routeTag)
        ) ?: return null
        if (plain.size < LENGTH_BYTES) return null
        val innerLength = ByteBuffer.wrap(plain, 0, LENGTH_BYTES).order(ByteOrder.BIG_ENDIAN).int
        if (innerLength !in OmniFrame.HEADER_SIZE..MAX_INNER_FRAME_BYTES) return null
        if (innerLength > plain.size - LENGTH_BYTES) return null
        return plain.copyOfRange(LENGTH_BYTES, LENGTH_BYTES + innerLength)
    }

    companion object {
        private val MAGIC = byteArrayOf(0x4F, 0x52, 0x43, 0x32) // ORC2
        private const val VERSION: Byte = 1
        const val MAX_HOPS = 3
        const val DEFAULT_HOPS = 2
        const val ID_BYTES = 16
        const val ROUTE_TAG_BYTES = 16
        private const val LENGTH_BYTES = 4
        private const val PADDING_BUCKET_BYTES = 256
        private const val MAX_INNER_FRAME_BYTES = OmniFrame.HEADER_SIZE + 65_535
        private const val MIN_CIPHER_TEXT_BYTES = PADDING_BUCKET_BYTES
        private const val MAX_CIPHER_TEXT_BYTES = 66_048
        private const val FIXED_HEADER_BYTES = 72
        const val MAX_PACKED_BYTES = FIXED_HEADER_BYTES + MAX_CIPHER_TEXT_BYTES
        private val ROUTE_LABEL = "OmniRelay/RelayCapsule/route/v1".toByteArray(Charsets.UTF_8)
        private val CONTENT_LABEL = "OmniRelay/RelayCapsule/content/v1".toByteArray(Charsets.UTF_8)
        private val random = SecureRandom()

        fun isCapsule(bytes: ByteArray): Boolean =
            bytes.size >= MAGIC.size && MAGIC.indices.all { bytes[it] == MAGIC[it] }

        fun seal(innerFrame: ByteArray, sharedKey: ByteArray, maxHops: Int = DEFAULT_HOPS): RelayCapsule {
            require(innerFrame.size in OmniFrame.HEADER_SIZE..MAX_INNER_FRAME_BYTES) {
                "Invalid inner OmniFrame length"
            }
            require(maxHops in 1..MAX_HOPS) { "Relay hops must be in 1..$MAX_HOPS" }
            val capsuleId = ByteArray(ID_BYTES).also(random::nextBytes)
            val routeTag = routeTagFor(sharedKey, capsuleId)
            val required = LENGTH_BYTES + innerFrame.size
            val paddedLength = ((required + PADDING_BUCKET_BYTES - 1) / PADDING_BUCKET_BYTES) *
                PADDING_BUCKET_BYTES
            require(paddedLength <= MAX_CIPHER_TEXT_BYTES) { "Inner frame is too large to pad" }
            val padded = ByteArray(paddedLength).also(random::nextBytes)
            ByteBuffer.wrap(padded).order(ByteOrder.BIG_ENDIAN).putInt(innerFrame.size).put(innerFrame)
            val contentKey = contextKey(sharedKey, CONTENT_LABEL, capsuleId)
            val encrypted = CryptoEngine.encryptPayload(
                padded,
                contentKey,
                authenticatedData(capsuleId, routeTag)
            )
            return RelayCapsule(
                maxHops,
                capsuleId,
                routeTag,
                encrypted.iv,
                encrypted.macTag,
                encrypted.cipherText
            )
        }

        fun unpack(bytes: ByteArray): RelayCapsule? = runCatching {
            if (bytes.size !in FIXED_HEADER_BYTES..MAX_PACKED_BYTES || !isCapsule(bytes)) return null
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            val magic = ByteArray(MAGIC.size).also(buffer::get)
            if (!magic.contentEquals(MAGIC) || buffer.get() != VERSION) return null
            val remainingHops = buffer.get().toInt() and 0xFF
            if (remainingHops !in 0..MAX_HOPS || buffer.short.toInt() != 0) return null
            val cipherLength = buffer.int
            if (cipherLength !in MIN_CIPHER_TEXT_BYTES..MAX_CIPHER_TEXT_BYTES) return null
            if (bytes.size != FIXED_HEADER_BYTES + cipherLength) return null
            RelayCapsule(
                remainingHops = remainingHops,
                capsuleId = ByteArray(ID_BYTES).also(buffer::get),
                routeTag = ByteArray(ROUTE_TAG_BYTES).also(buffer::get),
                iv = ByteArray(CryptoEngine.IV_LENGTH_BYTES).also(buffer::get),
                macTag = ByteArray(CryptoEngine.MAC_TAG_LENGTH_BYTES).also(buffer::get),
                cipherText = ByteArray(cipherLength).also(buffer::get)
            )
        }.getOrNull()

        private fun routeTagFor(sharedKey: ByteArray, capsuleId: ByteArray): ByteArray =
            contextKey(sharedKey, ROUTE_LABEL, capsuleId).copyOf(ROUTE_TAG_BYTES)

        private fun contextKey(sharedKey: ByteArray, label: ByteArray, context: ByteArray): ByteArray {
            require(sharedKey.size >= CryptoEngine.X25519_KEY_SIZE) { "Relay key must be 32 bytes" }
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(sharedKey.copyOf(CryptoEngine.X25519_KEY_SIZE), "HmacSHA256"))
            mac.update(label)
            mac.update(0)
            mac.update(context)
            return mac.doFinal()
        }

        private fun authenticatedData(capsuleId: ByteArray, routeTag: ByteArray): ByteArray =
            MAGIC + byteArrayOf(VERSION) + capsuleId + routeTag
    }
}
