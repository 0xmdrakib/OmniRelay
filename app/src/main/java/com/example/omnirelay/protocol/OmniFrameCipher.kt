package com.example.omnirelay.protocol

import java.security.MessageDigest

/** Canonical protocol-v2 payload protection, including direction and identity binding. */
object OmniFrameCipher {
    const val RECIPIENT_PREFIX_BYTES = 8

    fun seal(
        metadata: OmniFrame,
        plaintext: ByteArray,
        pairSharedSecret: ByteArray,
        senderPublicKey: ByteArray,
        recipientPublicKey: ByteArray
    ): OmniFrame {
        val sender = CryptoEngine.normalizePublicKey(senderPublicKey)
        val recipient = CryptoEngine.normalizePublicKey(recipientPublicKey)
        require(MessageDigest.isEqual(metadata.ephemeralPublicKey, sender)) {
            "Frame sender does not match the encryption identity"
        }
        val contentKey = CryptoEngine.deriveOmniFrameContentKey(
            pairSharedSecret,
            sender,
            recipient
        )
        val encrypted = CryptoEngine.encryptPayload(
            plaintext,
            contentKey,
            metadata.authenticatedData(recipient)
        )
        return metadata.copy(
            macTag = encrypted.macTag,
            encryptedPayload = recipient.copyOf(RECIPIENT_PREFIX_BYTES) + encrypted.iv + encrypted.cipherText
        )
    }

    fun open(
        frame: OmniFrame,
        pairSharedSecret: ByteArray,
        recipientPublicKey: ByteArray
    ): ByteArray? = runCatching {
        val recipient = CryptoEngine.normalizePublicKey(recipientPublicKey)
        val minimumSize = RECIPIENT_PREFIX_BYTES + CryptoEngine.IV_LENGTH_BYTES
        require(frame.encryptedPayload.size >= minimumSize)
        val recipientPrefix = frame.encryptedPayload.copyOfRange(0, RECIPIENT_PREFIX_BYTES)
        require(MessageDigest.isEqual(recipientPrefix, recipient.copyOf(RECIPIENT_PREFIX_BYTES)))
        val ivStart = RECIPIENT_PREFIX_BYTES
        val cipherStart = ivStart + CryptoEngine.IV_LENGTH_BYTES
        val encrypted = CryptoEngine.EncryptedResult(
            cipherText = frame.encryptedPayload.copyOfRange(cipherStart, frame.encryptedPayload.size),
            iv = frame.encryptedPayload.copyOfRange(ivStart, cipherStart),
            macTag = frame.macTag
        )
        val contentKey = CryptoEngine.deriveOmniFrameContentKey(
            pairSharedSecret,
            frame.ephemeralPublicKey,
            recipient
        )
        CryptoEngine.decryptPayload(
            encrypted,
            contentKey,
            frame.authenticatedData(recipient)
        ) ?: error("Frame authentication failed")
    }.getOrNull()
}
