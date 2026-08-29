package com.example.omnirelay.protocol

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Cryptographic primitives used by OmniRelay.
 *
 * Identity links contain the raw 32-byte X25519 public key. Payload keys are
 * derived from a real X25519 agreement and HKDF-SHA256, then encrypted with
 * AES-256-GCM. No private key bytes are ever used directly as an AES key.
 */
object CryptoEngine {

    const val X25519_KEY_SIZE = 32
    const val IV_LENGTH_BYTES = 12
    const val MAC_TAG_LENGTH_BYTES = 16
    private const val AEAD_TAG_LENGTH_BITS = MAC_TAG_LENGTH_BYTES * 8

    private val random = SecureRandom()
    private val x25519PublicDerPrefix = hex("302a300506032b656e032100")
    private val x25519PrivateDerPrefix = hex("302e020100300506032b656e04220420")
    private val hkdfInfo = "OmniRelay/X25519/AES-256-GCM/v1".toByteArray(Charsets.UTF_8)
    private val omniFrameContentLabel =
        "OmniRelay/OmniFrame/content-key/v2\u0000".toByteArray(Charsets.UTF_8)
    private val backendRouteLabel =
        "OmniRelay/Backend-Route/v1\u0000".toByteArray(Charsets.UTF_8)

    data class KeyPairData(
        val publicKey: ByteArray,
        val privateKey: ByteArray
    )

    data class SigningKeyPairData(
        val publicKeyDer: ByteArray,
        val privateKeyDer: ByteArray
    )

    data class EncryptedResult(
        val cipherText: ByteArray,
        val iv: ByteArray,
        val macTag: ByteArray
    )

    fun generateX25519KeyPair(): KeyPairData {
        val keyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair()
        return KeyPairData(
            publicKey = normalizePublicKey(keyPair.public.encoded),
            privateKey = normalizePrivateKey(keyPair.private.encoded)
        )
    }

    fun generateEd25519KeyPair(): SigningKeyPairData {
        val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        return SigningKeyPairData(pair.public.encoded, pair.private.encoded)
    }

    fun signEd25519(privateKeyDer: ByteArray, message: ByteArray): ByteArray {
        val key = KeyFactory.getInstance("Ed25519").generatePrivate(PKCS8EncodedKeySpec(privateKeyDer))
        return Signature.getInstance("Ed25519").run {
            initSign(key)
            update(message)
            sign()
        }
    }

    fun verifyEd25519(publicKeyDer: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        runCatching {
            val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(publicKeyDer))
            Signature.getInstance("Ed25519").run {
                initVerify(key)
                update(message)
                verify(signature)
            }
        }.getOrDefault(false)

    fun isValidX25519KeyPair(pair: KeyPairData): Boolean = runCatching {
        val probe = generateX25519KeyPair()
        MessageDigest.isEqual(
            deriveSharedSecret(pair.privateKey, probe.publicKey),
            deriveSharedSecret(probe.privateKey, pair.publicKey)
        )
    }.getOrDefault(false)

    fun isValidEd25519KeyPair(pair: SigningKeyPairData): Boolean = runCatching {
        val challenge = ByteArray(32).also(random::nextBytes)
        verifyEd25519(pair.publicKeyDer, challenge, signEd25519(pair.privateKeyDer, challenge))
    }.getOrDefault(false)

    /** Converts either raw or standard DER-encoded X25519 keys to 32 raw bytes. */
    fun normalizePublicKey(key: ByteArray): ByteArray = normalizeRawKey(key, x25519PublicDerPrefix)

    fun normalizePrivateKey(key: ByteArray): ByteArray = normalizeRawKey(key, x25519PrivateDerPrefix)

    fun deriveSharedSecret(localPrivateKey: ByteArray, remotePublicKey: ByteArray): ByteArray {
        val privateKey = KeyFactory.getInstance("X25519").generatePrivate(
            PKCS8EncodedKeySpec(x25519PrivateDerPrefix + normalizePrivateKey(localPrivateKey))
        )
        val publicKey = KeyFactory.getInstance("X25519").generatePublic(
            X509EncodedKeySpec(x25519PublicDerPrefix + normalizePublicKey(remotePublicKey))
        )
        val agreement = KeyAgreement.getInstance("X25519")
        agreement.init(privateKey)
        agreement.doPhase(publicKey, true)
        return hkdfSha256(agreement.generateSecret(), hkdfInfo, X25519_KEY_SIZE)
    }

    fun deviceIdForPublicKey(publicKey: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(normalizePublicKey(publicKey))
            .joinToString("") { "%02x".format(it) }

    /** Per-call media key shared only by the two paired X25519 identities. */
    fun deriveCallMediaKey(
        localPrivateKey: ByteArray,
        remotePublicKey: ByteArray,
        callId: String
    ): ByteArray {
        require(callId.isNotBlank()) { "Call ID is required for media key derivation" }
        val sharedSecret = deriveSharedSecret(localPrivateKey, remotePublicKey)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(sharedSecret, "HmacSHA256"))
        mac.update("OmniRelay/LiveKit-E2EE/v1\n".toByteArray(Charsets.UTF_8))
        return mac.doFinal(callId.toByteArray(Charsets.UTF_8))
    }

    /** Derives a direction-specific content key so A→B ciphertext cannot authenticate as B→A. */
    fun deriveOmniFrameContentKey(
        pairSharedSecret: ByteArray,
        senderPublicKey: ByteArray,
        recipientPublicKey: ByteArray
    ): ByteArray {
        require(pairSharedSecret.size >= X25519_KEY_SIZE) { "Pair secret must be 32 bytes" }
        val sender = normalizePublicKey(senderPublicKey)
        val recipient = normalizePublicKey(recipientPublicKey)
        require(!MessageDigest.isEqual(sender, recipient)) { "Sender and recipient must be distinct" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(pairSharedSecret.copyOf(X25519_KEY_SIZE), "HmacSHA256"))
        mac.update(omniFrameContentLabel)
        mac.update(sender)
        mac.update(recipient)
        return mac.doFinal()
    }

    /** Recipient-issued capability used only to admit this sender→recipient route at the backend. */
    fun deriveBackendRouteToken(
        pairSharedSecret: ByteArray,
        senderPublicKey: ByteArray,
        recipientPublicKey: ByteArray
    ): ByteArray {
        require(pairSharedSecret.size >= X25519_KEY_SIZE) { "Pair secret must be 32 bytes" }
        val sender = normalizePublicKey(senderPublicKey)
        val recipient = normalizePublicKey(recipientPublicKey)
        require(!MessageDigest.isEqual(sender, recipient)) { "Sender and recipient must be distinct" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(pairSharedSecret.copyOf(X25519_KEY_SIZE), "HmacSHA256"))
        mac.update(backendRouteLabel)
        mac.update(sender)
        mac.update(recipient)
        return mac.doFinal()
    }

    /** Proves possession of the Secret Link's X25519 private key during relay registration. */
    fun registrationX25519Proof(
        localPrivateKey: ByteArray,
        serverEphemeralPublicKey: ByteArray,
        deviceId: String,
        nonceBase64: String,
        signingPublicKeyBase64: String
    ): ByteArray {
        require(deviceId.matches(Regex("[0-9a-f]{64}"))) { "Invalid relay device ID" }
        require(nonceBase64.isNotBlank() && signingPublicKeyBase64.isNotBlank())
        val pairSharedSecret = deriveSharedSecret(localPrivateKey, serverEphemeralPublicKey)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(pairSharedSecret, "HmacSHA256"))
        mac.update("OmniRelay/Register-X25519/v2\u0000".toByteArray(Charsets.UTF_8))
        mac.update(deviceId.toByteArray(Charsets.UTF_8))
        mac.update(0)
        mac.update(nonceBase64.toByteArray(Charsets.UTF_8))
        mac.update(0)
        mac.update(signingPublicKeyBase64.toByteArray(Charsets.UTF_8))
        return mac.doFinal()
    }

    fun encryptPayload(
        plainText: ByteArray,
        masterKey: ByteArray,
        authenticatedData: ByteArray? = null
    ): EncryptedResult {
        require(masterKey.size >= X25519_KEY_SIZE) { "AES-256 requires a 32-byte key" }
        val iv = ByteArray(IV_LENGTH_BYTES).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(masterKey.copyOf(X25519_KEY_SIZE), "AES"),
            GCMParameterSpec(AEAD_TAG_LENGTH_BITS, iv)
        )
        authenticatedData?.let(cipher::updateAAD)

        val cipherTextWithTag = cipher.doFinal(plainText)
        return EncryptedResult(
            cipherText = cipherTextWithTag.copyOfRange(0, cipherTextWithTag.size - MAC_TAG_LENGTH_BYTES),
            iv = iv,
            macTag = cipherTextWithTag.copyOfRange(
                cipherTextWithTag.size - MAC_TAG_LENGTH_BYTES,
                cipherTextWithTag.size
            )
        )
    }

    fun decryptPayload(
        encryptedResult: EncryptedResult,
        masterKey: ByteArray,
        authenticatedData: ByteArray? = null
    ): ByteArray? = runCatching {
        require(masterKey.size >= X25519_KEY_SIZE) { "AES-256 requires a 32-byte key" }
        require(encryptedResult.iv.size == IV_LENGTH_BYTES) { "Invalid GCM IV" }
        require(encryptedResult.macTag.size == MAC_TAG_LENGTH_BYTES) { "Invalid GCM tag" }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(masterKey.copyOf(X25519_KEY_SIZE), "AES"),
            GCMParameterSpec(AEAD_TAG_LENGTH_BITS, encryptedResult.iv)
        )
        authenticatedData?.let(cipher::updateAAD)
        cipher.doFinal(encryptedResult.cipherText + encryptedResult.macTag)
    }.getOrNull()

    private fun hkdfSha256(inputKeyMaterial: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val zeroSalt = ByteArray(mac.macLength)
        mac.init(SecretKeySpec(zeroSalt, "HmacSHA256"))
        val pseudoRandomKey = mac.doFinal(inputKeyMaterial)

        val output = ByteArray(outputLength)
        var previous = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < outputLength) {
            mac.init(SecretKeySpec(pseudoRandomKey, "HmacSHA256"))
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val count = minOf(previous.size, outputLength - written)
            previous.copyInto(output, written, 0, count)
            written += count
            counter++
        }
        return output
    }

    private fun normalizeRawKey(key: ByteArray, derPrefix: ByteArray): ByteArray {
        if (key.size == X25519_KEY_SIZE) return key.copyOf()
        require(key.size == derPrefix.size + X25519_KEY_SIZE && key.startsWithBytes(derPrefix)) {
            "Invalid X25519 key encoding"
        }
        return key.copyOfRange(derPrefix.size, key.size)
    }

    private fun ByteArray.startsWithBytes(prefix: ByteArray): Boolean =
        size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }

    private fun hex(value: String): ByteArray =
        value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
