package com.example.omnirelay.network

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class RelayCredentials(val deviceId: String, val token: String, val accountUid: String)

class SecureTokenStore(context: Context) {
    private val prefs = context.getSharedPreferences("OmniRelaySecure", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_ALIAS = "omnirelay_relay_credentials_v1"
        private const val KEY_DEVICE_ID = "relay_device_id"
        private const val KEY_TOKEN_CIPHER = "relay_token_cipher"
        private const val KEY_ACCOUNT_UID_CIPHER = "relay_account_uid_cipher"
        private const val KEY_REGISTRATION_VERSION = "relay_registration_version"
        private const val CURRENT_REGISTRATION_VERSION = 3
        private val ACCOUNT_UID_AAD = "OmniRelay/FirebaseAccountUid/v1".toByteArray(Charsets.UTF_8)
    }

    fun load(): RelayCredentials? {
        if (prefs.getInt(KEY_REGISTRATION_VERSION, 0) != CURRENT_REGISTRATION_VERSION) return null
        val deviceId = prefs.getString(KEY_DEVICE_ID, null) ?: return null
        val encoded = prefs.getString(KEY_TOKEN_CIPHER, null) ?: return null
        return runCatching {
            require(deviceId.matches(Regex("[0-9a-f]{64}")))
            val packed = Base64.decode(encoded, Base64.NO_WRAP)
            require(packed.size > 12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, packed, 0, 12))
            val plaintext = cipher.doFinal(packed.copyOfRange(12, packed.size))
            try {
                require(plaintext.size > Int.SIZE_BYTES)
                val buffer = ByteBuffer.wrap(plaintext)
                val uidLength = buffer.int
                require(uidLength in 1..512 && buffer.remaining() > uidLength)
                val uidBytes = ByteArray(uidLength).also(buffer::get)
                val tokenBytes = ByteArray(buffer.remaining()).also(buffer::get)
                val accountUid = String(uidBytes, Charsets.UTF_8)
                val token = String(tokenBytes, Charsets.UTF_8)
                require(accountUid.length in 1..128 && token.length in 32..512)
                require(boundAccountUid() == accountUid)
                RelayCredentials(deviceId, token, accountUid)
            } finally {
                plaintext.fill(0)
            }
        }.getOrNull()
    }

    fun save(credentials: RelayCredentials) {
        require(credentials.accountUid.length in 1..128) { "Invalid account UID" }
        require(credentials.token.length in 32..512) { "Invalid relay session token" }
        require(bindAccountUid(credentials.accountUid)) { "Device identity belongs to another account" }
        val uidBytes = credentials.accountUid.toByteArray(Charsets.UTF_8)
        val tokenBytes = credentials.token.toByteArray(Charsets.UTF_8)
        require(uidBytes.size <= 512) { "Account UID encoding is too large" }
        val plaintext = ByteBuffer.allocate(Int.SIZE_BYTES + uidBytes.size + tokenBytes.size)
            .putInt(uidBytes.size)
            .put(uidBytes)
            .put(tokenBytes)
            .array()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        try {
            val encrypted = cipher.iv + cipher.doFinal(plaintext)
            prefs.edit()
                .putString(KEY_DEVICE_ID, credentials.deviceId)
                .putString(KEY_TOKEN_CIPHER, Base64.encodeToString(encrypted, Base64.NO_WRAP))
                .putInt(KEY_REGISTRATION_VERSION, CURRENT_REGISTRATION_VERSION)
                .apply()
        } finally {
            plaintext.fill(0)
            uidBytes.fill(0)
            tokenBytes.fill(0)
        }
    }

    fun clear() {
        prefs.edit()
            .remove(KEY_DEVICE_ID)
            .remove(KEY_TOKEN_CIPHER)
            .remove(KEY_REGISTRATION_VERSION)
            .apply()
    }

    /**
     * Permanently binds this app-data identity to the first verified Firebase UID.
     * Session sign-out deliberately does not clear this value; only an explicit app-data reset does.
     */
    @Synchronized
    fun bindAccountUid(accountUid: String): Boolean {
        require(accountUid.length in 1..128) { "Invalid account UID" }
        val existingCiphertext = prefs.getString(KEY_ACCOUNT_UID_CIPHER, null)
        if (existingCiphertext != null) return boundAccountUid() == accountUid
        val plaintext = accountUid.toByteArray(Charsets.UTF_8)
        require(plaintext.size <= 512) { "Account UID encoding is too large" }
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            cipher.updateAAD(ACCOUNT_UID_AAD)
            val packed = cipher.iv + cipher.doFinal(plaintext)
            prefs.edit()
                .putString(KEY_ACCOUNT_UID_CIPHER, Base64.encodeToString(packed, Base64.NO_WRAP))
                .commit()
        } finally {
            plaintext.fill(0)
        }
    }

    fun boundAccountUid(): String? {
        val encoded = prefs.getString(KEY_ACCOUNT_UID_CIPHER, null) ?: return null
        return runCatching {
            val packed = Base64.decode(encoded, Base64.NO_WRAP)
            require(packed.size > 12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, packed, 0, 12))
            cipher.updateAAD(ACCOUNT_UID_AAD)
            val plaintext = cipher.doFinal(packed.copyOfRange(12, packed.size))
            try {
                val uid = String(plaintext, Charsets.UTF_8)
                require(uid.length in 1..128 && plaintext.size <= 512)
                uid
            } finally {
                plaintext.fill(0)
            }
        }.getOrNull()
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }
}
