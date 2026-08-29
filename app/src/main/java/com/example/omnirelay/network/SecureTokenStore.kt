package com.example.omnirelay.network

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class RelayCredentials(val deviceId: String, val token: String)

class SecureTokenStore(context: Context) {
    private val prefs = context.getSharedPreferences("OmniRelaySecure", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_ALIAS = "omnirelay_relay_credentials_v1"
        private const val KEY_DEVICE_ID = "relay_device_id"
        private const val KEY_TOKEN_CIPHER = "relay_token_cipher"
        private const val KEY_REGISTRATION_VERSION = "relay_registration_version"
        private const val CURRENT_REGISTRATION_VERSION = 2
    }

    fun load(): RelayCredentials? {
        if (prefs.getInt(KEY_REGISTRATION_VERSION, 0) != CURRENT_REGISTRATION_VERSION) return null
        val deviceId = prefs.getString(KEY_DEVICE_ID, null) ?: return null
        val encoded = prefs.getString(KEY_TOKEN_CIPHER, null) ?: return null
        return runCatching {
            val packed = Base64.decode(encoded, Base64.NO_WRAP)
            require(packed.size > 12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, packed, 0, 12))
            RelayCredentials(deviceId, String(cipher.doFinal(packed.copyOfRange(12, packed.size)), Charsets.UTF_8))
        }.getOrNull()
    }

    fun save(credentials: RelayCredentials) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.iv + cipher.doFinal(credentials.token.toByteArray(Charsets.UTF_8))
        prefs.edit()
            .putString(KEY_DEVICE_ID, credentials.deviceId)
            .putString(KEY_TOKEN_CIPHER, Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .putInt(KEY_REGISTRATION_VERSION, CURRENT_REGISTRATION_VERSION)
            .apply()
    }

    fun clear() {
        prefs.edit()
            .remove(KEY_DEVICE_ID)
            .remove(KEY_TOKEN_CIPHER)
            .remove(KEY_REGISTRATION_VERSION)
            .apply()
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
