package com.example.omnirelay.utils

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import com.example.omnirelay.protocol.CryptoEngine
import org.json.JSONArray
import org.json.JSONObject

data class PairedContact(
    val name: String,
    val secretLink: String,
    val dateAddedMs: Long = System.currentTimeMillis()
)

/**
 * Manages persistent app settings, identity keys, network options, and mutual paired contacts.
 */
class SettingsManager(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences("OmniRelayPrefs", Context.MODE_PRIVATE)
    private val secretProtector = LocalSecretProtector()

    companion object {
        private const val KEY_PUB_KEY = "my_public_key_base64"
        private const val KEY_PRIV_KEY = "my_private_key_base64"
        private const val KEY_PRIV_KEY_ENCRYPTED = "my_private_key_encrypted"
        private const val KEY_MY_NAME = "my_display_name"
        private const val KEY_SIGNING_PUB = "my_signing_public_key_base64"
        private const val KEY_SIGNING_PRIV = "my_signing_private_key_base64"
        private const val KEY_SIGNING_PRIV_ENCRYPTED = "my_signing_private_key_encrypted"
        private const val KEY_PAIRED_CONTACTS_JSON = "paired_contacts_json_array"

        // Network Toggles
        private const val KEY_BLE_ENABLED = "setting_ble_enabled"
        private const val KEY_WIFI_AWARE_ENABLED = "setting_wifi_aware_enabled"
        private const val KEY_RELAY_MODE_ENABLED = "setting_relay_mode_enabled"

        // Audio Toggles
        private const val KEY_NOISE_SUPPRESSION = "setting_noise_suppression"
        private const val KEY_ECHO_CANCELLATION = "setting_echo_cancellation"
    }

    /**
     * Gets the persistent Identity KeyPair. Generates and saves one on first launch.
     */
    fun getMyIdentity(): CryptoEngine.KeyPairData {
        val pubBase64 = prefs.getString(KEY_PUB_KEY, null)
        val encryptedPrivate = prefs.getString(KEY_PRIV_KEY_ENCRYPTED, null)
        val legacyPrivate = prefs.getString(KEY_PRIV_KEY, null)
        val privateBytes = encryptedPrivate?.let(secretProtector::decrypt)
            ?: legacyPrivate?.let { Base64.decode(it, Base64.NO_WRAP) }

        if (pubBase64 != null && privateBytes != null) {
            val publicKey = CryptoEngine.normalizePublicKey(Base64.decode(pubBase64, Base64.NO_WRAP))
            val privateKey = CryptoEngine.normalizePrivateKey(privateBytes)
            // Migrate identities created by older builds that stored DER encodings.
            if (publicKey.size != Base64.decode(pubBase64, Base64.NO_WRAP).size ||
                privateKey.size != privateBytes.size || legacyPrivate != null
            ) {
                saveIdentity(publicKey, privateKey)
            }
            return CryptoEngine.KeyPairData(publicKey, privateKey)
        }

        val newKeyPair = CryptoEngine.generateX25519KeyPair()
        saveIdentity(newKeyPair.publicKey, newKeyPair.privateKey)

        return newKeyPair
    }

    fun getMySecretLink(): String {
        return Base64.encodeToString(getMyIdentity().publicKey, Base64.NO_WRAP)
    }

    fun getMyDisplayName(): String {
        return prefs.getString(KEY_MY_NAME, "Omni Device") ?: "Omni Device"
    }

    fun getMySigningIdentity(): CryptoEngine.SigningKeyPairData {
        val publicKey = prefs.getString(KEY_SIGNING_PUB, null)
        val encryptedPrivate = prefs.getString(KEY_SIGNING_PRIV_ENCRYPTED, null)
        val legacyPrivate = prefs.getString(KEY_SIGNING_PRIV, null)
        val privateKey = encryptedPrivate?.let(secretProtector::decrypt)
            ?: legacyPrivate?.let { Base64.decode(it, Base64.NO_WRAP) }
        if (publicKey != null && privateKey != null) {
            if (legacyPrivate != null) {
                prefs.edit()
                    .putString(KEY_SIGNING_PRIV_ENCRYPTED, secretProtector.encrypt(privateKey))
                    .remove(KEY_SIGNING_PRIV)
                    .apply()
            }
            return CryptoEngine.SigningKeyPairData(
                Base64.decode(publicKey, Base64.NO_WRAP),
                privateKey
            )
        }
        val pair = CryptoEngine.generateEd25519KeyPair()
        prefs.edit()
            .putString(KEY_SIGNING_PUB, Base64.encodeToString(pair.publicKeyDer, Base64.NO_WRAP))
            .putString(KEY_SIGNING_PRIV_ENCRYPTED, secretProtector.encrypt(pair.privateKeyDer))
            .remove(KEY_SIGNING_PRIV)
            .apply()
        return pair
    }

    fun setMyDisplayName(name: String) {
        prefs.edit().putString(KEY_MY_NAME, name.ifBlank { "Omni Device" }).apply()
    }

    // --- Paired Contacts Management ---

    fun getPairedContacts(): List<PairedContact> {
        val jsonStr = prefs.getString(KEY_PAIRED_CONTACTS_JSON, "[]") ?: "[]"
        val list = mutableListOf<PairedContact>()
        try {
            val jsonArray = JSONArray(jsonStr)
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                val storedLink = obj.optString("secretLink", "")
                val canonicalLink = decodePublicKey(storedLink)?.let {
                    Base64.encodeToString(it, Base64.NO_WRAP)
                } ?: storedLink
                list.add(
                    PairedContact(
                        name = obj.optString("name", "Mutual Peer"),
                        secretLink = canonicalLink,
                        dateAddedMs = obj.optLong("dateAddedMs", System.currentTimeMillis())
                    )
                )
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return list
    }

    fun addPairedContact(name: String, secretLink: String): Boolean {
        val cleanLink = secretLink.trim()
        val publicKey = decodePublicKey(cleanLink) ?: return false
        val canonicalLink = Base64.encodeToString(publicKey, Base64.NO_WRAP)
        if (canonicalLink == getMySecretLink()) return false

        val currentList = getPairedContacts().toMutableList()
        // Remove duplicate if already exists
        currentList.removeAll { decodePublicKey(it.secretLink)?.contentEquals(publicKey) == true }

        val contactName = name.trim().ifBlank { "Receiver Device ${currentList.size + 1}" }
        currentList.add(0, PairedContact(name = contactName, secretLink = canonicalLink))

        saveContactsList(currentList)
        return true
    }

    fun removePairedContact(secretLink: String) {
        val keyToRemove = decodePublicKey(secretLink)
        val currentList = getPairedContacts().toMutableList()
        currentList.removeAll { contact ->
            if (keyToRemove == null) contact.secretLink == secretLink.trim()
            else decodePublicKey(contact.secretLink)?.contentEquals(keyToRemove) == true
        }
        saveContactsList(currentList)
    }

    private fun saveContactsList(list: List<PairedContact>) {
        val jsonArray = JSONArray()
        for (c in list) {
            val obj = JSONObject()
            obj.put("name", c.name)
            obj.put("secretLink", c.secretLink)
            obj.put("dateAddedMs", c.dateAddedMs)
            jsonArray.put(obj)
        }
        prefs.edit().putString(KEY_PAIRED_CONTACTS_JSON, jsonArray.toString()).apply()
    }

    fun isPairedContact(publicKey: ByteArray): Boolean {
        val normalized = runCatching { CryptoEngine.normalizePublicKey(publicKey) }.getOrNull() ?: return false
        return getPairedContacts().any { decodePublicKey(it.secretLink)?.contentEquals(normalized) == true }
    }

    fun getContactNameForLink(secretLink: String): String {
        val key = decodePublicKey(secretLink) ?: return "Paired Contact"
        return getPairedContacts().find {
            decodePublicKey(it.secretLink)?.contentEquals(key) == true
        }?.name ?: "Paired Contact"
    }

    fun getPairedContactForPrefix(publicKeyPrefix: ByteArray): PairedContact? {
        if (publicKeyPrefix.isEmpty()) return null
        return getPairedContacts().find { contact ->
            val key = decodePublicKey(contact.secretLink) ?: return@find false
            key.size >= publicKeyPrefix.size &&
                publicKeyPrefix.indices.all { key[it] == publicKeyPrefix[it] }
        }
    }

    fun decodePublicKey(secretLink: String): ByteArray? = runCatching {
        val decoded = Base64.decode(secretLink.trim(), Base64.NO_WRAP)
        CryptoEngine.normalizePublicKey(decoded)
    }.getOrNull()

    private fun saveIdentity(publicKey: ByteArray, privateKey: ByteArray) {
        prefs.edit()
            .putString(KEY_PUB_KEY, Base64.encodeToString(publicKey, Base64.NO_WRAP))
            .putString(KEY_PRIV_KEY_ENCRYPTED, secretProtector.encrypt(privateKey))
            .remove(KEY_PRIV_KEY)
            .apply()
    }

    // --- Network & Protocol Options ---

    var isBleEnabled: Boolean
        get() = prefs.getBoolean(KEY_BLE_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_BLE_ENABLED, value).apply()

    var isWifiAwareEnabled: Boolean
        get() = prefs.getBoolean(KEY_WIFI_AWARE_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_WIFI_AWARE_ENABLED, value).apply()

    var isRelayModeEnabled: Boolean
        get() = prefs.getBoolean(KEY_RELAY_MODE_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_RELAY_MODE_ENABLED, value).apply()

    // --- Audio Settings ---

    var isNoiseSuppressionEnabled: Boolean
        get() = prefs.getBoolean(KEY_NOISE_SUPPRESSION, true)
        set(value) = prefs.edit().putBoolean(KEY_NOISE_SUPPRESSION, value).apply()

    var isEchoCancellationEnabled: Boolean
        get() = prefs.getBoolean(KEY_ECHO_CANCELLATION, true)
        set(value) = prefs.edit().putBoolean(KEY_ECHO_CANCELLATION, value).apply()
}
