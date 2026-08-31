package com.example.omnirelay.utils

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import com.example.omnirelay.protocol.CryptoEngine
import com.example.omnirelay.routing.AdaptiveResourcePolicy.UserResourceTier
import org.json.JSONArray
import org.json.JSONObject

data class PairedContact(
    val name: String,
    val secretLink: String,
    val accountUid: String? = null,
    val deviceId: String? = null,
    val dateAddedMs: Long = System.currentTimeMillis()
)

class IdentityUnavailableException(message: String) : IllegalStateException(message)

/**
 * Manages persistent app settings, identity keys, network options, and mutual paired contacts.
 */
class SettingsManager(
    context: Context,
    private val observeExternalChanges: Boolean = true
) : AutoCloseable {

    private val prefs: SharedPreferences = context.getSharedPreferences("OmniRelayPrefs", Context.MODE_PRIVATE)
    private val secretProtector = LocalSecretProtector()
    @Volatile private var cachedIdentity: CryptoEngine.KeyPairData? = null
    @Volatile private var cachedSigningIdentity: CryptoEngine.SigningKeyPairData? = null
    @Volatile private var cachedContacts: List<PairedContact>? = null
    private val preferenceListener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == KEY_PAIRED_CONTACTS_JSON) cachedContacts = null
    }

    init {
        if (observeExternalChanges) {
            prefs.registerOnSharedPreferenceChangeListener(preferenceListener)
        }
    }

    @Synchronized
    override fun close() {
        if (observeExternalChanges) {
            prefs.unregisterOnSharedPreferenceChangeListener(preferenceListener)
        }
        cachedIdentity?.let {
            it.publicKey.fill(0)
            it.privateKey.fill(0)
        }
        cachedSigningIdentity?.let {
            it.publicKeyDer.fill(0)
            it.privateKeyDer.fill(0)
        }
        cachedIdentity = null
        cachedSigningIdentity = null
        cachedContacts = null
    }

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
        private const val KEY_MESH_RELAY_ENABLED = "setting_mesh_relay_enabled"
        private const val KEY_RESOURCE_TIER = "setting_resource_tier"

        // Audio Toggles
        private const val KEY_NOISE_SUPPRESSION = "setting_noise_suppression"
        private const val KEY_ECHO_CANCELLATION = "setting_echo_cancellation"
        const val FREE_CONTACT_LIMIT = 20
        private const val MAX_PAIRED_CONTACTS = FREE_CONTACT_LIMIT
    }

    /**
     * Gets the persistent Identity KeyPair. Generates and saves one on first launch.
     */
    fun getMyIdentity(): CryptoEngine.KeyPairData {
        cachedIdentity?.let { return it.copy(publicKey = it.publicKey.copyOf(), privateKey = it.privateKey.copyOf()) }
        val pubBase64 = prefs.getString(KEY_PUB_KEY, null)
        val encryptedPrivate = prefs.getString(KEY_PRIV_KEY_ENCRYPTED, null)
        val legacyPrivate = prefs.getString(KEY_PRIV_KEY, null)
        val storedPublic = pubBase64?.let { encoded ->
            runCatching { Base64.decode(encoded, Base64.NO_WRAP) }
                .getOrElse { throw IdentityUnavailableException("Stored X25519 public identity is invalid") }
        }
        val normalizedPublic = storedPublic?.let { encoded ->
            runCatching { CryptoEngine.normalizePublicKey(encoded) }
                .getOrElse { throw IdentityUnavailableException("Stored X25519 public identity is invalid") }
        }
        val privateBytes = runCatching {
            encryptedPrivate?.let { secretProtector.decrypt(it, x25519Purpose(normalizedPublic)) }
                ?: legacyPrivate?.let { Base64.decode(it, Base64.NO_WRAP) }
        }.getOrElse {
            throw IdentityUnavailableException("Stored X25519 private identity cannot be unlocked")
        }

        if (normalizedPublic != null && privateBytes != null) {
            val publicKey = normalizedPublic
            val privateKey = runCatching { CryptoEngine.normalizePrivateKey(privateBytes) }
                .getOrElse { throw IdentityUnavailableException("Stored X25519 private identity is invalid") }
            val pair = CryptoEngine.KeyPairData(publicKey, privateKey)
            if (!CryptoEngine.isValidX25519KeyPair(pair)) {
                throw IdentityUnavailableException("Stored X25519 identity key pair does not match")
            }
            // Migrate identities created by older builds that stored DER encodings.
            if (storedPublic.size != publicKey.size ||
                privateKey.size != privateBytes.size || legacyPrivate != null ||
                encryptedPrivate?.let(secretProtector::needsMigration) == true
            ) {
                saveIdentity(publicKey, privateKey)
            }
            cachedIdentity = pair
            return pair.copy(publicKey = pair.publicKey.copyOf(), privateKey = pair.privateKey.copyOf())
        }
        if (pubBase64 != null || encryptedPrivate != null || legacyPrivate != null) {
            throw IdentityUnavailableException(
                "Existing X25519 identity cannot be unlocked; reset must be explicit"
            )
        }

        val newKeyPair = CryptoEngine.generateX25519KeyPair()
        saveIdentity(newKeyPair.publicKey, newKeyPair.privateKey)
        cachedIdentity = newKeyPair
        return newKeyPair.copy(
            publicKey = newKeyPair.publicKey.copyOf(),
            privateKey = newKeyPair.privateKey.copyOf()
        )
    }

    fun getMySecretLink(): String {
        return Base64.encodeToString(getMyIdentity().publicKey, Base64.NO_WRAP)
    }

    fun getMyDisplayName(): String {
        return prefs.getString(KEY_MY_NAME, "Omni Device") ?: "Omni Device"
    }

    fun getMySigningIdentity(): CryptoEngine.SigningKeyPairData {
        cachedSigningIdentity?.let {
            return it.copy(publicKeyDer = it.publicKeyDer.copyOf(), privateKeyDer = it.privateKeyDer.copyOf())
        }
        val publicKey = prefs.getString(KEY_SIGNING_PUB, null)
        val encryptedPrivate = prefs.getString(KEY_SIGNING_PRIV_ENCRYPTED, null)
        val legacyPrivate = prefs.getString(KEY_SIGNING_PRIV, null)
        val publicBytes = publicKey?.let {
            runCatching { Base64.decode(it, Base64.NO_WRAP) }
                .getOrElse { throw IdentityUnavailableException("Stored Ed25519 public identity is invalid") }
        }
        val privateKey = runCatching {
            encryptedPrivate?.let { secretProtector.decrypt(it, ed25519Purpose(publicBytes)) }
                ?: legacyPrivate?.let { Base64.decode(it, Base64.NO_WRAP) }
        }.getOrElse {
            throw IdentityUnavailableException("Stored Ed25519 private identity cannot be unlocked")
        }
        if (publicBytes != null && privateKey != null) {
            val pair = CryptoEngine.SigningKeyPairData(publicBytes, privateKey)
            if (!CryptoEngine.isValidEd25519KeyPair(pair)) {
                throw IdentityUnavailableException("Stored Ed25519 identity key pair does not match")
            }
            if (legacyPrivate != null || encryptedPrivate?.let(secretProtector::needsMigration) == true) {
                saveSigningIdentity(pair)
            }
            cachedSigningIdentity = pair
            return pair.copy(
                publicKeyDer = pair.publicKeyDer.copyOf(),
                privateKeyDer = pair.privateKeyDer.copyOf()
            )
        }
        if (publicKey != null || encryptedPrivate != null || legacyPrivate != null) {
            throw IdentityUnavailableException(
                "Existing Ed25519 identity cannot be unlocked; reset must be explicit"
            )
        }
        val pair = CryptoEngine.generateEd25519KeyPair()
        saveSigningIdentity(pair)
        cachedSigningIdentity = pair
        return pair.copy(
            publicKeyDer = pair.publicKeyDer.copyOf(),
            privateKeyDer = pair.privateKeyDer.copyOf()
        )
    }

    private fun saveSigningIdentity(pair: CryptoEngine.SigningKeyPairData) {
        val publicBase64 = Base64.encodeToString(pair.publicKeyDer, Base64.NO_WRAP)
        val persisted = prefs.edit()
            .putString(KEY_SIGNING_PUB, publicBase64)
            .putString(
                KEY_SIGNING_PRIV_ENCRYPTED,
                secretProtector.encrypt(pair.privateKeyDer, ed25519Purpose(pair.publicKeyDer))
            )
            .remove(KEY_SIGNING_PRIV)
            .commit()
        if (!persisted) {
            throw IdentityUnavailableException("Ed25519 identity could not be persisted safely")
        }
    }

    fun setMyDisplayName(name: String) {
        prefs.edit().putString(KEY_MY_NAME, name.ifBlank { "Omni Device" }).apply()
    }

    // --- Paired Contacts Management ---

    fun getPairedContacts(): List<PairedContact> {
        cachedContacts?.let { return it.toList() }
        return synchronized(this) {
            cachedContacts?.let { return@synchronized it.toList() }
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
                        accountUid = obj.optString("accountUid").takeIf { it.isNotBlank() },
                        deviceId = obj.optString("deviceId").takeIf { it.isNotBlank() },
                        dateAddedMs = obj.optLong("dateAddedMs", System.currentTimeMillis())
                    )
                )
            }
        } catch (_: Exception) {
            // Corrupt contact data fails closed to an empty allow-list.
        }
            list.take(MAX_PAIRED_CONTACTS).also { cachedContacts = it }.toList()
        }
    }

    fun addPairedContact(name: String, secretLink: String): Boolean {
        val cleanLink = secretLink.trim()
        val publicKey = decodePublicKey(cleanLink) ?: return false
        val canonicalLink = Base64.encodeToString(publicKey, Base64.NO_WRAP)
        if (canonicalLink == getMySecretLink()) return false

        val currentList = getPairedContacts().toMutableList()
        // Remove duplicate if already exists
        currentList.removeAll { decodePublicKey(it.secretLink)?.contentEquals(publicKey) == true }
        if (currentList.size >= MAX_PAIRED_CONTACTS) return false

        val contactName = name.trim().ifBlank { "Receiver Device ${currentList.size + 1}" }
        currentList.add(0, PairedContact(name = contactName, secretLink = canonicalLink))

        saveContactsList(currentList)
        return true
    }

    fun syncAccountContacts(contacts: List<com.example.omnirelay.network.AccountContact>): Int {
        val valid = contacts.mapNotNull { remote ->
            val key = remote.publicKeyBase64?.let(::decodePublicKey) ?: return@mapNotNull null
            val canonicalLink = Base64.encodeToString(key, Base64.NO_WRAP)
            if (canonicalLink == getMySecretLink()) return@mapNotNull null
            PairedContact(
                name = remote.email.substringBefore('@').ifBlank { "Mutual Contact" },
                secretLink = canonicalLink,
                accountUid = remote.accountUid,
                deviceId = remote.deviceId
            )
        }.distinctBy { it.accountUid ?: it.secretLink }.take(MAX_PAIRED_CONTACTS)
        val manual = getPairedContacts().filter { it.accountUid == null }
        val merged = (valid + manual).distinctBy { it.accountUid ?: it.secretLink }.take(MAX_PAIRED_CONTACTS)
        saveContactsList(merged)
        return valid.size
    }

    fun removeAccountContact(accountUid: String) {
        saveContactsList(getPairedContacts().filterNot { it.accountUid == accountUid })
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
            c.accountUid?.let { obj.put("accountUid", it) }
            c.deviceId?.let { obj.put("deviceId", it) }
            obj.put("dateAddedMs", c.dateAddedMs)
            jsonArray.put(obj)
        }
        val snapshot = list.take(MAX_PAIRED_CONTACTS).toList()
        cachedContacts = snapshot
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
        val persisted = prefs.edit()
            .putString(KEY_PUB_KEY, Base64.encodeToString(publicKey, Base64.NO_WRAP))
            .putString(
                KEY_PRIV_KEY_ENCRYPTED,
                secretProtector.encrypt(privateKey, x25519Purpose(publicKey))
            )
            .remove(KEY_PRIV_KEY)
            .commit()
        if (!persisted) {
            throw IdentityUnavailableException("X25519 identity could not be persisted safely")
        }
    }

    private fun x25519Purpose(publicKey: ByteArray?): String =
        "OmniRelay/X25519Identity/v2:" + (publicKey?.let {
            Base64.encodeToString(it, Base64.NO_WRAP)
        } ?: "missing")

    private fun ed25519Purpose(publicKey: ByteArray?): String =
        "OmniRelay/Ed25519Identity/v2:" + (publicKey?.let {
            Base64.encodeToString(it, Base64.NO_WRAP)
        } ?: "missing")

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

    /** Explicit opt-in for carrying opaque third-party nearby relay capsules. */
    var isMeshRelayEnabled: Boolean
        get() = prefs.getBoolean(KEY_MESH_RELAY_ENABLED, false)
        set(value) = prefs.edit().putBoolean(KEY_MESH_RELAY_ENABLED, value).apply()

    var resourceTier: UserResourceTier
        get() = runCatching {
            UserResourceTier.valueOf(
                prefs.getString(KEY_RESOURCE_TIER, UserResourceTier.MINIMAL.name)
                    ?: UserResourceTier.MINIMAL.name
            )
        }.getOrDefault(UserResourceTier.MINIMAL)
        set(value) = prefs.edit().putString(KEY_RESOURCE_TIER, value.name).apply()

    // --- Audio Settings ---

    var isNoiseSuppressionEnabled: Boolean
        get() = prefs.getBoolean(KEY_NOISE_SUPPRESSION, true)
        set(value) = prefs.edit().putBoolean(KEY_NOISE_SUPPRESSION, value).apply()

    var isEchoCancellationEnabled: Boolean
        get() = prefs.getBoolean(KEY_ECHO_CANCELLATION, true)
        set(value) = prefs.edit().putBoolean(KEY_ECHO_CANCELLATION, value).apply()
}
