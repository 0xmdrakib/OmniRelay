package com.example.omnirelay.protocol

import java.security.MessageDigest

/**
 * Bounded replay state for opaque relay capsules.
 *
 * Recipient delivery is scoped to the pair identity as well as immutable capsule bytes, preventing
 * one authenticated contact from reserving another contact's public capsule ID. Forwarding tracks
 * the greatest mutable hop value seen so a forged lower-hop copy cannot suppress a later useful copy.
 */
internal class RelayReplayTracker(private val maxEntries: Int) {
    private val delivered = LinkedHashMap<String, Unit>(maxEntries, 0.75f, true)
    private val forwarded = LinkedHashMap<String, Int>(maxEntries, 0.75f, true)

    init {
        require(maxEntries > 0)
    }

    fun markAuthenticatedDelivery(pairPeerPublicKey: ByteArray, capsule: RelayCapsule): Boolean {
        require(pairPeerPublicKey.size == CryptoEngine.X25519_KEY_SIZE)
        val pairPeer = sha256(pairPeerPublicKey).toHex()
        val id = "$pairPeer:${immutableFingerprint(capsule)}"
        return synchronized(delivered) {
            if (delivered.containsKey(id)) return@synchronized false
            delivered[id] = Unit
            trim(delivered)
            true
        }
    }

    fun markForwardProgress(capsule: RelayCapsule): Boolean {
        val id = immutableFingerprint(capsule)
        return synchronized(forwarded) {
            val previous = forwarded[id]
            if (previous != null && previous >= capsule.remainingHops) return@synchronized false
            forwarded[id] = capsule.remainingHops
            trim(forwarded)
            true
        }
    }

    private fun immutableFingerprint(capsule: RelayCapsule): String = sha256(
        capsule.capsuleId + capsule.routeTag + capsule.iv + capsule.macTag + capsule.cipherText
    ).toHex()

    private fun <T> trim(cache: LinkedHashMap<String, T>) {
        while (cache.size > maxEntries) {
            cache.entries.iterator().run {
                if (hasNext()) {
                    next()
                    remove()
                }
            }
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
