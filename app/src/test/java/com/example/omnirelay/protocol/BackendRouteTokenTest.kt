package com.example.omnirelay.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class BackendRouteTokenTest {
    @Test
    fun routeTokensAreDeterministicAndDirectional() {
        val secret = ByteArray(32) { (it * 3 + 1).toByte() }
        val sender = ByteArray(32) { (it + 5).toByte() }
        val recipient = ByteArray(32) { (255 - it).toByte() }

        val first = CryptoEngine.deriveBackendRouteToken(secret, sender, recipient)
        val second = CryptoEngine.deriveBackendRouteToken(secret, sender, recipient)
        val reverse = CryptoEngine.deriveBackendRouteToken(secret, recipient, sender)

        assertEquals(32, first.size)
        assertArrayEquals(first, second)
        assertFalse(first.contentEquals(reverse))
    }

    @Test
    fun routeTokenMatchesBackendInteropVector() {
        val secret = ByteArray(32) { it.toByte() }
        val sender = ByteArray(32) { (it + 32).toByte() }
        val recipient = ByteArray(32) { (it + 64).toByte() }

        assertEquals(
            "7dd82dddd93c7dde1962c2fb68a48e10f7e802b85df6cbf51de6bc0badbdeec1",
            CryptoEngine.deriveBackendRouteToken(secret, sender, recipient).toHex()
        )
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
