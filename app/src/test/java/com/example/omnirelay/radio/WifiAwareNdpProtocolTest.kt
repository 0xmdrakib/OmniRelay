package com.example.omnirelay.radio

import com.example.omnirelay.protocol.OmniFrame
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WifiAwareNdpProtocolTest {
    private val sharedSecret = ByteArray(32) { (it * 7 + 3).toByte() }
    private val clientPublicKey = ByteArray(32) { (it + 1).toByte() }
    private val serverPublicKey = ByteArray(32) { (255 - it).toByte() }

    @Test
    fun ndpPassphraseIsSymmetricBoundedAndPairSpecific() {
        val client = WifiAwareNdpProtocol.deriveNdpPassphrase(
            sharedSecret,
            clientPublicKey,
            serverPublicKey
        )
        val server = WifiAwareNdpProtocol.deriveNdpPassphrase(
            sharedSecret,
            serverPublicKey,
            clientPublicKey
        )

        assertEquals(client, server)
        assertEquals(43, client.length)
        assertTrue(client.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        assertFalse(
            client == WifiAwareNdpProtocol.deriveNdpPassphrase(
                sharedSecret.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() },
                clientPublicKey,
                serverPublicKey
            )
        )
    }

    @Test
    fun authenticatedControlRoundTripsAndRejectsTampering() {
        val connectionId = ByteArray(16) { it.toByte() }
        val encoded = WifiAwareNdpProtocol.encodeControl(
            WifiAwareNdpProtocol.ControlType.READY,
            clientPublicKey,
            connectionId,
            41_337,
            sharedSecret
        )

        val decoded = WifiAwareNdpProtocol.decodeControl(encoded, sharedSecret)
        assertNotNull(decoded)
        assertEquals(WifiAwareNdpProtocol.ControlType.READY, decoded!!.type)
        assertArrayEquals(clientPublicKey.copyOf(12), decoded.senderPrefix)
        assertArrayEquals(connectionId, decoded.connectionId)
        assertEquals(41_337, decoded.port)

        val tampered = encoded.copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() }
        assertNull(WifiAwareNdpProtocol.decodeControl(tampered, sharedSecret))
        assertNull(WifiAwareNdpProtocol.decodeControl(encoded, ByteArray(32) { 9 }))
    }

    @Test
    fun discoveryAndAuthenticatedControlsUseTheSameCanonicalPrefix() {
        val connectionId = ByteArray(16) { (it + 4).toByte() }
        val discoveryPrefix = WifiAwareNdpProtocol.identityPrefix(clientPublicKey)
        val request = WifiAwareNdpProtocol.encodeControl(
            WifiAwareNdpProtocol.ControlType.REQUEST,
            clientPublicKey,
            connectionId,
            0,
            sharedSecret
        )

        assertEquals(OmniFrame.COMPACT_KEY_PREFIX_SIZE, WifiAwareNdpProtocol.IDENTITY_PREFIX_BYTES)
        assertEquals(WifiAwareNdpProtocol.IDENTITY_PREFIX_BYTES, discoveryPrefix.size)
        assertArrayEquals(discoveryPrefix, WifiAwareNdpProtocol.peekControlSenderPrefix(request))
        assertArrayEquals(
            discoveryPrefix,
            WifiAwareNdpProtocol.decodeControl(request, sharedSecret)?.senderPrefix
        )
    }

    @Test
    fun controlPortIsBoundToControlRole() {
        val connectionId = ByteArray(16)
        val request = WifiAwareNdpProtocol.encodeControl(
            WifiAwareNdpProtocol.ControlType.REQUEST,
            clientPublicKey,
            connectionId,
            0,
            sharedSecret
        )
        assertEquals(
            WifiAwareNdpProtocol.ControlType.REQUEST,
            WifiAwareNdpProtocol.decodeControl(request, sharedSecret)?.type
        )

        assertFails<IllegalArgumentException> {
            WifiAwareNdpProtocol.encodeControl(
                WifiAwareNdpProtocol.ControlType.REQUEST,
                clientPublicKey,
                connectionId,
                443,
                sharedSecret
            )
        }
    }

    @Test
    fun mutualHandshakeDerivesIdenticalDirectionalSecrets() {
        val connectionId = ByteArray(16) { (it * 5).toByte() }
        val client = WifiAwareNdpProtocol.createClientHandshake(
            connectionId,
            sharedSecret,
            clientPublicKey,
            serverPublicKey
        )
        val server = WifiAwareNdpProtocol.acceptClientHandshake(
            client.hello,
            connectionId,
            sharedSecret,
            serverPublicKey,
            clientPublicKey
        )
        assertNotNull(server)
        val completed = WifiAwareNdpProtocol.completeClientHandshake(
            client,
            server!!.reply,
            sharedSecret,
            clientPublicKey,
            serverPublicKey
        )
        assertNotNull(completed)
        assertArrayEquals(server.secrets.clientToServerKey, completed!!.clientToServerKey)
        assertArrayEquals(server.secrets.serverToClientKey, completed.serverToClientKey)
        assertArrayEquals(server.secrets.clientNoncePrefix, completed.clientNoncePrefix)
        assertArrayEquals(server.secrets.serverNoncePrefix, completed.serverNoncePrefix)
    }

    @Test
    fun handshakeRejectsWrongPairSecretAndModifiedProof() {
        val connectionId = ByteArray(16) { it.toByte() }
        val client = WifiAwareNdpProtocol.createClientHandshake(
            connectionId,
            sharedSecret,
            clientPublicKey,
            serverPublicKey
        )
        assertNull(
            WifiAwareNdpProtocol.acceptClientHandshake(
                client.hello,
                connectionId,
                ByteArray(32) { 0x55 },
                serverPublicKey,
                clientPublicKey
            )
        )

        val modified = client.hello.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertNull(
            WifiAwareNdpProtocol.acceptClientHandshake(
                modified,
                connectionId,
                sharedSecret,
                serverPublicKey,
                clientPublicKey
            )
        )
    }

    @Test
    fun secureRecordsAreBidirectionalAndRejectReplay() {
        val secrets = completeHandshake()
        val clientWriter = secrets.writer(isClient = true)
        val serverReader = secrets.reader(isClient = false)
        val serverWriter = secrets.writer(isClient = false)
        val clientReader = secrets.reader(isClient = true)
        val first = ByteArray(4_096) { (it and 0xFF).toByte() }
        val second = "reply".toByteArray()

        val clientRecord = clientWriter.seal(first)
        assertArrayEquals(first, serverReader.open(clientRecord))
        assertNull(serverReader.open(clientRecord))
        assertArrayEquals(second, clientReader.open(serverWriter.seal(second)))
    }

    @Test
    fun failedAuthenticationDoesNotAdvanceReceiveSequence() {
        val secrets = completeHandshake()
        val writer = secrets.writer(isClient = true)
        val reader = secrets.reader(isClient = false)
        val record = writer.seal("authenticated".toByteArray())
        val damaged = record.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }

        assertNull(reader.open(damaged))
        assertArrayEquals("authenticated".toByteArray(), reader.open(record))
    }

    @Test
    fun streamFramingHandlesMultipleRecordsWithoutBoundaryAmbiguity() {
        val secrets = completeHandshake()
        val output = ByteArrayOutputStream()
        val writer = secrets.writer(isClient = true)
        WifiAwareNdpProtocol.writePacket(output, writer, ByteArray(17) { 1 })
        WifiAwareNdpProtocol.writePacket(output, writer, ByteArray(8_192) { 2 })

        val input = ByteArrayInputStream(output.toByteArray())
        val reader = secrets.reader(isClient = false)
        assertArrayEquals(ByteArray(17) { 1 }, WifiAwareNdpProtocol.readPacket(input, reader))
        assertArrayEquals(ByteArray(8_192) { 2 }, WifiAwareNdpProtocol.readPacket(input, reader))
        assertNull(WifiAwareNdpProtocol.readPacket(input, reader))
    }

    @Test
    fun recordSizeIsStrictlyBounded() {
        val writer = completeHandshake().writer(isClient = true)
        assertFails<IllegalArgumentException> { writer.seal(ByteArray(0)) }
        assertFails<IllegalArgumentException> {
            writer.seal(ByteArray(WifiAwareNdpProtocol.MAX_PACKET_BYTES + 1))
        }
    }

    private fun completeHandshake(): WifiAwareNdpProtocol.SessionSecrets {
        val connectionId = ByteArray(16) { (it + 20).toByte() }
        val client = WifiAwareNdpProtocol.createClientHandshake(
            connectionId,
            sharedSecret,
            clientPublicKey,
            serverPublicKey
        )
        val server = requireNotNull(
            WifiAwareNdpProtocol.acceptClientHandshake(
                client.hello,
                connectionId,
                sharedSecret,
                serverPublicKey,
                clientPublicKey
            )
        )
        return requireNotNull(
            WifiAwareNdpProtocol.completeClientHandshake(
                client,
                server.reply,
                sharedSecret,
                clientPublicKey,
                serverPublicKey
            )
        )
    }

    private inline fun <reified T : Throwable> assertFails(block: () -> Unit) {
        try {
            block()
        } catch (throwable: Throwable) {
            assertTrue("Expected ${T::class.java.name}, got ${throwable::class.java.name}", throwable is T)
            return
        }
        throw AssertionError("Expected ${T::class.java.name}")
    }
}
