package com.example.omnirelay.radio

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Pure wire and cryptographic state for the Wi-Fi Aware data path.
 *
 * The Android NDP is itself requested as a PSK-protected link. This layer additionally binds the
 * socket to the mutually paired X25519 secret, derives fresh per-connection directional keys, and
 * protects every stream record with AES-256-GCM and a strictly increasing sequence number.
 * It deliberately does not claim forward secrecy: the current identity agreement is static X25519.
 */
internal object WifiAwareNdpProtocol {
    const val IDENTITY_KEY_BYTES = 32
    const val IDENTITY_PREFIX_BYTES = 12
    const val CONNECTION_ID_BYTES = 16
    const val MAX_PACKET_BYTES = 128 * 1024
    const val HANDSHAKE_BYTES = 70

    private const val VERSION: Byte = 1
    private const val CONTROL_TAG_BYTES = 16
    private const val NONCE_BYTES = 32
    private const val PROOF_BYTES = 16
    private const val RECORD_NONCE_PREFIX_BYTES = 4
    private const val RECORD_HEADER_BYTES = 18
    private const val GCM_TAG_BYTES = 16
    private const val GCM_TAG_BITS = GCM_TAG_BYTES * 8
    private const val CLIENT_ROLE: Byte = 1
    private const val SERVER_ROLE: Byte = 2

    private val controlMagic = byteArrayOf(0x4F, 0x52, 0x4E, 0x44) // ORND
    private val handshakeMagic = byteArrayOf(0x4F, 0x52, 0x4E, 0x48) // ORNH
    private val recordMagic = byteArrayOf(0x4F, 0x52, 0x4E, 0x52) // ORNR
    private val random = SecureRandom()

    /** Canonical discovery/control routing prefix. Every NDP map key uses this exact width. */
    fun identityPrefix(publicKey: ByteArray): ByteArray {
        require(publicKey.size == IDENTITY_KEY_BYTES) { "Identity public key must be 32 bytes" }
        return publicKey.copyOf(IDENTITY_PREFIX_BYTES)
    }

    enum class ControlType(val wireValue: Byte) {
        REQUEST(1),
        READY(2);

        companion object {
            fun fromWire(value: Byte): ControlType? = entries.firstOrNull { it.wireValue == value }
        }
    }

    data class ControlMessage(
        val type: ControlType,
        val senderPrefix: ByteArray,
        val connectionId: ByteArray,
        val port: Int
    )

    data class ClientHandshakeState(
        val hello: ByteArray,
        internal val connectionId: ByteArray,
        internal val clientNonce: ByteArray
    )

    data class SessionSecrets(
        val clientToServerKey: ByteArray,
        val serverToClientKey: ByteArray,
        val clientNoncePrefix: ByteArray,
        val serverNoncePrefix: ByteArray
    ) {
        fun writer(isClient: Boolean): RecordWriter = if (isClient) {
            RecordWriter(clientToServerKey, clientNoncePrefix, CLIENT_ROLE)
        } else {
            RecordWriter(serverToClientKey, serverNoncePrefix, SERVER_ROLE)
        }

        fun reader(isClient: Boolean): RecordReader = if (isClient) {
            RecordReader(serverToClientKey, serverNoncePrefix, SERVER_ROLE)
        } else {
            RecordReader(clientToServerKey, clientNoncePrefix, CLIENT_ROLE)
        }
    }

    data class ServerHandshakeResult(
        val reply: ByteArray,
        val secrets: SessionSecrets
    )

    class RecordWriter internal constructor(
        key: ByteArray,
        noncePrefix: ByteArray,
        private val direction: Byte
    ) {
        private val key = key.copyOf()
        private val noncePrefix = noncePrefix.copyOf()
        private var nextSequence = 0L

        @Synchronized
        fun seal(packet: ByteArray): ByteArray {
            check(nextSequence >= 0) { "Secure record sequence exhausted" }
            val record = sealRecord(packet, key, noncePrefix, direction, nextSequence)
            nextSequence = if (nextSequence == Long.MAX_VALUE) -1 else nextSequence + 1
            return record
        }
    }

    class RecordReader internal constructor(
        key: ByteArray,
        noncePrefix: ByteArray,
        private val direction: Byte
    ) {
        private val key = key.copyOf()
        private val noncePrefix = noncePrefix.copyOf()
        private var expectedSequence = 0L

        @Synchronized
        fun open(record: ByteArray): ByteArray? {
            if (expectedSequence < 0) return null
            val packet = openRecord(record, key, noncePrefix, direction, expectedSequence) ?: return null
            expectedSequence = if (expectedSequence == Long.MAX_VALUE) -1 else expectedSequence + 1
            return packet
        }
    }

    fun randomConnectionId(): ByteArray = ByteArray(CONNECTION_ID_BYTES).also(random::nextBytes)

    /** Produces a deterministic 43-character PSK passphrase accepted by the public NDP API. */
    fun deriveNdpPassphrase(
        sharedSecret: ByteArray,
        localPublicKey: ByteArray,
        peerPublicKey: ByteArray
    ): String {
        requireKeyMaterial(sharedSecret, localPublicKey, peerPublicKey)
        val info = domain("NDP-PSK") + orderedIdentities(localPublicKey, peerPublicKey)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hkdf(sharedSecret, info, 32))
    }

    fun encodeControl(
        type: ControlType,
        senderPublicKey: ByteArray,
        connectionId: ByteArray,
        port: Int,
        sharedSecret: ByteArray
    ): ByteArray {
        require(senderPublicKey.size == IDENTITY_KEY_BYTES) { "Identity public key must be 32 bytes" }
        require(connectionId.size == CONNECTION_ID_BYTES) { "Connection ID must be 16 bytes" }
        require(sharedSecret.size >= 32) { "Pair secret must be at least 32 bytes" }
        require((type == ControlType.REQUEST && port == 0) ||
            (type == ControlType.READY && port in 1..65_535)
        ) { "Invalid NDP control port" }

        val authenticated = ByteBuffer.allocate(CONTROL_AUTHENTICATED_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .put(controlMagic)
            .put(VERSION)
            .put(type.wireValue)
            .put(senderPublicKey, 0, IDENTITY_PREFIX_BYTES)
            .put(connectionId)
            .putShort(port.toShort())
            .array()
        return authenticated + authenticationTag(
            hkdf(sharedSecret, domain("CONTROL"), 32),
            authenticated,
            CONTROL_TAG_BYTES
        )
    }

    fun isControl(packet: ByteArray): Boolean =
        packet.size == CONTROL_BYTES && packet.copyOfRange(0, controlMagic.size).contentEquals(controlMagic)

    /** Extracts only the routing prefix; callers must authenticate with [decodeControl] before use. */
    fun peekControlSenderPrefix(packet: ByteArray): ByteArray? {
        if (!isControl(packet) || packet[4] != VERSION) return null
        return packet.copyOfRange(6, 6 + IDENTITY_PREFIX_BYTES)
    }

    fun decodeControl(packet: ByteArray, sharedSecret: ByteArray): ControlMessage? = runCatching {
        require(sharedSecret.size >= 32)
        require(isControl(packet))
        val authenticated = packet.copyOfRange(0, CONTROL_AUTHENTICATED_BYTES)
        val suppliedTag = packet.copyOfRange(CONTROL_AUTHENTICATED_BYTES, packet.size)
        val expectedTag = authenticationTag(
            hkdf(sharedSecret, domain("CONTROL"), 32),
            authenticated,
            CONTROL_TAG_BYTES
        )
        require(MessageDigest.isEqual(suppliedTag, expectedTag))

        val buffer = ByteBuffer.wrap(authenticated).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(controlMagic.size).also(buffer::get)
        require(magic.contentEquals(controlMagic) && buffer.get() == VERSION)
        val type = requireNotNull(ControlType.fromWire(buffer.get()))
        val prefix = ByteArray(IDENTITY_PREFIX_BYTES).also(buffer::get)
        val connectionId = ByteArray(CONNECTION_ID_BYTES).also(buffer::get)
        val port = buffer.short.toInt() and 0xFFFF
        require((type == ControlType.REQUEST && port == 0) ||
            (type == ControlType.READY && port in 1..65_535))
        ControlMessage(type, prefix, connectionId, port)
    }.getOrNull()

    fun createClientHandshake(
        connectionId: ByteArray,
        sharedSecret: ByteArray,
        clientPublicKey: ByteArray,
        serverPublicKey: ByteArray
    ): ClientHandshakeState {
        requireConnectionMaterial(connectionId, sharedSecret, clientPublicKey, serverPublicKey)
        val clientNonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        val header = handshakeHeader(CLIENT_ROLE, connectionId, clientNonce)
        val authKey = authenticationKey(sharedSecret, clientPublicKey, serverPublicKey, connectionId)
        return ClientHandshakeState(
            hello = header + authenticationTag(authKey, header, PROOF_BYTES),
            connectionId = connectionId.copyOf(),
            clientNonce = clientNonce
        )
    }

    fun acceptClientHandshake(
        hello: ByteArray,
        expectedConnectionId: ByteArray,
        sharedSecret: ByteArray,
        serverPublicKey: ByteArray,
        clientPublicKey: ByteArray
    ): ServerHandshakeResult? = runCatching {
        requireConnectionMaterial(expectedConnectionId, sharedSecret, serverPublicKey, clientPublicKey)
        val parsed = parseHandshake(hello, CLIENT_ROLE) ?: error("Malformed client hello")
        require(MessageDigest.isEqual(parsed.connectionId, expectedConnectionId))
        val authKey = authenticationKey(sharedSecret, serverPublicKey, clientPublicKey, expectedConnectionId)
        require(MessageDigest.isEqual(parsed.proof, authenticationTag(authKey, parsed.header, PROOF_BYTES)))

        val serverNonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        val replyHeader = handshakeHeader(SERVER_ROLE, expectedConnectionId, serverNonce)
        val proofInput = replyHeader + parsed.nonce
        val reply = replyHeader + authenticationTag(authKey, proofInput, PROOF_BYTES)
        ServerHandshakeResult(
            reply = reply,
            secrets = deriveSessionSecrets(
                sharedSecret,
                serverPublicKey,
                clientPublicKey,
                expectedConnectionId,
                parsed.nonce,
                serverNonce
            )
        )
    }.getOrNull()

    fun completeClientHandshake(
        state: ClientHandshakeState,
        reply: ByteArray,
        sharedSecret: ByteArray,
        clientPublicKey: ByteArray,
        serverPublicKey: ByteArray
    ): SessionSecrets? = runCatching {
        requireConnectionMaterial(state.connectionId, sharedSecret, clientPublicKey, serverPublicKey)
        val parsed = parseHandshake(reply, SERVER_ROLE) ?: error("Malformed server hello")
        require(MessageDigest.isEqual(parsed.connectionId, state.connectionId))
        val authKey = authenticationKey(sharedSecret, clientPublicKey, serverPublicKey, state.connectionId)
        require(MessageDigest.isEqual(
            parsed.proof,
            authenticationTag(authKey, parsed.header + state.clientNonce, PROOF_BYTES)
        ))
        deriveSessionSecrets(
            sharedSecret,
            clientPublicKey,
            serverPublicKey,
            state.connectionId,
            state.clientNonce,
            parsed.nonce
        )
    }.getOrNull()

    fun readHandshake(input: InputStream): ByteArray? = readExactlyOrEof(input, HANDSHAKE_BYTES)

    fun writePacket(output: OutputStream, writer: RecordWriter, packet: ByteArray) {
        output.write(writer.seal(packet))
        output.flush()
    }

    /** Returns null only for a clean EOF before the next record starts. */
    fun readPacket(input: InputStream, reader: RecordReader): ByteArray? {
        val header = readExactlyOrEof(input, RECORD_HEADER_BYTES) ?: return null
        val plainLength = parseRecordPlainLength(header)
            ?: throw NdpProtocolException("Invalid secure-record header")
        val encryptedBody = readExactlyOrEof(input, plainLength + GCM_TAG_BYTES)
            ?: throw EOFException("Truncated secure record")
        return reader.open(header + encryptedBody)
            ?: throw NdpProtocolException("Secure-record authentication or sequence failure")
    }

    private data class ParsedHandshake(
        val header: ByteArray,
        val connectionId: ByteArray,
        val nonce: ByteArray,
        val proof: ByteArray
    )

    private fun parseHandshake(packet: ByteArray, expectedRole: Byte): ParsedHandshake? = runCatching {
        require(packet.size == HANDSHAKE_BYTES)
        val header = packet.copyOfRange(0, HANDSHAKE_BYTES - PROOF_BYTES)
        val buffer = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(handshakeMagic.size).also(buffer::get)
        require(magic.contentEquals(handshakeMagic))
        require(buffer.get() == VERSION && buffer.get() == expectedRole)
        val connectionId = ByteArray(CONNECTION_ID_BYTES).also(buffer::get)
        val nonce = ByteArray(NONCE_BYTES).also(buffer::get)
        ParsedHandshake(
            header,
            connectionId,
            nonce,
            packet.copyOfRange(header.size, packet.size)
        )
    }.getOrNull()

    private fun handshakeHeader(role: Byte, connectionId: ByteArray, nonce: ByteArray): ByteArray =
        ByteBuffer.allocate(HANDSHAKE_BYTES - PROOF_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .put(handshakeMagic)
            .put(VERSION)
            .put(role)
            .put(connectionId)
            .put(nonce)
            .array()

    private fun deriveSessionSecrets(
        sharedSecret: ByteArray,
        localPublicKey: ByteArray,
        peerPublicKey: ByteArray,
        connectionId: ByteArray,
        clientNonce: ByteArray,
        serverNonce: ByteArray
    ): SessionSecrets {
        val info = domain("SESSION") + orderedIdentities(localPublicKey, peerPublicKey) +
            connectionId + clientNonce + serverNonce
        val material = hkdf(sharedSecret, info, 72)
        return SessionSecrets(
            clientToServerKey = material.copyOfRange(0, 32),
            serverToClientKey = material.copyOfRange(32, 64),
            clientNoncePrefix = material.copyOfRange(64, 68),
            serverNoncePrefix = material.copyOfRange(68, 72)
        )
    }

    private fun authenticationKey(
        sharedSecret: ByteArray,
        localPublicKey: ByteArray,
        peerPublicKey: ByteArray,
        connectionId: ByteArray
    ): ByteArray = hkdf(
        sharedSecret,
        domain("HANDSHAKE") + orderedIdentities(localPublicKey, peerPublicKey) + connectionId,
        32
    )

    private fun sealRecord(
        packet: ByteArray,
        key: ByteArray,
        noncePrefix: ByteArray,
        direction: Byte,
        sequence: Long
    ): ByteArray {
        require(packet.isNotEmpty()) { "NDP packet must not be empty" }
        require(packet.size <= MAX_PACKET_BYTES) { "NDP packet exceeds the bounded record size" }
        val header = ByteBuffer.allocate(RECORD_HEADER_BYTES).order(ByteOrder.BIG_ENDIAN)
            .put(recordMagic)
            .put(VERSION)
            .put(direction)
            .putLong(sequence)
            .putInt(packet.size)
            .array()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, recordNonce(noncePrefix, sequence))
        )
        cipher.updateAAD(header)
        return header + cipher.doFinal(packet)
    }

    private fun openRecord(
        record: ByteArray,
        key: ByteArray,
        noncePrefix: ByteArray,
        expectedDirection: Byte,
        expectedSequence: Long
    ): ByteArray? = runCatching {
        require(record.size >= RECORD_HEADER_BYTES + GCM_TAG_BYTES)
        val header = record.copyOfRange(0, RECORD_HEADER_BYTES)
        val buffer = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(recordMagic.size).also(buffer::get)
        require(magic.contentEquals(recordMagic))
        require(buffer.get() == VERSION && buffer.get() == expectedDirection)
        val sequence = buffer.long
        val plainLength = buffer.int
        require(sequence == expectedSequence)
        require(plainLength in 1..MAX_PACKET_BYTES)
        require(record.size == RECORD_HEADER_BYTES + plainLength + GCM_TAG_BYTES)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, recordNonce(noncePrefix, sequence))
        )
        cipher.updateAAD(header)
        cipher.doFinal(record, RECORD_HEADER_BYTES, record.size - RECORD_HEADER_BYTES)
    }.getOrNull()

    private fun parseRecordPlainLength(header: ByteArray): Int? = runCatching {
        require(header.size == RECORD_HEADER_BYTES)
        val buffer = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(recordMagic.size).also(buffer::get)
        require(magic.contentEquals(recordMagic))
        require(buffer.get() == VERSION)
        buffer.get() // Direction is authenticated and validated by RecordReader.
        buffer.long
        buffer.int.also { require(it in 1..MAX_PACKET_BYTES) }
    }.getOrNull()

    private fun recordNonce(prefix: ByteArray, sequence: Long): ByteArray {
        require(prefix.size == RECORD_NONCE_PREFIX_BYTES)
        return ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
            .put(prefix)
            .putLong(sequence)
            .array()
    }

    private fun readExactlyOrEof(input: InputStream, count: Int): ByteArray? {
        val output = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = input.read(output, offset, count - offset)
            if (read < 0) {
                if (offset == 0) return null
                throw EOFException("Expected $count bytes, received $offset")
            }
            if (read == 0) continue
            offset += read
        }
        return output
    }

    private fun authenticationTag(key: ByteArray, message: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message).copyOf(length)
    }

    private fun hkdf(inputKeyMaterial: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        require(outputLength in 1..(255 * 32))
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(ByteArray(mac.macLength), "HmacSHA256"))
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

    private fun orderedIdentities(first: ByteArray, second: ByteArray): ByteArray =
        if (compareUnsigned(first, second) <= 0) first + second else second + first

    private fun compareUnsigned(first: ByteArray, second: ByteArray): Int {
        val count = minOf(first.size, second.size)
        for (index in 0 until count) {
            val comparison = (first[index].toInt() and 0xFF) - (second[index].toInt() and 0xFF)
            if (comparison != 0) return comparison
        }
        return first.size - second.size
    }

    private fun requireConnectionMaterial(
        connectionId: ByteArray,
        sharedSecret: ByteArray,
        localPublicKey: ByteArray,
        peerPublicKey: ByteArray
    ) {
        require(connectionId.size == CONNECTION_ID_BYTES) { "Connection ID must be 16 bytes" }
        requireKeyMaterial(sharedSecret, localPublicKey, peerPublicKey)
    }

    private fun requireKeyMaterial(
        sharedSecret: ByteArray,
        localPublicKey: ByteArray,
        peerPublicKey: ByteArray
    ) {
        require(sharedSecret.size >= 32) { "Pair secret must be at least 32 bytes" }
        require(localPublicKey.size == IDENTITY_KEY_BYTES) { "Local identity key must be 32 bytes" }
        require(peerPublicKey.size == IDENTITY_KEY_BYTES) { "Peer identity key must be 32 bytes" }
        require(!MessageDigest.isEqual(localPublicKey, peerPublicKey)) { "Peer identity must be distinct" }
    }

    private fun domain(label: String): ByteArray =
        "OmniRelay/WiFi-Aware/$label/v1\u0000".toByteArray(Charsets.UTF_8)

    private const val CONTROL_AUTHENTICATED_BYTES =
        4 + 1 + 1 + IDENTITY_PREFIX_BYTES + CONNECTION_ID_BYTES + 2
    private const val CONTROL_BYTES = CONTROL_AUTHENTICATED_BYTES + CONTROL_TAG_BYTES
}

internal class NdpProtocolException(message: String) : Exception(message)
