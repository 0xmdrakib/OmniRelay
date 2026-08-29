package com.example.omnirelay.radio

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySession
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareNetworkInfo
import android.net.wifi.aware.WifiAwareNetworkSpecifier
import android.net.wifi.aware.WifiAwareSession
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.annotation.RequiresApi
import com.example.omnirelay.protocol.OmniFrame
import com.example.omnirelay.protocol.RelayCapsule
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Wi-Fi Aware discovery plus an on-demand, pair-authenticated Network Data Path.
 *
 * API 29+ uses a PSK-protected NDP and a mutually authenticated AES-GCM socket stream for paired
 * peers. API 26-28 remains compatible through encrypted OmniFrame follow-up messages because the
 * public peer IPv6/port transport information needed for a reliable socket path is exposed from
 * API 29. NDP links are never opened proactively for relay broadcasts, which bounds volunteer
 * phone radio, callback, socket, and memory use.
 */
class WifiAwareMeshManager(
    private val context: Context,
    identityPublicKey: ByteArray,
    private val peerCredentialsProvider: (ByteArray) -> PeerCredentials? = { null }
) {

    data class PeerCredentials(
        val publicKey: ByteArray,
        val sharedSecret: ByteArray
    )

    companion object {
        const val TAG = "WifiAwareMeshManager"
        const val SERVICE_NAME = "OmniRelayNANService"
        private const val HELLO_MARKER: Byte = 0x7E
        private const val MAX_FOLLOWUP_PACKET_BYTES = 200
        private const val MAX_ACTIVE_NDP_CHANNELS = 8
        private const val MAX_ACTIVE_NDP_SETUPS = 8
        private const val DISCOVERY_PREFIX_BYTES = WifiAwareNdpProtocol.IDENTITY_PREFIX_BYTES
        private const val MAX_PENDING_PEERS = 16
        private const val MAX_PENDING_PACKETS_PER_PEER = 32
        private const val MAX_PENDING_BYTES_PER_PEER = 1024 * 1024
        private const val MAX_PENDING_BYTES_GLOBAL = 4 * 1024 * 1024
        private const val NDP_SETUP_TIMEOUT_MS = 20_000
        private const val HANDSHAKE_TIMEOUT_MS = 12_000
        private const val CHANNEL_IDLE_TIMEOUT_MS = 120_000
        private const val TCP_PROTOCOL_NUMBER = 6
        private const val SOCKET_BUFFER_BYTES = 256 * 1024
        private const val MAX_UNAUTHENTICATED_ACCEPTS = 3
        private const val MAX_RAW_RELAY_PEERS = 64
        private const val RAW_RELAY_PEER_TTL_MS = 2 * 60 * 1_000L
        private const val MAX_PAIRED_RELAY_TARGETS_PER_BROADCAST = 8
        private const val MAX_RAW_RELAY_TARGETS_PER_BROADCAST = 8
        private const val MAX_RAW_RELAY_FRAGMENTS_PER_MINUTE = 240
        private const val REATTACH_INITIAL_DELAY_MS = 1_000L
        private const val REATTACH_MAX_DELAY_MS = 30_000L
        private const val REATTACH_STABILITY_RESET_MS = 60_000L
    }

    private enum class DiscoveryRole { SUBSCRIBER, PUBLISHER }
    private enum class NdpRole { CLIENT, SERVER }

    private data class AwarePeer(
        val session: DiscoverySession,
        val handle: PeerHandle,
        val role: DiscoveryRole
    )

    private class PeerState(val prefix: ByteArray) {
        @Volatile var subscriberEndpoint: AwarePeer? = null
        @Volatile var publisherEndpoint: AwarePeer? = null

        fun followUpEndpoint(): AwarePeer? = subscriberEndpoint ?: publisherEndpoint
    }

    private class PendingQueue {
        val packets = ArrayDeque<ByteArray>()
        var byteCount = 0
        var setupConnectionId: String? = null
    }

    private class NdpSetup(
        val peerKey: String,
        val connectionId: ByteArray,
        val credentials: PeerCredentials,
        val endpoint: AwarePeer,
        val role: NdpRole,
        val advertisedPort: Int,
        val serverSocket: ServerSocket?
    ) {
        val connectionKey: String = connectionId.toHexStatic()
        val connectStarted = AtomicBoolean(false)
        val acceptStarted = AtomicBoolean(false)
        val completed = AtomicBoolean(false)
        @Volatile var callback: ConnectivityManager.NetworkCallback? = null
        @Volatile var network: Network? = null
    }

    private inner class SecureChannel(
        val peerKey: String,
        val connectionKey: String,
        val socket: Socket,
        val input: BufferedInputStream,
        val output: BufferedOutputStream,
        val writer: WifiAwareNdpProtocol.RecordWriter,
        val reader: WifiAwareNdpProtocol.RecordReader,
        val callback: ConnectivityManager.NetworkCallback
    ) {
        private val closed = AtomicBoolean(false)
        private val outputLock = Any()

        fun send(packet: ByteArray): Boolean {
            if (closed.get()) return false
            return runCatching {
                synchronized(outputLock) {
                    check(!closed.get())
                    WifiAwareNdpProtocol.writePacket(output, writer, packet)
                }
                true
            }.getOrElse {
                Log.w(TAG, "Secure Wi-Fi Aware write failed", it)
                closeChannel(this, "Wi-Fi Aware socket write failed", notify = true)
                false
            }
        }

        fun closeTransport() {
            if (!closed.compareAndSet(false, true)) return
            runCatching { socket.close() }
            unregisterNetworkCallback(callback)
        }
    }

    private val identityPublicKey = identityPublicKey.copyOf().also {
        require(it.size == WifiAwareNdpProtocol.IDENTITY_KEY_BYTES) {
            "Wi-Fi Aware identity key must be 32 bytes"
        }
    }
    private val identityPrefix = WifiAwareNdpProtocol.identityPrefix(this.identityPublicKey)
    private val handler = Handler(Looper.getMainLooper())
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    /** Contact-resolved discovery candidates only; NDP still authenticates them cryptographically. */
    private val peers = ConcurrentHashMap<String, PeerState>()
    /** Unauthenticated nodes are bounded/expiring and may receive opaque relay capsules only. */
    private val rawRelayPeers = BoundedExpiringPeerCache<String, AwarePeer>(
        MAX_RAW_RELAY_PEERS,
        RAW_RELAY_PEER_TTL_MS
    )
    private val rawRelayFragmentBudget = FixedWindowPermitBudget(
        MAX_RAW_RELAY_FRAGMENTS_PER_MINUTE,
        60_000L
    )
    private val seenNdpControlIds = BoundedExpiringPeerCache<String, Unit>(
        512,
        2 * 60_000L
    )
    private val reattachBackoff = BoundedRetryBackoff(
        REATTACH_INITIAL_DELAY_MS,
        REATTACH_MAX_DELAY_MS
    )
    private val pendingQueues = ConcurrentHashMap<String, PendingQueue>()
    private val pendingBytesGlobal = AtomicInteger(0)
    private val setups = ConcurrentHashMap<String, NdpSetup>()
    private val responderSetupByPeer = ConcurrentHashMap<String, String>()
    private val channels = ConcurrentHashMap<String, SecureChannel>()
    private val messageIds = AtomicInteger(1)
    private val attachmentGeneration = AtomicInteger(0)
    private val fragmentAssembler = NearbyFrameFragmentCodec.Assembler()
    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    private var wifiAwareManager: WifiAwareManager? = null
    private var awareSession: WifiAwareSession? = null
    private var publishSession: PublishDiscoverySession? = null
    private var subscribeSession: SubscribeDiscoverySession? = null
    private var reattachJob: Job? = null
    private var stabilityResetJob: Job? = null
    @Volatile private var attaching = false
    @Volatile private var attachmentDesired = false
    @Volatile private var highBandwidthNdpAllowed = false
    @Volatile private var suppressSessionCallbacks = false
    @Volatile private var closing = false

    var onFrameReceivedListener: ((ByteArray) -> Unit)? = null
    var onPeerDiscoveredListener: ((ByteArray) -> Unit)? = null
    var onDeliveryResultListener: ((Boolean, String) -> Unit)? = null

    val isSupported: Boolean
        get() = context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)

    /** Socket NDP needs WifiAwareNetworkInfo, which is public from API 29. */
    val isNdpSocketSupported: Boolean
        get() = isSupported && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            connectivityManager != null

    val activeNdpChannelCount: Int
        get() = channels.size

    val isAttachmentDesired: Boolean
        get() = attachmentDesired

    val isTerminallyClosed: Boolean
        get() = closing

    fun setHighBandwidthNdpAllowed(allowed: Boolean) {
        if (highBandwidthNdpAllowed == allowed) return
        highBandwidthNdpAllowed = allowed
        if (!allowed) closeDataPaths("High-bandwidth Wi-Fi Aware paused", preservePending = true)
    }

    init {
        if (isSupported) {
            wifiAwareManager = context.getSystemService(Context.WIFI_AWARE_SERVICE) as? WifiAwareManager
        }
    }

    @SuppressLint("MissingPermission")
    fun attachToNANCluster() {
        if (closing) return
        attachmentDesired = true
        attachIfNeeded()
    }

    @SuppressLint("MissingPermission")
    private fun attachIfNeeded() {
        val manager = wifiAwareManager ?: return
        if (closing || !attachmentDesired || awareSession != null || attaching) return
        if (!manager.isAvailable) {
            scheduleReattach("Wi-Fi Aware is temporarily unavailable")
            return
        }
        attaching = true
        val generation = attachmentGeneration.incrementAndGet()
        runCatching {
            manager.attach(object : AttachCallback() {
                override fun onAttached(session: WifiAwareSession) {
                    if (generation != attachmentGeneration.get()) {
                        session.close()
                        return
                    }
                    attaching = false
                    if (closing || !attachmentDesired) {
                        session.close()
                        return
                    }
                    reattachJob = null
                    awareSession = session
                    startPublishService(session, generation)
                    startSubscribeService(session, generation)
                }

                override fun onAttachFailed() {
                    if (generation != attachmentGeneration.get()) return
                    attaching = false
                    Log.e(TAG, "Unable to attach to Wi-Fi Aware")
                    scheduleReattach("Wi-Fi Aware attach failed")
                }

                override fun onAwareSessionTerminated() {
                    if (generation != attachmentGeneration.get()) return
                    attachmentGeneration.incrementAndGet()
                    attaching = false
                    synchronized(this@WifiAwareMeshManager) {
                        stabilityResetJob?.cancel()
                        stabilityResetJob = null
                    }
                    awareSession = null
                    publishSession = null
                    subscribeSession = null
                    closeDataPaths("Wi-Fi Aware session ended", preservePending = true)
                    peers.clear()
                    rawRelayPeers.clear()
                    if (!suppressSessionCallbacks) {
                        scheduleReattach("Android terminated the Wi-Fi Aware session")
                    }
                }
            }, handler)
        }.onFailure {
            if (generation != attachmentGeneration.get()) return@onFailure
            attaching = false
            Log.w(TAG, "Wi-Fi Aware permission or attach failure", it)
            scheduleReattach("Wi-Fi Aware attach threw an exception")
        }
    }

    @SuppressLint("MissingPermission")
    private fun startPublishService(session: WifiAwareSession, generation: Int) {
        val config = PublishConfig.Builder()
            .setServiceName(SERVICE_NAME)
            .setServiceSpecificInfo(identityPrefix)
            .build()
        session.publish(config, object : DiscoverySessionCallback() {
            override fun onPublishStarted(session: PublishDiscoverySession) {
                if (generation != attachmentGeneration.get()) {
                    session.close()
                    return
                }
                publishSession = session
                markDiscoveryReadyIfComplete()
            }

            override fun onSessionConfigFailed() {
                if (generation != attachmentGeneration.get()) return
                recoverDiscoverySessions("Wi-Fi Aware publish configuration failed")
            }

            override fun onMessageReceived(peerHandle: PeerHandle, message: ByteArray) {
                if (generation != attachmentGeneration.get()) return
                processMessage(DiscoveryRole.PUBLISHER, publishSession ?: return, peerHandle, message)
            }

            override fun onMessageSendSucceeded(messageId: Int) {
                onDeliveryResultListener?.invoke(true, "Wi-Fi Aware signaling delivered")
            }

            override fun onMessageSendFailed(messageId: Int) {
                onDeliveryResultListener?.invoke(false, "Wi-Fi Aware signaling failed")
            }

            override fun onSessionTerminated() {
                if (generation != attachmentGeneration.get()) return
                publishSession = null
                if (!suppressSessionCallbacks) {
                    recoverDiscoverySessions("Android terminated Wi-Fi Aware publishing")
                }
            }
        }, handler)
    }

    @SuppressLint("MissingPermission")
    private fun startSubscribeService(session: WifiAwareSession, generation: Int) {
        val config = SubscribeConfig.Builder().setServiceName(SERVICE_NAME).build()
        session.subscribe(config, object : DiscoverySessionCallback() {
            override fun onSubscribeStarted(session: SubscribeDiscoverySession) {
                if (generation != attachmentGeneration.get()) {
                    session.close()
                    return
                }
                subscribeSession = session
                markDiscoveryReadyIfComplete()
            }

            override fun onSessionConfigFailed() {
                if (generation != attachmentGeneration.get()) return
                recoverDiscoverySessions("Wi-Fi Aware subscribe configuration failed")
            }

            override fun onServiceDiscovered(
                peerHandle: PeerHandle,
                serviceSpecificInfo: ByteArray,
                matchFilter: MutableList<ByteArray>?
            ) {
                if (generation != attachmentGeneration.get()) return
                if (serviceSpecificInfo.size < DISCOVERY_PREFIX_BYTES) return
                val prefix = serviceSpecificInfo.copyOf(DISCOVERY_PREFIX_BYTES)
                if (MessageDigest.isEqual(prefix, identityPrefix)) return
                val activeSession = subscribeSession ?: return
                val endpoint = AwarePeer(activeSession, peerHandle, DiscoveryRole.SUBSCRIBER)
                if (credentialsFor(prefix) != null) {
                    registerPairedPeer(prefix, endpoint)
                } else {
                    rawRelayPeers.put(prefix.toHex(), endpoint)
                }
            }

            override fun onServiceLost(peerHandle: PeerHandle, reason: Int) {
                if (generation != attachmentGeneration.get()) return
                peers.entries.forEach { entry ->
                    if (entry.value.subscriberEndpoint?.handle == peerHandle) {
                        entry.value.subscriberEndpoint = null
                        closePeerChannel(entry.key, "Wi-Fi Aware peer left range", notify = false)
                    }
                }
                rawRelayPeers.snapshot().forEach { (key, endpoint) ->
                    if (endpoint.handle == peerHandle) rawRelayPeers.remove(key)
                }
            }

            override fun onMessageReceived(peerHandle: PeerHandle, message: ByteArray) {
                if (generation != attachmentGeneration.get()) return
                processMessage(DiscoveryRole.SUBSCRIBER, subscribeSession ?: return, peerHandle, message)
            }

            override fun onMessageSendSucceeded(messageId: Int) {
                onDeliveryResultListener?.invoke(true, "Wi-Fi Aware signaling delivered")
            }

            override fun onMessageSendFailed(messageId: Int) {
                onDeliveryResultListener?.invoke(false, "Wi-Fi Aware signaling failed")
            }

            override fun onSessionTerminated() {
                if (generation != attachmentGeneration.get()) return
                subscribeSession = null
                if (!suppressSessionCallbacks) {
                    recoverDiscoverySessions("Android terminated Wi-Fi Aware subscription")
                }
            }
        }, handler)
    }

    private fun registerPairedPeer(prefix: ByteArray, endpoint: AwarePeer): PeerState {
        val prefixCopy = prefix.copyOf()
        rawRelayPeers.remove(prefixCopy.toHex())
        val state = peers.computeIfAbsent(prefixCopy.toHex()) { PeerState(prefixCopy) }
        when (endpoint.role) {
            DiscoveryRole.SUBSCRIBER -> state.subscriberEndpoint = endpoint
            DiscoveryRole.PUBLISHER -> state.publisherEndpoint = endpoint
        }
        onPeerDiscoveredListener?.invoke(prefixCopy)
        if (endpoint.role == DiscoveryRole.SUBSCRIBER && attachmentDesired) {
            val queue = pendingQueues[prefixCopy.toHex()]
            val shouldResume = queue != null && synchronized(queue) {
                queue.packets.isNotEmpty() && queue.setupConnectionId == null
            }
            if (shouldResume) {
                credentialsFor(prefixCopy)?.let { credentials ->
                    startInitiator(prefixCopy.toHex(), state, credentials)
                }
            }
        }
        return state
    }

    private fun processMessage(
        role: DiscoveryRole,
        session: DiscoverySession,
        peerHandle: PeerHandle,
        message: ByteArray
    ) {
        if (message.size == DISCOVERY_PREFIX_BYTES + 1 && message[0] == HELLO_MARKER) {
            val prefix = message.copyOfRange(1, message.size)
            if (!MessageDigest.isEqual(prefix, identityPrefix)) {
                val endpoint = AwarePeer(session, peerHandle, role)
                if (credentialsFor(prefix) != null) {
                    registerPairedPeer(prefix, endpoint)
                } else {
                    rawRelayPeers.put(prefix.toHex(), endpoint)
                }
            }
            return
        }

        if (WifiAwareNdpProtocol.isControl(message)) {
            val prefix = WifiAwareNdpProtocol.peekControlSenderPrefix(message) ?: return
            val credentials = credentialsFor(prefix) ?: return
            val control = WifiAwareNdpProtocol.decodeControl(message, credentials.sharedSecret) ?: return
            if (!MessageDigest.isEqual(prefix, control.senderPrefix)) return
            val controlReplayKey = "${control.type.name}:${control.connectionId.toHex()}"
            if (!seenNdpControlIds.putIfAbsent(controlReplayKey, Unit)) return
            val peer = registerPairedPeer(prefix, AwarePeer(session, peerHandle, role))
            when {
                control.type == WifiAwareNdpProtocol.ControlType.REQUEST &&
                    role == DiscoveryRole.PUBLISHER -> startResponder(peer, control, credentials)
                control.type == WifiAwareNdpProtocol.ControlType.READY &&
                    role == DiscoveryRole.SUBSCRIBER -> startClientNetwork(peer, control, credentials)
            }
            return
        }

        fragmentAssembler.accept(peerHandle.hashCode().toString(), message)?.let { packet ->
            if (packet.isNotEmpty()) onFrameReceivedListener?.invoke(packet)
        }
    }

    /**
     * Sends immediately on an established NDP, or queues a bounded packet while an on-demand NDP
     * is established. If NDP is unavailable, the existing follow-up signaling path is retained.
     */
    @SuppressLint("MissingPermission")
    fun sendFrame(targetPublicKey: ByteArray, packedFrame: ByteArray): Boolean {
        if (closing || !attachmentDesired ||
            targetPublicKey.size != WifiAwareNdpProtocol.IDENTITY_KEY_BYTES ||
            packedFrame.isEmpty() || packedFrame.size > WifiAwareNdpProtocol.MAX_PACKET_BYTES
        ) return false
        val targetPrefix = WifiAwareNdpProtocol.identityPrefix(targetPublicKey)
        val peerKey = targetPrefix.toHex()
        val peer = peers[peerKey] ?: return false
        val credentials = credentialsFor(targetPrefix, targetPublicKey) ?: run {
            demoteToRawRelayPeer(peerKey, peer)
            return false
        }

        channels[peerKey]?.let { channel ->
            if (channel.send(packedFrame)) return true
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            if (!highBandwidthNdpAllowed || !isNdpSocketSupported ||
                peer.subscriberEndpoint == null
            ) return false
            val isRealtimeVoice = OmniFrame.unpack(packedFrame)?.payloadType ==
                OmniFrame.PAYLOAD_TYPE_VOICE
            if (!isRealtimeVoice && !enqueuePending(peerKey, packedFrame)) {
                return false
            }
            if (isRealtimeVoice && queueForPeer(peerKey) == null) return false
            if (!startInitiator(peerKey, peer, credentials) &&
                pendingQueues[peerKey]?.setupConnectionId == null
            ) {
                fallbackPending(peerKey, peer)
            }
            // NDP setup is asynchronous. Returning false lets the service immediately use BLE or
            // an opaque relay capsule without exposing a direct frame over unauthenticated Aware.
            return false
        }
        return sendFollowUp(peer.followUpEndpoint(), packedFrame)
    }

    /** Sends only when a mutually authenticated NDP socket is already established. */
    fun hasHighBandwidthChannel(targetPublicKey: ByteArray): Boolean {
        if (!highBandwidthNdpAllowed || targetPublicKey.size != WifiAwareNdpProtocol.IDENTITY_KEY_BYTES) {
            return false
        }
        return channels.containsKey(
            WifiAwareNdpProtocol.identityPrefix(targetPublicKey).toHex()
        )
    }

    fun sendHighBandwidthFrame(targetPublicKey: ByteArray, packedFrame: ByteArray): Boolean {
        if (!highBandwidthNdpAllowed || closing || !attachmentDesired ||
            targetPublicKey.size != WifiAwareNdpProtocol.IDENTITY_KEY_BYTES ||
            packedFrame.isEmpty() || packedFrame.size > WifiAwareNdpProtocol.MAX_PACKET_BYTES
        ) return false
        val targetPrefix = WifiAwareNdpProtocol.identityPrefix(targetPublicKey)
        if (credentialsFor(targetPrefix, targetPublicKey) == null) return false
        return channels[targetPrefix.toHex()]?.send(packedFrame) == true
    }

    /**
     * Relays over already-open secure channels, otherwise over lightweight follow-up messages.
     * It intentionally never creates multiple high-power NDPs for a volunteer broadcast.
     */
    fun broadcastPacket(packedPacket: ByteArray): Int {
        if (closing || !attachmentDesired || RelayCapsule.unpack(packedPacket) == null ||
            packedPacket.size > WifiAwareNdpProtocol.MAX_PACKET_BYTES
        ) return 0
        var delivered = 0
        peers.entries.asSequence().take(MAX_PAIRED_RELAY_TARGETS_PER_BROADCAST).forEach { (peerKey, peer) ->
            val channel = channels[peerKey]
            val accepted = if (channel != null) {
                channel.send(packedPacket) || sendFollowUp(peer.followUpEndpoint(), packedPacket)
            } else {
                sendFollowUp(peer.followUpEndpoint(), packedPacket)
            }
            if (accepted) delivered++
        }
        var rawTargets = 0
        rawRelayPeers.snapshot().forEach { (peerKey, endpoint) ->
            if (rawTargets >= MAX_RAW_RELAY_TARGETS_PER_BROADCAST) return@forEach
            if (peers.containsKey(peerKey)) return@forEach
            if (sendRawRelayFollowUp(endpoint, packedPacket)) {
                delivered++
                rawTargets++
            }
        }
        return delivered
    }

    @SuppressLint("MissingPermission")
    private fun startInitiator(
        peerKey: String,
        peer: PeerState,
        credentials: PeerCredentials
    ): Boolean {
        if (!highBandwidthNdpAllowed || Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ||
            setups.size >= MAX_ACTIVE_NDP_SETUPS ||
            channels.size >= MAX_ACTIVE_NDP_CHANNELS
        ) return false
        val endpoint = peer.subscriberEndpoint ?: return false
        val queue = queueForPeer(peerKey) ?: return false
        synchronized(queue) {
            if (queue.setupConnectionId != null) return true
            val connectionId = WifiAwareNdpProtocol.randomConnectionId()
            val connectionKey = connectionId.toHex()
            val request = WifiAwareNdpProtocol.encodeControl(
                WifiAwareNdpProtocol.ControlType.REQUEST,
                identityPublicKey,
                connectionId,
                0,
                credentials.sharedSecret
            )
            return runCatching {
                endpoint.session.sendMessage(endpoint.handle, nextMessageId(), request)
                queue.setupConnectionId = connectionKey
                scheduleControlTimeout(peerKey, connectionKey)
                true
            }.getOrElse {
                Log.w(TAG, "Unable to request Wi-Fi Aware data path", it)
                false
            }
        }
    }

    private fun scheduleControlTimeout(peerKey: String, connectionKey: String) {
        ioScope.launch {
            delay((NDP_SETUP_TIMEOUT_MS + 5_000).toLong())
            val queue = pendingQueues[peerKey] ?: return@launch
            val shouldFallback = synchronized(queue) {
                queue.setupConnectionId == connectionKey && channels[peerKey] == null
            }
            if (shouldFallback) {
                val peer = peers[peerKey]
                if (peer != null) fallbackPending(peerKey, peer)
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun startResponder(
        peer: PeerState,
        control: WifiAwareNdpProtocol.ControlMessage,
        credentials: PeerCredentials
    ) {
        val peerKey = control.senderPrefix.toHex()
        if (closing || !highBandwidthNdpAllowed || channels[peerKey] != null ||
            setups.size >= MAX_ACTIVE_NDP_SETUPS ||
            channels.size >= MAX_ACTIVE_NDP_CHANNELS ||
            responderSetupByPeer.putIfAbsent(peerKey, control.connectionId.toHex()) != null
        ) return
        val endpoint = peer.publisherEndpoint ?: run {
            responderSetupByPeer.remove(peerKey)
            return
        }
        val serverSocket = runCatching {
            ServerSocket().apply {
                reuseAddress = false
                bind(InetSocketAddress(0))
                soTimeout = HANDSHAKE_TIMEOUT_MS
            }
        }.getOrElse {
            responderSetupByPeer.remove(peerKey)
            return
        }
        val setup = NdpSetup(
            peerKey = peerKey,
            connectionId = control.connectionId.copyOf(),
            credentials = credentials,
            endpoint = endpoint,
            role = NdpRole.SERVER,
            advertisedPort = serverSocket.localPort,
            serverSocket = serverSocket
        )

        if (!requestNetwork(setup)) {
            responderSetupByPeer.remove(peerKey, setup.connectionKey)
            runCatching { serverSocket.close() }
            return
        }

        val ready = WifiAwareNdpProtocol.encodeControl(
            WifiAwareNdpProtocol.ControlType.READY,
            identityPublicKey,
            setup.connectionId,
            setup.advertisedPort,
            credentials.sharedSecret
        )
        runCatching {
            endpoint.session.sendMessage(endpoint.handle, nextMessageId(), ready)
        }.onFailure { failSetup(setup.connectionKey, "Unable to announce Wi-Fi Aware data path") }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun startClientNetwork(
        peer: PeerState,
        control: WifiAwareNdpProtocol.ControlMessage,
        credentials: PeerCredentials
    ) {
        val peerKey = control.senderPrefix.toHex()
        if (closing || !highBandwidthNdpAllowed || channels[peerKey] != null) return
        val queue = pendingQueues[peerKey] ?: return
        val expectedConnectionKey = synchronized(queue) { queue.setupConnectionId }
        if (expectedConnectionKey != control.connectionId.toHex()) return
        if (setups.containsKey(expectedConnectionKey)) return
        val endpoint = peer.subscriberEndpoint ?: return
        val setup = NdpSetup(
            peerKey = peerKey,
            connectionId = control.connectionId.copyOf(),
            credentials = credentials,
            endpoint = endpoint,
            role = NdpRole.CLIENT,
            advertisedPort = control.port,
            serverSocket = null
        )
        if (!requestNetwork(setup)) {
            fallbackPending(peerKey, peer)
        }
    }

    @SuppressLint("MissingPermission")
    @RequiresApi(Build.VERSION_CODES.Q)
    private fun requestNetwork(setup: NdpSetup): Boolean {
        if (closing || !attachmentDesired || !highBandwidthNdpAllowed) return false
        val manager = connectivityManager ?: return false
        val passphrase = WifiAwareNdpProtocol.deriveNdpPassphrase(
            setup.credentials.sharedSecret,
            identityPublicKey,
            setup.credentials.publicKey
        )
        val specifierBuilder = WifiAwareNetworkSpecifier.Builder(
            setup.endpoint.session,
            setup.endpoint.handle
        ).setPskPassphrase(passphrase)
        if (setup.role == NdpRole.SERVER) {
            specifierBuilder
                .setPort(setup.advertisedPort)
                .setTransportProtocol(TCP_PROTOCOL_NUMBER)
        }
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
            .setNetworkSpecifier(specifierBuilder.build())
            .build()
        val callback = SetupNetworkCallback(setup.connectionKey)
        setup.callback = callback
        setups[setup.connectionKey] = setup
        return runCatching {
            manager.requestNetwork(request, callback, handler, NDP_SETUP_TIMEOUT_MS)
            true
        }.getOrElse {
            setups.remove(setup.connectionKey, setup)
            Log.w(TAG, "Wi-Fi Aware NDP request failed", it)
            false
        }
    }

    private inner class SetupNetworkCallback(
        private val connectionKey: String
    ) : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val setup = setups[connectionKey] ?: return
            setup.network = network
            if (setup.role == NdpRole.SERVER && setup.acceptStarted.compareAndSet(false, true)) {
                ioScope.launch { acceptAuthenticatedClient(setup) }
            }
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
            val setup = setups[connectionKey] ?: return
            if (setup.role == NdpRole.CLIENT) maybeConnectClient(setup, network, capabilities)
        }

        override fun onUnavailable() {
            failSetup(connectionKey, "Wi-Fi Aware data path unavailable")
        }

        override fun onLost(network: Network) {
            val setup = setups[connectionKey]
            if (setup != null) {
                failSetup(connectionKey, "Wi-Fi Aware data path lost during setup")
                return
            }
            channels.values.firstOrNull { it.connectionKey == connectionKey }?.let { channel ->
                closeChannel(channel, "Wi-Fi Aware data path lost", notify = true)
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun maybeConnectClient(
        setup: NdpSetup,
        network: Network,
        capabilities: NetworkCapabilities
    ) {
        val info = capabilities.transportInfo as? WifiAwareNetworkInfo ?: return
        val peerAddress = info.peerIpv6Addr ?: return
        val frameworkPort = info.port
        if (frameworkPort != 0 && frameworkPort != setup.advertisedPort) {
            failSetup(setup.connectionKey, "Authenticated NDP port mismatch")
            return
        }
        if (!setup.connectStarted.compareAndSet(false, true)) return
        ioScope.launch {
            runCatching {
                val socket = network.socketFactory.createSocket()
                configureSocket(socket, HANDSHAKE_TIMEOUT_MS)
                socket.connect(InetSocketAddress(peerAddress, setup.advertisedPort), HANDSHAKE_TIMEOUT_MS)
                authenticateClientSocket(setup, socket)
            }.onFailure {
                Log.w(TAG, "Wi-Fi Aware client socket failed", it)
                failSetup(setup.connectionKey, "Wi-Fi Aware authenticated socket failed")
            }
        }
    }

    private fun acceptAuthenticatedClient(setup: NdpSetup) {
        val serverSocket = setup.serverSocket ?: return
        var attempts = 0
        while (!closing && setups[setup.connectionKey] === setup &&
            attempts < MAX_UNAUTHENTICATED_ACCEPTS
        ) {
            val socket = try {
                serverSocket.accept()
            } catch (_: SocketTimeoutException) {
                break
            } catch (error: Exception) {
                if (!setup.completed.get()) Log.d(TAG, "Wi-Fi Aware accept ended", error)
                break
            }
            attempts++
            val authenticated = runCatching {
                configureSocket(socket, HANDSHAKE_TIMEOUT_MS)
                authenticateServerSocket(setup, socket)
                true
            }.getOrElse {
                Log.w(TAG, "Rejected unauthenticated Wi-Fi Aware socket", it)
                runCatching { socket.close() }
                false
            }
            if (authenticated) return
        }
        failSetup(setup.connectionKey, "No authenticated Wi-Fi Aware client connected")
    }

    private fun authenticateClientSocket(setup: NdpSetup, socket: Socket) {
        val input = BufferedInputStream(socket.getInputStream(), SOCKET_BUFFER_BYTES)
        val output = BufferedOutputStream(socket.getOutputStream(), SOCKET_BUFFER_BYTES)
        val clientState = WifiAwareNdpProtocol.createClientHandshake(
            setup.connectionId,
            setup.credentials.sharedSecret,
            identityPublicKey,
            setup.credentials.publicKey
        )
        output.write(clientState.hello)
        output.flush()
        val reply = WifiAwareNdpProtocol.readHandshake(input)
            ?: error("Server closed before authentication")
        val secrets = WifiAwareNdpProtocol.completeClientHandshake(
            clientState,
            reply,
            setup.credentials.sharedSecret,
            identityPublicKey,
            setup.credentials.publicKey
        ) ?: error("Server authentication failed")
        socket.soTimeout = CHANNEL_IDLE_TIMEOUT_MS
        installChannel(setup, socket, input, output, secrets, isClient = true)
    }

    private fun authenticateServerSocket(setup: NdpSetup, socket: Socket) {
        val input = BufferedInputStream(socket.getInputStream(), SOCKET_BUFFER_BYTES)
        val output = BufferedOutputStream(socket.getOutputStream(), SOCKET_BUFFER_BYTES)
        val hello = WifiAwareNdpProtocol.readHandshake(input)
            ?: error("Client closed before authentication")
        val result = WifiAwareNdpProtocol.acceptClientHandshake(
            hello,
            setup.connectionId,
            setup.credentials.sharedSecret,
            identityPublicKey,
            setup.credentials.publicKey
        ) ?: error("Client authentication failed")
        output.write(result.reply)
        output.flush()
        socket.soTimeout = CHANNEL_IDLE_TIMEOUT_MS
        installChannel(setup, socket, input, output, result.secrets, isClient = false)
    }

    private fun installChannel(
        setup: NdpSetup,
        socket: Socket,
        input: BufferedInputStream,
        output: BufferedOutputStream,
        secrets: WifiAwareNdpProtocol.SessionSecrets,
        isClient: Boolean
    ) {
        if (closing || !attachmentDesired || !highBandwidthNdpAllowed) {
            runCatching { socket.close() }
            failSetup(setup.connectionKey, "Wi-Fi Aware data path is disabled by resource policy")
            return
        }
        val callback = setup.callback ?: error("NDP callback missing")
        val candidate = SecureChannel(
            peerKey = setup.peerKey,
            connectionKey = setup.connectionKey,
            socket = socket,
            input = input,
            output = output,
            writer = secrets.writer(isClient),
            reader = secrets.reader(isClient),
            callback = callback
        )
        setup.completed.set(true)
        setups.remove(setup.connectionKey, setup)
        responderSetupByPeer.remove(setup.peerKey, setup.connectionKey)
        runCatching { setup.serverSocket?.close() }

        var selected: SecureChannel
        var displaced: SecureChannel? = null
        var rejectedForCapacity = false
        synchronized(channels) {
            val existing = channels[setup.peerKey]
            if (existing == null && channels.size >= MAX_ACTIVE_NDP_CHANNELS) {
                selected = candidate
                rejectedForCapacity = true
            } else if (existing == null || candidate.connectionKey < existing.connectionKey) {
                channels[setup.peerKey] = candidate
                selected = candidate
                displaced = existing
            } else {
                selected = existing
            }
        }
        if (rejectedForCapacity) {
            candidate.closeTransport()
            peers[setup.peerKey]?.let { fallbackPending(setup.peerKey, it) }
            return
        }
        if (selected !== candidate) {
            candidate.closeTransport()
            pendingQueues[setup.peerKey]?.let { queue ->
                synchronized(queue) { queue.setupConnectionId = null }
            }
            flushPendingToChannel(setup.peerKey, selected)
            return
        }
        displaced?.closeTransport()
        pendingQueues[setup.peerKey]?.let { queue ->
            synchronized(queue) { queue.setupConnectionId = null }
        }
        onDeliveryResultListener?.invoke(true, "Secure Wi-Fi Aware data path ready")
        startChannelReader(candidate)
        flushPendingToChannel(setup.peerKey, candidate)
    }

    private fun startChannelReader(channel: SecureChannel) {
        ioScope.launch {
            val failure = runCatching {
                while (!closing && channels[channel.peerKey] === channel) {
                    val packet = WifiAwareNdpProtocol.readPacket(channel.input, channel.reader) ?: break
                    onFrameReceivedListener?.invoke(packet)
                }
            }.exceptionOrNull()
            if (failure != null && failure !is SocketTimeoutException) {
                Log.w(TAG, "Secure Wi-Fi Aware reader ended", failure)
            }
            closeChannel(channel, "Wi-Fi Aware channel closed", notify = failure != null)
        }
    }

    private fun flushPendingToChannel(peerKey: String, channel: SecureChannel) {
        val packets = removeAndDrainPending(peerKey) ?: return
        val peer = peers[peerKey]
        packets.forEach { packet ->
            if (!channel.send(packet) && peer != null) {
                sendLegacyPairedFollowUp(peer.followUpEndpoint(), packet)
            }
        }
    }

    private fun enqueuePending(peerKey: String, packet: ByteArray): Boolean {
        val queue = queueForPeer(peerKey) ?: return false
        return synchronized(queue) {
            if (pendingQueues[peerKey] !== queue || packet.size > MAX_PENDING_BYTES_PER_PEER ||
                queue.packets.size >= MAX_PENDING_PACKETS_PER_PEER ||
                queue.byteCount + packet.size > MAX_PENDING_BYTES_PER_PEER
            ) return@synchronized false
            if (!reservePendingBytes(packet.size)) return@synchronized false
            queue.packets.addLast(packet.copyOf())
            queue.byteCount += packet.size
            true
        }
    }

    private fun fallbackPending(peerKey: String, peer: PeerState): Boolean {
        val packets = removeAndDrainPending(peerKey) ?: return false
        var accepted = false
        packets.forEach { packet ->
            accepted = sendLegacyPairedFollowUp(peer.followUpEndpoint(), packet) || accepted
        }
        return accepted
    }

    private fun queueForPeer(peerKey: String): PendingQueue? {
        pendingQueues[peerKey]?.let { return it }
        return synchronized(pendingQueues) {
            pendingQueues[peerKey] ?: if (pendingQueues.size >= MAX_PENDING_PEERS) {
                null
            } else {
                PendingQueue().also { pendingQueues[peerKey] = it }
            }
        }
    }

    private fun reservePendingBytes(bytes: Int): Boolean {
        while (true) {
            val current = pendingBytesGlobal.get()
            if (bytes < 0 || current > MAX_PENDING_BYTES_GLOBAL - bytes) return false
            if (pendingBytesGlobal.compareAndSet(current, current + bytes)) return true
        }
    }

    private fun removeAndDrainPending(peerKey: String): List<ByteArray>? {
        val queue = pendingQueues.remove(peerKey) ?: return null
        return synchronized(queue) {
            val releasedBytes = queue.byteCount
            buildList {
                while (queue.packets.isNotEmpty()) add(queue.packets.removeFirst())
            }.also {
                queue.byteCount = 0
                queue.setupConnectionId = null
                if (releasedBytes > 0) {
                    pendingBytesGlobal.updateAndGet { current -> (current - releasedBytes).coerceAtLeast(0) }
                }
            }
        }
    }

    /** API 29+ direct traffic waits for authenticated NDP; only legacy devices use this fallback. */
    private fun sendLegacyPairedFollowUp(peer: AwarePeer?, packet: ByteArray): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q && sendFollowUp(peer, packet)

    @SuppressLint("MissingPermission")
    private fun sendFollowUp(peer: AwarePeer?, packet: ByteArray): Boolean {
        peer ?: return false
        return runCatching {
            NearbyFrameFragmentCodec.fragment(packet, MAX_FOLLOWUP_PACKET_BYTES).forEach { fragment ->
                peer.session.sendMessage(peer.handle, nextMessageId(), fragment)
            }
            true
        }.getOrElse {
            Log.d(TAG, "Wi-Fi Aware follow-up fallback failed", it)
            false
        }
    }

    /** Unpaired nodes get only complete, opaque relay capsules under a strict fragment budget. */
    @SuppressLint("MissingPermission")
    private fun sendRawRelayFollowUp(peer: AwarePeer, capsule: ByteArray): Boolean {
        if (!RelayCapsule.isCapsule(capsule)) return false
        val fragments = runCatching {
            NearbyFrameFragmentCodec.fragment(capsule, MAX_FOLLOWUP_PACKET_BYTES)
        }.getOrNull() ?: return false
        if (!rawRelayFragmentBudget.tryAcquire(fragments.size)) return false
        return runCatching {
            fragments.forEach { fragment ->
                peer.session.sendMessage(peer.handle, nextMessageId(), fragment)
            }
            true
        }.getOrElse {
            Log.d(TAG, "Opaque raw-peer relay follow-up failed", it)
            false
        }
    }

    private fun failSetup(connectionKey: String, reason: String) {
        val setup = setups.remove(connectionKey) ?: return
        if (!setup.completed.compareAndSet(false, true)) return
        runCatching { setup.serverSocket?.close() }
        setup.callback?.let(::unregisterNetworkCallback)
        responderSetupByPeer.remove(setup.peerKey, connectionKey)
        if (setup.role == NdpRole.CLIENT && !closing && attachmentDesired &&
            !suppressSessionCallbacks && awareSession != null
        ) {
            peers[setup.peerKey]?.let { fallbackPending(setup.peerKey, it) }
        }
        if (!closing) onDeliveryResultListener?.invoke(false, reason)
    }

    private fun closeChannel(channel: SecureChannel, reason: String, notify: Boolean) {
        if (!channels.remove(channel.peerKey, channel)) {
            channel.closeTransport()
            return
        }
        channel.closeTransport()
        if (notify && !closing) onDeliveryResultListener?.invoke(false, reason)
    }

    private fun closePeerChannel(peerKey: String, reason: String, notify: Boolean) {
        channels[peerKey]?.let { closeChannel(it, reason, notify) }
    }

    private fun demoteToRawRelayPeer(peerKey: String, peer: PeerState) {
        if (!peers.remove(peerKey, peer)) return
        closePeerChannel(peerKey, "Peer is no longer mutually paired", notify = false)
        peer.followUpEndpoint()?.let { endpoint -> rawRelayPeers.put(peerKey, endpoint) }
    }

    private fun closeDataPaths(reason: String, preservePending: Boolean = false) {
        setups.keys.toList().forEach { failSetup(it, reason) }
        channels.values.toList().forEach { closeChannel(it, reason, notify = false) }
        if (preservePending) {
            pendingQueues.values.forEach { queue ->
                synchronized(queue) { queue.setupConnectionId = null }
            }
        } else {
            pendingQueues.keys.toList().forEach(::removeAndDrainPending)
        }
        responderSetupByPeer.clear()
    }

    private fun unregisterNetworkCallback(callback: ConnectivityManager.NetworkCallback) {
        runCatching { connectivityManager?.unregisterNetworkCallback(callback) }
    }

    private fun credentialsFor(prefix: ByteArray, expectedPublicKey: ByteArray? = null): PeerCredentials? =
        runCatching {
            val credentials = peerCredentialsProvider(prefix.copyOf()) ?: return@runCatching null
            require(credentials.publicKey.size == WifiAwareNdpProtocol.IDENTITY_KEY_BYTES)
            require(credentials.sharedSecret.size >= 32)
            require(credentials.publicKey.copyOf(prefix.size).contentEquals(prefix))
            if (expectedPublicKey != null) {
                require(MessageDigest.isEqual(credentials.publicKey, expectedPublicKey))
            }
            PeerCredentials(credentials.publicKey.copyOf(), credentials.sharedSecret.copyOf())
        }.getOrNull()

    private fun configureSocket(socket: Socket, timeoutMs: Int) {
        socket.tcpNoDelay = true
        runCatching { socket.keepAlive = false }
        runCatching { socket.receiveBufferSize = SOCKET_BUFFER_BYTES }
        runCatching { socket.sendBufferSize = SOCKET_BUFFER_BYTES }
        socket.soTimeout = timeoutMs
    }

    private fun nextMessageId(): Int = messageIds.getAndUpdate { current ->
        if (current == Int.MAX_VALUE) 1 else current + 1
    }

    private fun markDiscoveryReadyIfComplete() {
        if (publishSession != null && subscribeSession != null) {
            val readyGeneration = attachmentGeneration.get()
            synchronized(this) {
                reattachJob = null
                stabilityResetJob?.cancel()
                stabilityResetJob = ioScope.launch {
                    delay(REATTACH_STABILITY_RESET_MS)
                    if (!closing && attachmentDesired &&
                        readyGeneration == attachmentGeneration.get() &&
                        publishSession != null && subscribeSession != null
                    ) {
                        reattachBackoff.reset()
                    }
                }
            }
        }
    }

    private fun recoverDiscoverySessions(reason: String) {
        if (closing || !attachmentDesired) return
        Log.w(TAG, "$reason; scheduling bounded reattach")
        detachPlatformSessions(reason, preservePending = true)
        scheduleReattach(reason)
    }

    private fun scheduleReattach(reason: String) {
        if (closing || !attachmentDesired) return
        val delayMillis: Long
        synchronized(this) {
            if (reattachJob?.isActive == true) return
            delayMillis = reattachBackoff.nextDelayMillis()
            reattachJob = ioScope.launch {
                delay(delayMillis)
                handler.post {
                    synchronized(this@WifiAwareMeshManager) { reattachJob = null }
                    if (!closing && attachmentDesired) attachIfNeeded()
                }
            }
        }
        Log.d(TAG, "$reason; retrying Wi-Fi Aware in ${delayMillis}ms")
    }

    /**
     * Restartable policy detach. It releases discovery, NDP callbacks, and sockets but preserves
     * the IO scope so a later [attachToNANCluster] call can recover normally.
     */
    fun pause() {
        if (closing) return
        if (!attachmentDesired && awareSession == null && !attaching && reattachJob == null) return
        attachmentDesired = false
        synchronized(this) {
            reattachJob?.cancel()
            reattachJob = null
            stabilityResetJob?.cancel()
            stabilityResetJob = null
            reattachBackoff.reset()
        }
        detachPlatformSessions("Wi-Fi Aware paused by resource policy", preservePending = false)
    }

    private fun detachPlatformSessions(reason: String, preservePending: Boolean) {
        attachmentGeneration.incrementAndGet()
        attaching = false
        synchronized(this) {
            stabilityResetJob?.cancel()
            stabilityResetJob = null
        }
        suppressSessionCallbacks = true
        val publish = publishSession
        val subscribe = subscribeSession
        val aware = awareSession
        publishSession = null
        subscribeSession = null
        awareSession = null
        closeDataPaths(reason, preservePending)
        peers.clear()
        rawRelayPeers.clear()
        runCatching { publish?.close() }
        runCatching { subscribe?.close() }
        runCatching { aware?.close() }
        suppressSessionCallbacks = false
    }

    /** Terminal release for service destruction; unlike [pause], this instance cannot restart. */
    fun close() {
        if (closing) return
        closing = true
        attachmentDesired = false
        synchronized(this) {
            reattachJob?.cancel()
            reattachJob = null
            stabilityResetJob?.cancel()
            stabilityResetJob = null
        }
        detachPlatformSessions("Wi-Fi Aware manager closed", preservePending = false)
        seenNdpControlIds.clear()
        ioScope.cancel()
    }

    private fun ByteArray.toHex(): String = toHexStatic()
}

private fun ByteArray.toHexStatic(): String = joinToString("") { "%02x".format(it) }
