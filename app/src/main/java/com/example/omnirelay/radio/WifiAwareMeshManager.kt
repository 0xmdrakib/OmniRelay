package com.example.omnirelay.radio

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySession
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareSession
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.example.omnirelay.protocol.OmniFrame
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** Nearby high-throughput signaling transport that does not require an access point. */
class WifiAwareMeshManager(
    private val context: Context,
    identityPublicKey: ByteArray
) {

    companion object {
        const val TAG = "WifiAwareMeshManager"
        const val SERVICE_NAME = "OmniRelayNANService"
        private const val HELLO_MARKER: Byte = 0x7E
        private const val MAX_FOLLOWUP_PACKET_BYTES = 200
    }

    private data class AwarePeer(val session: DiscoverySession, val handle: PeerHandle)

    private val identityPrefix = identityPublicKey.copyOfRange(0, OmniFrame.COMPACT_KEY_PREFIX_SIZE)
    private val handler = Handler(Looper.getMainLooper())
    private val peers = ConcurrentHashMap<String, AwarePeer>()
    private val messageIds = AtomicInteger(1)
    private val fragmentAssembler = NearbyFrameFragmentCodec.Assembler()
    private var wifiAwareManager: WifiAwareManager? = null
    private var awareSession: WifiAwareSession? = null
    private var publishSession: PublishDiscoverySession? = null
    private var subscribeSession: SubscribeDiscoverySession? = null
    private var attaching = false

    var onFrameReceivedListener: ((ByteArray) -> Unit)? = null
    var onPeerDiscoveredListener: ((ByteArray) -> Unit)? = null
    var onDeliveryResultListener: ((Boolean, String) -> Unit)? = null

    val isSupported: Boolean
        get() = context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)

    init {
        if (isSupported) {
            wifiAwareManager = context.getSystemService(Context.WIFI_AWARE_SERVICE) as? WifiAwareManager
        }
    }

    @SuppressLint("MissingPermission")
    fun attachToNANCluster() {
        val manager = wifiAwareManager ?: return
        if (awareSession != null || attaching || !manager.isAvailable) return
        attaching = true
        manager.attach(object : AttachCallback() {
            override fun onAttached(session: WifiAwareSession) {
                attaching = false
                awareSession = session
                startPublishService(session)
                startSubscribeService(session)
            }

            override fun onAttachFailed() {
                attaching = false
                Log.e(TAG, "Unable to attach to Wi-Fi Aware")
            }
        }, handler)
    }

    @SuppressLint("MissingPermission")
    private fun startPublishService(session: WifiAwareSession) {
        val config = PublishConfig.Builder()
            .setServiceName(SERVICE_NAME)
            .setServiceSpecificInfo(identityPrefix)
            .build()
        session.publish(config, object : DiscoverySessionCallback() {
            override fun onPublishStarted(session: PublishDiscoverySession) {
                publishSession = session
            }

            override fun onMessageReceived(peerHandle: PeerHandle, message: ByteArray) {
                processMessage(publishSession ?: return, peerHandle, message)
            }

            override fun onMessageSendSucceeded(messageId: Int) {
                onDeliveryResultListener?.invoke(true, "Delivered over Wi-Fi Aware")
            }

            override fun onMessageSendFailed(messageId: Int) {
                onDeliveryResultListener?.invoke(false, "Wi-Fi Aware delivery failed")
            }
        }, handler)
    }

    @SuppressLint("MissingPermission")
    private fun startSubscribeService(session: WifiAwareSession) {
        val config = SubscribeConfig.Builder().setServiceName(SERVICE_NAME).build()
        session.subscribe(config, object : DiscoverySessionCallback() {
            override fun onSubscribeStarted(session: SubscribeDiscoverySession) {
                subscribeSession = session
            }

            override fun onServiceDiscovered(
                peerHandle: PeerHandle,
                serviceSpecificInfo: ByteArray,
                matchFilter: MutableList<ByteArray>?
            ) {
                if (serviceSpecificInfo.size < OmniFrame.COMPACT_KEY_PREFIX_SIZE) return
                val prefix = serviceSpecificInfo.copyOfRange(0, OmniFrame.COMPACT_KEY_PREFIX_SIZE)
                val activeSession = subscribeSession ?: return
                peers[prefix.toHex()] = AwarePeer(activeSession, peerHandle)
                onPeerDiscoveredListener?.invoke(prefix)
                activeSession.sendMessage(
                    peerHandle,
                    messageIds.getAndIncrement(),
                    byteArrayOf(HELLO_MARKER) + identityPrefix
                )
            }

            override fun onMessageReceived(peerHandle: PeerHandle, message: ByteArray) {
                processMessage(subscribeSession ?: return, peerHandle, message)
            }

            override fun onMessageSendSucceeded(messageId: Int) {
                onDeliveryResultListener?.invoke(true, "Delivered over Wi-Fi Aware")
            }

            override fun onMessageSendFailed(messageId: Int) {
                onDeliveryResultListener?.invoke(false, "Wi-Fi Aware delivery failed")
            }
        }, handler)
    }

    private fun processMessage(session: DiscoverySession, peerHandle: PeerHandle, message: ByteArray) {
        if (message.size == OmniFrame.COMPACT_KEY_PREFIX_SIZE + 1 && message[0] == HELLO_MARKER) {
            val prefix = message.copyOfRange(1, message.size)
            peers[prefix.toHex()] = AwarePeer(session, peerHandle)
            onPeerDiscoveredListener?.invoke(prefix)
        } else {
            fragmentAssembler.accept(peerHandle.hashCode().toString(), message)?.let { frame ->
                if (frame.size >= OmniFrame.HEADER_SIZE) onFrameReceivedListener?.invoke(frame)
            }
        }
    }

    @SuppressLint("MissingPermission")
    fun sendFrame(targetPublicKey: ByteArray, packedFrame: ByteArray): Boolean {
        val prefix = targetPublicKey.copyOfRange(0, OmniFrame.COMPACT_KEY_PREFIX_SIZE)
        val peer = peers[prefix.toHex()] ?: return false
        return runCatching {
            NearbyFrameFragmentCodec.fragment(packedFrame, MAX_FOLLOWUP_PACKET_BYTES).forEach { packet ->
                peer.session.sendMessage(peer.handle, messageIds.getAndIncrement(), packet)
            }
            true
        }.getOrElse {
            Log.e(TAG, "Wi-Fi Aware send failed", it)
            false
        }
    }

    fun close() {
        peers.clear()
        publishSession?.close()
        subscribeSession?.close()
        awareSession?.close()
        publishSession = null
        subscribeSession = null
        awareSession = null
        attaching = false
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
