package com.example.omnirelay.radio

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap

/**
 * PeerDiscoveryRegistry: Real-time peer node topology and mutual link swarm tracker.
 */
data class PeerNode(
    val nodeId: String,
    val rssi: Int,
    val hopCount: Int = 1,
    val isMutualLinked: Boolean = true,
    val linkQualityPercent: Int = 95,
    val lastSeenMs: Long = System.currentTimeMillis(),
    val supportedTransport: String = "BLE 5.3 PAwR"
)

object PeerDiscoveryRegistry {

    private val peerMap = ConcurrentHashMap<String, PeerNode>()
    private val _peers = MutableStateFlow<List<PeerNode>>(emptyList())
    val peers: StateFlow<List<PeerNode>> = _peers.asStateFlow()

    fun updatePeer(
        nodeId: String,
        rssi: Int,
        hopCount: Int = 1,
        transport: String = "BLE 5.3 PAwR",
        isMutualLinked: Boolean = true,
        quality: Int = qualityFromRssi(rssi)
    ) {
        peerMap[nodeId] = PeerNode(
            nodeId = nodeId,
            rssi = rssi,
            hopCount = hopCount,
            isMutualLinked = isMutualLinked,
            linkQualityPercent = quality,
            lastSeenMs = System.currentTimeMillis(),
            supportedTransport = transport
        )
        publishSnapshot()
    }

    fun toggleMutualLink(nodeId: String) {
        val existing = peerMap[nodeId] ?: return
        peerMap[nodeId] = existing.copy(isMutualLinked = !existing.isMutualLinked)
        publishSnapshot()
    }

    fun getActivePeers(timeoutMs: Long = 60000): List<PeerNode> {
        val now = System.currentTimeMillis()
        return peerMap.values.filter { (now - it.lastSeenMs) < timeoutMs }
    }

    fun getMutualLinkedPeers(): List<PeerNode> {
        return getActivePeers().filter { it.isMutualLinked }
    }

    fun getMutualPeerCount(): Int = getMutualLinkedPeers().size

    fun getPeerCount(): Int = getActivePeers().size

    fun isMutualPeerActive(nodeId: String, timeoutMs: Long = 20_000L): Boolean {
        val peer = peerMap[nodeId] ?: return false
        return peer.isMutualLinked && System.currentTimeMillis() - peer.lastSeenMs < timeoutMs
    }

    private fun qualityFromRssi(rssi: Int): Int = when {
        rssi >= -50 -> 100
        rssi <= -100 -> 0
        else -> ((rssi + 100) * 2).coerceIn(0, 100)
    }

    private fun publishSnapshot() {
        _peers.value = peerMap.values.sortedByDescending { it.lastSeenMs }
    }
}
