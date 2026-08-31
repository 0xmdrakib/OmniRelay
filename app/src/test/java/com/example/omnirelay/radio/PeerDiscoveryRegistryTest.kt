package com.example.omnirelay.radio

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PeerDiscoveryRegistryTest {
    @Test
    fun linkQualityIsDeterministicAndMutualReachabilityHonorsTheFlag() {
        val strong = "test-peer-strong"
        val weak = "test-peer-weak"
        PeerDiscoveryRegistry.updatePeer(strong, rssi = -50, isMutualLinked = true)
        PeerDiscoveryRegistry.updatePeer(weak, rssi = -90, isMutualLinked = false)

        val peers = PeerDiscoveryRegistry.getActivePeers()
        assertEquals(100, peers.first { it.nodeId == strong }.linkQualityPercent)
        assertEquals(20, peers.first { it.nodeId == weak }.linkQualityPercent)
        assertTrue(PeerDiscoveryRegistry.isMutualPeerActive(strong))
        assertFalse(PeerDiscoveryRegistry.isMutualPeerActive(weak))
    }
}
