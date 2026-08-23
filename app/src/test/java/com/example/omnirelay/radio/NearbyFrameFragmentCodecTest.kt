package com.example.omnirelay.radio

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NearbyFrameFragmentCodecTest {
    @Test
    fun fragmentedFrameReassemblesWhenPacketsArriveOutOfOrder() {
        val original = ByteArray(2_048) { (it and 0xFF).toByte() }
        val packets = NearbyFrameFragmentCodec.fragment(original, 73).reversed()
        val assembler = NearbyFrameFragmentCodec.Assembler()
        var result: ByteArray? = null
        packets.forEach { packet -> assembler.accept("peer", packet)?.let { result = it } }
        assertArrayEquals(original, result)
    }

    @Test
    fun incompleteTransferDoesNotProduceAFrame() {
        val packets = NearbyFrameFragmentCodec.fragment(ByteArray(500), 80)
        val assembler = NearbyFrameFragmentCodec.Assembler()
        packets.dropLast(1).forEach { assertNull(assembler.accept("peer", it)) }
    }
}
