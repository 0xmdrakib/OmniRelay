package com.example.omnirelay.radio

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Collections
import java.util.Random
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class NearbyFrameFragmentCodecAdversarialTest {
    @Test(timeout = 3_000L)
    fun seededRandomFramesReassembleAcrossOrderingsAndDuplicates() {
        val random = Random(0x5245415353454D42L)

        repeat(128) { iteration ->
            val original = ByteArray(1 + random.nextInt(8_192)).also(random::nextBytes)
            val packetLimit = 11 + random.nextInt(246)
            val packets = NearbyFrameFragmentCodec.fragment(original, packetLimit).toMutableList()
            if (packets.size > 1) packets.add(packets[random.nextInt(packets.size)].copyOf())
            Collections.shuffle(packets, random)

            val assembler = NearbyFrameFragmentCodec.Assembler()
            var reassembled: ByteArray? = null
            packets.forEach { packet ->
                assembler.accept("peer-$iteration", packet)?.let { candidate ->
                    if (candidate.contentEquals(original)) reassembled = candidate
                }
            }

            assertNotNull("iteration=$iteration packetLimit=$packetLimit", reassembled)
            assertArrayEquals(original, reassembled)
        }
    }

    @Test
    fun malformedFragmentMetadataNeverProducesAFrame() {
        val assembler = NearbyFrameFragmentCodec.Assembler()
        val malformed = listOf(
            fragmentPacket(transferId = 1, index = 0, total = 0),
            fragmentPacket(transferId = 2, index = 0, total = 8_193),
            fragmentPacket(transferId = 3, index = 1, total = 1),
            fragmentPacket(transferId = 4, index = 65_535, total = 2)
        )

        malformed.forEachIndexed { index, packet ->
            assertNull("malformed case $index", assembler.accept("peer", packet))
        }
    }

    @Test
    fun fragmentCountAboveHardLimitIsRejectedBeforeEmission() {
        assertThrows(IllegalArgumentException::class.java) {
            NearbyFrameFragmentCodec.fragment(ByteArray(8_193), 11)
        }
    }

    @Test
    fun maximumAllowedFragmentCountCanReassembleWithinBound() {
        val original = ByteArray(8_192) { (it and 0xFF).toByte() }
        val packets = NearbyFrameFragmentCodec.fragment(original, 11)
        val assembler = NearbyFrameFragmentCodec.Assembler()
        var reassembled: ByteArray? = null

        packets.asReversed().forEach { packet ->
            assembler.accept("bounded-peer", packet)?.let { reassembled = it }
        }

        assertArrayEquals(original, reassembled)
    }

    @Test
    fun sameTransferIdFromDifferentPeersCannotCrossContaminateAssemblies() {
        val original = ByteArray(1_024) { (it * 13).toByte() }
        val packets = NearbyFrameFragmentCodec.fragment(original, 64)
        val assembler = NearbyFrameFragmentCodec.Assembler()
        var firstResult: ByteArray? = null
        var secondResult: ByteArray? = null

        packets.forEach { packet ->
            assembler.accept("peer-a", packet)?.let { firstResult = it }
            assembler.accept("peer-b", packet)?.let { secondResult = it }
        }

        assertArrayEquals(original, firstResult)
        assertArrayEquals(original, secondResult)
    }

    private fun fragmentPacket(transferId: Int, index: Int, total: Int): ByteArray =
        ByteBuffer.allocate(11).order(ByteOrder.BIG_ENDIAN).apply {
            put(0x7D)
            put(0x52)
            putInt(transferId)
            putShort(index.toShort())
            putShort(total.toShort())
            put(0x01)
        }.array()
}
