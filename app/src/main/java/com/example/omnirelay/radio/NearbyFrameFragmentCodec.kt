package com.example.omnirelay.radio

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/** Small transport envelope for radios whose packet limit is below an OmniFrame. */
object NearbyFrameFragmentCodec {
    private const val MAGIC_ONE: Byte = 0x7D
    private const val MAGIC_TWO: Byte = 0x52
    private const val HEADER_BYTES = 10
    private const val MAX_FRAGMENTS = 8_192
    private const val ASSEMBLY_TTL_MS = 30_000L
    private val random = SecureRandom()

    fun fragment(frame: ByteArray, maxPacketBytes: Int): List<ByteArray> {
        require(maxPacketBytes > HEADER_BYTES) { "Radio packet limit is too small" }
        if (frame.size <= maxPacketBytes) return listOf(frame.copyOf())
        val bodyBytes = maxPacketBytes - HEADER_BYTES
        val total = (frame.size + bodyBytes - 1) / bodyBytes
        require(total <= MAX_FRAGMENTS) { "Frame requires too many radio fragments" }
        val transferId = random.nextInt()
        return (0 until total).map { index ->
            val start = index * bodyBytes
            val end = minOf(start + bodyBytes, frame.size)
            ByteBuffer.allocate(HEADER_BYTES + end - start).order(ByteOrder.BIG_ENDIAN).apply {
                put(MAGIC_ONE)
                put(MAGIC_TWO)
                putInt(transferId)
                putShort(index.toShort())
                putShort(total.toShort())
                put(frame, start, end - start)
            }.array()
        }
    }

    class Assembler {
        private data class Assembly(
            val parts: Array<ByteArray?>,
            val createdAtMs: Long = System.currentTimeMillis()
        )

        private val assemblies = ConcurrentHashMap<String, Assembly>()

        fun accept(peerId: String, packet: ByteArray): ByteArray? {
            if (!isFragment(packet)) return packet.copyOf()
            val buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)
            buffer.position(2)
            val transferId = buffer.int
            val index = buffer.short.toInt() and 0xFFFF
            val total = buffer.short.toInt() and 0xFFFF
            if (total !in 1..MAX_FRAGMENTS || index >= total || !buffer.hasRemaining()) return null
            prune()
            val key = "$peerId:$transferId"
            val assembly = assemblies.compute(key) { _, existing ->
                if (existing == null || existing.parts.size != total) Assembly(arrayOfNulls(total)) else existing
            } ?: return null
            assembly.parts[index] = ByteArray(buffer.remaining()).also(buffer::get)
            if (assembly.parts.any { it == null }) return null
            assemblies.remove(key)
            val size = assembly.parts.sumOf { it!!.size }
            return ByteArray(size).also { output ->
                var offset = 0
                for (part in assembly.parts) {
                    part!!.copyInto(output, offset)
                    offset += part.size
                }
            }
        }

        private fun prune() {
            val cutoff = System.currentTimeMillis() - ASSEMBLY_TTL_MS
            assemblies.entries.removeIf { it.value.createdAtMs < cutoff }
        }

        private fun isFragment(packet: ByteArray): Boolean =
            packet.size > HEADER_BYTES && packet[0] == MAGIC_ONE && packet[1] == MAGIC_TWO
    }
}
