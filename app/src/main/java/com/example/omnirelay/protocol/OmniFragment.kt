package com.example.omnirelay.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * OmniFragment: 12-byte Multipath Fragment Encapsulation Header.
 * Used for splitting large frames across fragmented networks (BLE MTU 244, Cell NAS 160).
 *
 * Header Layout:
 * [0..3]: Flow Identifier (32 bits)
 * [4..5]: Fragment Index (16 bits)
 * [6..7]: Total Fragments (16 bits)
 * [8]: Path ID Tag (8 bits: 0=Mesh, 1=Cellular, 2=LEO Sat)
 * [9]: FEC Block ID (8 bits)
 * [10..11]: Symbol Index (16 bits)
 */
data class OmniFragment(
    val flowId: Int,
    val fragmentIndex: Short,
    val totalFragments: Short,
    val pathIdTag: Byte,
    val fecBlockId: Byte,
    val symbolIndex: Short,
    val fragmentData: ByteArray
) {
    companion object {
        const val FRAGMENT_HEADER_SIZE = 12

        fun unpack(bytes: ByteArray): OmniFragment? {
            if (bytes.size < FRAGMENT_HEADER_SIZE) return null
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)

            val flowId = buffer.int
            val fragmentIndex = buffer.short
            val totalFragments = buffer.short
            val pathIdTag = buffer.get()
            val fecBlockId = buffer.get()
            val symbolIndex = buffer.short

            val dataLen = bytes.size - FRAGMENT_HEADER_SIZE
            val fragmentData = ByteArray(dataLen)
            buffer.get(fragmentData)

            return OmniFragment(
                flowId = flowId,
                fragmentIndex = fragmentIndex,
                totalFragments = totalFragments,
                pathIdTag = pathIdTag,
                fecBlockId = fecBlockId,
                symbolIndex = symbolIndex,
                fragmentData = fragmentData
            )
        }
    }

    fun pack(): ByteArray {
        val buffer = ByteBuffer.allocate(FRAGMENT_HEADER_SIZE + fragmentData.size).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(flowId)
        buffer.putShort(fragmentIndex)
        buffer.putShort(totalFragments)
        buffer.put(pathIdTag)
        buffer.put(fecBlockId)
        buffer.putShort(symbolIndex)
        buffer.put(fragmentData)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as OmniFragment
        return flowId == other.flowId &&
                fragmentIndex == other.fragmentIndex &&
                fragmentData.contentEquals(other.fragmentData)
    }

    override fun hashCode(): Int {
        var result = flowId
        result = 31 * result + fragmentIndex
        result = 31 * result + fragmentData.contentHashCode()
        return result
    }
}
