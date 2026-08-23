package com.example.omnirelay.protocol

import java.nio.ByteBuffer

/**
 * FecEngine: Forward Error Correction (FEC) Fountain Coding & Loss Recovery.
 * Generates parity symbols and reconstructs missing voice/data packets over lossy P2P mesh links.
 */
object FecEngine {

    data class FecSymbol(
        val blockId: Byte,
        val symbolIndex: Short,
        val isParity: Boolean,
        val data: ByteArray
    )

    /**
     * Encodes K source packets into K source symbols + N parity symbols (e.g. 30% redundancy).
     */
    fun encodeFecBlock(sourcePackets: List<ByteArray>, parityCount: Int, blockId: Byte): List<FecSymbol> {
        val maxLen = sourcePackets.maxOfOrNull { it.size } ?: return emptyList()
        val symbols = mutableListOf<FecSymbol>()

        // 1. Source Symbols
        for (i in sourcePackets.indices) {
            val paddedData = ByteArray(maxLen)
            System.arraycopy(sourcePackets[i], 0, paddedData, 0, sourcePackets[i].size)
            symbols.add(FecSymbol(blockId, i.toShort(), false, paddedData))
        }

        // 2. Parity Symbols using XOR Linear Combination (Fountain Code representation)
        val k = sourcePackets.size
        for (p in 0 until parityCount) {
            val parityData = ByteArray(maxLen)
            val coefficients = generateCoefficients(k, p)

            for (i in 0 until k) {
                if (coefficients[i]) {
                    val src = symbols[i].data
                    for (b in 0 until maxLen) {
                        parityData[b] = (parityData[b].toInt() xor src[b].toInt()).toByte()
                    }
                }
            }

            symbols.add(FecSymbol(blockId, (k + p).toShort(), true, parityData))
        }

        return symbols
    }

    /**
     * Attempts to reconstruct missing source packets from any K received symbols out of K+N.
     */
    fun decodeFecBlock(receivedSymbols: List<FecSymbol>, totalSourceCount: Int): List<ByteArray>? {
        if (receivedSymbols.size < totalSourceCount) return null // Insufficient symbols to reconstruct

        val maxLen = receivedSymbols.maxOfOrNull { it.data.size } ?: return null
        val sourceMap = mutableMapOf<Int, ByteArray>()

        // Collect available direct source symbols
        for (sym in receivedSymbols) {
            if (!sym.isParity && sym.symbolIndex < totalSourceCount) {
                sourceMap[sym.symbolIndex.toInt()] = sym.data
            }
        }

        // Check if all source symbols received directly
        if (sourceMap.size == totalSourceCount) {
            return (0 until totalSourceCount).map { sourceMap[it]!! }
        }

        // Attempt single-missing parity recovery
        val missingIndices = (0 until totalSourceCount).filter { !sourceMap.containsKey(it) }
        val paritySymbols = receivedSymbols.filter { it.isParity }

        for (missingIdx in missingIndices) {
            for (pSym in paritySymbols) {
                val pIndex = pSym.symbolIndex.toInt() - totalSourceCount
                val coeffs = generateCoefficients(totalSourceCount, pIndex)

                if (coeffs[missingIdx]) {
                    // Check if all other participants in parity sum are available
                    val dependenciesAvailable = (0 until totalSourceCount).all { i ->
                        i == missingIdx || !coeffs[i] || sourceMap.containsKey(i)
                    }

                    if (dependenciesAvailable) {
                        val recovered = ByteArray(maxLen)
                        System.arraycopy(pSym.data, 0, recovered, 0, maxLen)

                        for (i in 0 until totalSourceCount) {
                            if (i != missingIdx && coeffs[i]) {
                                val existing = sourceMap[i]!!
                                for (b in 0 until maxLen) {
                                    recovered[b] = (recovered[b].toInt() xor existing[b].toInt()).toByte()
                                }
                            }
                        }

                        sourceMap[missingIdx] = recovered
                        break
                    }
                }
            }
        }

        return if (sourceMap.size == totalSourceCount) {
            (0 until totalSourceCount).map { sourceMap[it]!! }
        } else {
            null // Decoding incomplete
        }
    }

    private fun generateCoefficients(sourceCount: Int, parityIndex: Int): BooleanArray {
        val coeffs = BooleanArray(sourceCount)
        if (parityIndex == 0) {
            // Parity 0 is systematic full XOR combination of all source packets
            coeffs.fill(true)
        } else {
            val seed = (parityIndex + 1) * 37
            for (i in 0 until sourceCount) {
                coeffs[i] = ((seed shr (i % 8)) and 1) == 1 || (i == (parityIndex % sourceCount))
            }
        }
        return coeffs
    }
}
