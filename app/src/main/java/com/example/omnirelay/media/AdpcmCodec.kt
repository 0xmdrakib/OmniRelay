package com.example.omnirelay.media

/**
 * AdpcmCodec: High-Intelligibility IMA-ADPCM (4-bit per sample) Audio Codec.
 * Encodes 16-bit PCM mono audio into 4-bit nibbles (4:1 compression ratio).
 * Converts 640-byte 16kHz PCM audio frames into 160-byte ADPCM frames with 100% speech clarity.
 */
object AdpcmCodec {

    private val INDEX_TABLE = intArrayOf(
        -1, -1, -1, -1, 2, 4, 6, 8,
        -1, -1, -1, -1, 2, 4, 6, 8
    )

    private val STEP_TABLE = intArrayOf(
        7, 8, 9, 10, 11, 12, 13, 14, 16, 17,
        19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
        50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
        130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
        337, 371, 408, 449, 494, 544, 598, 658, 724, 796,
        876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
        2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358,
        5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899,
        15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767
    )

    class State {
        var valprev: Int = 0
        var index: Int = 0
    }

    /**
     * Encodes 16-bit PCM byte array to 4-bit ADPCM byte array.
     */
    fun encode(pcm: ByteArray, state: State = State()): ByteArray {
        val sampleCount = pcm.size / 2
        val adpcm = ByteArray(sampleCount / 2)
        var bufferStep = false
        var outputByte = 0

        for (i in 0 until sampleCount) {
            val sample = ((pcm[i * 2 + 1].toInt() shl 8) or (pcm[i * 2].toInt() and 0xFF)).toShort().toInt()

            val step = STEP_TABLE[state.index]
            var diff = sample - state.valprev
            var delta = 0

            if (diff < 0) {
                delta = 8
                diff = -diff
            }

            var vpdiff = step shr 3
            if (diff >= step) {
                delta = delta or 4
                diff -= step
                vpdiff += step
            }
            if (diff >= (step shr 1)) {
                delta = delta or 2
                diff -= (step shr 1)
                vpdiff += (step shr 1)
            }
            if (diff >= (step shr 2)) {
                delta = delta or 1
                vpdiff += (step shr 2)
            }

            if ((delta and 8) != 0) {
                state.valprev -= vpdiff
            } else {
                state.valprev += vpdiff
            }

            state.valprev = state.valprev.coerceIn(-32768, 32767)

            state.index += INDEX_TABLE[delta]
            state.index = state.index.coerceIn(0, 88)

            if (bufferStep) {
                adpcm[i / 2] = ((delta shl 4) or (outputByte and 0x0F)).toByte()
            } else {
                outputByte = delta and 0x0F
            }
            bufferStep = !bufferStep
        }

        return adpcm
    }

    /**
     * Decodes 4-bit ADPCM byte array to 16-bit PCM byte array.
     */
    fun decode(adpcm: ByteArray, state: State = State()): ByteArray {
        val pcm = ByteArray(adpcm.size * 4)

        for (i in adpcm.indices) {
            val byteVal = adpcm[i].toInt() and 0xFF
            val delta1 = byteVal and 0x0F
            val delta2 = (byteVal shr 4) and 0x0F

            // Decode first nibble
            val sample1 = decodeNibble(delta1, state)
            pcm[i * 4] = (sample1 and 0xFF).toByte()
            pcm[i * 4 + 1] = ((sample1 shr 8) and 0xFF).toByte()

            // Decode second nibble
            val sample2 = decodeNibble(delta2, state)
            pcm[i * 4 + 2] = (sample2 and 0xFF).toByte()
            pcm[i * 4 + 3] = ((sample2 shr 8) and 0xFF).toByte()
        }

        return pcm
    }

    private fun decodeNibble(delta: Int, state: State): Int {
        val step = STEP_TABLE[state.index]
        var vpdiff = step shr 3

        if ((delta and 4) != 0) vpdiff += step
        if ((delta and 2) != 0) vpdiff += (step shr 1)
        if ((delta and 1) != 0) vpdiff += (step shr 2)

        if ((delta and 8) != 0) {
            state.valprev -= vpdiff
        } else {
            state.valprev += vpdiff
        }

        state.valprev = state.valprev.coerceIn(-32768, 32767)

        state.index += INDEX_TABLE[delta]
        state.index = state.index.coerceIn(0, 88)

        return state.valprev
    }
}
