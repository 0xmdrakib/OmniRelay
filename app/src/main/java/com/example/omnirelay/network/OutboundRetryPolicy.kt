package com.example.omnirelay.network

/** Prevents durable message reliability from turning expired call signaling into a ghost call. */
internal object OutboundRetryPolicy {
    const val MAX_CALL_SIGNAL_AGE_MS = 60_000L

    fun shouldAttempt(
        kind: String,
        envelopeCallId: String?,
        activeCallId: String?,
        createdAtMs: Long,
        nowMs: Long
    ): Boolean {
        if (kind != "call") return true
        if (envelopeCallId.isNullOrBlank() || envelopeCallId != activeCallId) return false
        if (createdAtMs < 0L || nowMs < createdAtMs) return false
        return nowMs - createdAtMs < MAX_CALL_SIGNAL_AGE_MS
    }
}
