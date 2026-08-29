package com.example.omnirelay.data.local

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "outbound_envelopes",
    indices = [Index("state"), Index("nextAttemptAtMs")]
)
data class OutboundEnvelopeEntity(
    @PrimaryKey val envelopeId: String,
    val recipientDeviceId: String,
    val recipientPublicKey: String,
    val kind: String,
    val callId: String?,
    val frameBase64: String,
    val state: String = STATE_QUEUED,
    val attemptCount: Int = 0,
    val nextAttemptAtMs: Long = 0,
    val createdAtMs: Long = System.currentTimeMillis()
) {
    companion object {
        const val STATE_QUEUED = "queued"
        const val STATE_SENDING = "sending"
        const val STATE_SENT = "sent"
        const val STATE_FAILED = "failed"
        const val STATE_CANCELLED = "cancelled"
    }
}
