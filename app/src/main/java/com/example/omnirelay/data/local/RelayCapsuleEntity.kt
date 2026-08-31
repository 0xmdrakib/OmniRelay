package com.example.omnirelay.data.local

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** Opaque, already E2EE-protected capsule retained briefly for opt-in delay-tolerant forwarding. */
@Entity(
    tableName = "relay_capsule_queue",
    indices = [Index("expiresAtMs"), Index("nextAttemptAtMs")]
)
data class RelayCapsuleEntity(
    @PrimaryKey val capsuleId: String,
    val packet: ByteArray,
    val expiresAtMs: Long,
    val nextAttemptAtMs: Long,
    val attemptCount: Int = 0,
    val createdAtMs: Long = System.currentTimeMillis()
)

data class RelayQueueStats(val itemCount: Int, val totalBytes: Long)
