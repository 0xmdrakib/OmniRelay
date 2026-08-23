package com.example.omnirelay.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "processed_envelopes")
data class ProcessedEnvelopeEntity(
    @PrimaryKey val envelopeId: String,
    val processedAtMs: Long = System.currentTimeMillis()
)
