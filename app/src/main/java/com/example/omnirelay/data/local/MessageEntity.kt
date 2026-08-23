package com.example.omnirelay.data.local

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "messages",
    indices = [Index("contactPublicKey"), Index("createdAtMs")]
)
data class MessageEntity(
    @PrimaryKey val messageId: String,
    val contactPublicKey: String,
    val contactName: String,
    val body: String,
    val direction: String,
    val status: String,
    val transport: String,
    val createdAtMs: Long
)
