package com.example.omnirelay.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface OmniDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertMessage(message: MessageEntity): Long

    @Query("SELECT * FROM messages ORDER BY createdAtMs ASC")
    fun observeMessages(): Flow<List<MessageEntity>>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertOutbound(envelope: OutboundEnvelopeEntity): Long

    @Query(
        "SELECT * FROM outbound_envelopes " +
            "WHERE state IN ('queued', 'failed') AND nextAttemptAtMs <= :nowMs " +
            "ORDER BY createdAtMs ASC LIMIT :limit"
    )
    suspend fun pendingOutbound(nowMs: Long, limit: Int = 50): List<OutboundEnvelopeEntity>

    @Query("UPDATE outbound_envelopes SET state = :state WHERE envelopeId = :envelopeId")
    suspend fun setOutboundState(envelopeId: String, state: String)

    @Query(
        "UPDATE outbound_envelopes SET state = 'failed', attemptCount = attemptCount + 1, " +
            "nextAttemptAtMs = :nextAttemptAtMs WHERE envelopeId = :envelopeId"
    )
    suspend fun markOutboundRetry(envelopeId: String, nextAttemptAtMs: Long)

    @Query("UPDATE messages SET status = :status, transport = :transport WHERE messageId = :messageId")
    suspend fun updateMessageStatus(messageId: String, status: String, transport: String)

    @Query("UPDATE messages SET status = :status WHERE messageId = :messageId")
    suspend fun setMessageStatus(messageId: String, status: String)

    @Query("UPDATE messages SET body = :encryptedBody WHERE messageId = :messageId")
    suspend fun updateMessageBody(messageId: String, encryptedBody: String)

    @Query(
        "SELECT messageId FROM messages WHERE contactPublicKey = :contactPublicKey " +
            "AND direction = 'incoming' AND transport = 'internet' AND status = 'delivered'"
    )
    suspend fun deliveredInternetMessages(contactPublicKey: String): List<String>

    @Query("SELECT status FROM messages WHERE messageId = :messageId LIMIT 1")
    suspend fun messageStatus(messageId: String): String?

    @Query("SELECT EXISTS(SELECT 1 FROM processed_envelopes WHERE envelopeId = :envelopeId)")
    suspend fun isEnvelopeProcessed(envelopeId: String): Boolean

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun markEnvelopeProcessed(envelope: ProcessedEnvelopeEntity): Long

    @Query("DELETE FROM processed_envelopes WHERE processedAtMs < :beforeMs")
    suspend fun pruneProcessed(beforeMs: Long)
}
