package com.example.omnirelay.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [
        MessageEntity::class,
        OutboundEnvelopeEntity::class,
        ProcessedEnvelopeEntity::class,
        RelayCapsuleEntity::class
    ],
    version = 2,
    exportSchema = true
)
abstract class OmniDatabase : RoomDatabase() {
    abstract fun omniDao(): OmniDao

    companion object {
        @Volatile private var instance: OmniDatabase? = null

        fun get(context: Context): OmniDatabase = instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(
                context.applicationContext,
                OmniDatabase::class.java,
                "omnirelay.db"
            ).addMigrations(MIGRATION_1_2).build().also { instance = it }
        }

        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS relay_capsule_queue (
                        capsuleId TEXT NOT NULL PRIMARY KEY,
                        packet BLOB NOT NULL,
                        expiresAtMs INTEGER NOT NULL,
                        nextAttemptAtMs INTEGER NOT NULL,
                        attemptCount INTEGER NOT NULL,
                        createdAtMs INTEGER NOT NULL
                    )
                    """.trimIndent()
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_relay_capsule_queue_expiresAtMs " +
                        "ON relay_capsule_queue(expiresAtMs)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_relay_capsule_queue_nextAttemptAtMs " +
                        "ON relay_capsule_queue(nextAttemptAtMs)"
                )
            }
        }
    }
}
