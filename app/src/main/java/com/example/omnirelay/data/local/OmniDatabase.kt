package com.example.omnirelay.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [MessageEntity::class, OutboundEnvelopeEntity::class, ProcessedEnvelopeEntity::class],
    version = 1,
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
            ).build().also { instance = it }
        }
    }
}
