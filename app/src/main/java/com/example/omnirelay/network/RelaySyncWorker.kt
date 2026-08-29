package com.example.omnirelay.network

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.example.omnirelay.service.OmniRelayService
import com.example.omnirelay.utils.SettingsManager

class RelaySyncWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {
    companion object { const val UNIQUE_NAME = "omnirelay-mailbox-sync" }

    override suspend fun doWork(): Result {
        if (!SettingsManager(applicationContext, observeExternalChanges = false)
                .isRelayModeEnabled
        ) return Result.success()
        return runCatching {
            ContextCompat.startForegroundService(
                applicationContext,
                Intent(applicationContext, OmniRelayService::class.java).setAction(OmniRelayService.ACTION_SYNC_MAILBOX)
            )
            Result.success()
        }.getOrElse { Result.retry() }
    }
}
