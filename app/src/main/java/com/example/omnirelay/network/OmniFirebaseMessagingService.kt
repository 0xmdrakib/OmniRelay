package com.example.omnirelay.network

import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import com.example.omnirelay.service.OmniRelayService
import com.example.omnirelay.auth.FirebaseAccountSession
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class OmniFirebaseMessagingService : FirebaseMessagingService() {
    override fun onRegistered(installationId: String) {
        wakeService(OmniRelayService.ACTION_UPDATE_PUSH_TOKEN, installationId)
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onNewToken(token: String) {
        wakeService(OmniRelayService.ACTION_UPDATE_PUSH_TOKEN, token)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        if (message.data["type"] != "mailbox_changed") return
        wakeService(OmniRelayService.ACTION_SYNC_MAILBOX, null)
    }

    private fun wakeService(action: String, token: String?) {
        if (!FirebaseAccountSession.isSignedIn(this)) {
            Log.i("OmniFCM", "Ignoring relay wake while no Google account is signed in")
            return
        }
        val intent = Intent(this, OmniRelayService::class.java).apply {
            this.action = action
            token?.let { putExtra(OmniRelayService.EXTRA_PUSH_TOKEN, it) }
        }
        runCatching { ContextCompat.startForegroundService(this, intent) }
            .onFailure {
                Log.w("OmniFCM", "Foreground wake rejected; scheduling WorkManager fallback", it)
                val request = OneTimeWorkRequestBuilder<RelaySyncWorker>()
                    .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                    .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                    .build()
                WorkManager.getInstance(this).enqueueUniqueWork(
                    RelaySyncWorker.UNIQUE_NAME,
                    ExistingWorkPolicy.REPLACE,
                    request
                )
            }
    }
}
