package com.example.omnirelay

import android.app.Application
import android.util.Log
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging
import com.example.omnirelay.network.RelaySyncWorker
import org.conscrypt.Conscrypt
import java.security.Security
import java.util.concurrent.TimeUnit

class OmniRelayApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        installModernCryptoProvider()
        initializeFirebaseIfConfigured()
        schedulePeriodicRelaySync()
    }

    private fun installModernCryptoProvider() {
        if (Security.getProvider("Conscrypt") == null) {
            val position = Security.insertProviderAt(Conscrypt.newProvider(), 1)
            check(position > 0) { "Unable to install modern cryptography provider" }
        }
    }

    private fun initializeFirebaseIfConfigured() {
        if (BuildConfig.FIREBASE_API_KEY.isBlank() ||
            BuildConfig.FIREBASE_APP_ID.isBlank() ||
            BuildConfig.FIREBASE_PROJECT_ID.isBlank() ||
            BuildConfig.FIREBASE_SENDER_ID.isBlank()
        ) {
            Log.i("OmniRelayApplication", "Firebase config absent; Google sign-in and relay startup are disabled")
            return
        }
        if (FirebaseApp.getApps(this).isEmpty()) {
            val options = FirebaseOptions.Builder()
                .setApiKey(BuildConfig.FIREBASE_API_KEY)
                .setApplicationId(BuildConfig.FIREBASE_APP_ID)
                .setProjectId(BuildConfig.FIREBASE_PROJECT_ID)
                .setGcmSenderId(BuildConfig.FIREBASE_SENDER_ID)
                .build()
            FirebaseApp.initializeApp(this, options)
        }
        FirebaseMessaging.getInstance().register()
            .addOnFailureListener { Log.w("OmniRelayApplication", "Unable to obtain FCM token", it) }
    }

    private fun schedulePeriodicRelaySync() {
        if (BuildConfig.BACKEND_BASE_URL.endsWith(".invalid")) return
        val request = PeriodicWorkRequestBuilder<RelaySyncWorker>(
            15, TimeUnit.MINUTES,
            5, TimeUnit.MINUTES
        )
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .setRequiresBatteryNotLow(true)
                    .build()
            )
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "omnirelay-periodic-mailbox-sync",
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }
}
