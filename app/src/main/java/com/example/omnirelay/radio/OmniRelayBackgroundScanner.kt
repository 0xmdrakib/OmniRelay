package com.example.omnirelay.radio

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.bluetooth.BluetoothManager
import android.bluetooth.le.*
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import com.example.omnirelay.auth.FirebaseAccountSession
import com.example.omnirelay.protocol.OmniFrame
import com.example.omnirelay.routing.AdaptiveResourcePolicy.UserResourceTier
import com.example.omnirelay.service.OmniRelayService
import com.example.omnirelay.utils.SettingsManager

/**
 * OmniRelayBackgroundScanner: Hardware PendingIntent-driven BLE Scan Receiver.
 * Persists BLE frame detection even when Application is in deep sleep (Doze Mode).
 */
class OmniRelayBackgroundScanner : BroadcastReceiver() {

    companion object {
        const val TAG = "BackgroundScanner"
        const val ACTION_BLE_SCAN_RESULT = "xyz.rakibhq.omnirelay.ACTION_BLE_SCAN_RESULT"
        const val REQUEST_CODE = 0x401
        private const val WAKE_DEBOUNCE_MS = 15_000L
        private const val WAKE_PREFS = "OmniRelayBackgroundWake"
        private const val KEY_LAST_WAKE_MS = "last_wake_ms"

        @SuppressLint("MissingPermission")
        fun registerPendingIntentScanner(context: Context) {
            val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)
                ?.adapter ?: return
            val scanner = adapter.bluetoothLeScanner ?: return

            val filter = ScanFilter.Builder()
                .setManufacturerData(
                    BleMeshManager.MANUFACTURER_ID,
                    byteArrayOf(0x20),
                    byteArrayOf(0xF0.toByte())
                )
                .build()

            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .setMatchMode(ScanSettings.MATCH_MODE_AGGRESSIVE)
                .setNumOfMatches(ScanSettings.MATCH_NUM_MAX_ADVERTISEMENT)
                .build()

            try {
                scanner.startScan(listOf(filter), settings, scannerPendingIntent(context))
                Log.i(TAG, "Hardware PendingIntent BLE Scanner registered successfully.")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to register PendingIntent BLE scanner", e)
            }
        }

        @SuppressLint("MissingPermission")
        fun unregisterPendingIntentScanner(context: Context) {
            val scanner = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)
                ?.adapter?.bluetoothLeScanner ?: return
            runCatching { scanner.stopScan(scannerPendingIntent(context)) }
                .onFailure { Log.w(TAG, "Unable to unregister background BLE scanner", it) }
        }

        private fun scannerPendingIntent(context: Context): PendingIntent {
            val intent = Intent(context, OmniRelayBackgroundScanner::class.java).apply {
                action = ACTION_BLE_SCAN_RESULT
            }
            return PendingIntent.getBroadcast(
                context,
                REQUEST_CODE,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            )
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_BLE_SCAN_RESULT) {
            if (!FirebaseAccountSession.isSignedIn(context)) return
            val results: ArrayList<ScanResult>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableArrayListExtra(
                    BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT,
                    ScanResult::class.java
                )
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableArrayListExtra(BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT)
            }

            val settings = SettingsManager(context.applicationContext, observeExternalChanges = false)
            results?.forEach { scanResult ->
                val presence = scanResult.scanRecord
                    ?.getManufacturerSpecificData(BleMeshManager.MANUFACTURER_ID)
                val frame = presence?.let(OmniFrame::unpack) ?: return@forEach
                val prefix = frame.ephemeralPublicKey.copyOf(OmniFrame.COMPACT_KEY_PREFIX_SIZE)
                val isPaired = settings.getPairedContactForPrefix(prefix) != null
                val volunteerWakeAllowed = settings.isMeshRelayEnabled &&
                    settings.resourceTier != UserResourceTier.MINIMAL
                if (isPaired || volunteerWakeAllowed) {
                    val wakePrefs = context.getSharedPreferences(WAKE_PREFS, Context.MODE_PRIVATE)
                    val now = System.currentTimeMillis()
                    val lastWake = wakePrefs.getLong(KEY_LAST_WAKE_MS, 0L)
                    if (now < lastWake || now - lastWake < WAKE_DEBOUNCE_MS) return@forEach
                    wakePrefs.edit().putLong(KEY_LAST_WAKE_MS, now).apply()
                    Log.d(TAG, "OmniRelay peer discovered in background; RSSI=${scanResult.rssi}")
                    val serviceIntent = Intent(context, OmniRelayService::class.java)
                    runCatching { context.startForegroundService(serviceIntent) }
                        .onFailure { Log.w(TAG, "Unable to wake foreground service", it) }
                }
            }
        }
    }
}
