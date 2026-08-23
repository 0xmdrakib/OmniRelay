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
import com.example.omnirelay.service.OmniRelayService

/**
 * OmniRelayBackgroundScanner: Hardware PendingIntent-driven BLE Scan Receiver.
 * Persists BLE frame detection even when Application is in deep sleep (Doze Mode).
 */
class OmniRelayBackgroundScanner : BroadcastReceiver() {

    companion object {
        const val TAG = "BackgroundScanner"
        const val ACTION_BLE_SCAN_RESULT = "com.example.omnirelay.ACTION_BLE_SCAN_RESULT"
        const val REQUEST_CODE = 0x401

        @SuppressLint("MissingPermission")
        fun registerPendingIntentScanner(context: Context) {
            val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)
                ?.adapter ?: return
            val scanner = adapter.bluetoothLeScanner ?: return

            val filter = ScanFilter.Builder()
                .setManufacturerData(
                    BleMeshManager.MANUFACTURER_ID,
                    byteArrayOf(0x10),
                    byteArrayOf(0xF0.toByte())
                )
                .build()

            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .setMatchMode(ScanSettings.MATCH_MODE_AGGRESSIVE)
                .setNumOfMatches(ScanSettings.MATCH_NUM_MAX_ADVERTISEMENT)
                .build()

            val intent = Intent(context, OmniRelayBackgroundScanner::class.java).apply {
                action = ACTION_BLE_SCAN_RESULT
            }

            val pendingIntent = PendingIntent.getBroadcast(
                context,
                REQUEST_CODE,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            )

            try {
                scanner.startScan(listOf(filter), settings, pendingIntent)
                Log.i(TAG, "Hardware PendingIntent BLE Scanner registered successfully.")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to register PendingIntent BLE scanner", e)
            }
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_BLE_SCAN_RESULT) {
            val results: ArrayList<ScanResult>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableArrayListExtra(
                    BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT,
                    ScanResult::class.java
                )
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableArrayListExtra(BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT)
            }

            results?.forEach { scanResult ->
                val presence = scanResult.scanRecord
                    ?.getManufacturerSpecificData(BleMeshManager.MANUFACTURER_ID)
                if (presence != null) {
                    Log.d(TAG, "OmniRelay peer discovered in background; RSSI=${scanResult.rssi}")
                    val serviceIntent = Intent(context, OmniRelayService::class.java)
                    runCatching { context.startForegroundService(serviceIntent) }
                        .onFailure { Log.w(TAG, "Unable to wake foreground service", it) }
                }
            }
        }
    }
}
