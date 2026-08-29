package com.example.omnirelay.routing

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import com.example.omnirelay.routing.AdaptiveResourcePolicy.Inputs
import com.example.omnirelay.routing.AdaptiveResourcePolicy.ThermalSeverity
import com.example.omnirelay.utils.SettingsManager

/** Reads only coarse device state needed to protect battery, heat, and user data. */
class AndroidResourceMonitor(context: Context) {
    private val appContext = context.applicationContext
    private val batteryManager = appContext.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
    private val powerManager = appContext.getSystemService(Context.POWER_SERVICE) as PowerManager
    private val connectivityManager =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun snapshot(
        settings: SettingsManager,
        isForeground: Boolean,
        isCallActive: Boolean
    ): Inputs = Inputs(
        isCharging = isCharging(),
        batteryPercent = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
            .takeIf { it in 0..100 } ?: 50,
        isPowerSaveMode = powerManager.isPowerSaveMode,
        thermalSeverity = thermalSeverity(),
        isMeteredNetwork = connectivityManager.isActiveNetworkMetered,
        isForeground = isForeground,
        isCallActive = isCallActive,
        relayOptIn = settings.isMeshRelayEnabled,
        resourceTier = settings.resourceTier
    )

    private fun isCharging(): Boolean {
        val status = appContext.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            ?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        return status == BatteryManager.BATTERY_STATUS_CHARGING ||
            status == BatteryManager.BATTERY_STATUS_FULL
    }

    private fun thermalSeverity(): ThermalSeverity {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return ThermalSeverity.NORMAL
        return when (powerManager.currentThermalStatus) {
            PowerManager.THERMAL_STATUS_NONE,
            PowerManager.THERMAL_STATUS_LIGHT -> ThermalSeverity.NORMAL
            PowerManager.THERMAL_STATUS_MODERATE -> ThermalSeverity.MODERATE
            PowerManager.THERMAL_STATUS_SEVERE -> ThermalSeverity.SEVERE
            else -> ThermalSeverity.CRITICAL
        }
    }
}
