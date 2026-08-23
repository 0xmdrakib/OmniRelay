package com.example.omnirelay.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

/** Restores nearby listeners and the relay stream after a device reboot. */
class OmniRelayBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        ContextCompat.startForegroundService(
            context,
            Intent(context, OmniRelayService::class.java).setAction(OmniRelayService.ACTION_SYNC_MAILBOX)
        )
    }
}
