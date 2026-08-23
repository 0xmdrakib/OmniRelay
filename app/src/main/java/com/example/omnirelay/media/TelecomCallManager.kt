package com.example.omnirelay.media

import android.content.Context
import android.net.Uri
import android.telecom.DisconnectCause
import androidx.core.telecom.CallAttributesCompat
import androidx.core.telecom.CallControlScope
import androidx.core.telecom.CallsManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/** Bridges OmniRelay VoIP state to Android Telecom and remote call surfaces. */
class TelecomCallManager(
    context: Context,
    private val scope: CoroutineScope,
    private val onSystemAnswer: () -> Unit,
    private val onSystemDisconnect: () -> Unit
) {
    private val callsManager = CallsManager(context.applicationContext).also {
        it.registerAppWithTelecom(CallsManager.CAPABILITY_BASELINE)
    }
    @Volatile private var control: CallControlScope? = null

    fun reportIncoming(displayName: String, callId: String) {
        addCall(displayName, callId, CallAttributesCompat.DIRECTION_INCOMING)
    }

    fun reportOutgoing(displayName: String, callId: String) {
        addCall(displayName, callId, CallAttributesCompat.DIRECTION_OUTGOING)
    }

    private fun addCall(displayName: String, callId: String, direction: Int) {
        scope.launch {
            val attributes = CallAttributesCompat(
                displayName,
                Uri.parse("omnirelay:$callId"),
                direction,
                CallAttributesCompat.CALL_TYPE_AUDIO_CALL,
                CallAttributesCompat.SUPPORTS_SET_INACTIVE
            )
            callsManager.addCall(
                attributes,
                onAnswer = { onSystemAnswer() },
                onDisconnect = { onSystemDisconnect() },
                onSetActive = {},
                onSetInactive = {}
            ) {
                control = this
            }
        }
    }

    fun answer() {
        scope.launch { control?.answer(CallAttributesCompat.CALL_TYPE_AUDIO_CALL) }
    }

    fun setActive() {
        scope.launch { control?.setActive() }
    }

    fun disconnect(cause: Int = DisconnectCause.LOCAL) {
        val current = control
        control = null
        scope.launch { current?.disconnect(DisconnectCause(cause)) }
    }
}
