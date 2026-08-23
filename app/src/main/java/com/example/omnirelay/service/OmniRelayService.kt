package com.example.omnirelay.service

import android.app.NotificationChannel
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.Ringtone
import android.media.RingtoneManager
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.util.Base64
import android.util.Log
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.core.app.NotificationCompat
import androidx.core.app.Person
import com.example.omnirelay.MainActivity
import com.example.omnirelay.data.local.MessageEntity
import com.example.omnirelay.data.local.OmniDatabase
import com.example.omnirelay.data.local.OutboundEnvelopeEntity
import com.example.omnirelay.data.local.ProcessedEnvelopeEntity
import com.example.omnirelay.media.VoiceStreamEngine
import com.example.omnirelay.media.TelecomCallManager
import com.example.omnirelay.network.CallStateRequest
import com.example.omnirelay.network.InternetRelayClient
import com.example.omnirelay.network.RelaySyncWorker
import com.example.omnirelay.network.SendEnvelopeRequest
import com.example.omnirelay.protocol.CryptoEngine
import com.example.omnirelay.protocol.OmniFrame
import com.example.omnirelay.radio.BleMeshManager
import com.example.omnirelay.radio.OmniRelayBackgroundScanner
import com.example.omnirelay.radio.PeerDiscoveryRegistry
import com.example.omnirelay.radio.WifiAwareMeshManager
import com.example.omnirelay.routing.MultiPathRouter
import com.example.omnirelay.routing.TransportPath
import com.example.omnirelay.utils.SettingsManager
import com.example.omnirelay.utils.LocalMessageProtector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.security.MessageDigest

data class CallInvite(
    val callerId: String,
    val callerPublicKey: String,
    val timestampMs: Long = System.currentTimeMillis()
)

/** Owns nearby transports, secure framing, call state and notifications. */
class OmniRelayService : Service() {

    companion object {
        const val TAG = "OmniRelayService"
        const val CHANNEL_ID = "omnirelay_service_channel"
        const val CALL_CHANNEL_ID = "omnirelay_calls_channel"
        const val MSG_CHANNEL_ID = "omnirelay_messages_channel"
        const val NOTIFICATION_ID = 0x99
        const val CALL_NOTIFICATION_ID = 0x101
        const val MSG_NOTIFICATION_ID = 0x102

        const val ACTION_ACCEPT_CALL = "com.example.omnirelay.ACTION_ACCEPT_CALL"
        const val ACTION_DECLINE_CALL = "com.example.omnirelay.ACTION_DECLINE_CALL"
        const val ACTION_END_CALL = "com.example.omnirelay.ACTION_END_CALL"
        const val ACTION_SYNC_MAILBOX = "com.example.omnirelay.ACTION_SYNC_MAILBOX"
        const val ACTION_UPDATE_PUSH_TOKEN = "com.example.omnirelay.ACTION_UPDATE_PUSH_TOKEN"
        const val EXTRA_PUSH_TOKEN = "push_token"

        private const val RECIPIENT_PREFIX_SIZE = 8
        private const val MAX_TEXT_BYTES = 60_000
    }

    private val binder = LocalBinder()
    lateinit var bleMeshManager: BleMeshManager
    lateinit var wifiAwareMeshManager: WifiAwareMeshManager
    lateinit var router: MultiPathRouter
    lateinit var voiceEngine: VoiceStreamEngine
    lateinit var settingsManager: SettingsManager
    lateinit var keyPair: CryptoEngine.KeyPairData

    private val _incomingCallState = MutableStateFlow<CallInvite?>(null)
    val incomingCallState: StateFlow<CallInvite?> = _incomingCallState.asStateFlow()
    private val _chatHistory = MutableStateFlow<List<MessageEntity>>(emptyList())
    val chatHistory: StateFlow<List<MessageEntity>> = _chatHistory.asStateFlow()
    @Volatile private var activeConversationLink: String? = null

    val isCallActive: StateFlow<Boolean> get() = voiceEngine.isCallActive
    val isMuted: StateFlow<Boolean> get() = voiceEngine.isMuted
    val isSpeakerOn: StateFlow<Boolean> get() = voiceEngine.isSpeakerOn
    val callDurationSeconds: StateFlow<Int> get() = voiceEngine.callDurationSeconds

    private var ringtonePlayer: Ringtone? = null
    private var activePeerPublicKey: ByteArray? = null
    private var activeCallId: String? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var database: OmniDatabase
    private lateinit var relayClient: InternetRelayClient
    private lateinit var telecomCallManager: TelecomCallManager
    private lateinit var messageProtector: LocalMessageProtector

    inner class LocalBinder : Binder() {
        fun getService(): OmniRelayService = this@OmniRelayService
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        settingsManager = SettingsManager(this)
        keyPair = settingsManager.getMyIdentity()
        database = OmniDatabase.get(this)
        messageProtector = LocalMessageProtector()
        relayClient = InternetRelayClient(this)
        bleMeshManager = BleMeshManager(this)
        wifiAwareMeshManager = WifiAwareMeshManager(this, keyPair.publicKey)
        router = MultiPathRouter()
        voiceEngine = VoiceStreamEngine(
            enableEchoCancellation = settingsManager.isEchoCancellationEnabled,
            enableNoiseSuppression = settingsManager.isNoiseSuppressionEnabled
        )
        telecomCallManager = TelecomCallManager(
            this,
            serviceScope,
            onSystemAnswer = { acceptIncomingCall(fromTelecom = true) },
            onSystemDisconnect = { stopVoiceCall(fromTelecom = true) }
        )

        voiceEngine.onVoiceBurstGenerated = voice@{ compressedBurst ->
            val target = activePeerPublicKey ?: return@voice
            runCatching {
                sendNearbyFrame(target, buildSecureFrame(OmniFrame.PAYLOAD_TYPE_VOICE, target, compressedBurst))
            }.onFailure { Log.e(TAG, "Nearby voice frame failed", it) }
        }

        bleMeshManager.onPeerDiscoveredListener = { publicKeyPrefix, rssi ->
            settingsManager.getPairedContactForPrefix(publicKeyPrefix)?.let { contact ->
                PeerDiscoveryRegistry.updatePeer(contact.secretLink, rssi, isMutualLinked = true)
                router.updatePathTelemetry(TransportPath.LOCAL_MESH, true, 25, 0f, rssi)
            }
        }

        bleMeshManager.onFrameReceivedListener = { frameBytes, rssi ->
            serviceScope.launch { handleReceivedFrame(frameBytes, rssi) }
        }
        wifiAwareMeshManager.onPeerDiscoveredListener = { publicKeyPrefix ->
            settingsManager.getPairedContactForPrefix(publicKeyPrefix)?.let { contact ->
                PeerDiscoveryRegistry.updatePeer(
                    contact.secretLink,
                    rssi = -45,
                    transport = "Wi-Fi Aware",
                    isMutualLinked = true
                )
                router.updatePathTelemetry(TransportPath.LOCAL_MESH, true, 10, 0f, -45)
            }
        }
        wifiAwareMeshManager.onFrameReceivedListener = { frameBytes ->
            serviceScope.launch { handleReceivedFrame(frameBytes, rssi = -45) }
        }

        serviceScope.launch {
            database.omniDao().observeMessages().collectLatest { messages ->
                _chatHistory.value = messages.map { message ->
                    message.copy(body = messageProtector.decryptForDisplay(message.body))
                }
                messages.filterNot { messageProtector.isEncrypted(it.body) }.forEach { legacy ->
                    database.omniDao().updateMessageBody(legacy.messageId, messageProtector.encrypt(legacy.body))
                }
            }
        }
        initializeInternetRelay()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundServiceNotification(includeMicrophone = false)
        when (intent?.action) {
            ACTION_ACCEPT_CALL -> acceptIncomingCall()
            ACTION_DECLINE_CALL -> declineIncomingCall()
            ACTION_END_CALL -> stopVoiceCall()
            ACTION_SYNC_MAILBOX -> initializeInternetRelay()
            ACTION_UPDATE_PUSH_TOKEN -> intent.getStringExtra(EXTRA_PUSH_TOKEN)?.let { token ->
                serviceScope.launch { updatePushToken(token) }
            }
        }

        if (settingsManager.isBleEnabled) {
            bleMeshManager.startActiveScanning()
            val presence = OmniFrame(
                payloadType = OmniFrame.PAYLOAD_TYPE_PRESENCE,
                ephemeralPublicKey = keyPair.publicKey
            ).packCompact()
            bleMeshManager.startAdvertising(presence)
            OmniRelayBackgroundScanner.registerPendingIntentScanner(this)
        }
        if (settingsManager.isWifiAwareEnabled) wifiAwareMeshManager.attachToNANCluster()
        return START_STICKY
    }

    fun initiateCall(targetAddress: String) {
        val target = settingsManager.decodePublicKey(targetAddress)
        if (target == null) {
            appendChatMessage("Call failed: invalid Secret Link")
            return
        }
        activePeerPublicKey = target
        val callId = UUID.randomUUID().toString()
        activeCallId = callId
        telecomCallManager.reportOutgoing(settingsManager.getContactNameForLink(targetAddress), callId)
        appendChatMessage("Outgoing call ringing")
        serviceScope.launch {
            val frame = buildSecureFrame(OmniFrame.PAYLOAD_TYPE_CALL_RING, target, ByteArray(0))
            val envelopeId = UUID.randomUUID().toString()
            val sentInternet = sendInternetEnvelope(frame, target, "call", callId, envelopeId)
            val sentNearby = !sentInternet && sendNearbyFrame(target, frame)
            if (sentNearby) database.omniDao().setOutboundState(envelopeId, OutboundEnvelopeEntity.STATE_SENT)
            val sent = sentInternet || sentNearby
            if (!sent) appendChatMessage("Call queued: waiting for a network path")
        }
    }

    fun acceptIncomingCall(fromTelecom: Boolean = false) {
        val invite = _incomingCallState.value ?: return
        val target = settingsManager.decodePublicKey(invite.callerPublicKey) ?: return
        stopRingtone()
        cancelNotification(CALL_NOTIFICATION_ID)
        _incomingCallState.value = null
        activePeerPublicKey = target
        if (!fromTelecom) telecomCallManager.answer()
        serviceScope.launch {
            val frame = buildSecureFrame(OmniFrame.PAYLOAD_TYPE_CALL_ACCEPT, target, ByteArray(0))
            val callId = activeCallId
            val internetSent = if (callId != null) transitionInternetCall(callId, "active", frame) else false
            if (internetSent) {
                connectInternetMedia(callId!!)
                appendChatMessage("Call connected with [${invite.callerId}]")
            } else if (sendNearbyFrame(target, frame)) {
                startVoiceMedia()
                appendChatMessage("Call connected with [${invite.callerId}]")
            } else {
                activePeerPublicKey = null
                appendChatMessage("Unable to answer: peer connection lost")
            }
        }
    }

    fun declineIncomingCall() {
        val invite = _incomingCallState.value
        val callIdToDecline = activeCallId
        stopRingtone()
        cancelNotification(CALL_NOTIFICATION_ID)
        _incomingCallState.value = null
        invite?.let { callInvite ->
            settingsManager.decodePublicKey(callInvite.callerPublicKey)?.let { target ->
                serviceScope.launch {
                    val frame = buildSecureFrame(OmniFrame.PAYLOAD_TYPE_CALL_DECLINE, target, ByteArray(0))
                    val transitioned = callIdToDecline?.let { transitionInternetCall(it, "declined", frame) } == true
                    if (!transitioned) sendNearbyFrame(target, frame)
                }
            }
        }
        activeCallId = null
        telecomCallManager.disconnect(android.telecom.DisconnectCause.REJECTED)
        appendChatMessage("Call rejected [${invite?.callerId ?: "Peer"}]")
    }

    fun stopVoiceCall(fromTelecom: Boolean = false) {
        val callIdToEnd = activeCallId
        activePeerPublicKey?.let { target ->
            serviceScope.launch {
                val frame = buildSecureFrame(OmniFrame.PAYLOAD_TYPE_CALL_END, target, ByteArray(0))
                val transitioned = callIdToEnd?.let { transitionInternetCall(it, "ended", frame) } == true
                if (!transitioned) sendNearbyFrame(target, frame)
            }
        }
        stopRingtone()
        cancelNotification(CALL_NOTIFICATION_ID)
        _incomingCallState.value = null
        activePeerPublicKey = null
        activeCallId = null
        if (!fromTelecom) telecomCallManager.disconnect()
        voiceEngine.stopCall()
        startForegroundServiceNotification(includeMicrophone = false)
        appendChatMessage("Voice call ended")
    }

    fun dispatchMessage(text: String, targetAddress: String): String {
        val cleanText = text.trim()
        if (cleanText.isEmpty()) return "Message is empty"
        if (cleanText.toByteArray(Charsets.UTF_8).size > MAX_TEXT_BYTES) {
            return "Message is too large (maximum 60 KB)"
        }
        val target = settingsManager.decodePublicKey(targetAddress)
            ?: return "Message failed: invalid Secret Link"
        val messageId = UUID.randomUUID().toString()
        val contactName = settingsManager.getContactNameForLink(targetAddress)
        serviceScope.launch {
            database.omniDao().insertMessage(MessageEntity(
                messageId, targetAddress, contactName, messageProtector.encrypt(cleanText),
                "outgoing", "queued", "pending", System.currentTimeMillis()
            ))
            val frame = buildSecureFrame(OmniFrame.PAYLOAD_TYPE_TEXT, target, cleanText.toByteArray(Charsets.UTF_8))
            val sentInternet = sendInternetEnvelope(frame, target, "message", null, messageId)
            val sentNearby = !sentInternet && sendNearbyFrame(target, frame)
            if (sentNearby) {
                database.omniDao().setOutboundState(messageId, OutboundEnvelopeEntity.STATE_SENT)
                database.omniDao().updateMessageStatus(messageId, "sent", "nearby")
            }
        }
        return "Queued securely for [$contactName]"
    }

    fun toggleMute(): Boolean = voiceEngine.toggleMute()
    fun toggleSpeaker(): Boolean = voiceEngine.toggleSpeaker(this)

    fun refreshConfiguration() {
        if (settingsManager.isBleEnabled) {
            bleMeshManager.startActiveScanning()
            bleMeshManager.startAdvertising(
                OmniFrame(payloadType = OmniFrame.PAYLOAD_TYPE_PRESENCE, ephemeralPublicKey = keyPair.publicKey)
                    .packCompact()
            )
        } else {
            bleMeshManager.stopActiveScanning()
            bleMeshManager.stopAdvertising()
        }
        if (settingsManager.isWifiAwareEnabled) wifiAwareMeshManager.attachToNANCluster()
        else wifiAwareMeshManager.close()
        if (settingsManager.isRelayModeEnabled) initializeInternetRelay()
        else relayClient.closeRealtime()
        voiceEngine.updateProcessingOptions(
            settingsManager.isEchoCancellationEnabled,
            settingsManager.isNoiseSuppressionEnabled
        )
    }

    fun setActiveConversation(secretLink: String?) {
        activeConversationLink = secretLink
        if (secretLink == null || !relayClient.isConfigured || !settingsManager.isRelayModeEnabled) return
        serviceScope.launch {
            for (messageId in database.omniDao().deliveredInternetMessages(secretLink)) {
                runCatching { relayClient.acknowledge(messageId, "read") }
                    .onSuccess { database.omniDao().setMessageStatus(messageId, "read") }
            }
        }
    }

    private fun buildSecureFrame(type: Byte, targetPublicKey: ByteArray, plaintext: ByteArray): ByteArray {
        val sharedKey = CryptoEngine.deriveSharedSecret(keyPair.privateKey, targetPublicKey)
        val encrypted = CryptoEngine.encryptPayload(plaintext, sharedKey, byteArrayOf(type))
        val envelope = targetPublicKey.copyOfRange(0, RECIPIENT_PREFIX_SIZE) +
            encrypted.iv + encrypted.cipherText
        val frame = OmniFrame(
            payloadType = type,
            pathVectorMap = router.getActivePathBitmask(),
            ephemeralPublicKey = keyPair.publicKey,
            macTag = encrypted.macTag,
            encryptedPayload = envelope
        )
        return frame.pack()
    }

    private fun sendNearbyFrame(targetPublicKey: ByteArray, packed: ByteArray): Boolean {
        if (settingsManager.isWifiAwareEnabled && wifiAwareMeshManager.sendFrame(targetPublicKey, packed)) {
            return true
        }
        return settingsManager.isBleEnabled && bleMeshManager.sendFrame(targetPublicKey, packed)
    }

    private fun initializeInternetRelay() {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled) return
        serviceScope.launch { establishInternetSession() }
    }

    private suspend fun establishInternetSession() {
        runCatching {
            relayClient.ensureRegistered(
                settingsManager.getMySecretLink(),
                settingsManager.getMySigningIdentity(),
                null
            )
            router.updatePathTelemetry(TransportPath.CELLULAR_CONTROL, true, 100, 0f, -70)
            relayClient.connectRealtime(
                onMailboxChanged = { serviceScope.launch { syncMailbox() } },
                onFailure = { scheduleRelayRetry() }
            )
            syncMailbox()
            processOutbox()
        }.onFailure {
            router.updatePathTelemetry(TransportPath.CELLULAR_CONTROL, false, 999, 1f, -127)
            Log.w(TAG, "Internet relay initialization deferred", it)
            scheduleRelayRetry()
        }
    }

    private suspend fun updatePushToken(token: String) {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled) return
        runCatching {
            relayClient.ensureRegistered(
                settingsManager.getMySecretLink(),
                settingsManager.getMySigningIdentity(),
                token
            )
            relayClient.updatePushToken(token)
        }.onFailure {
            Log.w(TAG, "Unable to update FCM token", it)
            scheduleRelayRetry()
        }
    }

    private suspend fun sendInternetEnvelope(
        packedFrame: ByteArray,
        targetPublicKey: ByteArray,
        kind: String,
        callId: String?,
        envelopeId: String = UUID.randomUUID().toString()
    ): Boolean {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled) return false
        val recipientDeviceId = CryptoEngine.deviceIdForPublicKey(targetPublicKey)
        val encodedFrame = Base64.encodeToString(packedFrame, Base64.NO_WRAP)
        val outbound = OutboundEnvelopeEntity(
            envelopeId = envelopeId,
            recipientDeviceId = recipientDeviceId,
            recipientPublicKey = Base64.encodeToString(targetPublicKey, Base64.NO_WRAP),
            kind = kind,
            callId = callId,
            frameBase64 = encodedFrame
        )
        database.omniDao().insertOutbound(outbound)
        return runCatching {
            relayClient.ensureRegistered(
                settingsManager.getMySecretLink(),
                settingsManager.getMySigningIdentity(),
                null
            )
            relayClient.sendEnvelope(SendEnvelopeRequest(
                envelopeId, recipientDeviceId, kind, callId, encodedFrame
            ))
            database.omniDao().setOutboundState(envelopeId, OutboundEnvelopeEntity.STATE_SENT)
            if (kind == "message") database.omniDao().updateMessageStatus(envelopeId, "sent", "internet")
            true
        }.getOrElse {
            Log.w(TAG, "Internet envelope queued for retry", it)
            database.omniDao().markOutboundRetry(envelopeId, System.currentTimeMillis() + 5_000)
            scheduleRelayRetry()
            false
        }
    }

    private suspend fun processOutbox() {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled) return
        for (outbound in database.omniDao().pendingOutbound(System.currentTimeMillis())) {
            val success = runCatching {
                database.omniDao().setOutboundState(outbound.envelopeId, OutboundEnvelopeEntity.STATE_SENDING)
                relayClient.sendEnvelope(SendEnvelopeRequest(
                    outbound.envelopeId,
                    outbound.recipientDeviceId,
                    outbound.kind,
                    outbound.callId,
                    outbound.frameBase64
                ))
                database.omniDao().setOutboundState(outbound.envelopeId, OutboundEnvelopeEntity.STATE_SENT)
                if (outbound.kind == "message") {
                    database.omniDao().updateMessageStatus(outbound.envelopeId, "sent", "internet")
                }
            }.isSuccess
            if (!success) {
                val delay = (5_000L shl outbound.attemptCount.coerceAtMost(8)).coerceAtMost(15 * 60_000L)
                database.omniDao().markOutboundRetry(outbound.envelopeId, System.currentTimeMillis() + delay)
            }
        }
    }

    private suspend fun syncMailbox() {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled || relayClient.credentials() == null) return
        runCatching {
            val mailbox = relayClient.fetchMailbox()
            for (status in mailbox.outboundStatuses) {
                database.omniDao().updateMessageStatus(status.envelopeId, status.state, "internet")
            }
            for (remote in mailbox.envelopes) {
                if (!database.omniDao().isEnvelopeProcessed(remote.envelopeId)) {
                    val frameBytes = Base64.decode(remote.frameBase64, Base64.NO_WRAP)
                    handleReceivedFrame(
                        frameBytes,
                        rssi = -40,
                        envelopeId = remote.envelopeId,
                        callId = remote.callId
                    )
                    database.omniDao().markEnvelopeProcessed(ProcessedEnvelopeEntity(remote.envelopeId))
                }
                val receiptState = if (database.omniDao().messageStatus(remote.envelopeId) == "read") {
                    "read"
                } else "delivered"
                relayClient.acknowledge(remote.envelopeId, receiptState)
            }
            database.omniDao().pruneProcessed(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(30))
        }.onFailure { Log.w(TAG, "Mailbox sync failed", it) }
    }

    private suspend fun transitionInternetCall(callId: String, state: String, packedFrame: ByteArray): Boolean {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled) return false
        return runCatching {
            relayClient.transitionCall(callId, CallStateRequest(
                state = state,
                envelopeId = UUID.randomUUID().toString(),
                frameBase64 = Base64.encodeToString(packedFrame, Base64.NO_WRAP)
            ))
            true
        }.getOrElse {
            Log.w(TAG, "Internet call transition failed", it)
            false
        }
    }

    private suspend fun connectInternetMedia(callId: String) {
        val peerPublicKey = activePeerPublicKey ?: return
        val mediaKey = Base64.encodeToString(
            CryptoEngine.deriveCallMediaKey(keyPair.privateKey, peerPublicKey, callId),
            Base64.NO_WRAP
        )
        runCatching { relayClient.callToken(callId) }
            .onSuccess { credentials ->
                withContext(Dispatchers.Main) {
                    startForegroundServiceNotification(includeMicrophone = true)
                    voiceEngine.startInternetCall(
                        this@OmniRelayService,
                        credentials.url,
                        credentials.token,
                        mediaKey,
                        onFailure = { error ->
                            Log.e(TAG, "Internet call media failed", error)
                            appendChatMessage("Call media connection failed")
                        }
                    )
                }
            }
            .onFailure {
                Log.e(TAG, "Unable to obtain call media token", it)
                appendChatMessage("Call media connection failed")
            }
    }

    private fun scheduleRelayRetry() {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled) return
        val request = OneTimeWorkRequestBuilder<RelaySyncWorker>()
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(this).enqueueUniqueWork(
            RelaySyncWorker.UNIQUE_NAME,
            ExistingWorkPolicy.REPLACE,
            request
        )
    }

    private suspend fun handleReceivedFrame(
        frameBytes: ByteArray,
        rssi: Int,
        envelopeId: String? = null,
        callId: String? = null
    ): Boolean {
        if (frameBytes.size < OmniFrame.HEADER_SIZE) return false
        val frame = OmniFrame.unpack(frameBytes) ?: return false
        if (!settingsManager.isPairedContact(frame.ephemeralPublicKey)) return false
        val nearbyDedupeId = if (envelopeId == null && frame.payloadType != OmniFrame.PAYLOAD_TYPE_VOICE) {
            "nearby:" + MessageDigest.getInstance("SHA-256").digest(frameBytes)
                .joinToString("") { "%02x".format(it) }
        } else null
        if (nearbyDedupeId != null && database.omniDao().isEnvelopeProcessed(nearbyDedupeId)) return false

        val plaintext = openSecureFrame(frame) ?: return false
        val senderLink = Base64.encodeToString(frame.ephemeralPublicKey, Base64.NO_WRAP)
        val contactName = settingsManager.getContactNameForLink(senderLink)
        PeerDiscoveryRegistry.updatePeer(senderLink, rssi, isMutualLinked = true)

        when (frame.payloadType) {
            OmniFrame.PAYLOAD_TYPE_CALL_RING -> {
                activeCallId = callId
                handleIncomingCallRing(contactName, senderLink)
            }
            OmniFrame.PAYLOAD_TYPE_CALL_ACCEPT -> handleCallAccepted(
                contactName,
                frame.ephemeralPublicKey,
                if (envelopeId != null) callId else null
            )
            OmniFrame.PAYLOAD_TYPE_CALL_DECLINE -> handleCallDeclined(contactName)
            OmniFrame.PAYLOAD_TYPE_CALL_END -> handleRemoteCallEnded(contactName)
            OmniFrame.PAYLOAD_TYPE_TEXT -> handleIncomingTextMsg(contactName, senderLink, plaintext, envelopeId)
            OmniFrame.PAYLOAD_TYPE_VOICE -> if (voiceEngine.isCallActive.value) {
                voiceEngine.receiveIncomingVoiceBurst(plaintext)
            }
        }
        if (nearbyDedupeId != null) {
            database.omniDao().markEnvelopeProcessed(ProcessedEnvelopeEntity(nearbyDedupeId))
        }
        return true
    }

    private fun openSecureFrame(frame: OmniFrame): ByteArray? {
        val minimumSize = RECIPIENT_PREFIX_SIZE + CryptoEngine.IV_LENGTH_BYTES
        if (frame.encryptedPayload.size < minimumSize) return null
        val recipientPrefix = frame.encryptedPayload.copyOfRange(0, RECIPIENT_PREFIX_SIZE)
        if (!recipientPrefix.contentEquals(keyPair.publicKey.copyOfRange(0, RECIPIENT_PREFIX_SIZE))) return null
        val ivStart = RECIPIENT_PREFIX_SIZE
        val cipherStart = ivStart + CryptoEngine.IV_LENGTH_BYTES
        val encrypted = CryptoEngine.EncryptedResult(
            cipherText = frame.encryptedPayload.copyOfRange(cipherStart, frame.encryptedPayload.size),
            iv = frame.encryptedPayload.copyOfRange(ivStart, cipherStart),
            macTag = frame.macTag
        )
        val sharedKey = runCatching {
            CryptoEngine.deriveSharedSecret(keyPair.privateKey, frame.ephemeralPublicKey)
        }.getOrNull() ?: return null
        return CryptoEngine.decryptPayload(encrypted, sharedKey, byteArrayOf(frame.payloadType))
    }

    private fun handleIncomingCallRing(callerName: String, callerPublicKey: String) {
        if (_incomingCallState.value != null || voiceEngine.isCallActive.value) return
        val platformCallId = activeCallId ?: UUID.randomUUID().toString().also { activeCallId = it }
        _incomingCallState.value = CallInvite(callerName, callerPublicKey)
        telecomCallManager.reportIncoming(callerName, platformCallId)
        playRingtone()
        postIncomingCallNotification(callerName)
        appendChatMessage("Incoming E2EE call from [$callerName]")
    }

    private fun handleCallAccepted(contactName: String, senderPublicKey: ByteArray, internetCallId: String?) {
        activePeerPublicKey = senderPublicKey.copyOf()
        activeCallId = internetCallId ?: activeCallId
        telecomCallManager.setActive()
        if (internetCallId != null) serviceScope.launch { connectInternetMedia(internetCallId) }
        else startVoiceMedia()
        appendChatMessage("Call accepted by [$contactName]")
    }

    private fun handleCallDeclined(contactName: String) {
        activePeerPublicKey = null
        activeCallId = null
        voiceEngine.stopCall()
        telecomCallManager.disconnect(android.telecom.DisconnectCause.REJECTED)
        appendChatMessage("Call declined by [$contactName]")
    }

    private fun handleRemoteCallEnded(contactName: String) {
        activePeerPublicKey = null
        activeCallId = null
        voiceEngine.stopCall()
        telecomCallManager.disconnect(android.telecom.DisconnectCause.REMOTE)
        startForegroundServiceNotification(includeMicrophone = false)
        appendChatMessage("Call ended by [$contactName]")
    }

    private suspend fun handleIncomingTextMsg(
        senderName: String,
        senderLink: String,
        plaintext: ByteArray,
        envelopeId: String?
    ) {
        val text = plaintext.toString(Charsets.UTF_8)
        val isOpenConversation = envelopeId != null && activeConversationLink == senderLink
        database.omniDao().insertMessage(MessageEntity(
            envelopeId ?: UUID.randomUUID().toString(), senderLink, senderName, messageProtector.encrypt(text),
            "incoming", if (isOpenConversation) "read" else "delivered",
            if (envelopeId == null) "nearby" else "internet", System.currentTimeMillis()
        ))
        postIncomingMessageNotification(senderName, text)
    }

    private fun startVoiceMedia() {
        startForegroundServiceNotification(includeMicrophone = true)
        voiceEngine.startCall()
        telecomCallManager.setActive()
    }

    private fun appendChatMessage(message: String) {
        Log.i(TAG, message)
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        stopRingtone()
        bleMeshManager.close()
        wifiAwareMeshManager.close()
        relayClient.closeRealtime()
        serviceScope.cancel()
        voiceEngine.stopCall()
        super.onDestroy()
    }

    private fun createNotificationChannels() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "OmniRelay connectivity", NotificationManager.IMPORTANCE_LOW)
        )
        manager.createNotificationChannel(
            NotificationChannel(CALL_CHANNEL_ID, "OmniRelay calls", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Incoming and active encrypted calls"
                enableVibration(true)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            }
        )
        manager.createNotificationChannel(
            NotificationChannel(MSG_CHANNEL_ID, "OmniRelay messages", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Incoming encrypted messages"
                enableVibration(true)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            }
        )
    }

    private fun startForegroundServiceNotification(includeMicrophone: Boolean) {
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(if (includeMicrophone) "OmniRelay call active" else "OmniRelay nearby service active")
            .setContentText(if (includeMicrophone) "Encrypted voice session in progress" else "Listening for paired nearby devices")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            var types = ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            if (includeMicrophone && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                types = types or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            }
            startForeground(NOTIFICATION_ID, notification, types)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun postIncomingCallNotification(callerId: String) {
        val acceptIntent = PendingIntent.getService(
            this, 1,
            Intent(this, OmniRelayService::class.java).setAction(ACTION_ACCEPT_CALL),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val declineIntent = PendingIntent.getService(
            this, 2,
            Intent(this, OmniRelayService::class.java).setAction(ACTION_DECLINE_CALL),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val contentIntent = PendingIntent.getActivity(
            this, 3, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val caller = Person.Builder().setName(callerId).setImportant(true).build()
        val notification = NotificationCompat.Builder(this, CALL_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.sym_call_incoming)
            .setContentIntent(contentIntent)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setStyle(NotificationCompat.CallStyle.forIncomingCall(caller, declineIntent, acceptIntent))
            .setFullScreenIntent(contentIntent, true)
            .setOngoing(true)
            .build()
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(CALL_NOTIFICATION_ID, notification)
    }

    private fun postIncomingMessageNotification(senderId: String, text: String) {
        val contentIntent = PendingIntent.getActivity(
            this, 4, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(this, MSG_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle(senderId)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .build()
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(MSG_NOTIFICATION_ID, notification)
    }

    private fun playRingtone() {
        runCatching {
            ringtonePlayer = RingtoneManager.getRingtone(
                applicationContext,
                RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
            ).also { it.play() }
        }.onFailure { Log.e(TAG, "Unable to play ringtone", it) }
    }

    private fun stopRingtone() {
        runCatching { ringtonePlayer?.stop() }
        ringtonePlayer = null
    }

    private fun cancelNotification(id: Int) {
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).cancel(id)
    }
}
