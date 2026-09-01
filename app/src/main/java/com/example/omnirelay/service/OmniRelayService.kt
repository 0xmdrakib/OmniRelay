package com.example.omnirelay.service

import android.app.NotificationChannel
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanSettings
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
import com.example.omnirelay.R
import com.example.omnirelay.auth.AccountAuthenticationRequiredException
import com.example.omnirelay.auth.FirebaseAccountSession
import com.example.omnirelay.data.local.MessageEntity
import com.example.omnirelay.data.local.OmniDatabase
import com.example.omnirelay.data.local.OutboundEnvelopeEntity
import com.example.omnirelay.data.local.ProcessedEnvelopeEntity
import com.example.omnirelay.data.local.RelayCapsuleEntity
import com.example.omnirelay.media.VoiceStreamEngine
import com.example.omnirelay.media.TelecomCallManager
import com.example.omnirelay.network.CallStateRequest
import com.example.omnirelay.network.InternetRelayClient
import com.example.omnirelay.network.OutboundRetryPolicy
import com.example.omnirelay.network.RelayHttpException
import com.example.omnirelay.network.RelaySyncWorker
import com.example.omnirelay.network.SendEnvelopeRequest
import com.example.omnirelay.protocol.CryptoEngine
import com.example.omnirelay.protocol.OmniFrame
import com.example.omnirelay.protocol.OmniFrameCipher
import com.example.omnirelay.protocol.RelayCapsule
import com.example.omnirelay.protocol.RelayReplayTracker
import com.example.omnirelay.radio.BleMeshManager
import com.example.omnirelay.radio.OmniRelayBackgroundScanner
import com.example.omnirelay.radio.PeerDiscoveryRegistry
import com.example.omnirelay.radio.WifiAwareMeshManager
import com.example.omnirelay.routing.MultiPathRouter
import com.example.omnirelay.routing.TransportPath
import com.example.omnirelay.routing.AdaptiveResourcePolicy
import com.example.omnirelay.routing.AndroidResourceMonitor
import com.example.omnirelay.routing.HourlyByteBudget
import com.example.omnirelay.routing.FixedWindowRateLimit
import com.example.omnirelay.utils.SettingsManager
import com.example.omnirelay.utils.IdentityUnavailableException
import com.example.omnirelay.utils.LocalMessageProtector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.LinkedHashMap
import java.util.concurrent.ConcurrentHashMap
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicLong
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.security.MessageDigest

data class CallInvite(
    val callerId: String,
    val callerPublicKey: String,
    val timestampMs: Long = System.currentTimeMillis()
)

private data class NearbyVoicePayload(
    val callId: String,
    val counter: Long,
    val codec: Byte,
    val audio: ByteArray
)

private data class WaitingCall(
    val callerName: String,
    val callerPublicKeyBase64: String,
    val callId: String,
    val peerPublicKey: ByteArray,
    val expiresAtMs: Long
)

private enum class InternetCallTransitionResult { SENT, UNAVAILABLE, PARTICIPANT_BUSY }

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
        const val IDENTITY_NOTIFICATION_ID = 0x103
        const val CALL_WAITING_NOTIFICATION_ID = 0x104

        const val ACTION_ACCEPT_CALL = "xyz.rakibhq.omnirelay.ACTION_ACCEPT_CALL"
        const val ACTION_DECLINE_CALL = "xyz.rakibhq.omnirelay.ACTION_DECLINE_CALL"
        const val ACTION_END_CALL = "xyz.rakibhq.omnirelay.ACTION_END_CALL"
        const val ACTION_SYNC_MAILBOX = "xyz.rakibhq.omnirelay.ACTION_SYNC_MAILBOX"
        const val ACTION_SYNC_CONTACTS = "xyz.rakibhq.omnirelay.ACTION_SYNC_CONTACTS"
        const val ACTION_UPDATE_PUSH_TOKEN = "xyz.rakibhq.omnirelay.ACTION_UPDATE_PUSH_TOKEN"
        const val EXTRA_PUSH_TOKEN = "push_token"

        private const val MAX_TEXT_BYTES = 60_000
        private const val OUTGOING_RING_TIMEOUT_MS = 60_000L
        private const val CALL_SIGNAL_MAX_AGE_MS = 60_000L
        private const val CALL_SIGNAL_MAX_FUTURE_SKEW_MS = 15_000L
        private const val CALL_LEASE_RENEW_INTERVAL_MS = 45_000L
        private const val MAX_NEARBY_PACKETS_PER_SECOND = 200
        private const val MAX_VOICE_PACKETS_PER_SECOND = 100
        private const val MAX_VOICE_COUNTER_JUMP = 500L
        private const val VOICE_HEADER_BYTES = 25
        private const val VOICE_CODEC_ADPCM: Byte = 0x01
        private const val VOICE_CODEC_PCM16: Byte = 0x02
        private const val MAX_VOLUNTEER_RELAY_PACKET_BYTES = 20 * 1024
        private const val MAX_VOLUNTEER_RELAY_INNER_BYTES = 20_000
        private const val MAX_RELAY_PACKETS_PER_MINUTE = 240
        private const val MAX_RELAY_FANOUT_RESERVATION = 16
        private const val MAX_STORED_RELAY_CAPSULES = 128
        private const val MAX_STORED_RELAY_BYTES = 4L * 1024L * 1024L
        private const val RELAY_CAPSULE_RETENTION_MS = 15L * 60L * 1_000L
        private const val RELAY_QUEUE_RETRY_BASE_MS = 15_000L
        private const val MAX_RELAY_QUEUE_ATTEMPTS = 4
        private const val RELAY_QUEUE_BATCH_SIZE = 16
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
    private val callState = CallStateMachine()
    private val waitingCallLock = Any()
    private val voiceCounterLock = Any()
    private val activeCallId: String? get() = callState.snapshot()?.callId
    private val activePeerPublicKey: ByteArray? get() = callState.snapshot()?.peerPublicKey
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var database: OmniDatabase
    private lateinit var relayClient: InternetRelayClient
    private lateinit var telecomCallManager: TelecomCallManager
    private lateinit var messageProtector: LocalMessageProtector
    private lateinit var resourceMonitor: AndroidResourceMonitor
    private val relayByteBudget = HourlyByteBudget()
    private val relayPacketRate = FixedWindowRateLimit(60_000L)
    private val nearbyPacketRate = FixedWindowRateLimit(1_000L)
    private val voicePacketRate = FixedWindowRateLimit(1_000L)
    private val outboxMutex = Mutex()
    private val mailboxSyncMutex = Mutex()
    private val relayQueueMutex = Mutex()
    private val pairSharedKeyCache = ConcurrentHashMap<String, ByteArray>()
    private val relayReplayTracker = RelayReplayTracker(4_096)
    private val seenVoiceFrames = LinkedHashMap<String, Unit>(8_192, 0.75f, true)
    private var bleScanDutyJob: Job? = null
    private var bleAdvertiseDutyJob: Job? = null
    private var incomingRingTimeoutJob: Job? = null
    private var callLeaseJob: Job? = null
    private var relayQueueJob: Job? = null
    @Volatile private var waitingCall: WaitingCall? = null
    private val outgoingVoiceCounter = AtomicLong(0)
    @Volatile private var lastIncomingVoiceCounter = -1L
    @Volatile private var appInForeground = false
    @Volatile private var initializationFailed = false

    inner class LocalBinder : Binder() {
        fun getService(): OmniRelayService = this@OmniRelayService
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        if (!FirebaseAccountSession.isSignedIn(this)) {
            initializationFailed = true
            Log.i(TAG, "Service startup skipped until Google authentication completes")
            stopSelf()
            return
        }
        settingsManager = SettingsManager(this)
        resourceMonitor = AndroidResourceMonitor(this)
        keyPair = try {
            settingsManager.getMyIdentity()
        } catch (error: IdentityUnavailableException) {
            initializationFailed = true
            Log.e(TAG, "Protected identity is unavailable; radio and relay startup aborted", error)
            postIdentityRecoveryNotification()
            stopSelf()
            return
        }
        database = OmniDatabase.get(this)
        messageProtector = LocalMessageProtector()
        relayClient = InternetRelayClient(this)
        bleMeshManager = BleMeshManager(this)
        wifiAwareMeshManager = WifiAwareMeshManager(
            context = this,
            identityPublicKey = keyPair.publicKey,
            peerCredentialsProvider = credentials@{ publicKeyPrefix ->
                val contact = settingsManager.getPairedContactForPrefix(publicKeyPrefix)
                    ?: return@credentials null
                val peerPublicKey = settingsManager.decodePublicKey(contact.secretLink)
                    ?: return@credentials null
                val sharedSecret = runCatching {
                    sharedKeyWith(peerPublicKey)
                }.getOrNull() ?: return@credentials null
                WifiAwareMeshManager.PeerCredentials(peerPublicKey, sharedSecret)
            }
        )
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

        voiceEngine.onVoiceBurstGenerated = voice@{ compressedBurst, pcmBurst ->
            val call = callState.snapshot()?.takeIf { it.phase == CallStateMachine.Phase.ACTIVE }
                ?: return@voice
            val target = call.peerPublicKey
            val callId = call.callId
            runCatching {
                val counter = outgoingVoiceCounter.getAndIncrement()
                val sentLossless = settingsManager.isWifiAwareEnabled &&
                    wifiAwareMeshManager.hasHighBandwidthChannel(target) &&
                    wifiAwareMeshManager.sendHighBandwidthFrame(
                        target,
                        buildSecureFrame(
                            OmniFrame.PAYLOAD_TYPE_VOICE,
                            target,
                            encodeVoicePayload(callId, counter, VOICE_CODEC_PCM16, pcmBurst)
                        )
                    )
                if (!sentLossless && settingsManager.isBleEnabled) {
                    val adpcmPayload = encodeVoicePayload(
                        callId,
                        counter,
                        VOICE_CODEC_ADPCM,
                        compressedBurst
                    )
                    bleMeshManager.sendFrame(
                        target,
                        buildSecureFrame(OmniFrame.PAYLOAD_TYPE_VOICE, target, adpcmPayload)
                    )
                }
            }.onFailure { Log.e(TAG, "Nearby voice frame failed", it) }
        }

        bleMeshManager.onPeerDiscoveredListener = { publicKeyPrefix, rssi ->
            settingsManager.getPairedContactForPrefix(publicKeyPrefix)?.let { contact ->
                PeerDiscoveryRegistry.updatePeer(contact.secretLink, rssi, isMutualLinked = true)
                router.updatePathTelemetry(TransportPath.LOCAL_MESH, true, 25, 0f, rssi)
            }
            serviceScope.launch { drainRelayCapsules() }
        }

        bleMeshManager.onFrameReceivedListener = { frameBytes, rssi ->
            if (nearbyPacketRate.tryAcquire(MAX_NEARBY_PACKETS_PER_SECOND)) {
                serviceScope.launch { handleNearbyPacket(frameBytes, rssi) }
            }
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
            serviceScope.launch { drainRelayCapsules() }
        }
        wifiAwareMeshManager.onFrameReceivedListener = { frameBytes ->
            if (nearbyPacketRate.tryAcquire(MAX_NEARBY_PACKETS_PER_SECOND)) {
                serviceScope.launch { handleNearbyPacket(frameBytes, rssi = -45) }
            }
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
        relayQueueJob = serviceScope.launch {
            while (isActive) {
                delay(30_000L)
                drainRelayCapsules()
            }
        }
        initializeInternetRelay()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (initializationFailed) return START_NOT_STICKY
        startForegroundServiceNotification(includeMicrophone = false)
        when (intent?.action) {
            ACTION_ACCEPT_CALL -> acceptIncomingCall()
            ACTION_DECLINE_CALL -> declineIncomingCall()
            ACTION_END_CALL -> stopVoiceCall()
            ACTION_SYNC_MAILBOX -> initializeInternetRelay()
            ACTION_SYNC_CONTACTS -> serviceScope.launch {
                runCatching {
                    ensureInternetRegistration(null)
                    syncAccountContacts(notifyIncoming = true)
                }.onFailure { Log.w(TAG, "Contact invitation sync deferred", it) }
            }
            ACTION_UPDATE_PUSH_TOKEN -> intent.getStringExtra(EXTRA_PUSH_TOKEN)?.let { token ->
                serviceScope.launch { updatePushToken(token) }
            }
        }

        applyResourcePolicy()
        return START_STICKY
    }

    fun setAppInForeground(isForeground: Boolean) {
        appInForeground = isForeground
        applyResourcePolicy()
    }

    fun initiateCall(targetAddress: String) {
        val target = settingsManager.decodePublicKey(targetAddress)
        if (target == null) {
            appendChatMessage("Call failed: invalid Secret Link")
            return
        }
        val callId = UUID.randomUUID().toString()
        if (callState.beginOutgoing(callId, target) == null) {
            appendChatMessage("Another call is already in progress")
            return
        }
        outgoingVoiceCounter.set(0)
        synchronized(voiceCounterLock) { lastIncomingVoiceCounter = -1L }
        applyResourcePolicy()
        telecomCallManager.reportOutgoing(settingsManager.getContactNameForLink(targetAddress), callId)
        appendChatMessage("Outgoing call ringing")
        serviceScope.launch {
            if (!callState.matches(callId, target, CallStateMachine.Phase.OUTGOING_RINGING)) {
                return@launch
            }
            val frame = buildSecureFrame(OmniFrame.PAYLOAD_TYPE_CALL_RING, target, encodeCallId(callId))
            val envelopeId = UUID.randomUUID().toString()
            val targetLink = Base64.encodeToString(target, Base64.NO_WRAP)
            val directNearby = PeerDiscoveryRegistry.isMutualPeerActive(targetLink)
            val (sentInternet, directNearbySent) = coroutineScope {
                val internet = async {
                    sendInternetEnvelope(frame, target, "call", callId, envelopeId)
                }
                val nearby = async {
                    directNearby &&
                        callState.matches(callId, target, CallStateMachine.Phase.OUTGOING_RINGING) &&
                        sendNearbyFrame(target, frame)
                }
                internet.await() to nearby.await()
            }
            val sentNearby = directNearbySent || (!sentInternet &&
                callState.matches(callId, target, CallStateMachine.Phase.OUTGOING_RINGING) &&
                sendNearbyFrame(target, frame))
            if (sentNearby) database.omniDao().markOutboundSentIfPending(envelopeId)
            val sent = sentInternet || sentNearby
            if (!sent) appendChatMessage("Call queued: waiting for a network path")
        }
        serviceScope.launch {
            delay(OUTGOING_RING_TIMEOUT_MS)
            if (callState.expire(callId, CallStateMachine.Phase.OUTGOING_RINGING) != null) {
                database.omniDao().cancelPendingCall(callId)
                telecomCallManager.disconnect(android.telecom.DisconnectCause.CANCELED)
                applyResourcePolicy()
                appendChatMessage("Outgoing call timed out")
                promoteWaitingCall()
            }
        }
    }

    fun acceptIncomingCall(fromTelecom: Boolean = false) {
        val invite = _incomingCallState.value
        val call = callState.beginLocalAccept() ?: return
        val target = call.peerPublicKey
        stopRingtone()
        incomingRingTimeoutJob?.cancel()
        cancelNotification(CALL_NOTIFICATION_ID)
        _incomingCallState.value = null
        if (!fromTelecom) telecomCallManager.answer()
        serviceScope.launch {
            val callId = call.callId
            val frame = buildSecureFrame(OmniFrame.PAYLOAD_TYPE_CALL_ACCEPT, target, encodeCallId(callId))
            val internetTransition = transitionInternetCall(callId, "active", frame, target)
            if (internetTransition == InternetCallTransitionResult.SENT) {
                if (callState.matches(callId, target, CallStateMachine.Phase.CONNECTING)) {
                    connectInternetMedia(callId, target)
                    appendChatMessage("Call connected with [${invite?.callerId ?: "Peer"}]")
                }
            } else if (internetTransition == InternetCallTransitionResult.PARTICIPANT_BUSY) {
                callState.terminateRemote(callId, target, CallStateMachine.Phase.CONNECTING)
                telecomCallManager.disconnect(android.telecom.DisconnectCause.BUSY)
                applyResourcePolicy()
                appendChatMessage("Unable to answer: one participant is already in another call")
                promoteWaitingCall()
            } else if (callState.matches(callId, target, CallStateMachine.Phase.CONNECTING) &&
                sendNearbyFrame(target, frame)
            ) {
                startVoiceMedia(callId, target)
                appendChatMessage("Call connected with [${invite?.callerId ?: "Peer"}]")
            } else {
                val cleared = callState.terminateRemote(
                    callId,
                    target,
                    CallStateMachine.Phase.CONNECTING
                )
                if (cleared != null) {
                    applyResourcePolicy()
                    appendChatMessage("Unable to answer: peer connection lost")
                }
            }
        }
    }

    fun declineIncomingCall() {
        val invite = _incomingCallState.value
        val call = callState.terminateLocal(CallStateMachine.Phase.INCOMING_RINGING) ?: return
        stopRingtone()
        incomingRingTimeoutJob?.cancel()
        cancelNotification(CALL_NOTIFICATION_ID)
        _incomingCallState.value = null
        serviceScope.launch {
            val frame = buildSecureFrame(
                OmniFrame.PAYLOAD_TYPE_CALL_DECLINE,
                call.peerPublicKey,
                encodeCallId(call.callId)
            )
            val transitioned = transitionInternetCall(
                call.callId,
                "declined",
                frame,
                call.peerPublicKey
            )
            if (transitioned != InternetCallTransitionResult.SENT) {
                sendNearbyFrame(call.peerPublicKey, frame)
            }
        }
        applyResourcePolicy()
        telecomCallManager.disconnect(android.telecom.DisconnectCause.REJECTED)
        appendChatMessage("Call rejected [${invite?.callerId ?: "Peer"}]")
        promoteWaitingCall()
    }

    fun stopVoiceCall(fromTelecom: Boolean = false) {
        val call = callState.terminateLocal()
        callLeaseJob?.cancel()
        callLeaseJob = null
        call?.let { ended ->
            serviceScope.launch {
                database.omniDao().cancelPendingCall(ended.callId)
                val frame = buildSecureFrame(
                    OmniFrame.PAYLOAD_TYPE_CALL_END,
                    ended.peerPublicKey,
                    encodeCallId(ended.callId)
                )
                val transitioned = transitionInternetCall(
                    ended.callId,
                    "ended",
                    frame,
                    ended.peerPublicKey
                )
                if (transitioned != InternetCallTransitionResult.SENT) {
                    sendNearbyFrame(ended.peerPublicKey, frame)
                }
            }
        }
        stopRingtone()
        incomingRingTimeoutJob?.cancel()
        cancelNotification(CALL_NOTIFICATION_ID)
        _incomingCallState.value = null
        if (!fromTelecom) telecomCallManager.disconnect()
        voiceEngine.stopCall()
        startForegroundServiceNotification(includeMicrophone = false)
        applyResourcePolicy()
        appendChatMessage("Voice call ended")
        promoteWaitingCall()
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
            val targetLink = Base64.encodeToString(target, Base64.NO_WRAP)
            val directNearby = PeerDiscoveryRegistry.isMutualPeerActive(targetLink)
            val (sentInternet, directNearbySent) = coroutineScope {
                val internet = async { sendInternetEnvelope(frame, target, "message", null, messageId) }
                val nearby = async { directNearby && sendNearbyFrame(target, frame) }
                internet.await() to nearby.await()
            }
            val sentNearby = directNearbySent || (!sentInternet && sendNearbyFrame(target, frame))
            if (sentNearby) {
                if (database.omniDao().markOutboundSentIfPending(messageId) == 1) {
                    database.omniDao().updateMessageStatus(messageId, "sent", "nearby")
                }
            }
        }
        return "Queued securely for [$contactName]"
    }

    fun toggleMute(): Boolean = voiceEngine.toggleMute()
    fun toggleSpeaker(): Boolean = voiceEngine.toggleSpeaker(this)

    fun refreshConfiguration() {
        applyResourcePolicy()
        if (settingsManager.isRelayModeEnabled) initializeInternetRelay()
        else relayClient.closeRealtime()
        voiceEngine.updateProcessingOptions(
            settingsManager.isEchoCancellationEnabled,
            settingsManager.isNoiseSuppressionEnabled
        )
    }

    private fun applyResourcePolicy(): AdaptiveResourcePolicy.Decision {
        val decision = AdaptiveResourcePolicy.evaluate(
            resourceMonitor.snapshot(
                settingsManager,
                isForeground = appInForeground,
                isCallActive = voiceEngine.isCallActive.value || activeCallId != null
            )
        )
        val activeOwnerUse = appInForeground || voiceEngine.isCallActive.value || activeCallId != null
        wifiAwareMeshManager.setHighBandwidthNdpAllowed(
            decision.isHighBandwidthNearbyTransferAllowed
        )
        bleScanDutyJob?.cancel()
        bleScanDutyJob = null
        bleAdvertiseDutyJob?.cancel()
        bleAdvertiseDutyJob = null
        if (!settingsManager.isBleEnabled || !decision.advertiseDutyCycle.isEnabled) {
            bleMeshManager.stopActiveScanning()
            bleMeshManager.stopAdvertising()
            OmniRelayBackgroundScanner.unregisterPendingIntentScanner(this)
        } else {
            if (activeOwnerUse && decision.scanDutyCycle.isEnabled) {
                bleMeshManager.startActiveScanning(
                    if (decision.isHighBandwidthNearbyTransferAllowed) {
                        ScanSettings.SCAN_MODE_LOW_LATENCY
                    } else {
                        ScanSettings.SCAN_MODE_BALANCED
                    }
                )
            } else if (decision.isThirdPartyRelayAllowed && decision.scanDutyCycle.isEnabled) {
                bleMeshManager.stopActiveScanning()
                bleScanDutyJob = serviceScope.launch {
                    val onMillis = decision.scanDutyCycle.onDurationMillis
                    val offMillis = decision.scanDutyCycle.periodMillis - onMillis
                    while (true) {
                        bleMeshManager.startActiveScanning(ScanSettings.SCAN_MODE_LOW_POWER)
                        delay(onMillis)
                        bleMeshManager.stopActiveScanning()
                        if (offMillis > 0) delay(offMillis)
                    }
                }
            } else {
                bleMeshManager.stopActiveScanning()
            }
            val presence = OmniFrame(
                payloadType = OmniFrame.PAYLOAD_TYPE_PRESENCE,
                ephemeralPublicKey = keyPair.publicKey
            ).packCompact()
            if (activeOwnerUse) {
                bleMeshManager.startAdvertising(
                    presence,
                    advertiseMode = AdvertiseSettings.ADVERTISE_MODE_BALANCED,
                    txPowerLevel = AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM
                )
            } else {
                bleMeshManager.stopAdvertising()
                bleAdvertiseDutyJob = serviceScope.launch {
                    val onMillis = decision.advertiseDutyCycle.onDurationMillis
                    val offMillis = decision.advertiseDutyCycle.periodMillis - onMillis
                    while (true) {
                        bleMeshManager.startAdvertising(
                            presence,
                            advertiseMode = AdvertiseSettings.ADVERTISE_MODE_LOW_POWER,
                            txPowerLevel = AdvertiseSettings.ADVERTISE_TX_POWER_LOW
                        )
                        delay(onMillis)
                        bleMeshManager.stopAdvertising()
                        if (offMillis > 0L) delay(offMillis)
                    }
                }
            }
            OmniRelayBackgroundScanner.registerPendingIntentScanner(this)
        }
        if (settingsManager.isWifiAwareEnabled && decision.scanDutyCycle.isEnabled &&
            (activeOwnerUse || decision.isThirdPartyRelayAllowed)
        ) {
            wifiAwareMeshManager.attachToNANCluster()
        } else {
            wifiAwareMeshManager.pause()
        }
        return decision
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
        val normalizedTarget = CryptoEngine.normalizePublicKey(targetPublicKey)
        val flags = (OmniFrame.FLAG_E2EE.toInt() or if (type == OmniFrame.PAYLOAD_TYPE_VOICE) {
            OmniFrame.FLAG_VOICE_STREAM.toInt()
        } else {
            OmniFrame.FLAG_RELAY_ALLOWED.toInt()
        }).toByte()
        val frameMetadata = OmniFrame(
            payloadType = type,
            flags = flags,
            pathVectorMap = router.getActivePathBitmask(),
            ephemeralPublicKey = keyPair.publicKey
        )
        val pairSharedKey = sharedKeyWith(normalizedTarget)
        return OmniFrameCipher.seal(
            frameMetadata,
            plaintext,
            pairSharedKey,
            keyPair.publicKey,
            normalizedTarget
        ).pack()
    }

    private fun encodeCallId(callId: String): ByteArray {
        val uuid = UUID.fromString(callId)
        return ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
            .putLong(uuid.mostSignificantBits)
            .putLong(uuid.leastSignificantBits)
            .array()
    }

    private fun decodeCallId(payload: ByteArray): String? = runCatching {
        if (payload.size != 16) return null
        val buffer = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
        UUID(buffer.long, buffer.long).toString()
    }.getOrNull()

    private fun sharedKeyWith(peerPublicKey: ByteArray): ByteArray {
        val normalized = CryptoEngine.normalizePublicKey(peerPublicKey)
        val cacheKey = Base64.encodeToString(normalized, Base64.NO_WRAP)
        return pairSharedKeyCache.computeIfAbsent(cacheKey) {
            CryptoEngine.deriveSharedSecret(keyPair.privateKey, normalized)
        }
    }

    private fun pairedPublicKeys(): List<ByteArray> = settingsManager.getPairedContacts()
        .asSequence()
        .take(512)
        .mapNotNull { settingsManager.decodePublicKey(it.secretLink) }
        .toList()

    private fun routeTokenBase64(targetPublicKey: ByteArray): String {
        val normalizedTarget = CryptoEngine.normalizePublicKey(targetPublicKey)
        val token = CryptoEngine.deriveBackendRouteToken(
            sharedKeyWith(normalizedTarget),
            keyPair.publicKey,
            normalizedTarget
        )
        return try {
            Base64.encodeToString(token, Base64.NO_WRAP)
        } finally {
            token.fill(0)
        }
    }

    private fun encodeVoicePayload(
        callId: String,
        counter: Long,
        codec: Byte,
        audio: ByteArray
    ): ByteArray =
        ByteBuffer.allocate(VOICE_HEADER_BYTES + audio.size).order(ByteOrder.BIG_ENDIAN).apply {
            put(encodeCallId(callId))
            putLong(counter)
            put(codec)
            put(audio)
        }.array()

    private fun decodeVoicePayload(payload: ByteArray): NearbyVoicePayload? = runCatching {
        if (payload.size < VOICE_HEADER_BYTES) return null
        val callId = decodeCallId(payload.copyOfRange(0, 16)) ?: return null
        val buffer = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
        buffer.position(16)
        val counter = buffer.long
        if (counter < 0) return null
        val codec = buffer.get()
        val audio = payload.copyOfRange(VOICE_HEADER_BYTES, payload.size)
        val expectedBytes = when (codec) {
            VOICE_CODEC_ADPCM -> VoiceStreamEngine.COMPRESSED_FRAME_BYTES
            VOICE_CODEC_PCM16 -> VoiceStreamEngine.RAW_FRAME_BYTES
            else -> return null
        }
        if (audio.size != expectedBytes) return null
        NearbyVoicePayload(callId, counter, codec, audio)
    }.getOrNull()

    private fun sendNearbyFrame(targetPublicKey: ByteArray, packed: ByteArray): Boolean {
        if (settingsManager.isWifiAwareEnabled && wifiAwareMeshManager.sendFrame(targetPublicKey, packed)) {
            return true
        }
        if (settingsManager.isBleEnabled && bleMeshManager.sendFrame(targetPublicKey, packed)) {
            return true
        }
        if (!settingsManager.isMeshRelayEnabled) return false
        if (packed.size > MAX_VOLUNTEER_RELAY_INNER_BYTES) return false
        val frame = OmniFrame.unpack(packed) ?: return false
        if (frame.payloadType == OmniFrame.PAYLOAD_TYPE_VOICE ||
            frame.payloadType == OmniFrame.PAYLOAD_TYPE_PRESENCE ||
            frame.flags.toInt() and OmniFrame.FLAG_RELAY_ALLOWED.toInt() == 0
        ) return false
        val decision = applyResourcePolicy()
        if (!decision.scanDutyCycle.isEnabled) return false
        val sharedKey = runCatching { sharedKeyWith(targetPublicKey) }.getOrNull() ?: return false
        val hops = decision.maxRelayHops.coerceAtLeast(1).coerceAtMost(RelayCapsule.MAX_HOPS)
        val capsule = RelayCapsule.seal(packed, sharedKey, hops).pack()
        if (capsule.size > MAX_VOLUNTEER_RELAY_PACKET_BYTES) return false
        val neighbors = broadcastNearbyPacket(capsule)
        if (neighbors == 0) serviceScope.launch { storeRelayCapsule(capsule) }
        return neighbors > 0
    }

    private fun broadcastNearbyPacket(packet: ByteArray): Int {
        var neighbors = 0
        if (settingsManager.isWifiAwareEnabled) neighbors += wifiAwareMeshManager.broadcastPacket(packet)
        if (settingsManager.isBleEnabled) neighbors += bleMeshManager.broadcastPacket(packet)
        return neighbors
    }

    private suspend fun storeRelayCapsule(packet: ByteArray): Boolean = relayQueueMutex.withLock {
        if (!settingsManager.isMeshRelayEnabled || packet.size > MAX_VOLUNTEER_RELAY_PACKET_BYTES) {
            return@withLock false
        }
        val capsule = RelayCapsule.unpack(packet) ?: return@withLock false
        val now = System.currentTimeMillis()
        val dao = database.omniDao()
        dao.pruneRelayCapsules(now, MAX_RELAY_QUEUE_ATTEMPTS)
        val stats = dao.relayQueueStats()
        if (stats.itemCount >= MAX_STORED_RELAY_CAPSULES ||
            stats.totalBytes + packet.size > MAX_STORED_RELAY_BYTES
        ) return@withLock false
        val id = capsule.capsuleId.joinToString("") { "%02x".format(it) }
        dao.insertRelayCapsule(
            RelayCapsuleEntity(
                capsuleId = id,
                packet = packet.copyOf(),
                expiresAtMs = now + RELAY_CAPSULE_RETENTION_MS,
                nextAttemptAtMs = now + RELAY_QUEUE_RETRY_BASE_MS
            )
        ) != -1L
    }

    private suspend fun drainRelayCapsules() = relayQueueMutex.withLock {
        if (!settingsManager.isMeshRelayEnabled) return@withLock
        val decision = applyResourcePolicy()
        if (!decision.isThirdPartyRelayAllowed) return@withLock
        val now = System.currentTimeMillis()
        val dao = database.omniDao()
        dao.pruneRelayCapsules(now, MAX_RELAY_QUEUE_ATTEMPTS)
        for (queued in dao.pendingRelayCapsules(now, RELAY_QUEUE_BATCH_SIZE)) {
            if (!relayPacketRate.tryAcquire(MAX_RELAY_PACKETS_PER_MINUTE)) break
            if (broadcastNearbyPacket(queued.packet) > 0) {
                dao.deleteRelayCapsule(queued.capsuleId)
            } else {
                val multiplier = 1L shl queued.attemptCount.coerceIn(0, 3)
                dao.deferRelayCapsule(
                    queued.capsuleId,
                    now + RELAY_QUEUE_RETRY_BASE_MS * multiplier
                )
            }
        }
    }

    private suspend fun handleNearbyPacket(packet: ByteArray, rssi: Int): Boolean {
        if (!RelayCapsule.isCapsule(packet)) return handleReceivedFrame(packet, rssi)
        if (packet.size > MAX_VOLUNTEER_RELAY_PACKET_BYTES ||
            !relayPacketRate.tryAcquire(MAX_RELAY_PACKETS_PER_MINUTE)
        ) return false
        val capsule = RelayCapsule.unpack(packet) ?: return false
        for (contact in settingsManager.getPairedContacts().take(512)) {
            val publicKey = settingsManager.decodePublicKey(contact.secretLink) ?: continue
            val sharedKey = runCatching { sharedKeyWith(publicKey) }.getOrNull() ?: continue
            val innerFrame = capsule.tryOpen(sharedKey) ?: continue
            if (!relayReplayTracker.markAuthenticatedDelivery(publicKey, capsule)) return true
            return handleReceivedFrame(innerFrame, rssi)
        }

        if (!relayReplayTracker.markForwardProgress(capsule)) return true
        val decision = applyResourcePolicy()
        val forwarded = capsule.forwarded() ?: return false
        val forwardedBytes = forwarded.pack()
        val reservedBytes = forwardedBytes.size.toLong() * MAX_RELAY_FANOUT_RESERVATION
        if (!decision.isThirdPartyRelayAllowed ||
            !relayByteBudget.tryConsume(reservedBytes, decision.relayByteBudgetPerHour)
        ) return false
        val neighbors = broadcastNearbyPacket(forwardedBytes)
        if (neighbors == 0) storeRelayCapsule(forwardedBytes)
        return true
    }

    private fun initializeInternetRelay() {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled ||
            !FirebaseAccountSession.isSignedIn(this)
        ) return
        serviceScope.launch { establishInternetSession() }
    }

    private suspend fun ensureInternetRegistration(fcmToken: String?) {
        val accountToken = FirebaseAccountSession.idToken(this)
        val signingIdentity = settingsManager.getMySigningIdentity()
        try {
            relayClient.ensureRegistered(
                keyPair,
                signingIdentity,
                fcmToken,
                pairedPublicKeys(),
                accountToken.uid,
                accountToken.idToken
            )
        } finally {
            signingIdentity.privateKeyDer.fill(0)
        }
    }

    private suspend fun establishInternetSession() {
        runCatching {
            ensureInternetRegistration(null)
            router.updatePathTelemetry(TransportPath.CELLULAR_CONTROL, true, 100, 0f, -70)
            relayClient.connectRealtime(
                onMailboxChanged = {
                    serviceScope.launch {
                        syncMailbox()
                        syncAccountContacts(notifyIncoming = true)
                    }
                },
                onFailure = { scheduleRelayRetry() }
            )
            syncAccountContacts(notifyIncoming = false)
            syncMailbox()
            processOutbox()
        }.onFailure {
            router.updatePathTelemetry(TransportPath.CELLULAR_CONTROL, false, 999, 1f, -127)
            Log.w(TAG, "Internet relay initialization deferred", it)
            if (it !is AccountAuthenticationRequiredException) scheduleRelayRetry()
        }
    }

    private suspend fun syncAccountContacts(notifyIncoming: Boolean) {
        val contacts = relayClient.fetchAccountContacts()
        val before = settingsManager.getPairedContacts().map { it.secretLink }.toSet()
        settingsManager.syncAccountContacts(contacts.contacts)
        val after = settingsManager.getPairedContacts().map { it.secretLink }.toSet()
        if (before != after) {
            pairSharedKeyCache.values.forEach { it.fill(0) }
            pairSharedKeyCache.clear()
            ensureInternetRegistration(null)
        }
        if (!notifyIncoming) return
        relayClient.fetchContactInvitations().invitations
            .filter { it.direction == "incoming" }
            .forEach { postContactInvitationNotification(it.counterpartEmail, it.invitationId) }
    }

    private suspend fun updatePushToken(token: String) {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled) return
        runCatching {
            ensureInternetRegistration(token)
            relayClient.updatePushToken(token)
        }.onFailure {
            Log.w(TAG, "Unable to update FCM token", it)
            if (it !is AccountAuthenticationRequiredException) scheduleRelayRetry()
        }
    }

    private suspend fun sendInternetEnvelope(
        packedFrame: ByteArray,
        targetPublicKey: ByteArray,
        kind: String,
        callId: String?,
        envelopeId: String = UUID.randomUUID().toString()
    ): Boolean {
        val recipientDeviceId = CryptoEngine.deviceIdForPublicKey(targetPublicKey)
        val encodedFrame = Base64.encodeToString(packedFrame, Base64.NO_WRAP)
        val outboundRouteToken = routeTokenBase64(targetPublicKey)
        val outbound = OutboundEnvelopeEntity(
            envelopeId = envelopeId,
            recipientDeviceId = recipientDeviceId,
            recipientPublicKey = Base64.encodeToString(targetPublicKey, Base64.NO_WRAP),
            kind = kind,
            callId = callId,
            frameBase64 = encodedFrame
        )
        database.omniDao().insertOutbound(outbound)
        if (kind == "call" && callId != activeCallId) {
            callId?.let { database.omniDao().cancelPendingCall(it) }
            return false
        }
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled) return false
        return runCatching {
            ensureInternetRegistration(null)
            if (database.omniDao().markOutboundSendingIfPending(envelopeId) != 1) return@runCatching false
            relayClient.sendEnvelope(
                SendEnvelopeRequest(
                    envelopeId = envelopeId,
                    recipientDeviceId = recipientDeviceId,
                    kind = kind,
                    callId = callId,
                    frameBase64 = encodedFrame,
                    routeTokenBase64 = outboundRouteToken
                )
            )
            val committed = database.omniDao().markOutboundSentIfSending(envelopeId) == 1
            if (kind == "message" && committed) {
                database.omniDao().updateMessageStatus(envelopeId, "sent", "internet")
            }
            // The server accepted the immutable envelope even if a concurrent local cancellation
            // won the Room compare-and-set. Never fall back and send a second copy in that case.
            true
        }.getOrElse {
            Log.w(TAG, "Internet envelope queued for retry", it)
            database.omniDao().markOutboundRetryIfSending(
                envelopeId,
                System.currentTimeMillis() + 5_000
            )
            if (it !is AccountAuthenticationRequiredException) scheduleRelayRetry()
            false
        }
    }

    private suspend fun processOutbox() {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled) return
        outboxMutex.withLock {
            val now = System.currentTimeMillis()
            for (outbound in database.omniDao().pendingOutbound(now)) {
                val retryableCallId = callState.snapshot()
                    ?.takeIf { it.phase == CallStateMachine.Phase.OUTGOING_RINGING }
                    ?.callId
                if (!OutboundRetryPolicy.shouldAttempt(
                        outbound.kind,
                        outbound.callId,
                        retryableCallId,
                        outbound.createdAtMs,
                        now
                    )
                ) {
                    outbound.callId?.let { database.omniDao().cancelPendingCall(it) }
                    continue
                }
                if (database.omniDao().markOutboundSendingIfPending(outbound.envelopeId) != 1) {
                    continue
                }
                val sendResult = runCatching {
                    val recipientPublicKey = Base64.decode(
                        outbound.recipientPublicKey,
                        Base64.NO_WRAP
                    )
                    relayClient.sendEnvelope(
                        SendEnvelopeRequest(
                            envelopeId = outbound.envelopeId,
                            recipientDeviceId = outbound.recipientDeviceId,
                            kind = outbound.kind,
                            callId = outbound.callId,
                            frameBase64 = outbound.frameBase64,
                            routeTokenBase64 = routeTokenBase64(recipientPublicKey)
                        )
                    )
                    val committed = database.omniDao().markOutboundSentIfSending(outbound.envelopeId) == 1
                    if (outbound.kind == "message" && committed) {
                        database.omniDao().updateMessageStatus(outbound.envelopeId, "sent", "internet")
                    }
                }
                val failure = sendResult.exceptionOrNull()
                if (failure != null) {
                    val terminalClientError = failure is RelayHttpException &&
                        failure.statusCode in setOf(400, 409, 410, 413, 422)
                    if (terminalClientError) {
                        database.omniDao().setOutboundState(
                            outbound.envelopeId,
                            OutboundEnvelopeEntity.STATE_CANCELLED
                        )
                        if (outbound.kind == "message") {
                            database.omniDao().updateMessageStatus(
                                outbound.envelopeId,
                                "failed",
                                "internet"
                            )
                        }
                        continue
                    }
                    val delay = (5_000L shl outbound.attemptCount.coerceAtMost(8))
                        .coerceAtMost(15 * 60_000L)
                    database.omniDao().markOutboundRetryIfSending(
                        outbound.envelopeId,
                        System.currentTimeMillis() + delay
                    )
                }
            }
        }
    }

    private suspend fun syncMailbox() {
        mailboxSyncMutex.withLock {
            if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled ||
                relayClient.credentials() == null
            ) return
            runCatching {
            val mailbox = relayClient.fetchMailbox()
            for (status in mailbox.outboundStatuses) {
                database.omniDao().updateMessageStatus(status.envelopeId, status.state, "internet")
            }
            for (remote in mailbox.envelopes) {
                // Never let a remote-selected envelope ID enter persistent dedupe before the
                // frame has parsed, matched a paired identity, and passed AEAD authentication.
                val accepted = runCatching {
                    val frameBytes = Base64.decode(remote.frameBase64, Base64.NO_WRAP)
                    handleReceivedFrame(
                        frameBytes,
                        rssi = -40,
                        envelopeId = remote.envelopeId,
                        callId = remote.callId
                    )
                }.getOrDefault(false)
                if (!accepted) {
                    relayClient.acknowledge(remote.envelopeId, "rejected")
                    continue
                }
                database.omniDao().markEnvelopeProcessed(ProcessedEnvelopeEntity(remote.envelopeId))
                val receiptState = if (database.omniDao().messageStatus(remote.envelopeId) == "read") {
                    "read"
                } else "delivered"
                relayClient.acknowledge(remote.envelopeId, receiptState)
            }
            database.omniDao().pruneProcessed(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(30))
            }.onFailure { Log.w(TAG, "Mailbox sync failed", it) }
        }
    }

    private suspend fun transitionInternetCall(
        callId: String,
        state: String,
        packedFrame: ByteArray,
        targetPublicKey: ByteArray
    ): InternetCallTransitionResult {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled) {
            return InternetCallTransitionResult.UNAVAILABLE
        }
        return runCatching {
            relayClient.transitionCall(callId, CallStateRequest(
                state = state,
                envelopeId = UUID.randomUUID().toString(),
                frameBase64 = Base64.encodeToString(packedFrame, Base64.NO_WRAP),
                routeTokenBase64 = routeTokenBase64(targetPublicKey)
            ))
            InternetCallTransitionResult.SENT
        }.getOrElse {
            Log.w(TAG, "Internet call transition failed", it)
            if (it is RelayHttpException && it.statusCode == 409 &&
                it.message?.contains("participant_busy") == true
            ) InternetCallTransitionResult.PARTICIPANT_BUSY
            else InternetCallTransitionResult.UNAVAILABLE
        }
    }

    private suspend fun connectInternetMedia(callId: String, peerPublicKey: ByteArray) {
        if (!callState.matches(callId, peerPublicKey, CallStateMachine.Phase.CONNECTING)) return
        val mediaKey = Base64.encodeToString(
            CryptoEngine.deriveCallMediaKey(keyPair.privateKey, peerPublicKey, callId),
            Base64.NO_WRAP
        )
        runCatching { relayClient.callToken(callId) }
            .onSuccess { credentials ->
                withContext(Dispatchers.Main) {
                    if (callState.activate(callId, peerPublicKey) == null) return@withContext
                    startForegroundServiceNotification(includeMicrophone = true)
                    voiceEngine.startInternetCall(
                        this@OmniRelayService,
                        credentials.url,
                        credentials.token,
                        mediaKey,
                        onFailure = { error ->
                            Log.e(TAG, "Internet call media failed", error)
                            failCurrentCall(callId, peerPublicKey, "Call media connection failed")
                        }
                    )
                    startCallLease(callId, peerPublicKey)
                    applyResourcePolicy()
                }
            }
            .onFailure {
                Log.e(TAG, "Unable to obtain call media token", it)
                failCurrentCall(callId, peerPublicKey, "Call media connection failed")
            }
    }

    private fun failCurrentCall(callId: String, peerPublicKey: ByteArray, message: String) {
        val cleared = callState.terminateRemote(
            callId,
            peerPublicKey,
            CallStateMachine.Phase.CONNECTING,
            CallStateMachine.Phase.ACTIVE
        ) ?: return
        callLeaseJob?.cancel()
        callLeaseJob = null
        voiceEngine.stopCall()
        telecomCallManager.disconnect(android.telecom.DisconnectCause.ERROR)
        startForegroundServiceNotification(includeMicrophone = false)
        applyResourcePolicy()
        appendChatMessage(message)
        serviceScope.launch { database.omniDao().cancelPendingCall(cleared.callId) }
    }

    private fun startCallLease(callId: String, peerPublicKey: ByteArray) {
        callLeaseJob?.cancel()
        callLeaseJob = serviceScope.launch {
            while (callState.matches(callId, peerPublicKey, CallStateMachine.Phase.ACTIVE)) {
                delay(CALL_LEASE_RENEW_INTERVAL_MS)
                if (!callState.matches(callId, peerPublicKey, CallStateMachine.Phase.ACTIVE)) break
                runCatching { relayClient.renewCallLease(callId) }
                    .onFailure { Log.w(TAG, "Unable to renew active call lease", it) }
            }
        }
    }

    private fun scheduleRelayRetry() {
        if (!relayClient.isConfigured || !settingsManager.isRelayModeEnabled ||
            !FirebaseAccountSession.isSignedIn(this)
        ) return
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
        if (frame.flags.toInt() and OmniFrame.FLAG_E2EE.toInt() == 0) return false
        val isVoiceFrame = frame.payloadType == OmniFrame.PAYLOAD_TYPE_VOICE
        val hasVoiceFlag = frame.flags.toInt() and OmniFrame.FLAG_VOICE_STREAM.toInt() != 0
        if (isVoiceFrame != hasVoiceFlag) return false
        if (!settingsManager.isPairedContact(frame.ephemeralPublicKey)) return false
        if (isVoiceFrame) {
            val encryptedVoiceHeaderBytes = OmniFrameCipher.RECIPIENT_PREFIX_BYTES +
                CryptoEngine.IV_LENGTH_BYTES + VOICE_HEADER_BYTES
            val validVoiceSize = frame.encryptedPayload.size ==
                encryptedVoiceHeaderBytes + VoiceStreamEngine.COMPRESSED_FRAME_BYTES ||
                frame.encryptedPayload.size == encryptedVoiceHeaderBytes + VoiceStreamEngine.RAW_FRAME_BYTES
            if (!validVoiceSize ||
                !voicePacketRate.tryAcquire(MAX_VOICE_PACKETS_PER_SECOND)
            ) return false
        }

        // Authentication precedes persistent dedupe so a spoofed public header cannot force Room work.
        val plaintext = openSecureFrame(frame) ?: return false
        val contentDedupeId = "frame:" + MessageDigest.getInstance("SHA-256").digest(
            frame.ephemeralPublicKey + byteArrayOf(frame.payloadType) + frame.macTag + frame.encryptedPayload
        ).joinToString("") { "%02x".format(it) }
        if (isVoiceFrame) {
            if (!markSeen(seenVoiceFrames, contentDedupeId, 8_192)) return true
        } else if (database.omniDao().isEnvelopeProcessed(contentDedupeId)) {
            return true
        }

        val senderLink = Base64.encodeToString(frame.ephemeralPublicKey, Base64.NO_WRAP)
        val contactName = settingsManager.getContactNameForLink(senderLink)
        val callSignalRemainingMs = when (frame.payloadType) {
            OmniFrame.PAYLOAD_TYPE_CALL_RING,
            OmniFrame.PAYLOAD_TYPE_CALL_ACCEPT,
            OmniFrame.PAYLOAD_TYPE_CALL_DECLINE,
            OmniFrame.PAYLOAD_TYPE_CALL_END -> frame.remainingLifetimeMillis(
                CALL_SIGNAL_MAX_AGE_MS,
                CALL_SIGNAL_MAX_FUTURE_SKEW_MS
            ) ?: return false
            else -> null
        }
        val authenticatedCallId = when (frame.payloadType) {
            OmniFrame.PAYLOAD_TYPE_CALL_RING,
            OmniFrame.PAYLOAD_TYPE_CALL_ACCEPT,
            OmniFrame.PAYLOAD_TYPE_CALL_DECLINE,
            OmniFrame.PAYLOAD_TYPE_CALL_END -> decodeCallId(plaintext) ?: return false
            else -> null
        }
        if (callId != null && authenticatedCallId != null && callId != authenticatedCallId) return false
        PeerDiscoveryRegistry.updatePeer(senderLink, rssi, isMutualLinked = true)

        when (frame.payloadType) {
            OmniFrame.PAYLOAD_TYPE_CALL_RING -> {
                val secureCallId = authenticatedCallId ?: return false
                when (callState.receiveIncomingRing(secureCallId, frame.ephemeralPublicKey)) {
                    CallStateMachine.RingResult.REJECTED -> return false
                    CallStateMachine.RingResult.BUSY -> {
                        val remaining = callSignalRemainingMs ?: return false
                        synchronized(waitingCallLock) {
                            waitingCall?.peerPublicKey?.fill(0)
                            waitingCall = WaitingCall(
                                callerName = contactName,
                                callerPublicKeyBase64 = senderLink,
                                callId = secureCallId,
                                peerPublicKey = frame.ephemeralPublicKey.copyOf(),
                                expiresAtMs = System.currentTimeMillis() + remaining
                            )
                        }
                        postCallWaitingNotification(contactName)
                        appendChatMessage("Call waiting from [$contactName]")
                    }
                    CallStateMachine.RingResult.DUPLICATE -> Unit
                    CallStateMachine.RingResult.NEW -> {
                        outgoingVoiceCounter.set(0)
                        synchronized(voiceCounterLock) { lastIncomingVoiceCounter = -1L }
                        handleIncomingCallRing(
                            contactName,
                            senderLink,
                            secureCallId,
                            callSignalRemainingMs ?: return false
                        )
                    }
                }
            }
            OmniFrame.PAYLOAD_TYPE_CALL_ACCEPT -> {
                val secureCallId = authenticatedCallId ?: return false
                val accepted = callState.acceptRemote(secureCallId, frame.ephemeralPublicKey)
                    ?: return false
                incomingRingTimeoutJob?.cancel()
                handleCallAccepted(
                    contactName,
                    accepted,
                    useInternetMedia = envelopeId != null
                )
            }
            OmniFrame.PAYLOAD_TYPE_CALL_DECLINE -> {
                val secureCallId = authenticatedCallId ?: return false
                val declined = callState.terminateRemote(
                    secureCallId,
                    frame.ephemeralPublicKey,
                    CallStateMachine.Phase.OUTGOING_RINGING
                ) ?: return false
                handleCallDeclined(contactName, declined)
            }
            OmniFrame.PAYLOAD_TYPE_CALL_END -> {
                val secureCallId = authenticatedCallId ?: return false
                val ended = callState.terminateRemote(secureCallId, frame.ephemeralPublicKey)
                    ?: return false
                handleRemoteCallEnded(contactName, ended)
            }
            OmniFrame.PAYLOAD_TYPE_TEXT -> {
                if (plaintext.size > MAX_TEXT_BYTES) return false
                handleIncomingTextMsg(
                    contactName,
                    senderLink,
                    plaintext,
                    envelopeId,
                    contentDedupeId
                )
            }
            OmniFrame.PAYLOAD_TYPE_VOICE -> {
                val voice = decodeVoicePayload(plaintext) ?: return false
                val currentCall = callState.snapshot() ?: return false
                if (currentCall.phase != CallStateMachine.Phase.ACTIVE ||
                    currentCall.callId != voice.callId ||
                    !currentCall.peerPublicKey.contentEquals(frame.ephemeralPublicKey)
                ) return false
                val valid = synchronized(voiceCounterLock) {
                    val counterDelta = if (lastIncomingVoiceCounter < 0L) {
                        voice.counter + 1L
                    } else {
                        voice.counter - lastIncomingVoiceCounter
                    }
                    if (!voiceEngine.isCallActive.value ||
                        counterDelta !in 1L..MAX_VOICE_COUNTER_JUMP ||
                        !callState.matches(
                            voice.callId,
                            frame.ephemeralPublicKey,
                            CallStateMachine.Phase.ACTIVE
                        )
                    ) return@synchronized false
                    lastIncomingVoiceCounter = voice.counter
                    true
                }
                if (!valid) return false
                voiceEngine.receiveIncomingVoiceBurst(
                    voice.audio,
                    isPcm = voice.codec == VOICE_CODEC_PCM16
                )
            }
            else -> return false
        }
        if (frame.payloadType != OmniFrame.PAYLOAD_TYPE_VOICE &&
            frame.payloadType != OmniFrame.PAYLOAD_TYPE_TEXT
        ) {
            database.omniDao().markEnvelopeProcessed(ProcessedEnvelopeEntity(contentDedupeId))
        }
        return true
    }

    private fun markSeen(cache: LinkedHashMap<String, Unit>, id: String, maxEntries: Int): Boolean =
        synchronized(cache) {
            if (cache.containsKey(id)) return@synchronized false
            cache[id] = Unit
            while (cache.size > maxEntries) cache.entries.iterator().run {
                if (hasNext()) {
                    next()
                    remove()
                }
            }
            true
        }

    private fun openSecureFrame(frame: OmniFrame): ByteArray? {
        val pairSharedKey = runCatching { sharedKeyWith(frame.ephemeralPublicKey) }.getOrNull() ?: return null
        return OmniFrameCipher.open(frame, pairSharedKey, keyPair.publicKey)
    }

    private fun handleIncomingCallRing(
        callerName: String,
        callerPublicKey: String,
        callId: String,
        remainingRingMillis: Long
    ) {
        val current = callState.snapshot()
        if (current?.callId != callId || current.phase != CallStateMachine.Phase.INCOMING_RINGING) {
            return
        }
        _incomingCallState.value = CallInvite(callerName, callerPublicKey)
        telecomCallManager.reportIncoming(callerName, callId)
        playRingtone()
        postIncomingCallNotification(callerName)
        appendChatMessage("Incoming E2EE call from [$callerName]")
        incomingRingTimeoutJob?.cancel()
        incomingRingTimeoutJob = serviceScope.launch {
            delay(remainingRingMillis.coerceAtMost(OUTGOING_RING_TIMEOUT_MS))
            val expired = callState.expire(callId, CallStateMachine.Phase.INCOMING_RINGING)
            if (expired != null) {
                _incomingCallState.value = null
                stopRingtone()
                cancelNotification(CALL_NOTIFICATION_ID)
                telecomCallManager.disconnect(android.telecom.DisconnectCause.MISSED)
                applyResourcePolicy()
                appendChatMessage("Missed encrypted call from [$callerName]")
            }
        }
    }

    private fun promoteWaitingCall() {
        if (callState.snapshot() != null) return
        val waiting = synchronized(waitingCallLock) {
            val candidate = waitingCall ?: return@synchronized null
            if (candidate.expiresAtMs <= System.currentTimeMillis()) {
                candidate.peerPublicKey.fill(0)
                waitingCall = null
                return@synchronized null
            }
            waitingCall = null
            candidate
        } ?: run {
            cancelNotification(CALL_WAITING_NOTIFICATION_ID)
            return
        }
        val remaining = waiting.expiresAtMs - System.currentTimeMillis()
        if (callState.receiveIncomingRing(waiting.callId, waiting.peerPublicKey) ==
            CallStateMachine.RingResult.NEW
        ) {
            cancelNotification(CALL_WAITING_NOTIFICATION_ID)
            handleIncomingCallRing(
                waiting.callerName,
                waiting.callerPublicKeyBase64,
                waiting.callId,
                remaining
            )
        } else {
            synchronized(waitingCallLock) { waitingCall = waiting }
        }
    }

    private fun handleCallAccepted(
        contactName: String,
        call: CallStateMachine.Session,
        useInternetMedia: Boolean
    ) {
        incomingRingTimeoutJob?.cancel()
        serviceScope.launch { database.omniDao().cancelPendingCall(call.callId) }
        telecomCallManager.setActive()
        if (useInternetMedia) {
            serviceScope.launch { connectInternetMedia(call.callId, call.peerPublicKey) }
        } else {
            startVoiceMedia(call.callId, call.peerPublicKey)
        }
        appendChatMessage("Call accepted by [$contactName]")
    }

    private fun handleCallDeclined(contactName: String, call: CallStateMachine.Session) {
        incomingRingTimeoutJob?.cancel()
        callLeaseJob?.cancel()
        callLeaseJob = null
        voiceEngine.stopCall()
        serviceScope.launch { database.omniDao().cancelPendingCall(call.callId) }
        telecomCallManager.disconnect(android.telecom.DisconnectCause.REJECTED)
        applyResourcePolicy()
        appendChatMessage("Call declined by [$contactName]")
        promoteWaitingCall()
    }

    private fun handleRemoteCallEnded(contactName: String, call: CallStateMachine.Session) {
        incomingRingTimeoutJob?.cancel()
        callLeaseJob?.cancel()
        callLeaseJob = null
        stopRingtone()
        cancelNotification(CALL_NOTIFICATION_ID)
        _incomingCallState.value = null
        voiceEngine.stopCall()
        serviceScope.launch { database.omniDao().cancelPendingCall(call.callId) }
        telecomCallManager.disconnect(android.telecom.DisconnectCause.REMOTE)
        startForegroundServiceNotification(includeMicrophone = false)
        applyResourcePolicy()
        appendChatMessage("Call ended by [$contactName]")
        promoteWaitingCall()
    }

    private suspend fun handleIncomingTextMsg(
        senderName: String,
        senderLink: String,
        plaintext: ByteArray,
        envelopeId: String?,
        contentDedupeId: String
    ) {
        val text = plaintext.toString(Charsets.UTF_8)
        val isOpenConversation = envelopeId != null && activeConversationLink == senderLink
        val inserted = database.omniDao().insertIncomingMessageOnce(
            MessageEntity(
                envelopeId ?: UUID.randomUUID().toString(), senderLink, senderName, messageProtector.encrypt(text),
                "incoming", if (isOpenConversation) "read" else "delivered",
                if (envelopeId == null) "nearby" else "internet", System.currentTimeMillis()
            ),
            ProcessedEnvelopeEntity(contentDedupeId)
        )
        if (inserted) postIncomingMessageNotification(senderName, text)
    }

    private fun startVoiceMedia(callId: String, peerPublicKey: ByteArray) {
        if (callState.activate(callId, peerPublicKey) == null) return
        startForegroundServiceNotification(includeMicrophone = true)
        voiceEngine.startCall()
        telecomCallManager.setActive()
        applyResourcePolicy()
    }

    private fun appendChatMessage(message: String) {
        Log.i(TAG, message)
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        callState.terminateLocal()
        callLeaseJob?.cancel()
        callLeaseJob = null
        relayQueueJob?.cancel()
        relayQueueJob = null
        stopRingtone()
        incomingRingTimeoutJob?.cancel()
        synchronized(waitingCallLock) {
            waitingCall?.peerPublicKey?.fill(0)
            waitingCall = null
        }
        cancelNotification(CALL_WAITING_NOTIFICATION_ID)
        if (::bleMeshManager.isInitialized) bleMeshManager.close()
        if (::wifiAwareMeshManager.isInitialized) wifiAwareMeshManager.close()
        if (::relayClient.isInitialized) relayClient.closeRealtime()
        pairSharedKeyCache.values.forEach { it.fill(0) }
        pairSharedKeyCache.clear()
        if (::keyPair.isInitialized) keyPair.privateKey.fill(0)
        serviceScope.cancel()
        if (::voiceEngine.isInitialized) voiceEngine.stopCall()
        if (::settingsManager.isInitialized) settingsManager.close()
        super.onDestroy()
    }

    private fun postIdentityRecoveryNotification() {
        val openApp = PendingIntent.getActivity(
            this,
            IDENTITY_NOTIFICATION_ID,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(this, MSG_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("OmniRelay identity locked")
            .setContentText("Open OmniRelay for recovery guidance. Networking was stopped safely.")
            .setContentIntent(openApp)
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .build()
        runCatching {
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(IDENTITY_NOTIFICATION_ID, notification)
        }.onFailure { Log.w(TAG, "Unable to show identity recovery notification", it) }
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
            .setSmallIcon(R.drawable.ic_notification)
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
            .setSmallIcon(R.drawable.ic_notification)
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

    private fun postCallWaitingNotification(callerId: String) {
        val contentIntent = PendingIntent.getActivity(
            this,
            5,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = NotificationCompat.Builder(this, CALL_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Another encrypted call is waiting")
            .setContentText(callerId)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .build()
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(CALL_WAITING_NOTIFICATION_ID, notification)
    }

    private fun postIncomingMessageNotification(senderId: String, text: String) {
        val contentIntent = PendingIntent.getActivity(
            this, 4, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(this, MSG_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
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

    private fun postContactInvitationNotification(email: String, invitationId: String) {
        val contentIntent = PendingIntent.getActivity(
            this,
            invitationId.hashCode(),
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = NotificationCompat.Builder(this, MSG_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("New mutual contact invitation")
            .setContentText(email)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .build()
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(invitationId.hashCode(), notification)
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
