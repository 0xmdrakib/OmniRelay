package com.example.omnirelay.network

import android.content.Context
import com.example.omnirelay.BuildConfig
import com.example.omnirelay.protocol.CryptoEngine
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.ConnectionPool
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Dispatcher
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class RelayHttpException(val statusCode: Int, message: String) : IOException(message)

class InternetRelayClient(context: Context) {
    private val credentialsStore = SecureTokenStore(context.applicationContext)
    private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }
    private val mediaType = "application/json; charset=utf-8".toMediaType()
    private val dispatcher = Dispatcher().apply {
        maxRequests = 8
        maxRequestsPerHost = 4
    }
    private val client = OkHttpClient.Builder()
        .dispatcher(dispatcher)
        .connectionPool(ConnectionPool(2, 5, TimeUnit.MINUTES))
        .connectTimeout(10, TimeUnit.SECONDS)
        .callTimeout(30, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .pingInterval(25, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()
    private val baseUrl = BuildConfig.BACKEND_BASE_URL.trimEnd('/')
    private val registrationMutex = Mutex()
    @Volatile private var syncedRouteFingerprint: String? = null
    @Volatile private var lastRouteSyncAtMillis: Long = 0L
    @Volatile private var socket: WebSocket? = null
    @Volatile private var closingSocket = false

    val isConfigured: Boolean get() = !baseUrl.endsWith(".invalid")

    fun credentials(): RelayCredentials? = credentialsStore.load()

    suspend fun ensureRegistered(
        identity: CryptoEngine.KeyPairData,
        signingIdentity: CryptoEngine.SigningKeyPairData,
        fcmToken: String?,
        authorizedPeers: List<ByteArray>
    ): RelayCredentials = registrationMutex.withLock {
        var credentials = credentialsStore.load()
        if (credentials == null) {
            credentials = register(identity, signingIdentity, fcmToken)
        } else if (fcmToken != null) {
            runCatching { updatePushToken(fcmToken) }
        }
        syncInboundRoutes(identity, authorizedPeers, credentials.deviceId)
        credentials
    }

    private suspend fun register(
        identity: CryptoEngine.KeyPairData,
        signingIdentity: CryptoEngine.SigningKeyPairData,
        fcmToken: String?
    ): RelayCredentials {
        val signingPublicKeyBase64 = android.util.Base64.encodeToString(
            signingIdentity.publicKeyDer,
            android.util.Base64.NO_WRAP
        )
        val publicKeyBase64 = android.util.Base64.encodeToString(
            identity.publicKey,
            android.util.Base64.NO_WRAP
        )
        val challengeBody = json.encodeToString(ChallengeRequest(publicKeyBase64, signingPublicKeyBase64))
        val challengeRequest = Request.Builder()
            .url("$baseUrl/v1/devices/challenge")
            .post(challengeBody.toRequestBody(mediaType))
            .build()
        val challenge = execute(challengeRequest).use { response ->
            if (!response.isSuccessful) throw RelayHttpException(response.code, response.body.string())
            json.decodeFromString<ChallengeResponse>(response.body.string())
        }
        val proof = "OmniRelay/Register/v2\n${challenge.deviceId}\n${challenge.nonceBase64}"
            .toByteArray(Charsets.UTF_8)
        val signature = CryptoEngine.signEd25519(signingIdentity.privateKeyDer, proof)
        val serverEphemeralPublicKey = android.util.Base64.decode(
            challenge.serverEphemeralPublicKeyBase64,
            android.util.Base64.NO_WRAP
        )
        val x25519Proof = CryptoEngine.registrationX25519Proof(
            identity.privateKey,
            serverEphemeralPublicKey,
            challenge.deviceId,
            challenge.nonceBase64,
            signingPublicKeyBase64
        )
        val body = json.encodeToString(RegisterRequest(
            challengeId = challenge.challengeId,
            publicKeyBase64 = publicKeyBase64,
            signingPublicKeyBase64 = signingPublicKeyBase64,
            nonceBase64 = challenge.nonceBase64,
            signatureBase64 = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP),
            x25519ProofBase64 = android.util.Base64.encodeToString(
                x25519Proof,
                android.util.Base64.NO_WRAP
            ),
            fcmToken = fcmToken
        ))
        val request = Request.Builder()
            .url("$baseUrl/v1/devices/register")
            .post(body.toRequestBody(mediaType))
            .build()
        val responseText = execute(request).use { response ->
            if (!response.isSuccessful) throw RelayHttpException(response.code, response.body.string())
            response.body.string()
        }
        return json.decodeFromString<RegisterResponse>(responseText).let {
            RelayCredentials(it.deviceId, it.token).also(credentialsStore::save)
        }
    }

    private suspend fun syncInboundRoutes(
        identity: CryptoEngine.KeyPairData,
        authorizedPeers: List<ByteArray>,
        deviceId: String
    ) {
        require(authorizedPeers.size <= 512) { "Too many inbound routes" }
        val normalizedPeers = authorizedPeers
            .map(CryptoEngine::normalizePublicKey)
            .filterNot { MessageDigest.isEqual(it, identity.publicKey) }
            .distinctBy(CryptoEngine::deviceIdForPublicKey)
            .sortedBy(CryptoEngine::deviceIdForPublicKey)
        val routeDigest = MessageDigest.getInstance("SHA-256").apply {
            update(deviceId.toByteArray(Charsets.UTF_8))
            normalizedPeers.forEach { update(it) }
        }
        val fingerprint = routeDigest.digest().joinToString("") { "%02x".format(it) }
        val now = System.currentTimeMillis()
        if (fingerprint == syncedRouteFingerprint && now >= lastRouteSyncAtMillis &&
            now - lastRouteSyncAtMillis < TimeUnit.HOURS.toMillis(1)
        ) return

        val routes = normalizedPeers.map { peerPublicKey ->
            val pairSecret = CryptoEngine.deriveSharedSecret(identity.privateKey, peerPublicKey)
            val routeToken = try {
                CryptoEngine.deriveBackendRouteToken(pairSecret, peerPublicKey, identity.publicKey)
            } finally {
                pairSecret.fill(0)
            }
            val routeTokenHash = MessageDigest.getInstance("SHA-256").digest(routeToken)
            try {
                InboundRouteAuthorization(
                    senderDeviceId = CryptoEngine.deviceIdForPublicKey(peerPublicKey),
                    routeTokenHashBase64 = android.util.Base64.encodeToString(
                        routeTokenHash,
                        android.util.Base64.NO_WRAP
                    )
                )
            } finally {
                routeToken.fill(0)
                routeTokenHash.fill(0)
            }
        }
        val body = json.encodeToString(ReplaceInboundRoutesRequest(routes))
        execute(
            authenticatedRequest("$baseUrl/v1/routes/inbound")
                .put(body.toRequestBody(mediaType))
                .build()
        ).use { requireSuccess(it) }
        syncedRouteFingerprint = fingerprint
        lastRouteSyncAtMillis = now
    }

    suspend fun updatePushToken(fcmToken: String?) {
        val body = json.encodeToString(PushTokenRequest(fcmToken))
        execute(authenticatedRequest("$baseUrl/v1/devices/push-token")
            .put(body.toRequestBody(mediaType)).build()).use { requireSuccess(it) }
    }

    suspend fun sendEnvelope(envelope: SendEnvelopeRequest) {
        val body = json.encodeToString(envelope)
        execute(authenticatedRequest("$baseUrl/v1/envelopes")
            .post(body.toRequestBody(mediaType)).build()).use { requireSuccess(it) }
    }

    suspend fun fetchMailbox(): MailboxResponse {
        return execute(authenticatedRequest("$baseUrl/v1/mailbox?limit=100").get().build()).use { response ->
            requireSuccess(response)
            json.decodeFromString(response.body.string())
        }
    }

    suspend fun acknowledge(envelopeId: String, state: String = "delivered") {
        val body = json.encodeToString(AckRequest(state))
        execute(authenticatedRequest("$baseUrl/v1/envelopes/$envelopeId/ack")
            .post(body.toRequestBody(mediaType)).build()).use { requireSuccess(it) }
    }

    suspend fun transitionCall(callId: String, requestBody: CallStateRequest) {
        val body = json.encodeToString(requestBody)
        execute(authenticatedRequest("$baseUrl/v1/calls/$callId/state")
            .post(body.toRequestBody(mediaType)).build()).use { requireSuccess(it) }
    }

    suspend fun callToken(callId: String): CallTokenResponse {
        return execute(authenticatedRequest("$baseUrl/v1/calls/$callId/token")
            .post(ByteArray(0).toRequestBody(null)).build()).use { response ->
            requireSuccess(response)
            json.decodeFromString(response.body.string())
        }
    }

    suspend fun renewCallLease(callId: String) {
        execute(
            authenticatedRequest("$baseUrl/v1/calls/$callId/lease")
                .post(ByteArray(0).toRequestBody(null))
                .build()
        ).use { requireSuccess(it) }
    }

    fun connectRealtime(onMailboxChanged: () -> Unit, onFailure: (Throwable) -> Unit = {}) {
        val request = runCatching {
            authenticatedRequest(
                baseUrl.replaceFirst("https://", "wss://").replaceFirst("http://", "ws://") + "/v1/stream"
            ).build()
        }.getOrElse { onFailure(it); return }
        closingSocket = false
        socket?.cancel()
        socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                if (text.contains("mailbox.changed") || text.contains("envelope.status")) onMailboxChanged()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (!closingSocket && socket === webSocket) onFailure(t)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (!closingSocket && socket === webSocket) {
                    onFailure(IOException("Relay stream closed: $code $reason"))
                }
            }
        })
    }

    fun closeRealtime() {
        closingSocket = true
        socket?.close(1000, "service stopped")
        socket = null
    }

    private fun authenticatedRequest(url: String): Request.Builder {
        val credentials = credentialsStore.load() ?: error("Relay device is not registered")
        return Request.Builder().url(url)
            .header("Authorization", "Bearer ${credentials.token}")
            .header("X-Device-Id", credentials.deviceId)
    }

    private suspend fun execute(request: Request): Response = suspendCancellableCoroutine { continuation ->
        val call = client.newCall(request)
        continuation.invokeOnCancellation { call.cancel() }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (continuation.isActive) continuation.resumeWithException(e)
            }

            override fun onResponse(call: Call, response: Response) {
                if (continuation.isActive) {
                    continuation.resume(response) { _, pendingResponse, _ -> pendingResponse.close() }
                } else {
                    response.close()
                }
            }
        })
    }

    private fun requireSuccess(response: Response) {
        if (response.code == 401) {
            credentialsStore.clear()
            syncedRouteFingerprint = null
            lastRouteSyncAtMillis = 0L
        }
        if (!response.isSuccessful) throw RelayHttpException(response.code, response.body.string())
    }
}
