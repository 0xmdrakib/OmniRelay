package com.example.omnirelay.network

import kotlinx.serialization.Serializable

@Serializable
data class ChallengeRequest(val publicKeyBase64: String, val signingPublicKeyBase64: String)

@Serializable
data class ChallengeResponse(
    val challengeId: String,
    val deviceId: String,
    val nonceBase64: String,
    val serverEphemeralPublicKeyBase64: String
)

@Serializable
data class RegisterRequest(
    val challengeId: String,
    val publicKeyBase64: String,
    val signingPublicKeyBase64: String,
    val nonceBase64: String,
    val signatureBase64: String,
    val x25519ProofBase64: String,
    val fcmToken: String? = null
)

@Serializable
data class RegisterResponse(val deviceId: String, val token: String)

@Serializable
data class PushTokenRequest(val fcmToken: String?)

@Serializable
data class InboundRouteAuthorization(
    val senderDeviceId: String,
    val routeTokenHashBase64: String
)

@Serializable
data class ReplaceInboundRoutesRequest(val routes: List<InboundRouteAuthorization>)

@Serializable
data class SendEnvelopeRequest(
    val envelopeId: String,
    val recipientDeviceId: String,
    val kind: String,
    val callId: String? = null,
    val frameBase64: String,
    val routeTokenBase64: String
)

@Serializable
data class RemoteEnvelope(
    val envelopeId: String,
    val senderId: String,
    val recipientId: String,
    val kind: String,
    val callId: String? = null,
    val frameBase64: String,
    val createdAt: String
)

@Serializable
data class OutboundStatus(val envelopeId: String, val state: String)

@Serializable
data class MailboxResponse(
    val envelopes: List<RemoteEnvelope>,
    val outboundStatuses: List<OutboundStatus> = emptyList()
)

@Serializable
data class AckRequest(val state: String)

@Serializable
data class CallStateRequest(
    val state: String,
    val envelopeId: String,
    val frameBase64: String,
    val routeTokenBase64: String
)

@Serializable
data class CallTokenResponse(val url: String, val token: String)
