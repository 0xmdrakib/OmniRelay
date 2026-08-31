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

@Serializable
data class ContactInvitationRequest(val email: String)

@Serializable
data class ContactInvitationResult(
    val status: String,
    val invitationId: String? = null,
    val remainingToday: Int? = null
)

@Serializable
data class ContactInvitation(
    val invitationId: String,
    val direction: String,
    val counterpartAccountUid: String,
    val counterpartEmail: String,
    val createdAt: String,
    val expiresAt: String
)

@Serializable
data class ContactInvitationsResponse(val invitations: List<ContactInvitation>)

@Serializable
data class ContactInvitationResponseRequest(val action: String)

@Serializable
data class AccountContact(
    val accountUid: String,
    val email: String,
    val deviceId: String? = null,
    val publicKeyBase64: String? = null
)

@Serializable
data class AccountContactsResponse(
    val contacts: List<AccountContact>,
    val plan: String,
    val contactLimit: Int,
    val dailyInvitationLimit: Int
)
