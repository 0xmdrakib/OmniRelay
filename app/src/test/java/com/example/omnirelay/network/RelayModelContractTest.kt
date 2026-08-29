package com.example.omnirelay.network

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayModelContractTest {
    private val json = Json { explicitNulls = false }

    @Test
    fun routeAuthorizationUsesHashInboundAndRawCapabilityOutbound() {
        val inbound = json.encodeToString(
            ReplaceInboundRoutesRequest(
                listOf(InboundRouteAuthorization("a".repeat(64), "hash-base64"))
            )
        )
        val outbound = json.encodeToString(
            SendEnvelopeRequest(
                envelopeId = "00000000-0000-0000-0000-000000000001",
                recipientDeviceId = "b".repeat(64),
                kind = "message",
                frameBase64 = "frame",
                routeTokenBase64 = "raw-base64"
            )
        )

        assertTrue(inbound.contains("\"routeTokenHashBase64\":\"hash-base64\""))
        assertFalse(inbound.contains("\"routeTokenBase64\""))
        assertTrue(outbound.contains("\"routeTokenBase64\":\"raw-base64\""))
    }

    @Test
    fun registrationCarriesTheExactChallengeId() {
        val encoded = json.encodeToString(
            RegisterRequest(
                challengeId = "00000000-0000-0000-0000-000000000002",
                publicKeyBase64 = "public",
                signingPublicKeyBase64 = "signing",
                nonceBase64 = "nonce",
                signatureBase64 = "signature",
                x25519ProofBase64 = "proof"
            )
        )
        assertTrue(encoded.contains("\"challengeId\":\"00000000-0000-0000-0000-000000000002\""))
    }
}
