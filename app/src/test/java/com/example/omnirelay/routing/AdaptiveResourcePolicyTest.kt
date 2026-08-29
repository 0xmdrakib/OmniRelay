package com.example.omnirelay.routing

import com.example.omnirelay.routing.AdaptiveResourcePolicy.DutyCycle
import com.example.omnirelay.routing.AdaptiveResourcePolicy.Inputs
import com.example.omnirelay.routing.AdaptiveResourcePolicy.ThermalSeverity
import com.example.omnirelay.routing.AdaptiveResourcePolicy.UserResourceTier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdaptiveResourcePolicyTest {

    @Test
    fun defaultsAreConservativeAndUserControlled() {
        val decision = AdaptiveResourcePolicy.evaluate()

        assertEquals(DutyCycle(500L, 60_000L), decision.scanDutyCycle)
        assertEquals(DutyCycle(250L, 30_000L), decision.advertiseDutyCycle)
        assertFalse(decision.isThirdPartyRelayAllowed)
        assertEquals(0L, decision.relayByteBudgetPerHour)
        assertEquals(0, decision.maxRelayHops)
        assertFalse(decision.isHighBandwidthDirectTransferAllowed)
    }

    @Test
    fun relayOptInAloneCannotOverrideMinimalTier() {
        val decision = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                relayOptIn = true,
                resourceTier = UserResourceTier.MINIMAL,
            ),
        )

        assertRelayDisabled(decision)
    }

    @Test
    fun balancedTierAllowsSmallUnmeteredRelayBudgetAtBatteryBoundary() {
        val belowBoundary = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                batteryPercent = 49,
                relayOptIn = true,
                resourceTier = UserResourceTier.BALANCED,
            ),
        )
        val atBoundary = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                batteryPercent = 50,
                relayOptIn = true,
                resourceTier = UserResourceTier.BALANCED,
            ),
        )

        assertRelayDisabled(belowBoundary)
        assertTrue(atBoundary.isThirdPartyRelayAllowed)
        assertEquals(32L * MIB, atBoundary.relayByteBudgetPerHour)
        assertEquals(1, atBoundary.maxRelayHops)
    }

    @Test
    fun chargingRequiresMinimumBatteryAndCannotReplaceExplicitOptIn() {
        val tooLow = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isCharging = true,
                batteryPercent = 19,
                relayOptIn = true,
                resourceTier = UserResourceTier.BALANCED,
            ),
        )
        val optedIn = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isCharging = true,
                batteryPercent = 20,
                relayOptIn = true,
                resourceTier = UserResourceTier.BALANCED,
            ),
        )
        val notOptedIn = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isCharging = true,
                batteryPercent = 100,
                relayOptIn = false,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )

        assertRelayDisabled(tooLow)
        assertTrue(optedIn.isThirdPartyRelayAllowed)
        assertRelayDisabled(notOptedIn)
    }

    @Test
    fun onlyGenerousTierMayRelayOnMeteredNetworkAndBudgetIsCapped() {
        val balanced = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isMeteredNetwork = true,
                relayOptIn = true,
                resourceTier = UserResourceTier.BALANCED,
            ),
        )
        val generous = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isMeteredNetwork = true,
                relayOptIn = true,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )

        assertRelayDisabled(balanced)
        assertTrue(generous.isThirdPartyRelayAllowed)
        assertEquals(16L * MIB, generous.relayByteBudgetPerHour)
        assertEquals(2, generous.maxRelayHops)
    }

    @Test
    fun generousUnmeteredRelayHasBoundedBudgetAndHopCount() {
        val ordinary = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                relayOptIn = true,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )
        val bestCase = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isCharging = true,
                batteryPercent = 80,
                relayOptIn = true,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )

        assertEquals(256L * MIB, ordinary.relayByteBudgetPerHour)
        assertEquals(2, ordinary.maxRelayHops)
        assertEquals(3, bestCase.maxRelayHops)
    }

    @Test
    fun activeCallPreemptsThirdPartyRelayAndRaisesRadioDuty() {
        val decision = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isCallActive = true,
                relayOptIn = true,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )

        assertRelayDisabled(decision)
        assertEquals(DutyCycle(4_000L, 5_000L), decision.scanDutyCycle)
        assertEquals(DutyCycle(1_000L, 2_000L), decision.advertiseDutyCycle)
        assertTrue(decision.isHighBandwidthDirectTransferAllowed)
    }

    @Test
    fun meteredHighBandwidthDirectUseRequiresActiveCallAndGenerousTier() {
        val foregroundOnly = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isMeteredNetwork = true,
                isForeground = true,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )
        val balancedCall = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isMeteredNetwork = true,
                isCallActive = true,
                resourceTier = UserResourceTier.BALANCED,
            ),
        )
        val generousCall = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isMeteredNetwork = true,
                isCallActive = true,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )

        assertFalse(foregroundOnly.isHighBandwidthDirectTransferAllowed)
        assertFalse(balancedCall.isHighBandwidthDirectTransferAllowed)
        assertTrue(generousCall.isHighBandwidthDirectTransferAllowed)
        assertTrue(foregroundOnly.isHighBandwidthNearbyTransferAllowed)
        assertTrue(balancedCall.isHighBandwidthNearbyTransferAllowed)
    }

    @Test
    fun directTransferBatteryBoundaryIsConservative() {
        val belowBoundary = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(batteryPercent = 24),
        )
        val atBoundary = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(batteryPercent = 25),
        )

        assertFalse(belowBoundary.isHighBandwidthDirectTransferAllowed)
        assertTrue(atBoundary.isHighBandwidthDirectTransferAllowed)
    }

    @Test
    fun powerSaveDisablesExpensiveWorkAndUsesLowDuty() {
        val decision = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                isPowerSaveMode = true,
                isCallActive = true,
                relayOptIn = true,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )

        assertRelayDisabled(decision)
        assertFalse(decision.isHighBandwidthDirectTransferAllowed)
        assertEquals(DutyCycle(500L, 60_000L), decision.scanDutyCycle)
        assertEquals(DutyCycle(250L, 30_000L), decision.advertiseDutyCycle)
    }

    @Test
    fun lowBatteryBoundaryUsesReducedDutyUnlessCharging() {
        val low = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(batteryPercent = 15),
        )
        val recovered = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(batteryPercent = 16),
        )
        val charging = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(isCharging = true, batteryPercent = 15),
        )

        assertEquals(DutyCycle(500L, 60_000L), low.scanDutyCycle)
        assertEquals(DutyCycle(2_000L, 10_000L), recovered.scanDutyCycle)
        assertEquals(DutyCycle(2_000L, 10_000L), charging.scanDutyCycle)
    }

    @Test
    fun severeThermalStateKeepsOnlyMinimalReachability() {
        val decision = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                thermalSeverity = ThermalSeverity.SEVERE,
                isCharging = true,
                isCallActive = true,
                relayOptIn = true,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )

        assertEquals(DutyCycle(250L, 120_000L), decision.scanDutyCycle)
        assertEquals(DutyCycle(250L, 60_000L), decision.advertiseDutyCycle)
        assertRelayDisabled(decision)
        assertFalse(decision.isHighBandwidthDirectTransferAllowed)
    }

    @Test
    fun criticalThermalStateDisablesRadiosEvenWhileCharging() {
        val decision = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                thermalSeverity = ThermalSeverity.CRITICAL,
                isCharging = true,
                relayOptIn = true,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )

        assertEquals(DutyCycle.DISABLED, decision.scanDutyCycle)
        assertEquals(DutyCycle.DISABLED, decision.advertiseDutyCycle)
        assertRelayDisabled(decision)
        assertFalse(decision.isHighBandwidthDirectTransferAllowed)
    }

    @Test
    fun moderateThermalStateCapsCallDutyWhileKeepingOwnerTransferAvailable() {
        val decision = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                thermalSeverity = ThermalSeverity.MODERATE,
                isCharging = true,
                batteryPercent = 100,
                isCallActive = true,
                resourceTier = UserResourceTier.GENEROUS,
            ),
        )

        assertEquals(DutyCycle(1_000L, 10_000L), decision.scanDutyCycle)
        assertEquals(DutyCycle(500L, 5_000L), decision.advertiseDutyCycle)
        assertTrue(decision.isHighBandwidthDirectTransferAllowed)
    }

    @Test
    fun zeroBatteryDisablesRadiosButChargingPreventsFalseShutdown() {
        val empty = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(batteryPercent = 0),
        )
        val charging = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(isCharging = true, batteryPercent = 0),
        )

        assertEquals(DutyCycle.DISABLED, empty.scanDutyCycle)
        assertEquals(DutyCycle.DISABLED, empty.advertiseDutyCycle)
        assertTrue(charging.scanDutyCycle.isEnabled)
        assertTrue(charging.advertiseDutyCycle.isEnabled)
    }

    @Test
    fun malformedBatteryTelemetryIsClampedTowardSafeBoundaries() {
        val negative = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(batteryPercent = -500),
        )
        val zero = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(batteryPercent = 0),
        )
        val excessive = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                batteryPercent = 500,
                relayOptIn = true,
                resourceTier = UserResourceTier.BALANCED,
            ),
        )
        val full = AdaptiveResourcePolicy.evaluate(
            favorableInputs().copy(
                batteryPercent = 100,
                relayOptIn = true,
                resourceTier = UserResourceTier.BALANCED,
            ),
        )

        assertEquals(zero, negative)
        assertEquals(full, excessive)
    }

    @Test
    fun dutyCycleRejectsInvalidWindows() {
        assertFailsWithIllegalArgument { DutyCycle(-1L, 1_000L) }
        assertFailsWithIllegalArgument { DutyCycle(1_001L, 1_000L) }
        assertFailsWithIllegalArgument { DutyCycle(0L, 0L) }
    }

    @Test
    fun decisionRejectsUnsafeOrInternallyInconsistentRelayLimits() {
        val disabled = DutyCycle.DISABLED

        assertFailsWithIllegalArgument {
            AdaptiveResourcePolicy.Decision(disabled, disabled, false, MIB, 1, false)
        }
        assertFailsWithIllegalArgument {
            AdaptiveResourcePolicy.Decision(disabled, disabled, true, 0L, 0, false)
        }
        assertFailsWithIllegalArgument {
            AdaptiveResourcePolicy.Decision(disabled, disabled, true, 257L * MIB, 1, false)
        }
        assertFailsWithIllegalArgument {
            AdaptiveResourcePolicy.Decision(disabled, disabled, true, MIB, 4, false)
        }
    }

    private fun favorableInputs() = Inputs(
        batteryPercent = 75,
        isMeteredNetwork = false,
        isForeground = true,
    )

    private fun assertRelayDisabled(decision: AdaptiveResourcePolicy.Decision) {
        assertFalse(decision.isThirdPartyRelayAllowed)
        assertEquals(0L, decision.relayByteBudgetPerHour)
        assertEquals(0, decision.maxRelayHops)
    }

    private fun assertFailsWithIllegalArgument(block: () -> Unit) {
        try {
            block()
            throw AssertionError("Expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // Expected.
        }
    }

    private companion object {
        const val MIB: Long = 1024L * 1024L
    }
}
