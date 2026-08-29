package com.example.omnirelay.routing

/**
 * Pure, deterministic resource policy for discovery and relay work.
 *
 * The policy deliberately defaults to the least resource-intensive tier and never permits
 * third-party relay traffic without explicit user opt-in. Callers should reevaluate whenever
 * any input changes and apply the returned limits atomically.
 */
object AdaptiveResourcePolicy {

    private const val MIB: Long = 1024L * 1024L
    private const val MAX_RELAY_BYTE_BUDGET_PER_HOUR: Long = 256L * MIB
    private const val MAX_RELAY_HOPS: Int = 3

    enum class ThermalSeverity {
        NORMAL,
        MODERATE,
        SEVERE,
        CRITICAL,
    }

    /** User-selected ceiling for resources donated to discovery and third-party relaying. */
    enum class UserResourceTier {
        /** Minimum background discovery; never carries third-party traffic. */
        MINIMAL,

        /** Small relay allowance on unmetered networks when the device has ample energy. */
        BALANCED,

        /** Larger allowance and a tightly capped metered fallback, still subject to safety gates. */
        GENEROUS,
    }

    data class Inputs(
        val isCharging: Boolean = false,
        val batteryPercent: Int = 50,
        val isPowerSaveMode: Boolean = false,
        val thermalSeverity: ThermalSeverity = ThermalSeverity.NORMAL,
        val isMeteredNetwork: Boolean = true,
        val isForeground: Boolean = false,
        val isCallActive: Boolean = false,
        val relayOptIn: Boolean = false,
        val resourceTier: UserResourceTier = UserResourceTier.MINIMAL,
    )

    /**
     * Radio duty cycle represented as an on-window inside a repeating period.
     * A zero on-window means fully disabled.
     */
    data class DutyCycle(
        val onDurationMillis: Long,
        val periodMillis: Long,
    ) {
        init {
            require(periodMillis > 0L) { "periodMillis must be positive" }
            require(onDurationMillis in 0L..periodMillis) {
                "onDurationMillis must be between zero and periodMillis"
            }
        }

        val isEnabled: Boolean
            get() = onDurationMillis > 0L

        val fraction: Double
            get() = onDurationMillis.toDouble() / periodMillis.toDouble()

        companion object {
            val DISABLED = DutyCycle(onDurationMillis = 0L, periodMillis = 60_000L)
        }
    }

    data class Decision(
        val scanDutyCycle: DutyCycle,
        val advertiseDutyCycle: DutyCycle,
        val isThirdPartyRelayAllowed: Boolean,
        val relayByteBudgetPerHour: Long,
        val maxRelayHops: Int,
        val isHighBandwidthDirectTransferAllowed: Boolean,
        val isHighBandwidthNearbyTransferAllowed: Boolean = isHighBandwidthDirectTransferAllowed,
    ) {
        init {
            require(relayByteBudgetPerHour in 0L..MAX_RELAY_BYTE_BUDGET_PER_HOUR) {
                "relay byte budget is outside the safe range"
            }
            require(maxRelayHops in 0..MAX_RELAY_HOPS) {
                "max relay hops is outside the safe range"
            }
            if (isThirdPartyRelayAllowed) {
                require(relayByteBudgetPerHour > 0L && maxRelayHops > 0) {
                    "enabled relay requires a positive byte budget and hop limit"
                }
            } else {
                require(relayByteBudgetPerHour == 0L && maxRelayHops == 0) {
                    "disabled relay must have a zero byte budget and zero hops"
                }
            }
        }
    }

    fun evaluate(inputs: Inputs = Inputs()): Decision {
        // Treat malformed telemetry conservatively instead of allowing it to relax a safety gate.
        val battery = inputs.batteryPercent.coerceIn(0, 100)

        val (scanDuty, advertiseDuty) = radioDutyCycles(inputs, battery)

        val hasRelayEnergy = battery >= 50 || (inputs.isCharging && battery >= 20)
        val relayNetworkAllowed =
            !inputs.isMeteredNetwork || inputs.resourceTier == UserResourceTier.GENEROUS
        val relayAllowed =
            inputs.relayOptIn &&
                inputs.resourceTier != UserResourceTier.MINIMAL &&
                !inputs.isPowerSaveMode &&
                inputs.thermalSeverity.isSafeForExpensiveWork() &&
                hasRelayEnergy &&
                relayNetworkAllowed &&
                !inputs.isCallActive

        val relayBudget = if (relayAllowed) relayBudget(inputs) else 0L
        val maxHops = if (relayAllowed) maxRelayHops(inputs, battery) else 0

        val ownerIsActivelyUsingTransport = inputs.isForeground || inputs.isCallActive
        val directTransferHasEnergy = inputs.isCharging || battery >= 25
        val directNetworkAllowed =
            !inputs.isMeteredNetwork ||
                (inputs.isCallActive && inputs.resourceTier == UserResourceTier.GENEROUS)
        val highBandwidthDirectAllowed =
            ownerIsActivelyUsingTransport &&
                directTransferHasEnergy &&
                !inputs.isPowerSaveMode &&
                inputs.thermalSeverity.isSafeForExpensiveWork() &&
                directNetworkAllowed
        val highBandwidthNearbyAllowed =
            ownerIsActivelyUsingTransport &&
                directTransferHasEnergy &&
                !inputs.isPowerSaveMode &&
                inputs.thermalSeverity.isSafeForExpensiveWork()

        return Decision(
            scanDutyCycle = scanDuty,
            advertiseDutyCycle = advertiseDuty,
            isThirdPartyRelayAllowed = relayAllowed,
            relayByteBudgetPerHour = relayBudget,
            maxRelayHops = maxHops,
            isHighBandwidthDirectTransferAllowed = highBandwidthDirectAllowed,
            isHighBandwidthNearbyTransferAllowed = highBandwidthNearbyAllowed,
        )
    }

    private fun radioDutyCycles(inputs: Inputs, battery: Int): Pair<DutyCycle, DutyCycle> {
        if (inputs.thermalSeverity == ThermalSeverity.CRITICAL ||
            (!inputs.isCharging && battery == 0)
        ) {
            return DutyCycle.DISABLED to DutyCycle.DISABLED
        }

        if (inputs.thermalSeverity == ThermalSeverity.SEVERE) {
            return DutyCycle(250L, 120_000L) to DutyCycle(250L, 60_000L)
        }

        if (inputs.isPowerSaveMode || (!inputs.isCharging && battery <= 15)) {
            return DutyCycle(500L, 60_000L) to DutyCycle(250L, 30_000L)
        }

        val normal = when {
            inputs.isCallActive ->
                DutyCycle(4_000L, 5_000L) to DutyCycle(1_000L, 2_000L)

            inputs.isForeground ->
                DutyCycle(2_000L, 10_000L) to DutyCycle(750L, 5_000L)

            inputs.resourceTier == UserResourceTier.GENEROUS ->
                DutyCycle(1_500L, 20_000L) to DutyCycle(750L, 10_000L)

            inputs.resourceTier == UserResourceTier.BALANCED ->
                DutyCycle(1_000L, 30_000L) to DutyCycle(500L, 15_000L)

            else ->
                DutyCycle(500L, 60_000L) to DutyCycle(250L, 30_000L)
        }

        if (inputs.thermalSeverity != ThermalSeverity.MODERATE) return normal

        return capDuty(normal.first, DutyCycle(1_000L, 10_000L)) to
            capDuty(normal.second, DutyCycle(500L, 5_000L))
    }

    private fun capDuty(candidate: DutyCycle, ceiling: DutyCycle): DutyCycle =
        if (candidate.fraction <= ceiling.fraction) candidate else ceiling

    private fun ThermalSeverity.isSafeForExpensiveWork(): Boolean =
        this == ThermalSeverity.NORMAL || this == ThermalSeverity.MODERATE

    private fun relayBudget(inputs: Inputs): Long = when (inputs.resourceTier) {
        UserResourceTier.MINIMAL -> 0L
        UserResourceTier.BALANCED -> 32L * MIB
        UserResourceTier.GENEROUS ->
            if (inputs.isMeteredNetwork) 16L * MIB else 256L * MIB
    }

    private fun maxRelayHops(inputs: Inputs, battery: Int): Int = when {
        inputs.resourceTier == UserResourceTier.BALANCED -> 1
        inputs.isCharging &&
            battery >= 80 &&
            !inputs.isMeteredNetwork &&
            inputs.thermalSeverity == ThermalSeverity.NORMAL -> 3

        else -> 2
    }
}
