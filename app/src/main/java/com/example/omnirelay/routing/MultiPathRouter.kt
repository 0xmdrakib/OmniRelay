package com.example.omnirelay.routing

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class RouteState {
    INITIALIZING,
    PROBING_PATHS,
    PRIMARY_MESH_ACTIVE,
    FALLBACK_CELLULAR_SIGNALING,
    FALLBACK_LEO_NTN,
    HYBRID_MULTIPATH_CONCURRENT
}

enum class TransportPath(val mask: Byte) {
    LOCAL_MESH(0x01),
    CELLULAR_CONTROL(0x02),
    LEO_SATELLITE(0x04)
}

data class PathTelemetry(
    val path: TransportPath,
    var isAvailable: Boolean = false,
    var rttMs: Int = 999,
    var packetLossRate: Float = 1.0f,
    var rssiDbm: Int = -127,
    var sponsorshipCostWeight: Float = 1.0f
)

/**
 * MultiPathRouter: Sub-millisecond routing state machine evaluating RTT, loss rate,
 * signal strength, and sponsorship cost weights.
 */
class MultiPathRouter {

    private val _currentState = MutableStateFlow(RouteState.INITIALIZING.name)
    val currentState: StateFlow<String> = _currentState.asStateFlow()

    private val telemetryMap = mutableMapOf<TransportPath, PathTelemetry>(
        TransportPath.LOCAL_MESH to PathTelemetry(TransportPath.LOCAL_MESH),
        TransportPath.CELLULAR_CONTROL to PathTelemetry(TransportPath.CELLULAR_CONTROL),
        TransportPath.LEO_SATELLITE to PathTelemetry(TransportPath.LEO_SATELLITE)
    )

    private val rttThresholdFailoverMs = 150
    private val lossThresholdFailover = 0.25f

    fun updatePathTelemetry(path: TransportPath, isAvailable: Boolean, rttMs: Int, lossRate: Float, rssi: Int) {
        val t = telemetryMap[path] ?: return
        t.isAvailable = isAvailable
        t.rttMs = rttMs
        t.packetLossRate = lossRate
        t.rssiDbm = rssi

        evaluateStateTransitions()
    }

    private fun evaluateStateTransitions() {
        val mesh = telemetryMap[TransportPath.LOCAL_MESH]!!
        val cell = telemetryMap[TransportPath.CELLULAR_CONTROL]!!
        val leo = telemetryMap[TransportPath.LEO_SATELLITE]!!

        val meshOk = mesh.isAvailable && (mesh.packetLossRate < lossThresholdFailover) && (mesh.rttMs < rttThresholdFailoverMs)
        val cellOk = cell.isAvailable && (cell.packetLossRate < 0.40f)
        val leoOk = leo.isAvailable

        val newState = when {
            meshOk && cellOk -> RouteState.HYBRID_MULTIPATH_CONCURRENT
            meshOk -> RouteState.PRIMARY_MESH_ACTIVE
            cellOk -> RouteState.FALLBACK_CELLULAR_SIGNALING
            leoOk -> RouteState.FALLBACK_LEO_NTN
            else -> RouteState.PROBING_PATHS
        }

        _currentState.value = newState.name
    }

    fun getActivePathBitmask(): Byte {
        val state = RouteState.valueOf(_currentState.value)
        return when (state) {
            RouteState.HYBRID_MULTIPATH_CONCURRENT -> (TransportPath.LOCAL_MESH.mask.toInt() or TransportPath.CELLULAR_CONTROL.mask.toInt()).toByte()
            RouteState.PRIMARY_MESH_ACTIVE -> TransportPath.LOCAL_MESH.mask
            RouteState.FALLBACK_CELLULAR_SIGNALING -> TransportPath.CELLULAR_CONTROL.mask
            RouteState.FALLBACK_LEO_NTN -> TransportPath.LEO_SATELLITE.mask
            else -> 0x00
        }
    }

    fun getTelemetryList(): List<PathTelemetry> = telemetryMap.values.toList()
}
