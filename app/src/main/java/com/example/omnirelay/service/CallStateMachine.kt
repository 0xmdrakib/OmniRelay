package com.example.omnirelay.service

/** Small, synchronized call FSM. Network/UI side effects occur only after a winning transition. */
internal class CallStateMachine {
    enum class Phase { OUTGOING_RINGING, INCOMING_RINGING, CONNECTING, ACTIVE }
    enum class RingResult { NEW, DUPLICATE, REJECTED }

    data class Session(
        val callId: String,
        val peerPublicKey: ByteArray,
        val phase: Phase
    )

    private data class State(
        val callId: String,
        val peerPublicKey: ByteArray,
        var phase: Phase
    )

    private val lock = Any()
    private var current: State? = null

    fun beginOutgoing(callId: String, peerPublicKey: ByteArray): Session? = synchronized(lock) {
        if (!valid(callId, peerPublicKey) || current != null) return@synchronized null
        current = State(callId, peerPublicKey.copyOf(), Phase.OUTGOING_RINGING)
        current!!.snapshot()
    }

    fun receiveIncomingRing(callId: String, peerPublicKey: ByteArray): RingResult = synchronized(lock) {
        if (!valid(callId, peerPublicKey)) return@synchronized RingResult.REJECTED
        val state = current
        if (state == null) {
            current = State(callId, peerPublicKey.copyOf(), Phase.INCOMING_RINGING)
            return@synchronized RingResult.NEW
        }
        if (state.callId == callId && state.peerPublicKey.contentEquals(peerPublicKey) &&
            state.phase == Phase.INCOMING_RINGING
        ) RingResult.DUPLICATE else RingResult.REJECTED
    }

    fun beginLocalAccept(): Session? = transitionCurrent(Phase.INCOMING_RINGING, Phase.CONNECTING)

    fun acceptRemote(callId: String, peerPublicKey: ByteArray): Session? = synchronized(lock) {
        val state = matchingState(callId, peerPublicKey) ?: return@synchronized null
        if (state.phase != Phase.OUTGOING_RINGING) return@synchronized null
        state.phase = Phase.CONNECTING
        state.snapshot()
    }

    fun activate(callId: String, peerPublicKey: ByteArray): Session? = synchronized(lock) {
        val state = matchingState(callId, peerPublicKey) ?: return@synchronized null
        if (state.phase != Phase.CONNECTING) return@synchronized null
        state.phase = Phase.ACTIVE
        state.snapshot()
    }

    fun terminateLocal(vararg allowed: Phase): Session? = synchronized(lock) {
        val state = current ?: return@synchronized null
        if (allowed.isNotEmpty() && state.phase !in allowed) return@synchronized null
        current = null
        state.snapshot()
    }

    fun terminateRemote(
        callId: String,
        peerPublicKey: ByteArray,
        vararg allowed: Phase
    ): Session? = synchronized(lock) {
        val state = matchingState(callId, peerPublicKey) ?: return@synchronized null
        if (allowed.isNotEmpty() && state.phase !in allowed) return@synchronized null
        current = null
        state.snapshot()
    }

    fun expire(callId: String, phase: Phase): Session? = synchronized(lock) {
        val state = current ?: return@synchronized null
        if (state.callId != callId || state.phase != phase) return@synchronized null
        current = null
        state.snapshot()
    }

    fun snapshot(): Session? = synchronized(lock) { current?.snapshot() }

    fun matches(callId: String, peerPublicKey: ByteArray, vararg phases: Phase): Boolean =
        synchronized(lock) {
            val state = matchingState(callId, peerPublicKey) ?: return@synchronized false
            phases.isEmpty() || state.phase in phases
        }

    private fun transitionCurrent(from: Phase, to: Phase): Session? = synchronized(lock) {
        val state = current ?: return@synchronized null
        if (state.phase != from) return@synchronized null
        state.phase = to
        state.snapshot()
    }

    private fun matchingState(callId: String, peerPublicKey: ByteArray): State? {
        val state = current ?: return null
        return state.takeIf {
            it.callId == callId && it.peerPublicKey.contentEquals(peerPublicKey)
        }
    }

    private fun valid(callId: String, peerPublicKey: ByteArray): Boolean =
        callId.isNotBlank() && peerPublicKey.size == 32

    private fun State.snapshot(): Session = Session(callId, peerPublicKey.copyOf(), phase)
}
