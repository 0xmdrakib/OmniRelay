package com.example.omnirelay.routing

/** Thread-safe rolling budget that prevents a relay volunteer from exceeding their policy cap. */
class HourlyByteBudget(
    private val clockMillis: () -> Long = System::currentTimeMillis
) {
    private var windowStartedAtMs = clockMillis()
    private var usedBytes = 0L

    @Synchronized
    fun tryConsume(byteCount: Long, limitBytes: Long): Boolean {
        require(byteCount >= 0) { "byteCount must not be negative" }
        val now = clockMillis()
        if (now < windowStartedAtMs || now - windowStartedAtMs >= WINDOW_MILLIS) {
            windowStartedAtMs = now
            usedBytes = 0L
        }
        if (limitBytes <= 0L || byteCount > limitBytes - usedBytes) return false
        usedBytes += byteCount
        return true
    }

    @Synchronized
    fun usedBytes(): Long = usedBytes

    companion object {
        private const val WINDOW_MILLIS = 60 * 60 * 1_000L
    }
}

class FixedWindowRateLimit(
    private val windowMillis: Long,
    private val clockMillis: () -> Long = System::currentTimeMillis
) {
    init { require(windowMillis > 0) }
    private var windowStartedAtMs = clockMillis()
    private var used = 0

    @Synchronized
    fun tryAcquire(limit: Int): Boolean {
        require(limit > 0)
        val now = clockMillis()
        if (now < windowStartedAtMs || now - windowStartedAtMs >= windowMillis) {
            windowStartedAtMs = now
            used = 0
        }
        if (used >= limit) return false
        used++
        return true
    }
}
