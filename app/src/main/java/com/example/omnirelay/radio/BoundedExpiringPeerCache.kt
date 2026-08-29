package com.example.omnirelay.radio

/** Small synchronized LRU/TTL cache used for unauthenticated discovery hints. */
internal class BoundedExpiringPeerCache<K, V>(
    private val maxEntries: Int,
    private val ttlMillis: Long,
    private val clockMillis: () -> Long = System::currentTimeMillis
) {
    init {
        require(maxEntries > 0)
        require(ttlMillis > 0)
    }

    private data class Entry<V>(val value: V, var lastSeenMillis: Long)
    private val entries = LinkedHashMap<K, Entry<V>>(maxEntries, 0.75f, true)

    @Synchronized
    fun put(key: K, value: V) {
        val now = clockMillis()
        pruneAt(now)
        entries[key] = Entry(value, now)
        while (entries.size > maxEntries) {
            val eldest = entries.entries.firstOrNull() ?: break
            entries.remove(eldest.key)
        }
    }

    @Synchronized
    fun putIfAbsent(key: K, value: V): Boolean {
        val now = clockMillis()
        pruneAt(now)
        if (entries.containsKey(key)) return false
        entries[key] = Entry(value, now)
        while (entries.size > maxEntries) {
            val eldest = entries.entries.firstOrNull() ?: break
            entries.remove(eldest.key)
        }
        return true
    }

    @Synchronized
    fun getOrPut(key: K, defaultValue: () -> V): V {
        val now = clockMillis()
        pruneAt(now)
        entries[key]?.let {
            it.lastSeenMillis = now
            return it.value
        }
        val value = defaultValue()
        entries[key] = Entry(value, now)
        while (entries.size > maxEntries) {
            val eldest = entries.entries.firstOrNull() ?: break
            entries.remove(eldest.key)
        }
        return value
    }

    @Synchronized
    fun snapshot(): List<Pair<K, V>> {
        pruneAt(clockMillis())
        return entries.map { it.key to it.value.value }
    }

    @Synchronized
    fun remove(key: K): V? = entries.remove(key)?.value

    @Synchronized
    fun clear() = entries.clear()

    @Synchronized
    fun size(): Int {
        pruneAt(clockMillis())
        return entries.size
    }

    private fun pruneAt(now: Long) {
        entries.entries.removeIf { (_, entry) ->
            now < entry.lastSeenMillis || now - entry.lastSeenMillis >= ttlMillis
        }
    }
}

/** Atomic fixed-window permit budget so a fragmented relay is sent whole or not at all. */
internal class FixedWindowPermitBudget(
    private val maxPermits: Int,
    private val windowMillis: Long,
    private val clockMillis: () -> Long = System::currentTimeMillis
) {
    init {
        require(maxPermits > 0)
        require(windowMillis > 0)
    }

    private var windowStartedAtMillis = clockMillis()
    private var usedPermits = 0

    @Synchronized
    fun tryAcquire(permits: Int): Boolean {
        require(permits > 0)
        val now = clockMillis()
        if (now < windowStartedAtMillis || now - windowStartedAtMillis >= windowMillis) {
            windowStartedAtMillis = now
            usedPermits = 0
        }
        if (permits > maxPermits - usedPermits) return false
        usedPermits += permits
        return true
    }

    @Synchronized
    fun usedPermits(): Int = usedPermits
}

/** Deterministic exponential retry state with a hard ceiling. */
internal class BoundedRetryBackoff(
    private val initialDelayMillis: Long,
    private val maxDelayMillis: Long
) {
    init {
        require(initialDelayMillis > 0)
        require(maxDelayMillis >= initialDelayMillis)
    }

    private var attempt = 0

    @Synchronized
    fun nextDelayMillis(): Long {
        val multiplier = 1L shl attempt.coerceIn(0, 30)
        val delay = if (initialDelayMillis > maxDelayMillis / multiplier) {
            maxDelayMillis
        } else {
            (initialDelayMillis * multiplier).coerceAtMost(maxDelayMillis)
        }
        attempt = (attempt + 1).coerceAtMost(30)
        return delay
    }

    @Synchronized
    fun reset() {
        attempt = 0
    }
}
