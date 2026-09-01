package com.example.omnirelay.diagnostics

import android.content.Context
import android.util.Log
import java.security.MessageDigest

/**
 * Keeps a small, local-only fingerprint of the previous uncaught Android failure.
 *
 * Exception messages and application data are deliberately excluded. The record is useful when a
 * device is not attached to adb and is consumed once on the next launch.
 */
object CrashDiagnostics {
    private const val TAG = "OmniRelayCrash"
    private const val PREFS = "OmniRelayCrashDiagnostics"
    private const val KEY_REFERENCE = "reference"
    private const val KEY_EXCEPTION = "exception"
    private const val KEY_THREAD = "thread"
    private const val KEY_STACK = "stack"
    private const val KEY_TIMESTAMP = "timestamp"

    data class PreviousCrash(
        val reference: String,
        val exceptionType: String,
        val threadName: String,
        val stack: String,
        val timestampMs: Long
    )

    @Volatile
    private var installed = false

    fun install(context: Context) {
        if (installed) return
        synchronized(this) {
            if (installed) return
            val appContext = context.applicationContext
            val previous = Thread.getDefaultUncaughtExceptionHandler()
            Thread.setDefaultUncaughtExceptionHandler { thread, error ->
                runCatching { record(appContext, thread, error) }
                    .onFailure { Log.e(TAG, "Unable to persist crash diagnostics", it) }
                previous?.uncaughtException(thread, error)
            }
            installed = true
        }
    }

    fun consumePreviousCrash(context: Context): PreviousCrash? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val reference = prefs.getString(KEY_REFERENCE, null) ?: return null
        val crash = PreviousCrash(
            reference = reference,
            exceptionType = prefs.getString(KEY_EXCEPTION, "Unknown") ?: "Unknown",
            threadName = prefs.getString(KEY_THREAD, "unknown") ?: "unknown",
            stack = prefs.getString(KEY_STACK, "") ?: "",
            timestampMs = prefs.getLong(KEY_TIMESTAMP, 0L)
        )
        prefs.edit().clear().apply()
        return crash
    }

    private fun record(context: Context, thread: Thread, error: Throwable) {
        val frames = error.stackTrace.take(18)
        val normalizedStack = frames.joinToString("\n") { frame ->
            "${frame.className}.${frame.methodName}(${frame.fileName ?: "Unknown"}:${frame.lineNumber})"
        }
        val exceptionType = error::class.java.name
        val digestInput = "$exceptionType\n$normalizedStack".toByteArray(Charsets.UTF_8)
        val reference = MessageDigest.getInstance("SHA-256")
            .digest(digestInput)
            .take(6)
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
            .uppercase()
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_REFERENCE, reference)
            .putString(KEY_EXCEPTION, exceptionType.take(160))
            .putString(KEY_THREAD, thread.name.take(80))
            .putString(KEY_STACK, normalizedStack.take(12_000))
            .putLong(KEY_TIMESTAMP, System.currentTimeMillis())
            .commit()
    }
}
