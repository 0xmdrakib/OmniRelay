package com.example.omnirelay.media

import android.annotation.SuppressLint
import android.content.Context
import android.media.*
import android.os.Build
import android.media.audiofx.AcousticEchoCanceler
import android.media.audiofx.NoiseSuppressor
import android.util.Log
import io.livekit.android.LiveKit
import io.livekit.android.RoomOptions
import io.livekit.android.e2ee.E2EEOptions
import io.livekit.android.room.Room
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ArrayBlockingQueue

/**
 * VoiceStreamEngine: Low-bitrate 16kHz speech capture, IMA-ADPCM frame compression,
 * de-jitter buffer synchronization, hardware Echo Cancellation & Noise Suppression, and AudioTrack playback.
 */
class VoiceStreamEngine(
    private var enableEchoCancellation: Boolean = true,
    private var enableNoiseSuppression: Boolean = true
) {

    companion object {
        const val TAG = "VoiceStreamEngine"
        const val SAMPLE_RATE = 16000
        const val CHANNEL_CONFIG_IN = AudioFormat.CHANNEL_IN_MONO
        const val CHANNEL_CONFIG_OUT = AudioFormat.CHANNEL_OUT_MONO
        const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
        const val FRAME_SIZE_SAMPLES = 320 // 20ms frame at 16kHz
        const val BYTES_PER_SAMPLE = 2
        const val RAW_FRAME_BYTES = FRAME_SIZE_SAMPLES * BYTES_PER_SAMPLE // 640 bytes
        const val COMPRESSED_FRAME_BYTES = RAW_FRAME_BYTES / 4
        private const val MAX_JITTER_FRAMES = 50
    }

    private var audioRecord: AudioRecord? = null
    private var audioTrack: AudioTrack? = null
    private var echoCanceler: AcousticEchoCanceler? = null
    private var noiseSuppressor: NoiseSuppressor? = null
    private var recordingJob: Job? = null
    private var playbackJob: Job? = null
    private var timerJob: Job? = null
    private var liveKitRoom: Room? = null

    private data class IncomingVoiceFrame(val isPcm: Boolean, val bytes: ByteArray)

    private val jitterBuffer = ArrayBlockingQueue<IncomingVoiceFrame>(MAX_JITTER_FRAMES)
    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    private val _isCallActive = MutableStateFlow(false)
    val isCallActive: StateFlow<Boolean> = _isCallActive.asStateFlow()

    private val _isMuted = MutableStateFlow(false)
    val isMuted: StateFlow<Boolean> = _isMuted.asStateFlow()

    private val _isSpeakerOn = MutableStateFlow(true)
    val isSpeakerOn: StateFlow<Boolean> = _isSpeakerOn.asStateFlow()

    private val _callDurationSeconds = MutableStateFlow(0)
    val callDurationSeconds: StateFlow<Int> = _callDurationSeconds.asStateFlow()

    var onVoiceBurstGenerated: ((adpcm: ByteArray, pcm: ByteArray) -> Unit)? = null

    fun updateProcessingOptions(echoCancellation: Boolean, noiseSuppression: Boolean) {
        enableEchoCancellation = echoCancellation
        enableNoiseSuppression = noiseSuppression
    }

    fun toggleMute(): Boolean {
        _isMuted.value = !_isMuted.value
        liveKitRoom?.let { room ->
            scope.launch {
                runCatching { room.localParticipant.setMicrophoneEnabled(!_isMuted.value) }
                    .onFailure { Log.e(TAG, "Unable to update LiveKit microphone", it) }
            }
        }
        return _isMuted.value
    }

    fun toggleSpeaker(context: Context): Boolean {
        _isSpeakerOn.value = !_isSpeakerOn.value
        try {
            val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                if (_isSpeakerOn.value) {
                    audioManager.availableCommunicationDevices
                        .firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER }
                        ?.let(audioManager::setCommunicationDevice)
                } else {
                    audioManager.clearCommunicationDevice()
                }
            } else {
                @Suppress("DEPRECATION")
                audioManager.isSpeakerphoneOn = _isSpeakerOn.value
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to toggle speakerphone", e)
        }
        return _isSpeakerOn.value
    }

    @SuppressLint("MissingPermission")
    fun startCall() {
        if (_isCallActive.value) return
        _isCallActive.value = true
        _callDurationSeconds.value = 0

        initAudioRecord()
        initAudioTrack()

        // Call duration ticking job
        timerJob = scope.launch {
            while (isActive && _isCallActive.value) {
                delay(1000)
                _callDurationSeconds.value += 1
            }
        }

        // 1. Microphone Recording Loop
        recordingJob = scope.launch {
            val buffer = ByteArray(RAW_FRAME_BYTES)
            try {
                if (audioRecord?.state == AudioRecord.STATE_INITIALIZED) {
                    audioRecord?.startRecording()
                    Log.i(TAG, "AudioRecord started capture successfully.")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start microphone capture", e)
            }

            while (isActive && _isCallActive.value) {
                val readBytes = try {
                    if (audioRecord?.recordingState == AudioRecord.RECORDSTATE_RECORDING && !_isMuted.value) {
                        audioRecord?.read(buffer, 0, RAW_FRAME_BYTES) ?: -1
                    } else -1
                } catch (e: Exception) { -1 }

                if (readBytes > 0 && !_isMuted.value) {
                    if (readBytes < RAW_FRAME_BYTES) buffer.fill(0, readBytes, RAW_FRAME_BYTES)
                    val compressedBurst = AdpcmCodec.encode(buffer)
                    onVoiceBurstGenerated?.invoke(compressedBurst, buffer.copyOf())
                } else {
                    delay(20)
                }
            }
        }

        // 2. De-jitter Buffer Playback Loop
        playbackJob = scope.launch {
            try {
                if (audioTrack?.state == AudioTrack.STATE_INITIALIZED) {
                    audioTrack?.play()
                    Log.i(TAG, "AudioTrack started playback successfully.")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start AudioTrack", e)
            }

            while (isActive && _isCallActive.value) {
                val incoming = jitterBuffer.poll()
                if (incoming != null) {
                    val pcmFrame = if (incoming.isPcm) {
                        incoming.bytes
                    } else try {
                        AdpcmCodec.decode(incoming.bytes)
                    } catch (e: Exception) {
                        ByteArray(RAW_FRAME_BYTES)
                    }
                    try {
                        if (audioTrack?.playState == AudioTrack.PLAYSTATE_PLAYING) {
                            audioTrack?.write(pcmFrame, 0, pcmFrame.size)
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error writing to AudioTrack", e)
                    }
                } else {
                    delay(5)
                }
            }
        }
    }

    fun startInternetCall(
        context: Context,
        url: String,
        token: String,
        e2eeSharedKey: String,
        onConnected: () -> Unit = {},
        onFailure: (Throwable) -> Unit = {}
    ) {
        if (_isCallActive.value || liveKitRoom != null) return
        scope.launch {
            try {
                require(e2eeSharedKey.length >= 32) { "Call media E2EE key is missing" }
                val room = LiveKit.create(
                    context.applicationContext,
                    RoomOptions(
                        e2eeOptions = E2EEOptions(e2eeSharedKey)
                    )
                )
                liveKitRoom = room
                room.connect(url, token)
                room.localParticipant.setMicrophoneEnabled(true)
                _isMuted.value = false
                _isCallActive.value = true
                _callDurationSeconds.value = 0
                timerJob?.cancel()
                timerJob = scope.launch {
                    while (isActive && _isCallActive.value) {
                        delay(1000)
                        _callDurationSeconds.value += 1
                    }
                }
                onConnected()
            } catch (error: Throwable) {
                runCatching { liveKitRoom?.disconnect() }
                liveKitRoom = null
                _isCallActive.value = false
                onFailure(error)
            }
        }
    }

    fun stopCall() {
        _isCallActive.value = false
        _callDurationSeconds.value = 0
        timerJob?.cancel()
        recordingJob?.cancel()
        playbackJob?.cancel()
        val room = liveKitRoom
        liveKitRoom = null
        if (room != null) scope.launch { runCatching { room.disconnect() } }

        try {
            echoCanceler?.enabled = false
            echoCanceler?.release()
            noiseSuppressor?.enabled = false
            noiseSuppressor?.release()

            audioRecord?.stop()
            audioRecord?.release()
            audioTrack?.stop()
            audioTrack?.release()
        } catch (e: Exception) {
            Log.e(TAG, "Error releasing audio hardware components", e)
        }
        echoCanceler = null
        noiseSuppressor = null
        audioRecord = null
        audioTrack = null
        jitterBuffer.clear()
        Log.i(TAG, "Voice Call stopped.")
    }

    fun receiveIncomingVoiceBurst(burst: ByteArray, isPcm: Boolean = false) {
        val expectedBytes = if (isPcm) RAW_FRAME_BYTES else COMPRESSED_FRAME_BYTES
        if (burst.size != expectedBytes) return
        val safeFrame = IncomingVoiceFrame(isPcm, burst.copyOf())
        if (!jitterBuffer.offer(safeFrame)) {
            jitterBuffer.poll()
            jitterBuffer.offer(safeFrame)
        }
    }

    @SuppressLint("MissingPermission")
    private fun initAudioRecord() {
        try {
            val minBufferSize = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG_IN, AUDIO_FORMAT)
            val bufferSize = maxOf(minBufferSize, RAW_FRAME_BYTES * 4)
            val record = AudioRecord(
                MediaRecorder.AudioSource.MIC,
                SAMPLE_RATE,
                CHANNEL_CONFIG_IN,
                AUDIO_FORMAT,
                bufferSize
            )
            audioRecord = record

            if (enableEchoCancellation && AcousticEchoCanceler.isAvailable()) {
                echoCanceler = AcousticEchoCanceler.create(record.audioSessionId)
                echoCanceler?.enabled = true
            }
            if (enableNoiseSuppression && NoiseSuppressor.isAvailable()) {
                noiseSuppressor = NoiseSuppressor.create(record.audioSessionId)
                noiseSuppressor?.enabled = true
            }
        } catch (e: Exception) {
            Log.e(TAG, "AudioRecord init failed", e)
        }
    }

    private fun initAudioTrack() {
        try {
            val minBufferSize = AudioTrack.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG_OUT, AUDIO_FORMAT)
            val bufferSize = maxOf(minBufferSize, RAW_FRAME_BYTES * 4)
            audioTrack = AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build()
                )
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setEncoding(AUDIO_FORMAT)
                        .setSampleRate(SAMPLE_RATE)
                        .setChannelMask(CHANNEL_CONFIG_OUT)
                        .build()
                )
                .setBufferSizeInBytes(bufferSize)
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()
        } catch (e: Exception) {
            Log.e(TAG, "AudioTrack init failed", e)
        }
    }
}
