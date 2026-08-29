package com.example.omnirelay.radio

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.util.Log
import com.example.omnirelay.protocol.OmniFrame
import com.example.omnirelay.protocol.RelayCapsule
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * BLE discovery and reliable GATT frame transport.
 *
 * Advertisements contain presence metadata only. Full encrypted frames are
 * written to the paired peer's GATT characteristic after discovery.
 */
class BleMeshManager(private val context: Context) {

    companion object {
        const val TAG = "BleMeshManager"
        const val MANUFACTURER_ID = 0x0A11
        private const val DESIRED_MTU = 517
        private const val DEFAULT_ATT_PAYLOAD = 20
        private const val MAX_GATT_FRAME_BYTES = 20 * 1024
        private const val MAX_PENDING_FRAMES = 32
        private const val MAX_PENDING_BYTES = 256 * 1024
        private const val MAX_DISCOVERED_PEERS = 64
        private const val MAX_CLIENT_SESSIONS = 8
        private const val MAX_BROADCAST_NEIGHBORS = 8
        private const val PEER_EXPIRY_MS = 2 * 60_000L
        private const val MAX_INGRESS_PACKETS_PER_SECOND = 2_048
        private const val MAX_INGRESS_BYTES_PER_SECOND = 256 * 1024
        private const val MAX_PEER_INGRESS_PACKETS_PER_SECOND = 128
        private const val MAX_PEER_INGRESS_BYTES_PER_SECOND = 32 * 1024
        val OMNI_SERVICE_UUID: UUID = UUID.fromString("9E10A001-4B52-4F1E-8B31-0192A0F81234")
        val OMNI_CHAR_UUID: UUID = UUID.fromString("9E10A002-4B52-4F1E-8B31-0192A0F81234")
    }

    private data class PeerEndpoint(
        val device: BluetoothDevice,
        val keyPrefix: ByteArray,
        val lastSeenMs: Long
    )

    private class ClientSession(
        val gatt: BluetoothGatt,
        val pendingFrames: ArrayDeque<ByteArray> = ArrayDeque(),
        val activeFragments: ArrayDeque<ByteArray> = ArrayDeque(),
        var pendingBytes: Int = 0,
        var ready: Boolean = false,
        var writeInFlight: Boolean = false,
        var mtuPayloadBytes: Int = DEFAULT_ATT_PAYLOAD
    )

    private class PeerIngressBudget {
        val packets = FixedWindowPermitBudget(MAX_PEER_INGRESS_PACKETS_PER_SECOND, 1_000L)
        val bytes = FixedWindowPermitBudget(MAX_PEER_INGRESS_BYTES_PER_SECOND, 1_000L)
    }

    private val bluetoothManager =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val bluetoothAdapter = bluetoothManager?.adapter
    private var bleAdvertiser: BluetoothLeAdvertiser? = bluetoothAdapter?.bluetoothLeAdvertiser
    private var bleScanner: BluetoothLeScanner? = bluetoothAdapter?.bluetoothLeScanner

    private var gattServer: BluetoothGattServer? = null
    private val discoveredPeers = ConcurrentHashMap<String, PeerEndpoint>()
    private val clientSessions = ConcurrentHashMap<String, ClientSession>()
    private val fragmentAssembler = NearbyFrameFragmentCodec.Assembler()
    private val ingressPacketBudget = FixedWindowPermitBudget(
        MAX_INGRESS_PACKETS_PER_SECOND,
        1_000L
    )
    private val ingressByteBudget = FixedWindowPermitBudget(
        MAX_INGRESS_BYTES_PER_SECOND,
        1_000L
    )
    private val peerIngressBudgets = BoundedExpiringPeerCache<String, PeerIngressBudget>(
        MAX_DISCOVERED_PEERS,
        PEER_EXPIRY_MS
    )
    private var isAdvertising = false
    private var isScanning = false
    private var activeScanMode: Int? = null
    private var activeAdvertiseMode: Int? = null
    private var activeTxPower: Int? = null
    private var advertisedPresence: ByteArray? = null

    var onFrameReceivedListener: ((ByteArray, Int) -> Unit)? = null
    var onPeerDiscoveredListener: ((ByteArray, Int) -> Unit)? = null
    var onDeliveryResultListener: ((Boolean, String) -> Unit)? = null

    init {
        setupGattServer()
    }

    @SuppressLint("MissingPermission")
    private fun setupGattServer() {
        val manager = bluetoothManager ?: return
        runCatching {
            gattServer = manager.openGattServer(context, gattServerCallback)
            val service = BluetoothGattService(OMNI_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            val characteristic = BluetoothGattCharacteristic(
                OMNI_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ or
                    BluetoothGattCharacteristic.PROPERTY_WRITE or
                    BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
            )
            service.addCharacteristic(characteristic)
            check(gattServer?.addService(service) == true) { "Unable to add OmniRelay GATT service" }
            Log.i(TAG, "BLE GATT server initialized")
        }.onFailure { Log.e(TAG, "GATT server initialization failed", it) }
    }

    @SuppressLint("MissingPermission")
    fun startAdvertising(
        compactPresenceFrame: ByteArray,
        advertiseMode: Int = AdvertiseSettings.ADVERTISE_MODE_LOW_POWER,
        txPowerLevel: Int = AdvertiseSettings.ADVERTISE_TX_POWER_LOW
    ) {
        require(compactPresenceFrame.size == OmniFrame.COMPACT_FRAME_SIZE) {
            "BLE advertisements must contain a ${OmniFrame.COMPACT_FRAME_SIZE}-byte presence frame"
        }
        if (bleAdvertiser == null) bleAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser
        val advertiser = bleAdvertiser ?: return
        if (gattServer == null) setupGattServer()
        if (isAdvertising && activeAdvertiseMode == advertiseMode && activeTxPower == txPowerLevel &&
            advertisedPresence?.contentEquals(compactPresenceFrame) == true
        ) return

        if (isAdvertising) runCatching { advertiser.stopAdvertising(advertiseCallback) }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(advertiseMode)
            .setTxPowerLevel(txPowerLevel)
            .setConnectable(true)
            .build()
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addManufacturerData(MANUFACTURER_ID, compactPresenceFrame)
            .build()

        runCatching {
            advertiser.startAdvertising(settings, data, advertiseCallback)
            isAdvertising = true
            activeAdvertiseMode = advertiseMode
            activeTxPower = txPowerLevel
            advertisedPresence = compactPresenceFrame.copyOf()
        }.onFailure {
            isAdvertising = false
            Log.e(TAG, "BLE advertising failed", it)
        }
    }

    /** Queues a full OmniFrame for a discovered paired peer. */
    @SuppressLint("MissingPermission")
    fun sendFrame(targetPublicKey: ByteArray, packedFrame: ByteArray): Boolean {
        if (targetPublicKey.size < OmniFrame.COMPACT_KEY_PREFIX_SIZE ||
            packedFrame.isEmpty() || packedFrame.size > MAX_GATT_FRAME_BYTES
        ) return false
        pruneDiscoveredPeers()
        val targetPrefix = targetPublicKey.copyOfRange(0, OmniFrame.COMPACT_KEY_PREFIX_SIZE)
        val endpoint = discoveredPeers[targetPrefix.toHex()] ?: return false
        val address = endpoint.device.address

        synchronized(clientSessions) {
            val existing = clientSessions[address]
            if (existing != null) {
                if (!enqueue(existing, packedFrame)) return false
                drainWrites(existing)
                return true
            }
            if (clientSessions.size >= MAX_CLIENT_SESSIONS) return false

            val gatt = endpoint.device.connectGatt(
                context,
                false,
                gattClientCallback,
                BluetoothDevice.TRANSPORT_LE
            ) ?: return false
            val session = ClientSession(gatt)
            if (!enqueue(session, packedFrame)) {
                runCatching { gatt.close() }
                return false
            }
            clientSessions[address] = session
        }
        return true
    }

    /** Sends an opaque relay capsule to every currently discovered neighbor. */
    fun broadcastPacket(packedPacket: ByteArray): Int {
        if (!RelayCapsule.isCapsule(packedPacket) || packedPacket.size > MAX_GATT_FRAME_BYTES) return 0
        pruneDiscoveredPeers()
        return discoveredPeers.values
            .sortedByDescending(PeerEndpoint::lastSeenMs)
            .distinctBy { it.device.address }
            .take(MAX_BROADCAST_NEIGHBORS)
            .count { endpoint -> sendFrame(endpoint.keyPrefix, packedPacket) }
    }

    private fun enqueue(session: ClientSession, frame: ByteArray): Boolean =
        synchronized(session) {
            if (session.pendingFrames.size >= MAX_PENDING_FRAMES ||
                session.pendingBytes + frame.size > MAX_PENDING_BYTES
            ) return@synchronized false
            session.pendingFrames.addLast(frame.copyOf())
            session.pendingBytes += frame.size
            true
        }

    @SuppressLint("MissingPermission")
    private fun drainWrites(session: ClientSession) {
        val packet = synchronized(session) {
            if (!session.ready || session.writeInFlight) return
            if (session.activeFragments.isEmpty()) {
                if (session.pendingFrames.isEmpty()) return
                val frame = session.pendingFrames.removeFirst()
                session.pendingBytes -= frame.size
                session.activeFragments.addAll(
                    NearbyFrameFragmentCodec.fragment(frame, session.mtuPayloadBytes)
                )
            }
            session.activeFragments.removeFirst().also { session.writeInFlight = true }
        }

        val characteristic = session.gatt.getService(OMNI_SERVICE_UUID)?.getCharacteristic(OMNI_CHAR_UUID)
        if (characteristic == null) {
            synchronized(session) { session.writeInFlight = false }
            failAndClose(session.gatt, "OmniRelay GATT characteristic unavailable")
            return
        }

        val started = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            session.gatt.writeCharacteristic(
                characteristic,
                packet,
                BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            ) == BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            characteristic.value = packet
            characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            @Suppress("DEPRECATION")
            session.gatt.writeCharacteristic(characteristic)
        }
        if (!started) {
            synchronized(session) { session.writeInFlight = false }
            failAndClose(session.gatt, "Unable to start BLE GATT write")
        }
    }

    @SuppressLint("MissingPermission")
    fun startActiveScanning(scanMode: Int = ScanSettings.SCAN_MODE_LOW_POWER) {
        if (bleScanner == null) bleScanner = bluetoothAdapter?.bluetoothLeScanner
        val scanner = bleScanner ?: return
        if (isScanning && activeScanMode == scanMode) return
        if (isScanning) runCatching { scanner.stopScan(scanCallback) }
        isScanning = false
        activeScanMode = null

        val filter = ScanFilter.Builder()
            .setManufacturerData(MANUFACTURER_ID, byteArrayOf(0x20), byteArrayOf(0xF0.toByte()))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(scanMode)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .build()
        runCatching {
            scanner.startScan(listOf(filter), settings, scanCallback)
            isScanning = true
            activeScanMode = scanMode
        }.onFailure {
            isScanning = false
            activeScanMode = null
            Log.e(TAG, "BLE scan start failed", it)
        }
    }

    @SuppressLint("MissingPermission")
    fun stopActiveScanning() {
        if (!isScanning) return
        runCatching { bleScanner?.stopScan(scanCallback) }
        isScanning = false
        activeScanMode = null
    }

    @SuppressLint("MissingPermission")
    fun stopAdvertising() {
        if (!isAdvertising) return
        runCatching { bleAdvertiser?.stopAdvertising(advertiseCallback) }
        isAdvertising = false
        activeAdvertiseMode = null
        activeTxPower = null
        advertisedPresence = null
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.d(TAG, "BLE presence advertising started")
        }

        override fun onStartFailure(errorCode: Int) {
            isAdvertising = false
            activeAdvertiseMode = null
            activeTxPower = null
            advertisedPresence = null
            Log.e(TAG, "BLE advertising failed with error $errorCode")
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult?) {
            result?.let(::processScanResult)
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>?) {
            results?.forEach(::processScanResult)
        }

        override fun onScanFailed(errorCode: Int) {
            isScanning = false
            Log.e(TAG, "BLE scan failed with error $errorCode")
        }
    }

    private fun processScanResult(result: ScanResult) {
        val compact = result.scanRecord?.getManufacturerSpecificData(MANUFACTURER_ID) ?: return
        val frame = OmniFrame.unpack(compact) ?: return
        val prefix = frame.ephemeralPublicKey.copyOfRange(0, OmniFrame.COMPACT_KEY_PREFIX_SIZE)
        val now = System.currentTimeMillis()
        val key = prefix.toHex()
        synchronized(discoveredPeers) {
            pruneDiscoveredPeers(now)
            if (!discoveredPeers.containsKey(key) && discoveredPeers.size >= MAX_DISCOVERED_PEERS) {
                discoveredPeers.entries.minByOrNull { it.value.lastSeenMs }?.let { oldest ->
                    discoveredPeers.remove(oldest.key, oldest.value)
                }
            }
            discoveredPeers[key] = PeerEndpoint(result.device, prefix, now)
        }
        onPeerDiscoveredListener?.invoke(prefix, result.rssi)
    }

    private fun pruneDiscoveredPeers(nowMs: Long = System.currentTimeMillis()) {
        val cutoff = nowMs - PEER_EXPIRY_MS
        synchronized(discoveredPeers) {
            discoveredPeers.entries.removeIf { it.value.lastSeenMs < cutoff }
        }
    }

    private val gattClientCallback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val session = clientSessions[gatt.device.address] ?: return
            if (status == BluetoothGatt.GATT_SUCCESS && newState == BluetoothProfile.STATE_CONNECTED) {
                if (!gatt.discoverServices()) failAndClose(gatt, "GATT service discovery failed to start")
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED || status != BluetoothGatt.GATT_SUCCESS) {
                failAndClose(gatt, "BLE peer disconnected (status=$status)")
            } else {
                session.ready = false
            }
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val session = clientSessions[gatt.device.address] ?: return
            if (status != BluetoothGatt.GATT_SUCCESS || gatt.getService(OMNI_SERVICE_UUID) == null) {
                failAndClose(gatt, "OmniRelay GATT service not found")
                return
            }
            if (!gatt.requestMtu(DESIRED_MTU)) {
                session.ready = true
                drainWrites(session)
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            val session = clientSessions[gatt.device.address] ?: return
            session.mtuPayloadBytes = if (status == BluetoothGatt.GATT_SUCCESS) mtu - 3 else DEFAULT_ATT_PAYLOAD
            session.ready = true
            drainWrites(session)
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            val session = clientSessions[gatt.device.address] ?: return
            synchronized(session) { session.writeInFlight = false }
            if (status != BluetoothGatt.GATT_SUCCESS) {
                failAndClose(gatt, "BLE write failed ($status)")
                return
            }
            onDeliveryResultListener?.invoke(true, "Delivered over BLE GATT")
            drainWrites(session)
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        @SuppressLint("MissingPermission")
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            val structurallyValid = characteristic?.uuid == OMNI_CHAR_UUID &&
                !preparedWrite && offset == 0 && value != null && value.isNotEmpty()
            val peerBudget = if (structurallyValid && device != null) {
                peerIngressBudgets.getOrPut(device.address, ::PeerIngressBudget)
            } else null
            val admitted = structurallyValid && peerBudget != null &&
                peerBudget.packets.tryAcquire(1) && peerBudget.bytes.tryAcquire(value.size) &&
                ingressPacketBudget.tryAcquire(1) && ingressByteBudget.tryAcquire(value.size)
            if (admitted && device != null) value.let { packet ->
                fragmentAssembler.accept(device.address, packet)?.let { frame ->
                    onFrameReceivedListener?.invoke(frame, -50)
                }
            }
            if (responseNeeded && device != null) {
                val status = when {
                    admitted -> BluetoothGatt.GATT_SUCCESS
                    structurallyValid -> BluetoothGatt.GATT_FAILURE
                    else -> BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
                }
                runCatching { gattServer?.sendResponse(device, requestId, status, offset, null) }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun failAndClose(gatt: BluetoothGatt, reason: String) {
        clientSessions.remove(gatt.device.address)
        runCatching { gatt.close() }
        onDeliveryResultListener?.invoke(false, reason)
    }

    @SuppressLint("MissingPermission")
    fun close() {
        stopAdvertising()
        stopActiveScanning()
        clientSessions.values.forEach { runCatching { it.gatt.close() } }
        clientSessions.clear()
        discoveredPeers.clear()
        peerIngressBudgets.clear()
        runCatching { gattServer?.close() }
        gattServer = null
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
