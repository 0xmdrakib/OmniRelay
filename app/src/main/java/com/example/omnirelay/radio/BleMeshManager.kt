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
        private const val MAX_PENDING_FRAMES = 128
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
        var ready: Boolean = false,
        var writeInFlight: Boolean = false,
        var mtuPayloadBytes: Int = DEFAULT_ATT_PAYLOAD
    )

    private val bluetoothManager =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val bluetoothAdapter = bluetoothManager?.adapter
    private var bleAdvertiser: BluetoothLeAdvertiser? = bluetoothAdapter?.bluetoothLeAdvertiser
    private var bleScanner: BluetoothLeScanner? = bluetoothAdapter?.bluetoothLeScanner

    private var gattServer: BluetoothGattServer? = null
    private val discoveredPeers = ConcurrentHashMap<String, PeerEndpoint>()
    private val clientSessions = ConcurrentHashMap<String, ClientSession>()
    private val fragmentAssembler = NearbyFrameFragmentCodec.Assembler()
    private var isAdvertising = false
    private var isScanning = false

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
    fun startAdvertising(compactPresenceFrame: ByteArray) {
        require(compactPresenceFrame.size == OmniFrame.COMPACT_FRAME_SIZE) {
            "BLE advertisements must contain a ${OmniFrame.COMPACT_FRAME_SIZE}-byte presence frame"
        }
        if (bleAdvertiser == null) bleAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser
        val advertiser = bleAdvertiser ?: return

        if (isAdvertising) runCatching { advertiser.stopAdvertising(advertiseCallback) }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addManufacturerData(MANUFACTURER_ID, compactPresenceFrame)
            .build()

        runCatching {
            advertiser.startAdvertising(settings, data, advertiseCallback)
            isAdvertising = true
        }.onFailure {
            isAdvertising = false
            Log.e(TAG, "BLE advertising failed", it)
        }
    }

    /** Queues a full OmniFrame for a discovered paired peer. */
    @SuppressLint("MissingPermission")
    fun sendFrame(targetPublicKey: ByteArray, packedFrame: ByteArray): Boolean {
        val targetPrefix = targetPublicKey.copyOfRange(0, OmniFrame.COMPACT_KEY_PREFIX_SIZE)
        val endpoint = discoveredPeers[targetPrefix.toHex()] ?: return false
        val address = endpoint.device.address

        synchronized(clientSessions) {
            val existing = clientSessions[address]
            if (existing != null) {
                enqueue(existing, packedFrame)
                drainWrites(existing)
                return true
            }

            val gatt = endpoint.device.connectGatt(
                context,
                false,
                gattClientCallback,
                BluetoothDevice.TRANSPORT_LE
            ) ?: return false
            val session = ClientSession(gatt)
            enqueue(session, packedFrame)
            clientSessions[address] = session
        }
        return true
    }

    private fun enqueue(session: ClientSession, frame: ByteArray) {
        synchronized(session) {
            if (session.pendingFrames.size >= MAX_PENDING_FRAMES) session.pendingFrames.removeFirst()
            session.pendingFrames.addLast(frame.copyOf())
        }
    }

    @SuppressLint("MissingPermission")
    private fun drainWrites(session: ClientSession) {
        val frame = synchronized(session) {
            if (!session.ready || session.writeInFlight || session.pendingFrames.isEmpty()) return
            session.pendingFrames.removeFirst().also { session.writeInFlight = true }
        }

        if (frame.size > session.mtuPayloadBytes) {
            val fragments = NearbyFrameFragmentCodec.fragment(frame, session.mtuPayloadBytes)
            synchronized(session) {
                session.writeInFlight = false
                for (index in fragments.indices.reversed()) session.pendingFrames.addFirst(fragments[index])
            }
            drainWrites(session)
            return
        }

        val characteristic = session.gatt.getService(OMNI_SERVICE_UUID)?.getCharacteristic(OMNI_CHAR_UUID)
        if (characteristic == null) {
            synchronized(session) { session.writeInFlight = false }
            onDeliveryResultListener?.invoke(false, "OmniRelay GATT characteristic unavailable")
            return
        }

        val started = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            session.gatt.writeCharacteristic(
                characteristic,
                frame,
                BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            ) == BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            characteristic.value = frame
            characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            @Suppress("DEPRECATION")
            session.gatt.writeCharacteristic(characteristic)
        }
        if (!started) {
            synchronized(session) { session.writeInFlight = false }
            onDeliveryResultListener?.invoke(false, "Unable to start BLE GATT write")
        }
    }

    @SuppressLint("MissingPermission")
    fun startActiveScanning() {
        if (bleScanner == null) bleScanner = bluetoothAdapter?.bluetoothLeScanner
        val scanner = bleScanner ?: return
        if (isScanning) return

        val filter = ScanFilter.Builder()
            .setManufacturerData(MANUFACTURER_ID, byteArrayOf(0x10), byteArrayOf(0xF0.toByte()))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .build()
        runCatching {
            scanner.startScan(listOf(filter), settings, scanCallback)
            isScanning = true
        }.onFailure { Log.e(TAG, "BLE scan start failed", it) }
    }

    @SuppressLint("MissingPermission")
    fun stopActiveScanning() {
        if (!isScanning) return
        runCatching { bleScanner?.stopScan(scanCallback) }
        isScanning = false
    }

    @SuppressLint("MissingPermission")
    fun stopAdvertising() {
        if (!isAdvertising) return
        runCatching { bleAdvertiser?.stopAdvertising(advertiseCallback) }
        isAdvertising = false
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.d(TAG, "BLE presence advertising started")
        }

        override fun onStartFailure(errorCode: Int) {
            isAdvertising = false
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
        discoveredPeers[prefix.toHex()] = PeerEndpoint(result.device, prefix, System.currentTimeMillis())
        onPeerDiscoveredListener?.invoke(prefix, result.rssi)
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
            onDeliveryResultListener?.invoke(
                status == BluetoothGatt.GATT_SUCCESS,
                if (status == BluetoothGatt.GATT_SUCCESS) "Delivered over BLE GATT" else "BLE write failed ($status)"
            )
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
            val valid = characteristic?.uuid == OMNI_CHAR_UUID &&
                !preparedWrite && offset == 0 && value != null && value.isNotEmpty()
            if (valid && device != null) value.let { packet ->
                fragmentAssembler.accept(device.address, packet)?.let { frame ->
                    onFrameReceivedListener?.invoke(frame, -50)
                }
            }
            if (responseNeeded && device != null) {
                val status = if (valid) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
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
        runCatching { gattServer?.close() }
        gattServer = null
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
