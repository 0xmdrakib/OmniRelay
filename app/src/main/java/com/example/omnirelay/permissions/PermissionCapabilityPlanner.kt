package com.example.omnirelay.permissions

/**
 * Pure Kotlin permission policy for OmniRelay.
 *
 * This planner deliberately has no Android framework dependency. UI and platform layers can map
 * [RuntimePermission] values to Manifest.permission constants and should request each returned
 * [PermissionRequestGroup] only when its [PermissionRequestGroup.stage] is reached by the user.
 * A capability here means "allowed by runtime permissions"; hardware support, radio state, and
 * network reachability still need to be checked by the platform layer.
 */
object PermissionCapabilityPlanner {

    enum class RuntimePermission {
        MICROPHONE,
        NOTIFICATIONS,
        BLUETOOTH_SCAN,
        BLUETOOTH_ADVERTISE,
        BLUETOOTH_CONNECT,
        NEARBY_WIFI_DEVICES,
        COARSE_LOCATION,
        FINE_LOCATION
    }

    /** The user action that should trigger a permission request, never app startup by itself. */
    enum class PermissionStage {
        ENABLE_BACKGROUND_ALERTS,
        START_OR_ANSWER_VOICE_CALL,
        ENABLE_BLUETOOTH_NEARBY,
        ENABLE_WIFI_AWARE,
        ENABLE_LEGACY_BLUETOOTH_DISCOVERY,
        ENABLE_LEGACY_NEARBY_DISCOVERY
    }

    data class GrantedPermissions(
        val microphone: Boolean = false,
        val notifications: Boolean = false,
        val bluetoothScan: Boolean = false,
        val bluetoothAdvertise: Boolean = false,
        val bluetoothConnect: Boolean = false,
        val nearbyWifiDevices: Boolean = false,
        val coarseLocation: Boolean = false,
        val fineLocation: Boolean = false
    )

    data class FeatureCapabilities(
        /** Internet text messaging itself needs no dangerous runtime permission. */
        val internetMessaging: Boolean,
        /** Whether incoming calls/messages can be surfaced through system notifications. */
        val backgroundIncomingAlerts: Boolean,
        /** Whether the app may capture audio for an accepted or outgoing call. */
        val voiceCalling: Boolean,
        val bluetoothDiscovery: Boolean,
        val bluetoothAdvertising: Boolean,
        val bluetoothConnections: Boolean,
        /** Full Bluetooth participation requires discovery, advertising, and connections. */
        val bluetoothRelay: Boolean,
        val wifiAware: Boolean,
        /** At least one complete nearby transport is permission-capable. */
        val nearbyPeerMessaging: Boolean,
        val nearbyPeerVoiceCalling: Boolean,
        val nearbyRelay: Boolean
    )

    data class PermissionRequestGroup(
        val stage: PermissionStage,
        /**
         * Permissions the platform layer must include for this one user-visible feature.
         * Android can require an already-granted companion permission in the same request.
         */
        val permissions: Set<RuntimePermission>,
        val title: String,
        val rationale: String
    )

    data class CapabilityPlan(
        val capabilities: FeatureCapabilities,
        /** Independent, on-demand groups; callers must not merge them into one request. */
        val permissionGroups: List<PermissionRequestGroup>
    )

    fun plan(
        apiLevel: Int,
        granted: GrantedPermissions = GrantedPermissions()
    ): CapabilityPlan {
        require(apiLevel >= 26) { "OmniRelay supports Android API 26 and newer" }

        val legacyBluetoothLocationGranted = when (apiLevel) {
            in 26..28 -> granted.coarseLocation || granted.fineLocation
            in 29..30 -> granted.fineLocation
            else -> false
        }

        val bluetoothDiscovery = when {
            apiLevel <= 30 -> legacyBluetoothLocationGranted
            else -> granted.bluetoothScan
        }
        // Before API 31 these are install-time Bluetooth permissions, not runtime grants.
        val bluetoothAdvertising = apiLevel <= 30 || granted.bluetoothAdvertise
        val bluetoothConnections = apiLevel <= 30 || granted.bluetoothConnect
        val bluetoothRelay =
            bluetoothDiscovery && bluetoothAdvertising && bluetoothConnections

        val wifiAware = when (apiLevel) {
            in 26..32 -> granted.fineLocation
            else -> granted.nearbyWifiDevices
        }

        val nearbyPeerMessaging = bluetoothRelay || wifiAware
        val backgroundIncomingAlerts = apiLevel < 33 || granted.notifications
        val capabilities = FeatureCapabilities(
            internetMessaging = true,
            backgroundIncomingAlerts = backgroundIncomingAlerts,
            voiceCalling = granted.microphone,
            bluetoothDiscovery = bluetoothDiscovery,
            bluetoothAdvertising = bluetoothAdvertising,
            bluetoothConnections = bluetoothConnections,
            bluetoothRelay = bluetoothRelay,
            wifiAware = wifiAware,
            nearbyPeerMessaging = nearbyPeerMessaging,
            nearbyPeerVoiceCalling = nearbyPeerMessaging && granted.microphone,
            nearbyRelay = nearbyPeerMessaging
        )

        val groups = buildList {
            if (apiLevel >= 33 && !granted.notifications) {
                add(
                    PermissionRequestGroup(
                        stage = PermissionStage.ENABLE_BACKGROUND_ALERTS,
                        permissions = setOf(RuntimePermission.NOTIFICATIONS),
                        title = "Stay informed about calls and messages",
                        rationale = "Allow notifications so OmniRelay can show incoming calls and " +
                            "messages while the app is not open. Without this permission, messaging " +
                            "still works when the app is running, but background alerts may not appear."
                    )
                )
            }

            if (!granted.microphone) {
                add(
                    PermissionRequestGroup(
                        stage = PermissionStage.START_OR_ANSWER_VOICE_CALL,
                        permissions = setOf(RuntimePermission.MICROPHONE),
                        title = "Talk during a voice call",
                        rationale = "Allow microphone access only when you start or answer a voice " +
                            "call. OmniRelay needs it to send your voice; text messaging and nearby " +
                            "discovery work without it."
                    )
                )
            }

            when {
                apiLevel in 26..28 && !legacyBluetoothLocationGranted -> {
                    add(
                        PermissionRequestGroup(
                            stage = PermissionStage.ENABLE_LEGACY_BLUETOOTH_DISCOVERY,
                            permissions = setOf(RuntimePermission.COARSE_LOCATION),
                            title = "Find paired Bluetooth devices",
                            rationale = "This Android version requires location permission for " +
                                "Bluetooth discovery. OmniRelay uses this access to find nearby paired " +
                                "devices, not to provide location tracking. Denying it leaves internet " +
                                "messaging available but disables Bluetooth discovery."
                        )
                    )
                }

                apiLevel in 29..30 && !legacyBluetoothLocationGranted -> {
                    add(
                        PermissionRequestGroup(
                            stage = PermissionStage.ENABLE_LEGACY_NEARBY_DISCOVERY,
                            permissions = setOf(RuntimePermission.FINE_LOCATION),
                            title = "Find nearby paired devices",
                            rationale = "Android 10 and 11 require precise location permission for " +
                                "Bluetooth and Wi-Fi Aware discovery. OmniRelay uses this access to " +
                                "find nearby paired devices, not to provide location tracking. Denying " +
                                "it leaves internet messaging available but disables nearby paths."
                        )
                    )
                }

                apiLevel >= 31 -> {
                    val missingBluetooth = buildSet {
                        if (!granted.bluetoothScan) add(RuntimePermission.BLUETOOTH_SCAN)
                        if (!granted.bluetoothAdvertise) add(RuntimePermission.BLUETOOTH_ADVERTISE)
                        if (!granted.bluetoothConnect) add(RuntimePermission.BLUETOOTH_CONNECT)
                    }
                    if (missingBluetooth.isNotEmpty()) {
                        add(
                            PermissionRequestGroup(
                                stage = PermissionStage.ENABLE_BLUETOOTH_NEARBY,
                                permissions = missingBluetooth,
                                title = "Connect through nearby Bluetooth devices",
                                rationale = "Allow nearby Bluetooth access so OmniRelay can discover, " +
                                    "advertise to, and connect with paired devices. This request does " +
                                    "not grant location access. Denying it disables the Bluetooth path " +
                                    "but leaves internet messaging available."
                            )
                        )
                    }
                }
            }

            when {
                (apiLevel in 26..28 || apiLevel in 31..32) && !granted.fineLocation -> {
                    val locationPermissions = if (apiLevel in 31..32) {
                        // Android 12/12L ignores a precise-location request unless approximate
                        // and precise location are requested together in the same dialog.
                        setOf(RuntimePermission.COARSE_LOCATION, RuntimePermission.FINE_LOCATION)
                    } else {
                        setOf(RuntimePermission.FINE_LOCATION)
                    }
                    add(
                        PermissionRequestGroup(
                            stage = PermissionStage.ENABLE_WIFI_AWARE,
                            permissions = locationPermissions,
                            title = "Find devices through Wi-Fi Aware",
                            rationale = "Android versions before Android 13 require precise location " +
                                "permission for Wi-Fi Aware discovery. OmniRelay uses this access to " +
                                "find nearby paired devices, not to provide location tracking. Denying " +
                                "it disables Wi-Fi Aware but leaves internet and permitted Bluetooth " +
                                "paths available."
                        )
                    )
                }

                apiLevel >= 33 && !granted.nearbyWifiDevices -> {
                    add(
                        PermissionRequestGroup(
                            stage = PermissionStage.ENABLE_WIFI_AWARE,
                            permissions = setOf(RuntimePermission.NEARBY_WIFI_DEVICES),
                            title = "Connect through nearby Wi-Fi devices",
                            rationale = "Allow nearby Wi-Fi device access so OmniRelay can discover " +
                                "paired devices and create a Wi-Fi Aware link. This permission does " +
                                "not grant location access. Denying it disables Wi-Fi Aware but leaves " +
                                "internet and permitted Bluetooth paths available."
                        )
                    )
                }
            }
        }

        return CapabilityPlan(capabilities = capabilities, permissionGroups = groups)
    }
}
