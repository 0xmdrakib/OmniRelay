package com.example.omnirelay.permissions

import com.example.omnirelay.permissions.PermissionCapabilityPlanner.GrantedPermissions
import com.example.omnirelay.permissions.PermissionCapabilityPlanner.PermissionStage
import com.example.omnirelay.permissions.PermissionCapabilityPlanner.RuntimePermission
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PermissionCapabilityPlannerTest {

    @Test
    fun api26UsesCoarseLocationAsLeastPrivilegeForNearbyDiscovery() {
        val missingPlan = PermissionCapabilityPlanner.plan(
            apiLevel = 26,
            granted = GrantedPermissions(microphone = true)
        )
        val locationGroup = missingPlan.group(PermissionStage.ENABLE_LEGACY_BLUETOOTH_DISCOVERY)
        assertEquals(setOf(RuntimePermission.COARSE_LOCATION), locationGroup.permissions)
        assertTrue(locationGroup.rationale.contains("requires location permission"))
        assertFalse(missingPlan.capabilities.bluetoothDiscovery)
        assertFalse(missingPlan.capabilities.wifiAware)
        assertEquals(
            setOf(RuntimePermission.FINE_LOCATION),
            missingPlan.group(PermissionStage.ENABLE_WIFI_AWARE).permissions
        )

        val grantedPlan = PermissionCapabilityPlanner.plan(
            apiLevel = 26,
            granted = GrantedPermissions(microphone = true, coarseLocation = true)
        )
        assertTrue(grantedPlan.capabilities.bluetoothRelay)
        assertFalse(grantedPlan.capabilities.wifiAware)
        assertTrue(grantedPlan.capabilities.nearbyPeerVoiceCalling) // Bluetooth is available.
        assertTrue(grantedPlan.capabilities.backgroundIncomingAlerts)

        val finePlan = PermissionCapabilityPlanner.plan(
            apiLevel = 26,
            granted = GrantedPermissions(microphone = true, fineLocation = true)
        )
        assertTrue(finePlan.capabilities.bluetoothRelay)
        assertTrue(finePlan.capabilities.wifiAware)
    }

    @Test
    fun api30RequiresFineLocationAndDoesNotInventModernBluetoothPermissions() {
        val plan = PermissionCapabilityPlanner.plan(
            apiLevel = 30,
            granted = GrantedPermissions(microphone = true, coarseLocation = true)
        )

        assertFalse(plan.capabilities.bluetoothDiscovery)
        assertTrue(plan.capabilities.bluetoothAdvertising)
        assertTrue(plan.capabilities.bluetoothConnections)
        assertFalse(plan.capabilities.wifiAware)
        assertEquals(
            setOf(RuntimePermission.FINE_LOCATION),
            plan.group(PermissionStage.ENABLE_LEGACY_NEARBY_DISCOVERY).permissions
        )
        assertTrue(plan.permissionGroups.none { it.stage == PermissionStage.ENABLE_WIFI_AWARE })
        assertTrue(plan.permissionGroups.none { group ->
            group.permissions.any { it.name.startsWith("BLUETOOTH_") }
        })
    }

    @Test
    fun api31SeparatesBluetoothAndRequestsApproximateWithPreciseWifiAwareLocation() {
        val plan = PermissionCapabilityPlanner.plan(
            apiLevel = 31,
            granted = GrantedPermissions(
                microphone = true,
                bluetoothScan = true,
                bluetoothAdvertise = true,
                bluetoothConnect = true
            )
        )

        assertTrue(plan.capabilities.bluetoothRelay)
        assertFalse(plan.capabilities.wifiAware)
        assertTrue(plan.capabilities.backgroundIncomingAlerts)
        assertTrue(plan.permissionGroups.none { it.stage == PermissionStage.ENABLE_BLUETOOTH_NEARBY })
        val wifiGroup = plan.group(PermissionStage.ENABLE_WIFI_AWARE)
        assertEquals(
            setOf(RuntimePermission.COARSE_LOCATION, RuntimePermission.FINE_LOCATION),
            wifiGroup.permissions
        )
        assertTrue(wifiGroup.rationale.contains("require precise location permission"))
    }

    @Test
    fun api32BluetoothGroupContainsOnlyMissingBluetoothPermissions() {
        val plan = PermissionCapabilityPlanner.plan(
            apiLevel = 32,
            granted = GrantedPermissions(
                microphone = true,
                bluetoothScan = true,
                fineLocation = true
            )
        )

        assertTrue(plan.capabilities.bluetoothDiscovery)
        assertFalse(plan.capabilities.bluetoothRelay)
        assertTrue(plan.capabilities.wifiAware)
        assertEquals(
            setOf(RuntimePermission.BLUETOOTH_ADVERTISE, RuntimePermission.BLUETOOTH_CONNECT),
            plan.group(PermissionStage.ENABLE_BLUETOOTH_NEARBY).permissions
        )
        assertTrue(plan.permissionGroups.none { it.stage == PermissionStage.ENABLE_WIFI_AWARE })
    }

    @Test
    fun api33ReturnsIndependentFeatureScopedPermissionStages() {
        val plan = PermissionCapabilityPlanner.plan(apiLevel = 33)

        assertTrue(plan.capabilities.internetMessaging)
        assertFalse(plan.capabilities.backgroundIncomingAlerts)
        assertFalse(plan.capabilities.voiceCalling)
        assertFalse(plan.capabilities.nearbyPeerMessaging)
        assertEquals(
            listOf(
                PermissionStage.ENABLE_BACKGROUND_ALERTS,
                PermissionStage.START_OR_ANSWER_VOICE_CALL,
                PermissionStage.ENABLE_BLUETOOTH_NEARBY,
                PermissionStage.ENABLE_WIFI_AWARE
            ),
            plan.permissionGroups.map { it.stage }
        )
        assertEquals(setOf(RuntimePermission.NOTIFICATIONS), plan.permissionGroups[0].permissions)
        assertEquals(setOf(RuntimePermission.MICROPHONE), plan.permissionGroups[1].permissions)
        assertEquals(
            setOf(
                RuntimePermission.BLUETOOTH_SCAN,
                RuntimePermission.BLUETOOTH_ADVERTISE,
                RuntimePermission.BLUETOOTH_CONNECT
            ),
            plan.permissionGroups[2].permissions
        )
        assertEquals(setOf(RuntimePermission.NEARBY_WIFI_DEVICES), plan.permissionGroups[3].permissions)
        assertTrue(plan.permissionGroups.none { RuntimePermission.FINE_LOCATION in it.permissions })
    }

    @Test
    fun api33FullGrantEnablesEveryPermissionCapabilityWithoutMoreRequests() {
        val plan = PermissionCapabilityPlanner.plan(
            apiLevel = 33,
            granted = GrantedPermissions(
                microphone = true,
                notifications = true,
                bluetoothScan = true,
                bluetoothAdvertise = true,
                bluetoothConnect = true,
                nearbyWifiDevices = true
            )
        )

        with(plan.capabilities) {
            assertTrue(internetMessaging)
            assertTrue(backgroundIncomingAlerts)
            assertTrue(voiceCalling)
            assertTrue(bluetoothRelay)
            assertTrue(wifiAware)
            assertTrue(nearbyPeerMessaging)
            assertTrue(nearbyPeerVoiceCalling)
            assertTrue(nearbyRelay)
        }
        assertTrue(plan.permissionGroups.isEmpty())
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsUnsupportedApiLevels() {
        PermissionCapabilityPlanner.plan(apiLevel = 25)
    }

    private fun PermissionCapabilityPlanner.CapabilityPlan.group(
        stage: PermissionStage
    ): PermissionCapabilityPlanner.PermissionRequestGroup =
        permissionGroups.single { it.stage == stage }
}
