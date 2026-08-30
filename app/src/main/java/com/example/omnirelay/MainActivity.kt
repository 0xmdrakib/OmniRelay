package com.example.omnirelay

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.automirrored.filled.VolumeOff
import androidx.compose.material.icons.automirrored.filled.VolumeUp
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.PhoneMissed
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.omnirelay.data.local.MessageEntity
import com.example.omnirelay.auth.GoogleAccountManager
import com.example.omnirelay.auth.GoogleAccountProfile
import com.example.omnirelay.auth.GoogleSignInCancelledException
import com.example.omnirelay.auth.NoAuthorizedGoogleAccountException
import com.example.omnirelay.network.InternetRelayClient
import com.example.omnirelay.network.SecureTokenStore
import com.example.omnirelay.permissions.PermissionCapabilityPlanner
import com.example.omnirelay.permissions.PermissionCapabilityPlanner.CapabilityPlan
import com.example.omnirelay.permissions.PermissionCapabilityPlanner.PermissionRequestGroup
import com.example.omnirelay.permissions.PermissionCapabilityPlanner.PermissionStage
import com.example.omnirelay.permissions.PermissionCapabilityPlanner.RuntimePermission
import com.example.omnirelay.radio.PeerDiscoveryRegistry
import com.example.omnirelay.radio.PeerNode
import com.example.omnirelay.service.CallInvite
import com.example.omnirelay.service.OmniRelayService
import com.example.omnirelay.theme.OmniRelayTheme
import com.example.omnirelay.routing.AdaptiveResourcePolicy.UserResourceTier
import com.example.omnirelay.utils.PairedContact
import com.example.omnirelay.utils.SettingsManager
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.Locale

private sealed interface AccountUiState {
    data object Unconfigured : AccountUiState
    data class SignedOut(val message: String? = null) : AccountUiState
    data object SigningIn : AccountUiState
    data class SignedIn(val profile: GoogleAccountProfile) : AccountUiState
}

private const val ACCOUNT_MISMATCH_MESSAGE =
    "This device identity belongs to a different Google account. Sign in with the original account, " +
        "or explicitly reset app data only after confirming identity recovery."

class MainActivity : ComponentActivity() {

    private var omniService: OmniRelayService? by mutableStateOf(null)
    private var isBound by mutableStateOf(false)
    private var activityStarted = false
    private var permissionRevision by mutableIntStateOf(0)
    private var pendingPermissionRationale by mutableStateOf<PermissionRequestGroup?>(null)
    private var identityStartupError by mutableStateOf<String?>(null)
    private lateinit var googleAccountManager: GoogleAccountManager
    private var accountUiState by mutableStateOf<AccountUiState>(AccountUiState.Unconfigured)

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as OmniRelayService.LocalBinder
            omniService = binder.getService()
            isBound = true
            omniService?.setAppInForeground(activityStarted)
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            omniService = null
            isBound = false
        }
    }

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {
        permissionRevision++
        omniService?.refreshConfiguration()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        identityStartupError = runCatching {
            SettingsManager(this, observeExternalChanges = false).use { settings ->
                settings.getMyIdentity().privateKey.fill(0)
                settings.getMySigningIdentity().privateKeyDer.fill(0)
            }
        }.exceptionOrNull()?.let {
            "Your encrypted device identity could not be unlocked. OmniRelay preserved it and " +
                "did not create a replacement identity. Restore the device/Keystore state or " +
                "explicitly reset app data only after confirming recovery options."
        }
        googleAccountManager = GoogleAccountManager(this)
        accountUiState = when {
            !googleAccountManager.isConfigured -> AccountUiState.Unconfigured
            else -> {
                val profile = googleAccountManager.currentProfile()
                when {
                    profile == null -> AccountUiState.SignedOut()
                    runCatching { SecureTokenStore(this).bindAccountUid(profile.uid) }.getOrDefault(false) ->
                        AccountUiState.SignedIn(profile)
                    else -> {
                        googleAccountManager.clearFirebaseSession()
                        AccountUiState.SignedOut(ACCOUNT_MISMATCH_MESSAGE)
                    }
                }
            }
        }
        if (identityStartupError == null && accountUiState is AccountUiState.SignedIn) {
            startAndBindService()
        }

        setContent {
            val authenticationScope = rememberCoroutineScope()
            val revision = permissionRevision
            val permissionPlan = remember(revision) { currentPermissionPlan() }
            OmniRelayTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xFFF3F2F8)
                ) {
                    val startupError = identityStartupError
                    if (startupError != null) {
                        IdentityUnavailableScreen(startupError)
                    } else {
                        when (val accountState = accountUiState) {
                            AccountUiState.Unconfigured -> GoogleAuthConfigurationScreen()
                            is AccountUiState.SignedOut -> GoogleSignInScreen(
                                isLoading = false,
                                message = accountState.message,
                                onAutomaticSignIn = {
                                    authenticationScope.launch { performGoogleSignIn(true) }
                                },
                                onSignIn = {
                                    authenticationScope.launch { performGoogleSignIn(false) }
                                }
                            )
                            AccountUiState.SigningIn -> GoogleSignInScreen(
                                isLoading = true,
                                message = null,
                                onAutomaticSignIn = {},
                                onSignIn = {}
                            )
                            is AccountUiState.SignedIn -> MinimalAppDashboard(
                                omniService = omniService,
                                permissionPlan = permissionPlan,
                                accountProfile = accountState.profile,
                                onSignOut = {
                                    authenticationScope.launch { performGoogleSignOut() }
                                },
                                onRequestPermission = ::showPermissionRationale
                            )
                        }
                    }
                }
            }
            pendingPermissionRationale?.let { group ->
                AlertDialog(
                    onDismissRequest = { pendingPermissionRationale = null },
                    title = { Text(group.title) },
                    text = { Text(group.rationale) },
                    confirmButton = {
                        TextButton(onClick = {
                            pendingPermissionRationale = null
                            requestPermissionLauncher.launch(
                                group.permissions.mapNotNull(::manifestPermission).toTypedArray()
                            )
                        }) { Text("CONTINUE") }
                    },
                    dismissButton = {
                        TextButton(onClick = { pendingPermissionRationale = null }) {
                            Text("NOT NOW")
                        }
                    }
                )
            }
        }
    }

    override fun onStart() {
        super.onStart()
        activityStarted = true
        omniService?.setAppInForeground(true)
    }

    override fun onResume() {
        super.onResume()
        permissionRevision++
    }

    override fun onStop() {
        omniService?.setAppInForeground(false)
        activityStarted = false
        super.onStop()
    }

    private fun currentPermissionPlan(): CapabilityPlan = PermissionCapabilityPlanner.plan(
        apiLevel = Build.VERSION.SDK_INT,
        granted = PermissionCapabilityPlanner.GrantedPermissions(
            microphone = isGranted(Manifest.permission.RECORD_AUDIO),
            notifications = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
                isGranted(Manifest.permission.POST_NOTIFICATIONS),
            bluetoothScan = Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
                isGranted(Manifest.permission.BLUETOOTH_SCAN),
            bluetoothAdvertise = Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
                isGranted(Manifest.permission.BLUETOOTH_ADVERTISE),
            bluetoothConnect = Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
                isGranted(Manifest.permission.BLUETOOTH_CONNECT),
            nearbyWifiDevices = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
                isGranted(Manifest.permission.NEARBY_WIFI_DEVICES),
            coarseLocation = isGranted(Manifest.permission.ACCESS_COARSE_LOCATION),
            fineLocation = isGranted(Manifest.permission.ACCESS_FINE_LOCATION)
        )
    )

    private fun isGranted(permission: String): Boolean =
        ContextCompat.checkSelfPermission(this, permission) == android.content.pm.PackageManager.PERMISSION_GRANTED

    private fun showPermissionRationale(stage: PermissionStage) {
        pendingPermissionRationale = currentPermissionPlan().permissionGroups
            .firstOrNull { it.stage == stage }
    }

    private fun manifestPermission(permission: RuntimePermission): String? = when (permission) {
        RuntimePermission.MICROPHONE -> Manifest.permission.RECORD_AUDIO
        RuntimePermission.NOTIFICATIONS -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.POST_NOTIFICATIONS
        } else null
        RuntimePermission.BLUETOOTH_SCAN -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            Manifest.permission.BLUETOOTH_SCAN
        } else null
        RuntimePermission.BLUETOOTH_ADVERTISE -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            Manifest.permission.BLUETOOTH_ADVERTISE
        } else null
        RuntimePermission.BLUETOOTH_CONNECT -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            Manifest.permission.BLUETOOTH_CONNECT
        } else null
        RuntimePermission.NEARBY_WIFI_DEVICES -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.NEARBY_WIFI_DEVICES
        } else null
        RuntimePermission.COARSE_LOCATION -> Manifest.permission.ACCESS_COARSE_LOCATION
        RuntimePermission.FINE_LOCATION -> Manifest.permission.ACCESS_FINE_LOCATION
    }

    private fun startAndBindService() {
        if (identityStartupError != null || accountUiState !is AccountUiState.SignedIn) return
        val intent = Intent(this, OmniRelayService::class.java)
        runCatching { ContextCompat.startForegroundService(this, intent) }
        if (!isBound) bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    private suspend fun performGoogleSignIn(authorizedAccountsOnly: Boolean) {
        if (accountUiState is AccountUiState.SigningIn) return
        accountUiState = AccountUiState.SigningIn
        try {
            val profile = googleAccountManager.signIn(authorizedAccountsOnly)
            if (!runCatching { SecureTokenStore(this).bindAccountUid(profile.uid) }.getOrDefault(false)) {
                googleAccountManager.signOut()
                accountUiState = AccountUiState.SignedOut(ACCOUNT_MISMATCH_MESSAGE)
                return
            }
            accountUiState = AccountUiState.SignedIn(profile)
            startAndBindService()
        } catch (_: NoAuthorizedGoogleAccountException) {
            accountUiState = AccountUiState.SignedOut()
        } catch (_: GoogleSignInCancelledException) {
            accountUiState = AccountUiState.SignedOut(
                if (authorizedAccountsOnly) null else "Google sign-in was cancelled."
            )
        } catch (_: Exception) {
            accountUiState = AccountUiState.SignedOut(
                if (authorizedAccountsOnly) null
                else "Google could not complete sign-in. Check Play Services and your connection, then try again."
            )
        }
    }

    private suspend fun performGoogleSignOut() {
        accountUiState = AccountUiState.SigningIn
        val signOutRelayClient = InternetRelayClient(this)
        if (signOutRelayClient.isConfigured && signOutRelayClient.credentials() != null) {
            withTimeoutOrNull(3_000) {
                runCatching { signOutRelayClient.revokeSession() }
            }
        }
        omniService?.setAppInForeground(false)
        if (isBound) {
            unbindService(serviceConnection)
            isBound = false
        }
        omniService = null
        stopService(Intent(this, OmniRelayService::class.java))
        SecureTokenStore(this).clear()
        googleAccountManager.signOut()
        accountUiState = AccountUiState.SignedOut()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (isBound) {
            unbindService(serviceConnection)
            isBound = false
        }
    }
}

// ==========================================
// LUXURY SOFT PASTEL GLASS UI DASHBOARD
// ==========================================
@Composable
fun GoogleAuthConfigurationScreen() {
    Box(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        contentAlignment = Alignment.Center
    ) {
        Card(
            modifier = Modifier.fillMaxWidth().widthIn(max = 480.dp),
            shape = RoundedCornerShape(28.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White)
        ) {
            Column(modifier = Modifier.padding(28.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Box(
                    modifier = Modifier.size(58.dp).background(Color(0xFFFFE7D9), RoundedCornerShape(18.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Default.AdminPanelSettings, contentDescription = null, tint = Color(0xFFFF6B5A))
                }
                Spacer(Modifier.height(18.dp))
                Text("Google sign-in needs configuration", fontWeight = FontWeight.Black, fontSize = 20.sp)
                Spacer(Modifier.height(10.dp))
                Text(
                    "This build is locked because its Firebase and Google OAuth client settings are missing. " +
                        "Install a production-configured build to continue.",
                    color = Color(0xFF7E7E9A),
                    fontSize = 13.sp,
                    lineHeight = 20.sp
                )
            }
        }
    }
}

@Composable
fun GoogleSignInScreen(
    isLoading: Boolean,
    message: String?,
    onAutomaticSignIn: () -> Unit,
    onSignIn: () -> Unit
) {
    LaunchedEffect(Unit) { onAutomaticSignIn() }
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.linearGradient(
                    listOf(Color(0xFFF3F2F8), Color(0xFFFFF4EC), Color(0xFFEDE9FF))
                )
            )
            .padding(24.dp),
        contentAlignment = Alignment.Center
    ) {
        Card(
            modifier = Modifier.fillMaxWidth().widthIn(max = 480.dp),
            shape = RoundedCornerShape(30.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(30.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Box(
                    modifier = Modifier
                        .size(64.dp)
                        .background(
                            Brush.linearGradient(listOf(Color(0xFF7C66FF), Color(0xFF6C5CE7))),
                            RoundedCornerShape(20.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Default.CellTower, contentDescription = null, tint = Color.White, modifier = Modifier.size(32.dp))
                }
                Spacer(Modifier.height(20.dp))
                Text("Welcome to OmniRelay", fontWeight = FontWeight.Black, fontSize = 24.sp, color = Color(0xFF1E1C2E))
                Spacer(Modifier.height(8.dp))
                Text(
                    "Sign in before messaging or calling. Your Google account controls access; " +
                        "your E2EE Secret Link and private keys remain protected on this device.",
                    color = Color(0xFF7E7E9A),
                    fontSize = 13.sp,
                    lineHeight = 20.sp
                )
                if (message != null) {
                    Spacer(Modifier.height(14.dp))
                    Text(message, color = Color(0xFFFF5A5F), fontSize = 12.sp)
                }
                Spacer(Modifier.height(24.dp))
                Button(
                    onClick = onSignIn,
                    enabled = !isLoading,
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF1E1C2E),
                        contentColor = Color.White
                    )
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = Color.White,
                            strokeWidth = 2.dp
                        )
                        Spacer(Modifier.width(10.dp))
                        Text("CHECKING ACCOUNT", fontWeight = FontWeight.Bold)
                    } else {
                        Text("G", fontWeight = FontWeight.Black, fontSize = 18.sp)
                        Spacer(Modifier.width(12.dp))
                        Text("CONTINUE WITH GOOGLE", fontWeight = FontWeight.Bold)
                    }
                }
                Spacer(Modifier.height(16.dp))
                Text(
                    "The relay stores only the verified account UID for device ownership—never your Google password.",
                    color = Color(0xFF9A9AB0),
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )
            }
        }
    }
}

@Composable
fun IdentityUnavailableScreen(message: String) {
    Box(modifier = Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
        Card(
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White)
        ) {
            Column(modifier = Modifier.padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(Icons.Default.Lock, contentDescription = null, tint = Color(0xFFFF7675))
                Spacer(Modifier.height(12.dp))
                Text("Identity safely locked", fontWeight = FontWeight.Black, fontSize = 18.sp)
                Spacer(Modifier.height(8.dp))
                Text(message, color = Color(0xFF7E7E9A), fontSize = 13.sp)
            }
        }
    }
}

@Composable
fun MinimalAppDashboard(
    omniService: OmniRelayService?,
    permissionPlan: CapabilityPlan,
    accountProfile: GoogleAccountProfile,
    onSignOut: () -> Unit,
    onRequestPermission: (PermissionStage) -> Unit
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var selectedTab by remember { mutableIntStateOf(0) }

    val settingsManager = remember { SettingsManager(context) }
    DisposableEffect(settingsManager) {
        onDispose { settingsManager.close() }
    }

    val serviceCallActive by (omniService?.isCallActive?.collectAsState(initial = false) ?: remember { mutableStateOf(false) })
    val isMuted by (omniService?.isMuted?.collectAsState(initial = false) ?: remember { mutableStateOf(false) })
    val isSpeakerOn by (omniService?.isSpeakerOn?.collectAsState(initial = true) ?: remember { mutableStateOf(true) })
    val callDurationSec by (omniService?.callDurationSeconds?.collectAsState(initial = 0) ?: remember { mutableStateOf(0) })

    val incomingCallInvite by (omniService?.incomingCallState?.collectAsState(initial = null) ?: remember { mutableStateOf(null) })
    val persistentMessages by (omniService?.chatHistory?.collectAsState(initial = emptyList()) ?: remember { mutableStateOf(emptyList()) })

    var refreshTrigger by remember { mutableIntStateOf(0) }
    val pairedContacts = remember(refreshTrigger) { settingsManager.getPairedContacts() }

    // React to hardware discovery updates instead of taking a one-time snapshot.
    val discoveredPeers by PeerDiscoveryRegistry.peers.collectAsState()
    val activeMeshNodes = remember(discoveredPeers) {
        val now = System.currentTimeMillis()
        discoveredPeers.filter { it.isMutualLinked && now - it.lastSeenMs < 60_000 }
    }

    // Active paired contacts online (with prefix matching for BLE compact packets)
    val onlinePairedLinks = remember(activeMeshNodes, pairedContacts) {
        activeMeshNodes.mapNotNull { node ->
            pairedContacts.find { c ->
                val pLink = c.secretLink.trim()
                val nId = node.nodeId.trim()
                pLink == nId || pLink.startsWith(nId.take(12)) || nId.startsWith(pLink.take(12))
            }?.secretLink
        }.toSet()
    }

    var activeChatContact by remember { mutableStateOf<PairedContact?>(null) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFFF3F2F8))
    ) {
        // Soft pastel gradient ambient circles
        Canvas(modifier = Modifier.fillMaxSize()) {
            drawCircle(
                brush = Brush.radialGradient(listOf(Color(0xFFE2DCFF).copy(alpha = 0.6f), Color.Transparent)),
                radius = 650f,
                center = Offset(size.width * 0.9f, 50f)
            )
            drawCircle(
                brush = Brush.radialGradient(listOf(Color(0xFFD6F5E3).copy(alpha = 0.5f), Color.Transparent)),
                radius = 600f,
                center = Offset(-50f, size.height * 0.9f)
            )
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
        ) {
            // Header Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 18.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .clip(RoundedCornerShape(14.dp))
                            .background(Brush.linearGradient(listOf(Color(0xFF7C66FF), Color(0xFF6C5CE7)))),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.CellTower, contentDescription = null, tint = Color.White, modifier = Modifier.size(22.dp))
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "OmniRelay",
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF1E1C2E),
                            fontSize = 20.sp,
                            letterSpacing = 0.3.sp
                        )
                        Text(
                            text = "Private Hybrid E2EE",
                            color = Color(0xFF7E7E9A),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }

                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = Color(0xFFEBE6FF),
                    shadowElevation = 0.dp
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(7.dp)
                                .clip(CircleShape)
                                .background(if (onlinePairedLinks.isNotEmpty()) Color(0xFF00B894) else Color(0xFFFF7675))
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "${onlinePairedLinks.size} Reachable",
                            color = Color(0xFF6C5CE7),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            // Incoming Call Banner
            val currentInvite = incomingCallInvite
            if (currentInvite != null) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 8.dp),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFFF7675)),
                    elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Call, contentDescription = null, tint = Color.White)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("INCOMING HD CALL", fontWeight = FontWeight.Bold, color = Color.White, fontSize = 12.sp, letterSpacing = 1.sp)
                            }
                            Text("Ringing...", color = Color.White.copy(alpha = 0.9f), fontSize = 11.sp)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(currentInvite.callerId, color = Color.White, fontWeight = FontWeight.Black, fontSize = 18.sp, maxLines = 1)
                        Spacer(modifier = Modifier.height(16.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Button(
                                onClick = {
                                    if (permissionPlan.capabilities.voiceCalling) {
                                        omniService?.acceptIncomingCall()
                                    } else {
                                        onRequestPermission(PermissionStage.START_OR_ANSWER_VOICE_CALL)
                                    }
                                },
                                modifier = Modifier.weight(1f).height(48.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00B894)),
                                shape = RoundedCornerShape(14.dp)
                            ) {
                                Text("ACCEPT", color = Color.White, fontWeight = FontWeight.Bold)
                            }
                            Button(
                                onClick = { omniService?.declineIncomingCall() },
                                modifier = Modifier.weight(1f).height(48.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2D2D44)),
                                shape = RoundedCornerShape(14.dp)
                            ) {
                                Text("DECLINE", color = Color.White, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // Tab Body Content
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                when (selectedTab) {
                    0 -> PairedChatsScreen(
                        pairedContacts = pairedContacts,
                        onlinePairedLinks = onlinePairedLinks,
                        messages = persistentMessages,
                        activeChatContact = activeChatContact,
                        onSelectChat = { contact ->
                            activeChatContact = contact
                            omniService?.setActiveConversation(contact?.secretLink)
                        },
                        onSendMessage = { text, targetLink -> omniService?.dispatchMessage(text, targetLink) },
                        onStartCall = { targetLink ->
                            if (permissionPlan.capabilities.voiceCalling) {
                                omniService?.initiateCall(targetLink)
                                selectedTab = 1
                            } else {
                                onRequestPermission(PermissionStage.START_OR_ANSWER_VOICE_CALL)
                            }
                        },
                        onNavigateToSettings = { selectedTab = 2 }
                    )
                    1 -> CallsScreen(
                        omniService = omniService,
                        pairedContacts = pairedContacts,
                        onlinePairedLinks = onlinePairedLinks,
                        isVoiceCallActive = serviceCallActive,
                        isMuted = isMuted,
                        isSpeakerOn = isSpeakerOn,
                        callDurationSec = callDurationSec,
                        onStartCall = { targetLink ->
                            if (permissionPlan.capabilities.voiceCalling) {
                                omniService?.initiateCall(targetLink)
                            } else {
                                onRequestPermission(PermissionStage.START_OR_ANSWER_VOICE_CALL)
                            }
                        },
                        onEndCall = { omniService?.stopVoiceCall() },
                        onToggleMute = { omniService?.toggleMute() },
                        onToggleSpeaker = { omniService?.toggleSpeaker() },
                        onNavigateToSettings = { selectedTab = 2 }
                    )
                    2 -> SettingsScreen(
                        settingsManager = settingsManager,
                        permissionPlan = permissionPlan,
                        accountProfile = accountProfile,
                        onSignOut = onSignOut,
                        onRequestPermission = onRequestPermission,
                        onSettingsUpdated = {
                            refreshTrigger++
                            omniService?.refreshConfiguration()
                        }
                    )
                }
            }

            // Floating Bottom Navigation Bar
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 20.dp, top = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Surface(
                    modifier = Modifier
                        .height(64.dp)
                        .clip(RoundedCornerShape(32.dp))
                        .shadow(12.dp, RoundedCornerShape(32.dp)),
                    color = Color(0xFF1E1C2E)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        PillNavItem(
                            icon = Icons.Default.ChatBubble,
                            label = "Chats",
                            isSelected = selectedTab == 0,
                            onClick = { selectedTab = 0 }
                        )
                        PillNavItem(
                            icon = Icons.Default.Call,
                            label = "Calls",
                            isSelected = selectedTab == 1,
                            onClick = { selectedTab = 1 }
                        )
                        PillNavItem(
                            icon = Icons.Default.Settings,
                            label = "Settings",
                            isSelected = selectedTab == 2,
                            onClick = { selectedTab = 2 }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun PillNavItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxHeight()
            .clip(RoundedCornerShape(24.dp))
            .background(if (isSelected) Color(0xFF6C5CE7) else Color.Transparent)
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp),
        contentAlignment = Alignment.Center
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = if (isSelected) Color.White else Color(0xFF8E8EA8),
                modifier = Modifier.size(20.dp)
            )
            if (isSelected) {
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = label,
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp
                )
            }
        }
    }
}

// ==========================================
// TAB 0: PAIRED CHATS & CONVERSATIONS
// ==========================================
@Composable
fun PairedChatsScreen(
    pairedContacts: List<PairedContact>,
    onlinePairedLinks: Set<String>,
    messages: List<MessageEntity>,
    activeChatContact: PairedContact?,
    onSelectChat: (PairedContact?) -> Unit,
    onSendMessage: (String, String) -> Unit,
    onStartCall: (String) -> Unit,
    onNavigateToSettings: () -> Unit
) {
    var messageText by remember { mutableStateOf("") }

    if (activeChatContact != null) {
        // Individual Chat View
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp)
        ) {
            // Chat Header Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                        IconButton(
                            onClick = { onSelectChat(null) },
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = Color(0xFF1E1C2E))
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Box(
                            modifier = Modifier
                                .size(44.dp)
                                .clip(CircleShape)
                                .background(Brush.linearGradient(listOf(Color(0xFF7C66FF), Color(0xFF6C5CE7)))),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = activeChatContact.name.take(1).uppercase(),
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 18.sp
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(activeChatContact.name, fontWeight = FontWeight.Bold, color = Color(0xFF1E1C2E), fontSize = 15.sp)
                            val isOnline = onlinePairedLinks.contains(activeChatContact.secretLink)
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 2.dp)) {
                                Box(modifier = Modifier.size(6.dp).clip(CircleShape).background(if (isOnline) Color(0xFF00B894) else Color(0xFFB2BEC3)))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(if (isOnline) "Online • E2EE Active" else "Offline • Swarm Queued", color = if (isOnline) Color(0xFF00B894) else Color(0xFF7E7E9A), fontSize = 11.sp)
                            }
                        }
                    }

                    IconButton(
                        onClick = { onStartCall(activeChatContact.secretLink) },
                        modifier = Modifier.size(44.dp).background(Color(0xFFEBE6FF), CircleShape)
                    ) {
                        Icon(Icons.Default.Call, contentDescription = "Call", tint = Color(0xFF6C5CE7), modifier = Modifier.size(20.dp))
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Chat Messages Thread
            val conversationMessages = messages.filter {
                it.contactPublicKey == activeChatContact.secretLink
            }
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(conversationMessages, key = { it.messageId }) { msg ->
                    val isOutgoing = msg.direction == "outgoing"

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = if (isOutgoing) Arrangement.End else Arrangement.Start
                    ) {
                        Surface(
                            modifier = Modifier.widthIn(max = 280.dp),
                            shape = RoundedCornerShape(
                                topStart = 20.dp,
                                topEnd = 20.dp,
                                bottomStart = if (isOutgoing) 20.dp else 4.dp,
                                bottomEnd = if (isOutgoing) 4.dp else 20.dp
                            ),
                            color = if (isOutgoing) Color(0xFF6C5CE7) else Color.White,
                            shadowElevation = 1.dp
                        ) {
                            Column(modifier = Modifier.padding(14.dp)) {
                                Text(
                                    text = msg.body,
                                    color = if (isOutgoing) Color.White else Color(0xFF1E1C2E),
                                    fontSize = 14.sp
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = if (isOutgoing) {
                                        when (msg.status) {
                                            "queued" -> "Queued"
                                            "sent" -> "✓ Sent"
                                            "delivered" -> "✓ Delivered"
                                            "read" -> "✓✓ Read"
                                            else -> msg.status
                                        }
                                    } else "✓ Received",
                                    color = if (isOutgoing) Color.White.copy(alpha = 0.7f) else Color(0xFF9E9EB8),
                                    fontSize = 9.sp,
                                    modifier = Modifier.align(Alignment.End)
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Message Input Bar
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 76.dp),
                shape = RoundedCornerShape(28.dp),
                color = Color.White,
                shadowElevation = 4.dp
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = messageText,
                        onValueChange = { messageText = it },
                        placeholder = { Text("Type an encrypted message...", color = Color(0xFF9E9EB8), fontSize = 14.sp) },
                        modifier = Modifier.weight(1f),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color.Transparent,
                            unfocusedBorderColor = Color.Transparent,
                            focusedTextColor = Color(0xFF1E1C2E),
                            unfocusedTextColor = Color(0xFF1E1C2E)
                        ),
                        singleLine = true
                    )

                    IconButton(
                        onClick = {
                            if (messageText.isNotBlank()) {
                                onSendMessage(messageText, activeChatContact.secretLink)
                                messageText = ""
                            }
                        },
                        modifier = Modifier
                            .size(46.dp)
                            .background(Color(0xFF6C5CE7), CircleShape)
                    ) {
                        Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send", tint = Color.White, modifier = Modifier.size(18.dp))
                    }
                }
            }
        }
    } else {
        // Paired Contacts List View
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "PAIRED CONTACTS",
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF7E7E9A),
                        fontSize = 12.sp,
                        letterSpacing = 1.sp
                    )

                    TextButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Default.PersonAdd, contentDescription = null, tint = Color(0xFF6C5CE7), modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("+ Pair Link", color = Color(0xFF6C5CE7), fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                }
            }

            if (pairedContacts.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth().padding(top = 20.dp),
                        shape = RoundedCornerShape(22.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(32.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(60.dp)
                                    .clip(CircleShape)
                                    .background(Color(0xFFEBE6FF)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.VpnKey, contentDescription = null, tint = Color(0xFF6C5CE7), modifier = Modifier.size(28.dp))
                            }
                            Spacer(modifier = Modifier.height(16.dp))
                            Text("No Mutual Contacts Paired", fontWeight = FontWeight.Bold, color = Color(0xFF1E1C2E), fontSize = 16.sp)
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "Exchange Secret Links in Settings. Delivery uses the internet relay when available or nearby peer-to-peer radio.",
                                color = Color(0xFF7E7E9A),
                                fontSize = 12.sp,
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center
                            )
                            Spacer(modifier = Modifier.height(20.dp))
                            Button(
                                onClick = onNavigateToSettings,
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6C5CE7)),
                                shape = RoundedCornerShape(14.dp)
                            ) {
                                Text("Go to Settings & Add Link", color = Color.White, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            } else {
                items(pairedContacts) { contact ->
                    val isOnline = onlinePairedLinks.contains(contact.secretLink)
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelectChat(contact) },
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                                Box(
                                    modifier = Modifier
                                        .size(48.dp)
                                        .clip(CircleShape)
                                        .background(Brush.linearGradient(listOf(Color(0xFF7C66FF), Color(0xFF6C5CE7)))),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(contact.name.take(1).uppercase(), color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                                }
                                Spacer(modifier = Modifier.width(14.dp))
                                Column {
                                    Text(contact.name, fontWeight = FontWeight.Bold, color = Color(0xFF1E1C2E), fontSize = 15.sp)
                                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 4.dp)) {
                                        Box(modifier = Modifier.size(6.dp).clip(CircleShape).background(if (isOnline) Color(0xFF00B894) else Color(0xFFB2BEC3)))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(if (isOnline) "Online • Reachable" else "Offline", color = if (isOnline) Color(0xFF00B894) else Color(0xFF7E7E9A), fontSize = 11.sp)
                                    }
                                }
                            }

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                IconButton(
                                    onClick = { onSelectChat(contact) },
                                    modifier = Modifier.size(40.dp).background(Color(0xFFEBE6FF), CircleShape)
                                ) {
                                    Icon(Icons.Default.ChatBubble, contentDescription = "Chat", tint = Color(0xFF6C5CE7), modifier = Modifier.size(18.dp))
                                }

                                IconButton(
                                    onClick = { onStartCall(contact.secretLink) },
                                    modifier = Modifier.size(40.dp).background(if (isOnline) Color(0xFF00B894) else Color(0xFFDFE6E9), CircleShape)
                                ) {
                                    Icon(Icons.Default.Call, contentDescription = "Call", tint = Color.White, modifier = Modifier.size(18.dp))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ==========================================
// TAB 1: CALLS & HD VOICE CONTROLLER
// ==========================================
@Composable
fun CallsScreen(
    omniService: OmniRelayService?,
    pairedContacts: List<PairedContact>,
    onlinePairedLinks: Set<String>,
    isVoiceCallActive: Boolean,
    isMuted: Boolean,
    isSpeakerOn: Boolean,
    callDurationSec: Int,
    onStartCall: (String) -> Unit,
    onEndCall: () -> Unit,
    onToggleMute: () -> Unit,
    onToggleSpeaker: () -> Unit,
    onNavigateToSettings: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Active Voice Call Card Controller
        if (isVoiceCallActive) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(26.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1C2E)),
                    elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Surface(
                                shape = RoundedCornerShape(10.dp),
                                color = Color(0xFF6C5CE7).copy(alpha = 0.3f)
                            ) {
                                Text(
                                    text = "E2EE ADAPTIVE VOICE",
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFFB4A7FA),
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                )
                            }
                            val minutes = callDurationSec / 60
                            val seconds = callDurationSec % 60
                            Text(
                                String.format(Locale.US, "%02d:%02d", minutes, seconds),
                                color = Color.White,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 16.sp
                            )
                        }

                        Spacer(modifier = Modifier.height(20.dp))

                        Box(
                            modifier = Modifier
                                .size(70.dp)
                                .clip(CircleShape)
                                .background(Brush.linearGradient(listOf(Color(0xFF7C66FF), Color(0xFF6C5CE7)))),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.Mic, contentDescription = null, tint = Color.White, modifier = Modifier.size(32.dp))
                        }

                        Spacer(modifier = Modifier.height(12.dp))
                        Text("ACTIVE SECURE CALL", color = Color(0xFF8E8EA8), fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)

                        Spacer(modifier = Modifier.height(20.dp))

                        // Waveform Animation Bars
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(36.dp),
                            horizontalArrangement = Arrangement.SpaceEvenly,
                            verticalAlignment = Alignment.Bottom
                        ) {
                            repeat(16) { idx ->
                                val heightRatio by rememberInfiniteTransition(label = "Wave").animateFloat(
                                    initialValue = 0.25f + (idx % 4) * 0.15f,
                                    targetValue = 0.9f - (idx % 3) * 0.2f,
                                    animationSpec = infiniteRepeatable(
                                        animation = tween(220 + idx * 30, easing = LinearEasing),
                                        repeatMode = RepeatMode.Reverse
                                    ),
                                    label = "Bar"
                                )
                                Box(
                                    modifier = Modifier
                                        .width(5.dp)
                                        .fillMaxHeight(heightRatio)
                                        .clip(RoundedCornerShape(3.dp))
                                        .background(Color(0xFF6C5CE7))
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(28.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceEvenly
                        ) {
                            IconButton(
                                onClick = onToggleMute,
                                modifier = Modifier
                                    .size(52.dp)
                                    .background(if (isMuted) Color(0xFFFF7675) else Color(0xFF2D2D40), CircleShape)
                            ) {
                                Icon(if (isMuted) Icons.Default.MicOff else Icons.Default.Mic, contentDescription = null, tint = Color.White)
                            }

                            IconButton(
                                onClick = onToggleSpeaker,
                                modifier = Modifier
                                    .size(52.dp)
                                    .background(if (isSpeakerOn) Color(0xFF6C5CE7) else Color(0xFF2D2D40), CircleShape)
                            ) {
                                Icon(if (isSpeakerOn) Icons.AutoMirrored.Filled.VolumeUp else Icons.AutoMirrored.Filled.VolumeOff, contentDescription = null, tint = Color.White)
                            }

                            IconButton(
                                onClick = onEndCall,
                                modifier = Modifier
                                    .size(52.dp)
                                    .background(Color(0xFFD63031), CircleShape)
                            ) {
                                Icon(Icons.Default.CallEnd, contentDescription = null, tint = Color.White)
                            }
                        }
                    }
                }
            }
        }

        item {
            Text(
                text = "PAIRED CONTACTS",
                fontWeight = FontWeight.Bold,
                color = Color(0xFF7E7E9A),
                fontSize = 12.sp,
                letterSpacing = 1.sp
            )
        }

        val reachableContacts = pairedContacts

        if (reachableContacts.isEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(22.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(28.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(Icons.AutoMirrored.Filled.PhoneMissed, contentDescription = null, tint = Color(0xFFB2BEC3), modifier = Modifier.size(44.dp))
                        Spacer(modifier = Modifier.height(12.dp))
                        Text("No Paired Contacts", fontWeight = FontWeight.Bold, color = Color(0xFF1E1C2E), fontSize = 15.sp)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Add a mutual Secret Link to call over internet relay or nearby radio.",
                            color = Color(0xFF7E7E9A),
                            fontSize = 12.sp,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                    }
                }
            }
        } else {
            items(reachableContacts) { contact ->
                val isNearby = onlinePairedLinks.contains(contact.secretLink)
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                            Box(
                                modifier = Modifier
                                    .size(46.dp)
                                    .clip(CircleShape)
                                    .background(Color(0xFFEBE6FF)),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(contact.name.take(1).uppercase(), color = Color(0xFF6C5CE7), fontWeight = FontWeight.Bold, fontSize = 16.sp)
                            }
                            Spacer(modifier = Modifier.width(14.dp))
                            Column {
                                Text(contact.name, fontWeight = FontWeight.Bold, color = Color(0xFF1E1C2E), fontSize = 15.sp)
                                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 2.dp)) {
                                    Box(modifier = Modifier.size(6.dp).clip(CircleShape).background(if (isNearby) Color(0xFF00B894) else Color(0xFF6C5CE7)))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        if (isNearby) "Nearby • High Signal" else "Internet relay • Ring or queue",
                                        color = if (isNearby) Color(0xFF00B894) else Color(0xFF6C5CE7),
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }

                        Button(
                            onClick = { onStartCall(contact.secretLink) },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00B894)),
                            shape = RoundedCornerShape(14.dp)
                        ) {
                            Icon(Icons.Default.Call, contentDescription = null, tint = Color.White, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("CALL", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}

// ==========================================
// TAB 2: PROFESSIONAL SETTINGS & PAIRING
// ==========================================
@Composable
fun SettingsScreen(
    settingsManager: SettingsManager,
    permissionPlan: CapabilityPlan,
    accountProfile: GoogleAccountProfile,
    onSignOut: () -> Unit,
    onRequestPermission: (PermissionStage) -> Unit,
    onSettingsUpdated: () -> Unit
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val myLink = settingsManager.getMySecretLink()
    val pairedContacts = settingsManager.getPairedContacts()

    var nameInput by remember { mutableStateOf("") }
    var linkInput by remember { mutableStateOf("") }

    var bleChecked by remember { mutableStateOf(settingsManager.isBleEnabled) }
    var wifiChecked by remember { mutableStateOf(settingsManager.isWifiAwareEnabled) }
    var relayChecked by remember { mutableStateOf(settingsManager.isRelayModeEnabled) }
    var meshRelayChecked by remember { mutableStateOf(settingsManager.isMeshRelayEnabled) }
    var resourceTier by remember { mutableStateOf(settingsManager.resourceTier) }

    var noiseSuppressionChecked by remember { mutableStateOf(settingsManager.isNoiseSuppressionEnabled) }
    var echoCancellationChecked by remember { mutableStateOf(settingsManager.isEchoCancellationEnabled) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text(
                text = "GOOGLE ACCOUNT",
                fontWeight = FontWeight.Bold,
                color = Color(0xFF7E7E9A),
                fontSize = 12.sp,
                letterSpacing = 1.sp
            )
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(18.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier.size(44.dp).background(Color(0xFFEBE6FF), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            accountProfile.displayName.take(1).uppercase(Locale.getDefault()),
                            color = Color(0xFF6C5CE7),
                            fontWeight = FontWeight.Black
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(accountProfile.displayName, color = Color(0xFF1E1C2E), fontWeight = FontWeight.Bold)
                        accountProfile.email?.let {
                            Text(it, color = Color(0xFF7E7E9A), fontSize = 11.sp, maxLines = 1)
                        }
                        Text("Device identity bound to verified account", color = Color(0xFF00A884), fontSize = 10.sp)
                    }
                    TextButton(onClick = onSignOut) {
                        Icon(Icons.Default.Logout, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(5.dp))
                        Text("SIGN OUT", fontWeight = FontWeight.Bold, fontSize = 11.sp)
                    }
                }
            }
        }

        if (permissionPlan.permissionGroups.isNotEmpty()) {
            item {
                Text(
                    text = "FEATURE PERMISSIONS",
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF7E7E9A),
                    fontSize = 12.sp,
                    letterSpacing = 1.sp
                )
            }
            items(permissionPlan.permissionGroups, key = { it.stage.name }) { group ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(group.title, fontWeight = FontWeight.Bold, color = Color(0xFF1E1C2E), fontSize = 14.sp)
                            Spacer(Modifier.height(4.dp))
                            Text(group.rationale, color = Color(0xFF7E7E9A), fontSize = 11.sp, maxLines = 3)
                        }
                        Spacer(Modifier.width(12.dp))
                        TextButton(onClick = { onRequestPermission(group.stage) }) {
                            Text("ENABLE", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        // Section: Identity & Secret Link
        item {
            Text(
                text = "YOUR IDENTITY & SECRET LINK",
                fontWeight = FontWeight.Bold,
                color = Color(0xFF7E7E9A),
                fontSize = 12.sp,
                letterSpacing = 1.sp
            )
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text("Your Secret Link", color = Color(0xFF1E1C2E), fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Text("Share this secret key with your contact so they can pair with you.", color = Color(0xFF7E7E9A), fontSize = 12.sp)

                    Spacer(modifier = Modifier.height(14.dp))

                    Surface(
                        shape = RoundedCornerShape(14.dp),
                        color = Color(0xFFF3F2F8),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(14.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = myLink.take(24) + "...",
                                color = Color(0xFF1E1C2E),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 13.sp,
                                modifier = Modifier.weight(1f)
                            )
                            Button(
                                onClick = {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                    val clip = android.content.ClipData.newPlainText("Secret Link", myLink)
                                    clipboard.setPrimaryClip(clip)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6C5CE7)),
                                shape = RoundedCornerShape(10.dp),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                            ) {
                                Icon(Icons.Default.ContentCopy, contentDescription = "Copy", tint = Color.White, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("COPY", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }

        // Section: Pair New Contact
        item {
            Text(
                text = "PAIR NEW MUTUAL CONTACT",
                fontWeight = FontWeight.Bold,
                color = Color(0xFF7E7E9A),
                fontSize = 12.sp,
                letterSpacing = 1.sp
            )
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text("Add Contact's Secret Link", color = Color(0xFF1E1C2E), fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = nameInput,
                        onValueChange = { nameInput = it },
                        placeholder = { Text("Contact Name (e.g. Receiver Phone)", color = Color(0xFFB2BEC3), fontSize = 13.sp) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp)
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = linkInput,
                        onValueChange = { linkInput = it },
                        placeholder = { Text("Paste Secret Link...", color = Color(0xFFB2BEC3), fontSize = 13.sp) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp)
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    Button(
                        onClick = {
                            if (settingsManager.addPairedContact(nameInput, linkInput)) {
                                nameInput = ""
                                linkInput = ""
                                onSettingsUpdated()
                            }
                        },
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6C5CE7)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Default.PersonAdd, contentDescription = null, tint = Color.White, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("PAIR & ADD CONTACT", color = Color.White, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // Section: Paired Contacts List
        item {
            Text(
                text = "PAIRED CONTACTS SWARM (${pairedContacts.size})",
                fontWeight = FontWeight.Bold,
                color = Color(0xFF7E7E9A),
                fontSize = 12.sp,
                letterSpacing = 1.sp
            )
        }

        if (pairedContacts.isEmpty()) {
            item {
                Text("No paired contacts added yet.", color = Color(0xFF7E7E9A), fontSize = 13.sp)
            }
        } else {
            items(pairedContacts) { contact ->
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    color = Color.White,
                    shadowElevation = 1.dp
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                            Icon(Icons.Default.Lock, contentDescription = null, tint = Color(0xFF00B894), modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(contact.name, fontWeight = FontWeight.Bold, color = Color(0xFF1E1C2E), fontSize = 14.sp)
                                Text(contact.secretLink.take(16) + "...", color = Color(0xFF7E7E9A), fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                            }
                        }

                        IconButton(
                            onClick = {
                                settingsManager.removePairedContact(contact.secretLink)
                                onSettingsUpdated()
                            },
                            modifier = Modifier.size(36.dp).background(Color(0xFFFF7675).copy(alpha = 0.15f), CircleShape)
                        ) {
                            Icon(Icons.Default.Delete, contentDescription = "Remove", tint = Color(0xFFFF7675), modifier = Modifier.size(18.dp))
                        }
                    }
                }
            }
        }

        // Section: Connection & Protocol Options (Restored!)
        item {
            Text(
                text = "NETWORK & ROUTING PROTOCOLS",
                fontWeight = FontWeight.Bold,
                color = Color(0xFF7E7E9A),
                fontSize = 12.sp,
                letterSpacing = 1.sp
            )
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Bluetooth LE + GATT", color = Color(0xFF1E1C2E), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Filtered low-power discovery and encrypted data", color = Color(0xFF7E7E9A), fontSize = 11.sp)
                        }
                        Switch(
                            checked = bleChecked,
                            onCheckedChange = {
                                bleChecked = it
                                settingsManager.isBleEnabled = it
                                if (it && !permissionPlan.capabilities.bluetoothRelay) {
                                    permissionPlan.permissionGroups.firstOrNull { group ->
                                        group.stage == PermissionStage.ENABLE_BLUETOOTH_NEARBY ||
                                            group.stage == PermissionStage.ENABLE_LEGACY_BLUETOOTH_DISCOVERY ||
                                            group.stage == PermissionStage.ENABLE_LEGACY_NEARBY_DISCOVERY
                                    }?.let { group -> onRequestPermission(group.stage) }
                                }
                                onSettingsUpdated()
                            },
                            colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = Color(0xFF6C5CE7))
                        )
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp), color = Color(0xFFF3F2F8))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Wi-Fi Aware (NAN)", color = Color(0xFF1E1C2E), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Nearby discovery and encrypted signaling", color = Color(0xFF7E7E9A), fontSize = 11.sp)
                        }
                        Switch(
                            checked = wifiChecked,
                            onCheckedChange = {
                                wifiChecked = it
                                settingsManager.isWifiAwareEnabled = it
                                if (it && !permissionPlan.capabilities.wifiAware) {
                                    permissionPlan.permissionGroups.firstOrNull { group ->
                                        group.stage == PermissionStage.ENABLE_WIFI_AWARE ||
                                            group.stage == PermissionStage.ENABLE_LEGACY_NEARBY_DISCOVERY
                                    }?.let { group -> onRequestPermission(group.stage) }
                                }
                                onSettingsUpdated()
                            },
                            colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = Color(0xFF6C5CE7))
                        )
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp), color = Color(0xFFF3F2F8))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Internet Relay & Durable Queue", color = Color(0xFF1E1C2E), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Instant WebSocket delivery with encrypted retry mailbox", color = Color(0xFF7E7E9A), fontSize = 11.sp)
                        }
                        Switch(
                            checked = relayChecked,
                            onCheckedChange = {
                                relayChecked = it
                                settingsManager.isRelayModeEnabled = it
                                onSettingsUpdated()
                            },
                            colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = Color(0xFF6C5CE7))
                        )
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp), color = Color(0xFFF3F2F8))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Private Multi-Hop Volunteer", color = Color(0xFF1E1C2E), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Opt in to forward padded opaque capsules; voice is never relayed", color = Color(0xFF7E7E9A), fontSize = 11.sp)
                        }
                        Switch(
                            checked = meshRelayChecked,
                            onCheckedChange = {
                                meshRelayChecked = it
                                settingsManager.isMeshRelayEnabled = it
                                if (it && resourceTier == UserResourceTier.MINIMAL) {
                                    resourceTier = UserResourceTier.BALANCED
                                    settingsManager.resourceTier = resourceTier
                                }
                                onSettingsUpdated()
                            },
                            colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = Color(0xFF6C5CE7))
                        )
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp), color = Color(0xFFF3F2F8))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Resource Profile", color = Color(0xFF1E1C2E), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Controls battery, heat, data budget, and maximum relay hops", color = Color(0xFF7E7E9A), fontSize = 11.sp)
                        }
                        TextButton(onClick = {
                            val tiers = UserResourceTier.entries
                            resourceTier = tiers[(resourceTier.ordinal + 1) % tiers.size]
                            settingsManager.resourceTier = resourceTier
                            onSettingsUpdated()
                        }) {
                            Text(resourceTier.name, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                        }
                    }
                }
            }
        }

        // Section: Audio & Voice Hardware Options
        item {
            Text(
                text = "AUDIO & VOICE HARDWARE ENGINE",
                fontWeight = FontWeight.Bold,
                color = Color(0xFF7E7E9A),
                fontSize = 12.sp,
                letterSpacing = 1.sp
            )
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Hardware Noise Suppression", color = Color(0xFF1E1C2E), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Filter background wind & room noise", color = Color(0xFF7E7E9A), fontSize = 11.sp)
                        }
                        Switch(
                            checked = noiseSuppressionChecked,
                            onCheckedChange = {
                                noiseSuppressionChecked = it
                                settingsManager.isNoiseSuppressionEnabled = it
                                onSettingsUpdated()
                            },
                            colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = Color(0xFF6C5CE7))
                        )
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp), color = Color(0xFFF3F2F8))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Acoustic Echo Cancellation", color = Color(0xFF1E1C2E), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Prevent speaker feedback loop during call", color = Color(0xFF7E7E9A), fontSize = 11.sp)
                        }
                        Switch(
                            checked = echoCancellationChecked,
                            onCheckedChange = {
                                echoCancellationChecked = it
                                settingsManager.isEchoCancellationEnabled = it
                                onSettingsUpdated()
                            },
                            colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = Color(0xFF6C5CE7))
                        )
                    }
                }
            }
        }

        item { Spacer(modifier = Modifier.height(90.dp)) }
    }
}
