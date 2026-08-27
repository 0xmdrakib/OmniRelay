# Setup and deployment

This guide covers local two-phone testing, self-hosted production deployment,
Android release configuration, and automated checks.

[Back to README](../README.md) · [Architecture](PRODUCTION_ARCHITECTURE.md) ·
[Release checklist](RELEASE_CHECKLIST.md)

## Prerequisites

- Git access to the private repository
- JDK 17 and Android SDK 36 for Android builds; use the included Gradle wrapper
- Docker with Compose for the backend, database, LiveKit, and coturn
- PowerShell for the commands below; use PowerShell 7 on a Linux server
- Node.js 24 and the pnpm version pinned in `backend/package.json` for backend
  development and tests outside Docker
- Two physical Android 8.0+ phones for end-to-end tests; nearby mode depends on
  each device's BLE/Wi-Fi Aware support

Run commands from the repository root unless a section says otherwise. Replace
all `YOUR_...` values and example domains with your own configuration.

## Local server

### 1. Prepare the configuration

On a fresh checkout, copy the configuration template:

```powershell
Copy-Item .env.example .env
```

Do not overwrite an existing `.env`: it may contain deployment secrets. Replace
every `CHANGE_ME` value with a strong, unique value. For LAN testing, also set:

```dotenv
PUBLIC_HOST=YOUR_PC_IP
LIVEKIT_PUBLIC_URL=ws://YOUR_PC_IP:7880
BACKEND_BIND_ADDRESS=0.0.0.0
LIVEKIT_HTTP_BIND_ADDRESS=0.0.0.0
TRUST_PROXY=false
```

`YOUR_PC_IP` must be the host's LAN address reachable from both phones, not
`127.0.0.1`. Set `TURN_REALM` to your chosen TURN realm. Leave
`FIREBASE_SERVICE_ACCOUNT_JSON` empty if testing without push wake-ups.

### 2. Render LiveKit configuration

Use the same host, API key, and secrets that you placed in `.env`:

```powershell
./deploy/render-config.ps1 `
  -PublicHost 'YOUR_PC_IP' `
  -LiveKitApiKey 'YOUR_LIVEKIT_API_KEY' `
  -LiveKitApiSecret 'YOUR_LIVEKIT_API_SECRET' `
  -TurnSharedSecret 'YOUR_TURN_SHARED_SECRET'
```

The generated `deploy/livekit.generated.yaml` is ignored by Git. Keep it and
`.env` private. Commands containing actual secrets can be retained in shell
history; do not share terminal recordings or logs containing those values.

### 3. Start and check the services

```powershell
docker compose up -d --build
Invoke-RestMethod http://127.0.0.1:8080/healthz
docker compose ps
```

Keep the host and Docker running throughout the test. Allow the required ports
on the private LAN only:

| Service | Ports |
| --- | --- |
| Relay HTTP/WebSocket | TCP 8080 |
| LiveKit signaling and media | TCP 7880, 7881; UDP 50000–50100 |
| TURN | UDP 3478, 49160–49200 |

The coturn service uses host networking in [compose.yaml](../compose.yaml).
Verify that the test host's Docker networking and firewall expose the UDP path
to both phones; a healthy HTTP endpoint alone does not verify call media.

## LAN test APK

With JDK 17 selected, build an APK for the same LAN host:

```powershell
./gradlew.bat assembleDebug -POMNIRELAY_BACKEND_URL=http://YOUR_PC_IP:8080
```

On Linux or macOS, use `./gradlew` instead of `./gradlew.bat`. The APK is written
to `app/build/outputs/apk/debug/app-debug.apk` and is intentionally excluded
from Git.

1. Install the APK on both phones and connect them to the reachable LAN.
2. Grant the requested notification, microphone, and nearby-device permissions.
3. Copy each phone's Secret Link from Settings and add it as a contact on the
   other phone. Both phones must add each other.
4. Test messaging, delivery states, incoming calls, and two-way audio.
5. Test nearby transport separately with internet disabled, then work through
   the remaining [device-validation checklist](RELEASE_CHECKLIST.md#device-validation).

The default backend URL is `https://relay.example.invalid`. CI APKs built with
that default are build artifacts, not configured internet-test clients. Build
with your reachable backend URL before testing relay delivery.

## Production deployment

Use a maintained public Linux host with Docker Compose and PowerShell 7. Run
these steps from a checkout on that server, not on a PC that will be switched
off after testing.

### 1. Configure DNS and generate secrets

Point your relay and LiveKit DNS names at the public server. On a checkout
without an existing `.env`, run:

```powershell
./deploy/initialize-production.ps1 `
  -PublicIp 'YOUR_PUBLIC_IP' `
  -RelayDomain 'relay.example.com' `
  -LiveKitDomain 'livekit.example.com'
```

The script generates random database, LiveKit, and TURN credentials and creates
the ignored `.env` and LiveKit configuration. It refuses to overwrite an
existing `.env`; preserve existing deployment secrets when updating a server.

### 2. Configure Firebase push delivery

Create a Firebase Android app for the intended application ID. Configure both
sides using the same Firebase project:

- **Server:** Put the service-account JSON on one line in the server `.env` as
  `FIREBASE_SERVICE_ACCOUNT_JSON`. This private credential stays on the server.
- **Android:** Provide the four client values shown under
  [Android release configuration](#android-release-configuration).

Without this configuration, HTTP/WebSocket delivery remains available, but
FCM wake-ups are disabled. Background delivery must be tested with real devices,
Firebase credentials, and the applicable Android battery restrictions.

### 3. Open the required ports and start the stack

Allow TCP 80, 443, and 7881, plus UDP 3478, 49160–49200, and 50000–50100.
Keep relay port 8080 and LiveKit signaling port 7880 bound to loopback in
production; Caddy fronts them with TLS.

```powershell
./deploy/start-production.ps1
Invoke-RestMethod https://relay.example.com/healthz
```

The script validates Compose configuration, starts the production profile,
and checks local relay health. Caddy handles certificates for the configured
domains when DNS and network access are ready. Verify public HTTPS separately;
local health does not prove public TLS, FCM, TURN, or two-way audio works.

Set up encrypted database backups, a tested restore procedure, uptime and disk
monitoring, and credential recovery before accepting production traffic.

## Android release configuration

Before publishing, choose a permanent application ID to replace
`com.example.omnirelay`, update the Firebase app registration accordingly, and
create a release keystore with a secure backup.

Store build values in your **user-level** Gradle properties, such as
`%USERPROFILE%/.gradle/gradle.properties` on Windows or
`~/.gradle/gradle.properties` on Linux/macOS, never in the repository's
`gradle.properties`:

```properties
OMNIRELAY_BACKEND_URL=https://relay.example.com
OMNIRELAY_FIREBASE_API_KEY=YOUR_FIREBASE_API_KEY
OMNIRELAY_FIREBASE_APP_ID=YOUR_FIREBASE_APP_ID
OMNIRELAY_FIREBASE_PROJECT_ID=YOUR_FIREBASE_PROJECT_ID
OMNIRELAY_FIREBASE_SENDER_ID=YOUR_FIREBASE_SENDER_ID
OMNIRELAY_KEYSTORE_FILE=C:/secure/omnirelay-release.jks
OMNIRELAY_KEYSTORE_PASSWORD=YOUR_KEYSTORE_PASSWORD
OMNIRELAY_KEY_ALIAS=YOUR_KEY_ALIAS
OMNIRELAY_KEY_PASSWORD=YOUR_KEY_PASSWORD
```

Use an absolute keystore path appropriate for the build machine. Restrict access
to the keystore and user-level properties file. The app initializes Firebase
from the four Gradle values; do not commit service-account credentials or
Firebase configuration files.

Build the release APK and Android App Bundle:

```powershell
./gradlew.bat assembleRelease bundleRelease
```

Outputs are placed under `app/build/outputs/apk/release/` and
`app/build/outputs/bundle/release/`. Without the signing properties, the release
build is unsigned. Verify the signing certificate and complete the
[release checklist](RELEASE_CHECKLIST.md) before distributing an artifact.

## Tests

### Android

```powershell
./gradlew.bat testDebugUnitTest lintDebug assembleDebug assembleRelease --no-daemon
```

### Backend

From the repository root, use Node.js 24 and activate the pinned package manager:

```powershell
corepack enable
cd backend
pnpm install --frozen-lockfile
pnpm typecheck
pnpm build
pnpm test:unit
pnpm audit --prod
```

For integration tests, keep the local server and PostgreSQL running. While
still in `backend`, set the endpoint and expected LiveKit URL for that server:

```powershell
$env:INTEGRATION_BASE_URL='http://127.0.0.1:8080'
$env:EXPECTED_LIVEKIT_URL='ws://YOUR_PC_IP:7880'
pnpm test:integration
```

`INTEGRATION_BASE_URL` must be set; otherwise the integration test is skipped.
These tests exercise backend registration, message delivery, acknowledgements,
and call signaling/token authorization, not physical radios or live microphone
audio. See the [CI workflow](../.github/workflows/ci.yml) for the automated checks.
