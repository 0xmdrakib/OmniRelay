# Setup and deployment

This guide covers local two/three-phone testing, self-hosted production deployment,
Android release configuration, and automated checks.

[Back to README](../README.md) · [Architecture](PRODUCTION_ARCHITECTURE.md) ·
[Release checklist](RELEASE_CHECKLIST.md)

## Prerequisites

- Git
- JDK 17 and Android SDK 36 for Android builds; use the included Gradle wrapper
- Docker with Compose for the backend, database, LiveKit, and coturn
- PowerShell for the commands below; use PowerShell 7 on a Linux server
- Node.js 24 and the pnpm version pinned in `backend/package.json` for backend
  development and tests outside Docker
- Node.js 22–24 and the package manager pinned in `website/package.json` for the
  isolated public-site build
- Two physical Android 8.0+ phones for end-to-end tests; nearby mode depends on
  each device's BLE/Wi-Fi Aware support. Use three phones to validate volunteer
  opportunistic forwarding behavior.

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
`127.0.0.1`. Set `TURN_REALM` to your chosen TURN realm. Google login is now a
required account gate, so set a real `FIREBASE_SERVICE_ACCOUNT_JSON` before
testing internet registration. Missing Admin configuration leaves health checks
available but rejects every new registration token.

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
./gradlew.bat assembleDebug `
  -POMNIRELAY_BACKEND_URL=http://YOUR_PC_IP:8080 `
  -POMNIRELAY_FIREBASE_API_KEY=YOUR_FIREBASE_API_KEY `
  -POMNIRELAY_FIREBASE_APP_ID=YOUR_FIREBASE_APP_ID `
  -POMNIRELAY_FIREBASE_PROJECT_ID=YOUR_FIREBASE_PROJECT_ID `
  -POMNIRELAY_FIREBASE_SENDER_ID=YOUR_FIREBASE_SENDER_ID `
  -POMNIRELAY_GOOGLE_WEB_CLIENT_ID=YOUR_WEB_OAUTH_CLIENT_ID
```

On Linux or macOS, use `./gradlew` instead of `./gradlew.bat`. The APK is written
to `app/build/outputs/apk/debug/app-debug.apk` and is intentionally excluded
from Git.

1. Install the APK on both phones, connect them to the reachable LAN, and sign
   in with an authorized Google account on each device.
2. Invoke each feature and grant its notification, microphone, Bluetooth, or
   Wi-Fi permission when requested. OmniRelay deliberately does not request all
   permissions at first launch; denial should disable only the affected feature.
3. Copy each phone's Secret Link from Settings and add it as a contact on the
   other phone. Both phones must add each other. While online, each phone then
   synchronizes its hashed inbound route authorizations; an identity that was
   merely registered cannot send to the mailbox.
4. Test messaging, delivery states, incoming calls, and two-way audio.
5. Test nearby transport separately with internet disabled, then work through
   the remaining [device-validation checklist](RELEASE_CHECKLIST.md#device-validation).

The first successful Google sign-in is bound to the local cryptographic device
identity using Android Keystore. Signing out removes the relay session but does
not remove that ownership binding. A different Google account is refused so it
cannot inherit local contacts or message history; changing ownership requires an
explicit app-data reset, which also destroys the local Secret Link and unrecovered data.

For a three-phone relay test, opt the middle phone into **Volunteer nearby
relay**, select BALANCED or GENEROUS, and keep sender and receiver outside direct
radio reach while each can simultaneously reach the middle phone. Test text and call signaling;
live audio is intentionally not carried by a third-party phone. The volunteer
setting is off by default and remains disabled in MINIMAL mode. The current
volunteer path does not persist capsules after the immediate forwarding attempt.

On API 29+, Wi-Fi Aware can establish an on-demand pair-authenticated NDP socket;
API 26–28 uses encrypted follow-up fallback. An established NDP carries lossless
16 kHz PCM voice, while BLE uses ADPCM. Do not make production throughput or
battery claims until the physical-device NDP release gate passes.

The default backend URL is `https://relay.example.invalid`. CI APKs built with
that default are build artifacts, not configured internet-test clients. Build
with your reachable backend URL before testing relay delivery.

Wire protocol v2 deliberately rejects vulnerable v1 frames. Upgrade both phones
and the backend together. Stale v1 outbox records fail terminally instead of
retrying or downgrading; clear pre-release test history when starting a clean run.

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

### 2. Configure required Firebase Authentication and push delivery

Create a Firebase Android app for the intended application ID. In Firebase
Authentication, enable the Google provider. Register both debug and release
SHA-1/SHA-256 certificate fingerprints and create a Web OAuth client ID. Configure
both sides using the same Firebase project:

- **Server:** Put the complete service-account JSON on one line in the server
  `.env` as `FIREBASE_SERVICE_ACCOUNT_JSON`. This private credential stays on
  the server and verifies Firebase ID tokens as well as sending FCM wake-ups.
- **Android:** Provide the five client values shown under
  [Android release configuration](#android-release-configuration).

Without the Android values, the app fails closed on its configuration screen.
Without the server service account, cryptographic device registration returns
`401` and internet relay delivery cannot begin. Background delivery must be
tested with real devices, Firebase credentials, and applicable battery restrictions.

### 3. Open the required ports and start the stack

Allow TCP 80, 443, and 7881, plus UDP 3478, 49160–49200, and 50000–50100.
Keep relay port 8080 and LiveKit signaling port 7880 bound to loopback in
production; Caddy fronts them with TLS.

```powershell
./deploy/start-production.ps1
Invoke-RestMethod https://relay.example.com/readyz
```

The script validates Compose configuration, starts the production profile,
and checks local relay health. Caddy handles certificates for the configured
domains when DNS and network access are ready. Verify public HTTPS separately;
Liveness remains available at `/healthz`; `/readyz` fails until PostgreSQL and
Firebase account registration are configured. Readiness still does not prove
public TLS, FCM delivery, TURN, or two-way audio works.

Set up encrypted database backups, a tested restore procedure, uptime and disk
monitoring, and credential recovery before accepting production traffic.

### Low-cost host profile

The generated configuration starts conservatively: four PostgreSQL pool
connections, 64 admitted HTTP requests, 768 TCP connections, 512 WebSockets,
four active plus 256 queued FCM jobs, 100 pending envelopes per sender/recipient
pair, four outstanding registration challenges per identity, a 120-second active
call lease, 16 challenges per verified account, finite query/request timeouts,
and 500-row cleanup batches every 15 minutes.
These controls protect a small server from unlimited queues; they are not a
universal capacity estimate.

Keep the defaults for initial private testing. Measure CPU, memory, database
connections, p95 request latency, mailbox growth, and LiveKit/TURN bandwidth
before raising any limit. Audio media—not encrypted text—is normally the main
bandwidth cost, especially when TURN relays it. Scale media and signaling
separately when usage grows.

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
OMNIRELAY_GOOGLE_WEB_CLIENT_ID=YOUR_WEB_OAUTH_CLIENT_ID
OMNIRELAY_KEYSTORE_FILE=C:/secure/omnirelay-release.jks
OMNIRELAY_KEYSTORE_PASSWORD=YOUR_KEYSTORE_PASSWORD
OMNIRELAY_KEY_ALIAS=YOUR_KEY_ALIAS
OMNIRELAY_KEY_PASSWORD=YOUR_KEY_PASSWORD
```

Use an absolute keystore path appropriate for the build machine. Restrict access
to the keystore and user-level properties file. The app initializes Firebase
from the five Gradle values; do not commit service-account credentials or
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

### Public website

The site is intentionally independent from the Android and backend projects:

```powershell
cd website
pnpm install --frozen-lockfile
pnpm audit --audit-level=low
pnpm verify
```

For Vercel, select `website` as the project Root Directory. The bundle verifier
rejects Android/backend source markers, source maps, oversized public assets,
or a missing GitHub Releases link. Before launch, replace the default social URL
if the final Vercel/custom domain is not `https://omnirelay.vercel.app`.
