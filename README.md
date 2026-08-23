# OmniRelay

OmniRelay is a native Android E2EE messaging and audio-calling client with
internet relay plus nearby Wi-Fi Aware/BLE fallback.

## Build a LAN test APK

Build artifacts are intentionally excluded from Git. Create a debug APK for
your current PC address:

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat assembleDebug -POMNIRELAY_BACKEND_URL=http://YOUR_PC_IP:8080
```

The APK is generated at `app/build/outputs/apk/debug/app-debug.apk`.

Keep Docker Desktop and this PC on, keep both phones on the same reachable
network, install the APK on both phones, grant notifications/microphone/nearby
permissions, then exchange each phone's Secret Link in Settings. If Windows
Firewall prompts, allow Docker/Java on the private network. The local services
use ports 8080, 7880, 7881, 3478/UDP, 49160-49200/UDP, and 50000-50100/UDP.

For LAN testing set `BACKEND_BIND_ADDRESS=0.0.0.0`,
`LIVEKIT_HTTP_BIND_ADDRESS=0.0.0.0`, `TRUST_PROXY=false`, and
`LIVEKIT_PUBLIC_URL=ws://YOUR_PC_IP:7880` in the untracked `.env`. Render
`deploy/livekit.generated.yaml` with the same IP.

## Local server

Copy `.env.example` to the ignored `.env`, replace every placeholder with a
strong unique value, then render the LiveKit config:

```powershell
.\deploy\render-config.ps1 `
  -PublicHost 'YOUR_PC_IP' `
  -LiveKitApiKey 'omnirelay' `
  -LiveKitApiSecret 'A_LONG_RANDOM_SECRET' `
  -TurnSharedSecret 'ANOTHER_LONG_RANDOM_SECRET'

docker compose up -d --build
```

Check health with:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/healthz
docker compose ps
```

## Public production deployment

1. Point `RELAY_DOMAIN` and `LIVEKIT_DOMAIN` DNS records to a public server.
2. Generate ignored production configuration and strong random secrets:

   ```powershell
   .\deploy\initialize-production.ps1 `
     -PublicIp 'YOUR_PUBLIC_IP' `
     -RelayDomain 'relay.example.com' `
     -LiveKitDomain 'livekit.example.com'
   ```

3. Optionally add the one-line Firebase service-account JSON to the generated
   `.env` as `FIREBASE_SERVICE_ACCOUNT_JSON`.
4. Open TCP 80, 443, 7881 and UDP 3478, 49160-49200, 50000-50100.
5. Run `.\deploy\start-production.ps1`. It validates configuration, builds the
   stack, waits for health, and Caddy obtains TLS certificates for both domains.
6. Create an Android app in Firebase, enable Cloud Messaging, and supply its
   four client values as Gradle properties. Put the service-account JSON on one
   line in `FIREBASE_SERVICE_ACCOUNT_JSON` in the server `.env`.

Build Android with:

```powershell
.\gradlew.bat assembleRelease `
  -POMNIRELAY_BACKEND_URL=https://RELAY_DOMAIN `
  -POMNIRELAY_FIREBASE_API_KEY=... `
  -POMNIRELAY_FIREBASE_APP_ID=... `
  -POMNIRELAY_FIREBASE_PROJECT_ID=... `
  -POMNIRELAY_FIREBASE_SENDER_ID=...
```

For a signed release also provide `OMNIRELAY_KEYSTORE_FILE`,
`OMNIRELAY_KEYSTORE_PASSWORD`, `OMNIRELAY_KEY_ALIAS`, and
`OMNIRELAY_KEY_PASSWORD` in the user's Gradle properties, never in source.

Before the first Play Store release, replace the placeholder application ID
`com.example.omnirelay` with a permanent ID you control. An application ID
cannot be changed after publishing under that identity.

## Repository security

The repository intentionally excludes local SDK paths, runtime `.env` files,
Firebase configs/service accounts, generated LiveKit config, signing keys,
logs, databases, and APK/AAB artifacts. GitHub Actions runs secret scanning,
backend integration tests, Android tests/lint, and debug/release builds.
Dependabot monitors Gradle, pnpm, GitHub Actions, and the backend Docker image.

Keep this repository private. Store deployment values in the server's `.env`
or a secrets manager and release-signing values in the user-level Gradle
properties or CI secrets—never in tracked files.

## Tests

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat testDebugUnitTest assembleDebug

cd backend
npx pnpm install --frozen-lockfile
npx pnpm build
$env:INTEGRATION_BASE_URL='http://127.0.0.1:8080'
node --test --import tsx test/*.test.ts
```

See [production architecture](docs/PRODUCTION_ARCHITECTURE.md), the
[threat model](docs/THREAT_MODEL.md), and the
[release checklist](docs/RELEASE_CHECKLIST.md) before deployment.
