# OmniRelay production architecture

## Delivery model

OmniRelay now has two working delivery planes:

| Receiver state | Delivery path | Result |
| --- | --- | --- |
| Internet available | HTTPS mailbox + WebSocket/FCM wake; LiveKit audio | Instant messages and calls |
| No internet, peer is nearby | Wi-Fi Aware, then BLE GATT | Direct messages and ADPCM voice |
| Temporarily unreachable | Encrypted Room outbox + backend mailbox | Automatic retry/queued delivery |
| No internet and no reachable nearby radio | No physical path | Waits until a path returns |

An ordinary Android app cannot deliver to a far-away phone that has no SIM,
Wi-Fi, satellite, Bluetooth, or any other reachable radio path. True
sender-sponsored mobile data at arbitrary distance requires a carrier
zero-rating/sponsored-data agreement. This is a physical network constraint,
not an application limitation.

## Implemented components

- Android Compose client with mutual Secret Link contacts.
- X25519 + HKDF-SHA256 + AES-256-GCM opaque message/call envelopes.
- Bundled Conscrypt provider for X25519/Ed25519 support across minSdk 26+.
- Ed25519 challenge-signed backend registration and bearer-token rotation.
- Android Keystore wrapping for identity private keys and relay credentials.
- Room message history, real queued/sent/delivered/read status, deduplication,
  and durable outbound retry.
- Authenticated HTTPS mailbox and WebSocket instant events.
- Optional high-priority FCM wake-ups; push payloads contain no plaintext.
- Call ring/accept/decline/end signaling, CallStyle notifications, Android Core
  Telecom integration, and LiveKit WebRTC audio with TURN fallback. Internet
  media uses a per-call app-level E2EE key derived by the paired X25519 devices.
- BLE presence, GATT client/server, Wi-Fi Aware discovery, and radio packet
  fragmentation/reassembly.
- Fastify backend with PostgreSQL, idempotent envelope IDs, mailbox quotas,
  expiry cleanup, security headers, and rate limiting.
- Docker Compose services for backend, PostgreSQL, LiveKit, coturn, and optional
  Caddy automatic TLS termination.

## Security boundaries

The backend stores device IDs, public keys, push routing IDs, call state, and
opaque encrypted OmniFrames. Contact names, message plaintext, call audio, and
private keys are never sent to it. Incoming frames are decrypted only after the
sender key matches a locally paired contact.

The current message protocol provides confidentiality, integrity, replay
deduplication, strict sender/recipient frame binding, and authenticated backend
registration. Local message bodies and identity secrets are protected by
Android Keystore. The protocol uses long-lived
X25519 contact identities and therefore does not claim Signal-style forward
secrecy. Before a high-risk public launch, commission an independent protocol
and Android security audit; a reviewed Double Ratchet migration is recommended.

## Server routes

- `POST /v1/devices/challenge`
- `POST /v1/devices/register`
- `PUT /v1/devices/push-token`
- `POST /v1/envelopes`
- `GET /v1/mailbox`
- `POST /v1/envelopes/:id/ack`
- `POST /v1/calls/:id/state`
- `POST /v1/calls/:id/token`
- `GET /v1/stream` (WebSocket)
- `GET /healthz`

## Verification performed

- Backend strict TypeScript compilation and identity tests.
- Docker image build and live health checks for PostgreSQL, backend, LiveKit,
  and coturn.
- Two generated devices registering with signed challenges, exchanging a
  mailbox message, receiving a WebSocket event, acknowledging delivery,
  recovering the receipt, transitioning a call, and obtaining a LiveKit JWT.
- Android JVM tests, including crypto/frame and out-of-order nearby fragment
  reassembly.
- Debug APK and minified release APK builds with fatal lint enabled.

Physical BLE/Wi-Fi Aware, Doze/OEM battery behavior, microphone routing, FCM,
and end-to-end audio still require two real Android phones and real Firebase/
public infrastructure credentials; those cannot be simulated by a code build.
