# OmniRelay production architecture

## Delivery model

OmniRelay has two owner delivery planes plus an opt-in opportunistic nearby
forwarding path:

| Receiver state | Delivery path | Result |
| --- | --- | --- |
| Internet available | HTTPS mailbox + WebSocket/FCM wake; LiveKit audio | Instant messages and calls |
| No internet, peer is nearby | Authenticated Wi-Fi Aware NDP, then BLE GATT | Direct messages; lossless PCM on NDP or ADPCM on BLE |
| Peer is simultaneously reachable through opted-in nearby phones | Padded opaque relay capsule | Bounded text/call signaling forwarding; no durable volunteer queue |
| Temporarily unreachable | Encrypted Room outbox + backend mailbox | Automatic retry/queued delivery |
| No internet and no reachable nearby radio | No physical path | Waits until a path returns |

An ordinary Android app cannot deliver to a far-away phone that has no SIM,
Wi-Fi, satellite, Bluetooth, or any other reachable radio path. True
sender-sponsored mobile data at arbitrary distance requires a carrier
zero-rating/sponsored-data agreement. This is a physical network constraint,
not an application limitation.

## Implemented components

- Android Compose client with mutual Secret Link contacts.
- Wire-v2 directional X25519/HKDF/AES-256-GCM message/call envelopes. Sender,
  recipient, version, flags, path, priority, sequence, timestamp, and payload
  type are authenticated; reflected A→B ciphertext cannot validate as B→A.
- Bundled Conscrypt provider for X25519/Ed25519 support across minSdk 26+.
- Backend registration requires both an Ed25519 challenge signature and an
  ephemeral-DH proof of the Secret Link's X25519 private key, followed by
  bearer-token rotation.
- Each device synchronizes an inbound allow-list derived from mutual X25519 pair
  secrets. Senders present a direction-specific route capability; PostgreSQL
  stores only its SHA-256 hash. Registration alone does not authorize mailbox traffic.
- Android Keystore wrapping for identity private keys and relay credentials.
- Room message history, real queued/sent/delivered/read status, deduplication,
  and durable outbound retry.
- Authenticated HTTPS mailbox and WebSocket instant events.
- Optional high-priority FCM wake-ups; push payloads contain no plaintext.
- Call ring/accept/decline/end signaling, CallStyle notifications, Android Core
  Telecom integration, and LiveKit WebRTC audio with TURN fallback. Internet
  media uses a per-call app-level E2EE key derived by the paired X25519 devices.
- BLE presence/GATT plus API 29+ on-demand Wi-Fi Aware NDP sockets with pairwise
  PSK, mutual handshake, fresh directional AES-GCM record keys, strict sequence
  checking, bounded queues/channels, and API 26–28 encrypted follow-up fallback.
- An opt-in `RelayCapsule` envelope that re-encrypts and pads a complete frame,
  limits each forwarding step to a bounded hop counter, and lets intermediate phones forward
  it without learning the protected sender, recipient, payload type, or content.
- Adaptive scan/advertise duty cycles with battery, charging, power-save,
  metering, thermal, foreground, and active-call gates. Third-party relay is off
  by default and constrained by hourly byte and packet-rate limits.
- Feature-scoped permission planning: permissions are requested when the user
  invokes the corresponding feature, and denial disables only that capability.
- Fastify backend with PostgreSQL, idempotent envelope IDs, mailbox quotas,
  batched expiry cleanup, bounded request concurrency and database pooling,
  bounded TCP/WebSocket/FCM queues, 60-second call-signal expiry, per-pair
  mailbox admission, rejected-envelope progression, security headers, and rate limiting.
- Call state and its encrypted mailbox signal commit in one database transaction.
  Active state uses a short lease renewed by the foreground call instead of a
  multi-hour ghost-call record after process death.
- Docker Compose services for backend, PostgreSQL, LiveKit, coturn, and optional
  Caddy automatic TLS termination.

## Security boundaries

The backend stores device IDs, public keys, push routing IDs, hashed inbound
route capabilities and their sender/recipient device-ID relationship, call state,
and opaque encrypted OmniFrames. Contact names, message plaintext, call audio,
and private keys are never sent to it. Incoming frames are accepted only after
the authenticated sender key resolves to a locally paired contact.

Nearby volunteer phones see a random capsule identifier, a pseudorandom route
tag, padded ciphertext length, hop count, timing, and radio metadata. They do
not receive the inner frame header or content. They remain untrusted for
confidentiality and integrity but can still drop, delay, replay, reorder, or
traffic-analyze packets. Content deduplication, capsule replay suppression,
strict parse limits, and resource quotas bound these cases; they cannot create
an availability guarantee.

The current wire-v2 message protocol provides direction/identity-bound
confidentiality and integrity, replay
deduplication, active-call peer/call binding, and authenticated backend
registration. Local message bodies and identity secrets are protected by
Android Keystore. Existing identities fail closed if their protected key
material is corrupt or mismatched instead of being silently replaced.

Protocol v2 still uses long-lived X25519 contact identities and therefore does not
claim Signal-style forward secrecy or post-compromise security. The discovery
prefix is also stable and should not be treated as unlinkable. These are public
release gates, not hidden assumptions; see [Security evolution](SECURITY_EVOLUTION.md).

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

## Transport and cost boundaries

- BLE uses filtered, low-power background discovery and adapts to foreground or
  call demand. Volunteer traffic is never enabled by default.
- API 29+ Wi-Fi Aware has an implemented on-demand network data path and
  encrypted socket-record layer. It must remain pre-release until two-device OEM
  interoperability, reconnect, throughput, battery, and external protocol review pass.
- Direct NDP voice uses lossless 16 kHz PCM; BLE uses 32 kbps ADPCM. Internet
  audio remains LiveKit/WebRTC. Media selection does not route voice through volunteers.
- Third-party live voice is intentionally not forwarded. Real-time media uses a
  direct nearby path or LiveKit/WebRTC; relaying it through volunteer phones
  would materially increase energy, privacy, abuse, and latency risk.
- The default server pool and concurrency limits are suitable starting points
  for a small host, not a promise of a fixed user capacity. Measure real traffic
  and scale horizontally before increasing limits.

## Verification performed

- Backend strict TypeScript compilation, X25519/Ed25519 identity proofs, overload,
  cleanup, WebSocket, call-expiry, and cross-language cryptographic-vector tests.
- Docker image build and live health checks for PostgreSQL, backend, LiveKit,
  and coturn.
- Generated devices registering with X25519 and Ed25519 proofs, exchanging a
  mailbox message, receiving a WebSocket event, acknowledging delivery,
  recovering the receipt, transitioning a call, and obtaining a LiveKit JWT.
- Pure JVM tests cover directional/reflection-resistant crypto, cross-language
  registration vectors, frame parsing, malicious/truncated input, relay
  capsule tampering and forwarding, fragment resource limits, permission plans,
  and adaptive resource decisions.
- Backend unit tests cover configuration validation, identity, and routing
  behavior. Isolated Docker integration exercises registration, WebSocket wake,
  mailbox delivery/acknowledgement, call transitions, and LiveKit token issuance.
- Production dependencies are audited and the runtime image pins its base digest
  and applies Alpine security updates. A fresh private-image vulnerability scan
  remains mandatory for every release because vulnerability data changes.

Physical BLE/Wi-Fi Aware, multi-hop forwarding, Doze/OEM battery behavior,
microphone routing, FCM, and end-to-end audio still require real Android phones
and real Firebase/public infrastructure credentials; those cannot be proven by
a compiler or container test.
