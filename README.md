# OmniRelay

OmniRelay is a native Android app for private, end-to-end encrypted messaging
and voice calls, with a self-hosted internet relay and nearby radio fallback.

**Status:** Pre-release · Android 8.0+ · Physical-device validation pending

---

## Overview

OmniRelay is built around three bounded delivery paths:

- **Internet relay:** Encrypted messages and call signaling over HTTPS and
  WebSocket, optional Firebase push wake-ups, and LiveKit/WebRTC voice calls.
- **Nearby connection:** Direct communication over Wi-Fi Aware and Bluetooth
  LE GATT when supported devices are within radio range.
- **Opt-in nearby relay:** A reachable volunteer phone may opportunistically
  forward a padded, double-encrypted capsule without seeing the inner OmniFrame.
  This path is simultaneous and bounded; it is not durable volunteer storage or
  a third-party live-audio proxy.

Contacts pair by exchanging Secret Links. The app accepts incoming content
only from locally paired identities and keeps raw discovery nodes out of the
contact list.

## Features

- Mutual Secret Link pairing with custom contact names
- End-to-end encrypted messages and Keystore-protected local message storage
- Persistent chat history with queued, sent, delivered, and read states
- Durable message retries, delivery acknowledgements, and deduplication
- Ring, accept, decline, and end-call signaling with mute and speaker controls
- LiveKit/WebRTC audio with per-call media encryption and TURN fallback
- Incoming-call notifications and Android Telecom integration
- Optional FCM wake-ups without message or call plaintext in push payloads
- API 29+ Wi-Fi Aware NDP with pair-authenticated encrypted sockets; encrypted
  follow-up fallback on API 26–28 and bounded BLE GATT transport
- Protocol-v2 directional frame keys and immutable sender/recipient/header AEAD binding
- X25519 private-key proof plus Ed25519 signatures for backend registration
- Recipient-issued sender→recipient route capabilities; the backend stores only
  capability hashes and rejects mail from identities the recipient has not authorized
- Lossless 16 kHz PCM over an established NDP, ADPCM over BLE, and WebRTC internet audio
- Opt-in, hop-limited opportunistic forwarding with opaque padded relay capsules
- Adaptive radio duty cycles, thermal/battery gates, and strict volunteer quotas
- Feature-scoped Android permission requests with graceful degradation
- Self-hosted backend with authenticated devices, mailbox quotas, and rate limits
- Transactional call transitions and short renewable active-call leases to bound ghost state
- Low-cost server controls for bounded concurrency, database pooling, and cleanup

## Connection behavior

| Receiver condition | Available path | Expected behavior |
| --- | --- | --- |
| Internet connection available | HTTPS, WebSocket, optional FCM, and LiveKit | Online messaging and calls |
| No internet, but a compatible peer is nearby | Wi-Fi Aware or BLE GATT | Direct nearby communication |
| Destination is simultaneously reachable through opted-in nearby phones | Opaque relay capsule, up to three configured hops | Opportunistic text or call signaling; no durable queue or relayed live voice |
| Temporarily unreachable | Local outbox and server mailbox | Messages wait and retry when a path returns |
| No internet and no reachable nearby radio | No communication path | No instant delivery or live call |

Nearby mode does not require a SIM or an internet connection. It still requires
compatible hardware, permissions, radio range, and—when relaying—an explicit
volunteer opt-in. A sender's internet alone cannot reach a distant receiver that
has no network path. No application can manufacture a physical path where none
exists.

## Tech stack

- **Android:** Kotlin, Jetpack Compose, Room, WorkManager, and Core Telecom
- **Cryptography:** directional X25519/HKDF/AES-256-GCM, Ed25519, and Android Keystore
- **Connectivity:** OkHttp, Firebase Cloud Messaging, Wi-Fi Aware, and BLE GATT
- **Voice:** LiveKit/WebRTC, coturn, lossless PCM over NDP, and IMA-ADPCM over BLE
- **Backend:** Node.js 24, TypeScript, Fastify, WebSocket, and PostgreSQL
- **Infrastructure:** Docker Compose, Caddy TLS, and GitHub Actions

## Getting started

Clone the private repository using an account with access:

```powershell
git clone https://github.com/0xmdrakib/OmniRelay.git
cd OmniRelay
```

Follow the [setup guide](docs/SETUP.md) to start the local server, build a
configured APK, and pair two Android phones. For a public server, use the
[production deployment guide](docs/SETUP.md#production-deployment).

Credentials, signing keys, local configuration, and build artifacts stay outside
Git. Keep the repository private and store deployment secrets on the server or
in a secrets manager.

## Testing and release

The [CI workflow](.github/workflows/ci.yml) runs Android unit tests, lint,
debug/release builds, backend checks and integration tests, a Docker image
build, and full-history secret scanning. See the [test commands](docs/SETUP.md#tests)
to run the checks locally.

This is not yet a production release. Two-phone audio, three-phone nearby relay,
background delivery, Doze/OEM behavior, and real Firebase/public-network paths
still need physical-device testing. Automated checks do not establish those
guarantees.

The current wire-v2 protocol rejects vulnerable v1 frames and binds direction,
identities, and immutable metadata into AEAD. It still uses long-lived contact
keys and does not offer
Double Ratchet forward secrecy or post-compromise security. Review the
[security evolution plan](docs/SECURITY_EVOLUTION.md), the
[threat model](docs/THREAT_MODEL.md), and the
[release checklist](docs/RELEASE_CHECKLIST.md) before launch.

## Documentation

- [Setup and deployment](docs/SETUP.md) — prerequisites, local testing, Firebase,
  signing, production setup, and test commands
- [Production architecture](docs/PRODUCTION_ARCHITECTURE.md) — delivery paths,
  components, API routes, and security boundaries
- [Threat model](docs/THREAT_MODEL.md) — protections, trust boundaries, and limitations
- [Security evolution](docs/SECURITY_EVOLUTION.md) — current v2 guarantees and
  the ratcheted-session roadmap
- [Release checklist](docs/RELEASE_CHECKLIST.md) — infrastructure, device validation,
  security review, and distribution

---

## License

Copyright (c) 2026 OmniRelay. All rights reserved.
