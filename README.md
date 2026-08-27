# OmniRelay

OmniRelay is a native Android app for private, end-to-end encrypted messaging
and voice calls, with a self-hosted internet relay and nearby radio fallback.

**Status:** Pre-release · Android 8.0+ · Physical-device validation pending

---

## Overview

OmniRelay is built around two connection modes:

- **Internet relay:** Encrypted messages and call signaling over HTTPS and
  WebSocket, optional Firebase push wake-ups, and LiveKit/WebRTC voice calls.
- **Nearby connection:** Direct communication over Wi-Fi Aware and Bluetooth
  LE GATT when supported devices are within radio range.

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
- Wi-Fi Aware discovery, BLE presence, GATT transport, and packet reassembly
- Self-hosted backend with authenticated devices, mailbox quotas, and rate limits

## Connection behavior

| Receiver condition | Available path | Expected behavior |
| --- | --- | --- |
| Internet connection available | HTTPS, WebSocket, optional FCM, and LiveKit | Online messaging and calls |
| No internet, but a compatible peer is nearby | Wi-Fi Aware or BLE GATT | Direct nearby communication |
| Temporarily unreachable | Local outbox and server mailbox | Messages wait and retry when a path returns |
| No internet and no reachable nearby radio | No communication path | No instant delivery or live call |

Nearby mode does not require a SIM or an internet connection. It still requires
compatible hardware, permissions, and radio range. A sender's internet alone
cannot reach a distant receiver that has no network path.

## Tech stack

- **Android:** Kotlin, Jetpack Compose, Room, WorkManager, and Core Telecom
- **Cryptography:** X25519, HKDF-SHA256, AES-256-GCM, Ed25519, and Android Keystore
- **Connectivity:** OkHttp, Firebase Cloud Messaging, Wi-Fi Aware, and BLE GATT
- **Voice:** LiveKit/WebRTC, coturn, and IMA-ADPCM for nearby audio
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

This is not yet a production release. Two-phone audio, nearby transport,
background delivery, and real Firebase/public-network behavior still need
physical-device testing. Automated checks do not establish those guarantees.

The message protocol uses long-lived contact keys and does not currently offer
Double Ratchet forward secrecy. Review the [threat model](docs/THREAT_MODEL.md)
and complete the [release checklist](docs/RELEASE_CHECKLIST.md) before launch.

## Documentation

- [Setup and deployment](docs/SETUP.md) — prerequisites, local testing, Firebase,
  signing, production setup, and test commands
- [Production architecture](docs/PRODUCTION_ARCHITECTURE.md) — delivery paths,
  components, API routes, and security boundaries
- [Threat model](docs/THREAT_MODEL.md) — protections, trust boundaries, and limitations
- [Release checklist](docs/RELEASE_CHECKLIST.md) — infrastructure, device validation,
  security review, and distribution

---

## License

Copyright (c) 2026 OmniRelay. All rights reserved.

This project is **proprietary and confidential**, not open source. Use, copying,
modification, distribution, sublicensing, or publication requires prior written
authorization from the copyright holder. See the [license terms](LICENSE).
