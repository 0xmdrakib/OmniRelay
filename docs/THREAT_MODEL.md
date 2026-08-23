# OmniRelay threat model

## Security goals

- The relay must not learn message plaintext, call signaling plaintext, contact
  names, call media keys, private identity keys, or local message bodies.
- Only a locally paired X25519 identity may produce accepted user-visible
  traffic.
- Backend authentication, call transitions, mailbox acknowledgements, and
  idempotency IDs must not be transferable between unrelated devices.
- A compromised relay may delay, drop, replay, or reorder ciphertext, but must
  not be able to decrypt it or forge a valid bound frame.

## Trust boundaries

- Android Keystore protects identity, relay-token, and local message-storage
  keys on each device.
- PostgreSQL and the relay are trusted for availability and routing metadata,
  not for content confidentiality.
- LiveKit and TURN are trusted for availability. Call audio is additionally
  encrypted with a per-call key derived independently by the paired devices.
- FCM is a wake-up channel only and receives no message or call plaintext.

## Defenses

- X25519/HKDF/AES-256-GCM encrypted OmniFrames with recipient targeting.
- Ed25519 challenge-signed device registration and pinned signing identities.
- Thirty-day bearer expiry, hashed server-side tokens, strict frame/base64
  parsing, sender/recipient public-key binding, call-role state enforcement,
  replay deduplication, idempotency conflict detection, quotas, expiry, and
  rate limiting.
- Keystore-wrapped local identity and message keys, disabled Android backups,
  private lock-screen notification visibility, and no plaintext server logs.
- Loopback-only host binding by default for relay signaling endpoints; public
  production traffic terminates TLS at Caddy.

## Known limitations

- Long-lived contact X25519 identities do not provide Signal Double-Ratchet
  forward secrecy or post-compromise security for stored message ciphertext.
- Rooted/unlocked compromised devices, malicious accessibility services, or
  screen/microphone capture can expose content at the endpoint.
- Traffic timing, sender/recipient device IDs, ciphertext sizes, and call state
  are visible to the relay.
- Availability cannot be guaranteed when no internet, carrier, satellite, or
  nearby radio path physically exists.
- Physical two-device BLE, Wi-Fi Aware, Doze, OEM background restrictions, FCM,
  and audio routing require device-lab validation before production release.

## Release gate

A public production release requires a protocol/Android/backend infrastructure
security review, two-device and adverse-network tests, rotated production
secrets, signed artifacts, monitored backups, and an incident-response owner.
