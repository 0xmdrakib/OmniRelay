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
- A volunteer nearby phone must not learn the protected frame header or content
  and must have bounded ability to consume battery, memory, storage, or network.

## Trust boundaries

- Android Keystore protects identity, relay-token, and local message-storage
  keys on each device.
- PostgreSQL and the relay are trusted for availability and routing metadata,
  not for content confidentiality.
- Volunteer nearby phones are trusted for neither availability nor content.
  They receive only a padded relay capsule and observable radio/traffic metadata.
- LiveKit and TURN are trusted for availability. Call audio is additionally
  encrypted with a per-call key derived independently by the paired devices.
- FCM is a wake-up channel only and receives no message or call plaintext.
- Firebase Authentication and Google are trusted to authenticate account access.
  The relay receives the verified Firebase UID but not the Google password.

## Defenses

- Wire-v2 directional X25519/HKDF/AES-256-GCM OmniFrames. AEAD binds both full
  identities and immutable security-relevant header fields, preventing relabel/reflection.
- A second, purpose-separated AES-GCM relay-capsule layer with random capsule
  IDs, keyed route tags, random padding, replay suppression, and hop limits.
- Ed25519 challenge signatures plus ephemeral-DH proof of the X25519 private key,
  with pinned signing identities and versioned local relay credentials.
- Revocation-aware Firebase ID-token verification on both registration steps,
  account-bound challenges, immutable device→UID binding, revocable 30-day device sessions,
  and a separate Keystore-authenticated local owner binding that survives sign-out.
- Recipient-issued, direction-specific route capabilities prevent an arbitrary
  registered/Sybil identity from consuming another device's mailbox or FCM work;
  only capability hashes are retained in PostgreSQL.
- Thirty-day bearer expiry, hashed server-side tokens, strict frame/base64
  parsing, sender/recipient public-key binding, call-role state enforcement,
  replay deduplication, active-peer and encrypted call-ID binding, monotonic
  nearby voice counters, idempotency conflict detection, quotas, expiry, and
  rate limiting.
- Invalid/unpaired mailbox frames are rejected and progressed; per-pair pending
  limits prevent one sender from filling an entire recipient mailbox.
- Call transition and encrypted signal insertion are atomic. Active internet
  calls use a short renewable lease, bounding stale server state after client death.
- Keystore-wrapped local identity and message keys, disabled Android backups,
  private lock-screen notification visibility, and no plaintext server logs.
- Fail-closed identity loading and key-pair validation prevent silent identity
  replacement after corruption. Protected local secrets use purpose- and
  public-key-bound authenticated data.
- Canonical frame parsing, exact length/version/reserved-byte checks, bounded
  fragment assemblies, bounded capsule size, volunteer byte budgets, and packet
  rate limits reduce parser and resource-exhaustion attack surface.
- Loopback-only host binding by default for relay signaling endpoints; public
  production traffic terminates TLS at Caddy.

## Known limitations

- Long-lived contact X25519 identities do not provide Signal Double-Ratchet
  forward secrecy or post-compromise security for stored message ciphertext.
- BLE/Wi-Fi Aware discovery currently exposes a stable truncated identity
  prefix. It can enable local tracking and spoofed presence; rotating unlinkable
  discovery tokens are required before a privacy-sensitive public launch.
- Relay hop count is intentionally mutable so an untrusted phone can forward a
  capsule. An attacker can reduce it, drop a packet, replay it, correlate timing
  and padded size, or selectively deny service. Padding and cryptography do not
  hide radio-level timing or location.
- Route ownership is tested against locally paired keys. A device with a very
  large contact set pays bounded local work per received capsule; the contact
  count, capsule size, active assemblies, packet rate, and hourly bytes are
  capped, but physical-device abuse testing is still required.
- The API 29+ Wi-Fi Aware NDP uses a custom pair-authenticated handshake and
  directional AES-GCM record protocol. Its nonce/sequence construction is tested,
  but it still requires independent review or replacement by a maintained TLS 1.3/
  Noise implementation before a privacy-sensitive public release.
- Nearby opportunistic relaying is immediate, not durable store-and-forward.
  Devices that are not simultaneously connected cannot be bridged by this path.
- Rooted/unlocked compromised devices, malicious accessibility services, or
  screen/microphone capture can expose content at the endpoint.
- Traffic timing, sender/recipient device IDs, ciphertext sizes, and call state
  are visible to the relay. Hashed inbound-route rows also reveal the paired
  device-ID graph, even though contact names and capability preimages remain private.
- Availability cannot be guaranteed when no internet, carrier, satellite, or
  nearby radio path physically exists.
- Physical two-device BLE, Wi-Fi Aware, Doze, OEM background restrictions, FCM,
  and audio routing require device-lab validation before production release.
- Account self-service device listing, remote session revocation, account deletion,
  and ownership recovery are not yet implemented and remain release work.

## Release gate

A public production release requires a protocol/Android/backend infrastructure
security review, two- and three-device adverse-network tests, rotating discovery
identifiers, an approved forward-secure protocol migration, rotated production
secrets, signed artifacts, monitored backups, and an incident-response owner.
