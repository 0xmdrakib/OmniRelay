# Security evolution

This document separates protections implemented in wire protocol v2 from the
reviewed session-security work still required for a public release. Passing
automated tests is not a cryptographic audit.

## Implemented in wire v2

- V1 frames are rejected. V2 derives different A→B and B→A content keys and
  authenticates the full sender and recipient identities plus version, flags,
  path, priority, sequence, timestamp, and payload type. A captured A→B
  ciphertext cannot be relabeled as a B→A frame.
- Canonical parsing rejects unsupported versions, nonzero reserved bytes,
  unknown path bits or payload types, trailing bytes, malformed lengths, and
  noncanonical compact advertisements.
- Backend registration requires an Ed25519 signature and an ephemeral X25519-DH
  proof made with the Secret Link's private key. A public Secret Link alone can
  no longer claim its mailbox or FCM identity. Android and Node share a fixed RFC
  7748 interoperability vector.
- Call controls contain an encrypted call ID and use the authenticated frame
  timestamp for a 60-second freshness window. Local durable retries are cancelled
  when the call ends or expires; the backend stores only remaining lifetime.
- Content dedupe runs only after AEAD authentication. Active peer/call binding,
  voice codec/size checks, rate limits, monotonic counters, bounded counter jumps,
  and a fixed 50-frame jitter queue constrain call injection and memory abuse.
- Existing X25519 and Ed25519 pairs are validated at load. Identity creation and
  migration use checked durable writes; missing, mismatched, or undecryptable
  existing key material fails closed rather than silently changing identity.
- Android Keystore wrappers bind ciphertext to its purpose and public identity,
  while retaining one-way migration from the legacy local wrapper.
- A volunteer receives a second AES-GCM `RelayCapsule` around the complete frame.
  It has a random ID, keyed route tag, random 256-byte-bucket padding, bounded
  size, and bounded hop counter. Authenticated-recipient IDs and untrusted-forward
  fingerprints use separate replay caches, preventing pre-authentication ID poisoning.
- Fragment assemblies, raw discovery peers, NDP channels/setups, GATT sessions,
  pending bytes, ingress packets, relay fan-out, contacts tested per capsule,
  packet rate, and volunteer bytes all have explicit bounds. Volunteer relay is
  disabled by default and never carries voice.
- API 29+ Wi-Fi Aware uses an on-demand pair-derived PSK, authenticated setup,
  fresh directional socket keys, AES-GCM records, strict sequence checks, control
  replay suppression, bounded reconnect backoff, and 128 KiB records. API 26–28
  retains encrypted follow-up fallback.

## What wire v2 does not guarantee

- Long-lived contact X25519 keys do not provide Double Ratchet forward secrecy
  or post-compromise security. A later identity-key compromise can expose old
  captured v2 ciphertext.
- BLE/Wi-Fi Aware discovery uses a stable truncated identity prefix. It is
  locally linkable and advertisements are only routing hints, not proof that the
  real recipient received a frame.
- Relay padding hides the inner frame but not radio timing, approximate location,
  padded size, the mutable hop counter, or immediate-hop radio identifiers. A
  volunteer can drop, delay, duplicate, or selectively suppress traffic.
- Volunteer forwarding is an immediate best-effort flood with strict limits; it
  is not durable store-and-forward. No physical path means no delivery.
- The Wi-Fi Aware handshake/record layer is custom code. Automated vectors and
  adversarial tests do not replace independent review, and a maintained TLS 1.3
  or Noise implementation is preferable if it fits Android Aware sockets.
- The signaling backend sees device IDs, sender/recipient routing, timing,
  ciphertext size, delivery state, and call state. FCM sees wake metadata.

## Reviewed ratcheted-session target

A future protocol version should use established, independently reviewed
building blocks instead of extending the static v2 key schedule:

1. Use a maintained implementation of PQXDH for asynchronous setup, Double
   Ratchet for per-message key evolution, and Sesame-style multi-device session
   management. Store ratchet state transactionally and bound skipped keys.
2. Publish signed prekey bundles, pin negotiated protocol versions per contact,
   and define downgrade-resistant migration. Secret Links should explicitly
   version and bind encryption and signing identities.
3. Replace stable discovery prefixes with rotating unlinkable tokens. Define
   epoch skew, replay handling, contact lookup cost, and radio-level privacy tests.
4. Use a reviewed media-key lifecycle such as SFrame where it fits the media
   stack. Bind participant, call, direction, epoch, and counter; rotate on
   reconnect/membership changes and erase retired keys.
5. Replace or independently audit the custom NDP secure-record protocol, then
   run cross-OEM throughput, reconnect, battery, malformed-peer, and soak tests.
6. Add migration vectors, rollback/crash recovery, state-machine concurrency,
   fuzzing, and an external Android/backend/protocol assessment before rollout.

Primary specifications and implementations for design review:

- [Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal PQXDH specification](https://signal.org/docs/specifications/pqxdh/)
- [Signal Sesame specification](https://signal.org/docs/specifications/sesame/)
- [Signal libsignal repository](https://github.com/signalapp/libsignal)
- [NIST SP 800-38D: AES-GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [RFC 9605: SFrame](https://www.rfc-editor.org/info/rfc9605)

## Release decision

Wire v2 addresses the tested reflection/relabel forgery, public-key-only backend
registration takeover, stale-call races, pre-authentication dedupe poisoning,
cross-contact relay-ID poisoning, and identified voice/transport bounds from this
hardening pass. These controls reduce known attack paths; they are not a proof of
absence of other defects. The protocol still does not meet Signal-class forward
secrecy or metadata-anonymity requirements.
Public marketing and release approval must preserve that distinction until the
ratcheted-session work, rotating discovery, physical tests, and independent
security review are complete.
