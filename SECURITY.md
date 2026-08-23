# Security policy

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, private
keys, message content, or user data. Use GitHub's private vulnerability
reporting for this repository, or contact the repository owner privately.

Include the affected component, reproduction steps, impact, and any suggested
mitigation. Allow reasonable time for triage and remediation before disclosure.

## Supported version

Security fixes target the latest commit on `main`. No released version should
be treated as independently audited unless its release notes explicitly say so.

## Cryptographic scope

OmniRelay encrypts message payloads and call signaling end to end, encrypts
internet call media with a per-call key derived by the paired X25519 devices,
and protects local private keys and message bodies with Android Keystore.

The current messaging protocol does not claim Signal Double-Ratchet forward
secrecy. A professional public launch should include an independent protocol,
Android, backend, and infrastructure security review.
