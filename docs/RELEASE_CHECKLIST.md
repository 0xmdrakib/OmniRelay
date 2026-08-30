# Production release checklist

## Identity and ownership

- [ ] Replace `com.example.omnirelay` with a permanent application ID.
- [ ] Create and securely back up the release keystore and recovery material.
- [ ] Update `versionCode` and `versionName`.
- [ ] Confirm final app name, icons, privacy policy, and support contact.
- [ ] Enable Google sign-in, verify OAuth consent branding, register debug/release
      certificate fingerprints, and test account recovery.

## Infrastructure

- [ ] Provision a maintained public Linux host with automated security updates.
- [ ] Point relay and LiveKit DNS names to the host.
- [ ] Generate `.env` and LiveKit config with `initialize-production.ps1`.
- [ ] Configure Firebase Authentication and Cloud Messaging without committing
      client OAuth values or service-account configuration.
- [ ] Restrict the host firewall to documented TCP/UDP ports.
- [ ] Start with `start-production.ps1` and verify Caddy TLS, `/healthz`, and `/readyz`.
- [ ] Configure encrypted PostgreSQL backups and test a restore.
- [ ] Configure uptime, disk, certificate, container, and error monitoring.
- [ ] Load-test the intended small-host profile, record p95 latency and database
      saturation, and lower admission limits before adding server capacity.
- [ ] Verify cleanup remains batched and that overload returns bounded `503`
      responses instead of exhausting the process or database.

## Device validation

- [ ] Test two different physical Android devices on the same LAN.
- [ ] Test devices on separate mobile/Wi-Fi networks through TURN.
- [ ] Verify message queued/sent/delivered/read transitions.
- [ ] Verify an unpaired registered/Sybil device receives `403`, pairing enables
      delivery, and deleting the contact revokes its inbound route.
- [ ] Verify incoming ring, accept, decline, cancel, end, mute, speaker, and
      two-way app-level E2EE audio.
- [ ] Kill each participant during an active internet call and confirm the short
      server lease expires without a ghost active session.
- [ ] Verify BLE and Wi-Fi Aware fallback with internet disabled.
- [ ] Test three physical phones: sender, opted-in volunteer, and receiver. Verify
      successful simultaneous opportunistic forwarding, duplicate suppression, hop expiry, tamper
      rejection, relay opt-out, and that no live voice is sent through the volunteer.
- [ ] Validate MINIMAL/BALANCED/GENEROUS behavior while charging, on battery,
      metered/unmetered, in power-save, under thermal pressure, and during a call.
- [ ] Verify each permission can be denied independently without crashes or
      blocking unrelated internet messaging.
- [ ] Verify reboot, process death, Doze, notification denial, and OEM battery
      restrictions.
- [ ] Verify Android 8/API 26 and Android 13+/API 33 crypto initialization.
- [ ] Corrupt a test identity wrapper and confirm the app fails closed and offers
      recovery guidance without silently creating a new identity.
- [ ] Verify first sign-in, automatic returning-user sign-in, cancellation,
      sign-out, token refresh, expired 30-day device sessions, and re-registration.
- [ ] Prove a second Google account cannot claim an already-bound device identity
      and that a same-account cryptographic re-registration rotates its session.

## Security gate

- [ ] GitHub CI, dependency review, secret scan, lint, tests, and release build pass.
- [ ] `pnpm audit --prod` and Docker Scout report no high/critical findings.
- [ ] Rotate any credential ever used outside its intended environment.
- [ ] Complete independent mobile/backend/protocol/infrastructure review.
- [ ] Replace stable discovery prefixes with rotating unlinkable tokens.
- [ ] Complete and independently review the forward-secure protocol described in
      `SECURITY_EVOLUTION.md`; define migration and downgrade resistance.
- [ ] Validate the encrypted Wi-Fi Aware NDP on at least two API 29+ OEMs for
      simultaneous setup, reconnect, sustained throughput, battery, and abuse;
      independently review or replace its custom secure-record protocol.
- [ ] Document incident response, key rotation, data retention, and account
      ownership.

## Distribution

- [ ] Deploy only `website/` as the Vercel Root Directory and inspect the public
      bundle for application/backend source or secrets.
- [ ] Set the final canonical/social URL and verify the generated preview card.
- [ ] Publish the signed APK on a publicly accessible GitHub Release and verify
      that the website download link works in an anonymous browser session.
- [ ] Build a signed AAB from a clean checkout and pinned commit.
- [ ] Verify signing certificate fingerprints and archive the mapping file.
- [ ] Complete Play Console Data Safety, foreground-service, full-screen-intent,
      microphone, nearby-device, and privacy declarations.
- [ ] Use staged rollout and monitor delivery/call failures before expansion.
