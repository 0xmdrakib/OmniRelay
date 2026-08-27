# Production release checklist

## Identity and ownership

- [ ] Replace `com.example.omnirelay` with a permanent application ID.
- [ ] Create and securely back up the release keystore and recovery material.
- [ ] Update `versionCode` and `versionName`.
- [ ] Confirm final app name, icons, privacy policy, and support contact.

## Infrastructure

- [ ] Provision a maintained public Linux host with automated security updates.
- [ ] Point relay and LiveKit DNS names to the host.
- [ ] Generate `.env` and LiveKit config with `initialize-production.ps1`.
- [ ] Configure Firebase Cloud Messaging without committing either client or
      service-account configuration.
- [ ] Restrict the host firewall to documented TCP/UDP ports.
- [ ] Start with `start-production.ps1` and verify Caddy TLS and `/healthz`.
- [ ] Configure encrypted PostgreSQL backups and test a restore.
- [ ] Configure uptime, disk, certificate, container, and error monitoring.

## Device validation

- [ ] Test two different physical Android devices on the same LAN.
- [ ] Test devices on separate mobile/Wi-Fi networks through TURN.
- [ ] Verify message queued/sent/delivered/read transitions.
- [ ] Verify incoming ring, accept, decline, cancel, end, mute, speaker, and
      two-way app-level E2EE audio.
- [ ] Verify BLE and Wi-Fi Aware fallback with internet disabled.
- [ ] Verify reboot, process death, Doze, notification denial, and OEM battery
      restrictions.
- [ ] Verify Android 8/API 26 and Android 13+/API 33 crypto initialization.

## Security gate

- [ ] GitHub CI, dependency review, secret scan, lint, tests, and release build pass.
- [ ] `pnpm audit --prod` and Docker Scout report no high/critical findings.
- [ ] Rotate any credential ever used outside its intended environment.
- [ ] Complete independent mobile/backend/protocol/infrastructure review.
- [ ] Document incident response, key rotation, data retention, and account
      ownership.

## Distribution

- [ ] Build a signed AAB from a clean checkout and pinned commit.
- [ ] Verify signing certificate fingerprints and archive the mapping file.
- [ ] Complete Play Console Data Safety, foreground-service, full-screen-intent,
      microphone, nearby-device, and privacy declarations.
- [ ] Use staged rollout and monitor delivery/call failures before expansion.
