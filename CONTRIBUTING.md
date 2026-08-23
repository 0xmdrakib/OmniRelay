# Contributing

This is a private, proprietary repository. Only authorized collaborators may
contribute.

## Required checks

Before proposing a change:

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat testDebugUnitTest lintDebug assembleDebug

Set-Location backend
npx pnpm install --frozen-lockfile
npx pnpm typecheck
npx pnpm test:unit
npx pnpm audit
```

Changes to the wire format, identity storage, cryptography, registration,
authorization, call state, or deployment configuration require tests and a
security-impact explanation.

Never commit `.env`, `local.properties`, `google-services.json`, Firebase
service accounts, generated LiveKit configuration, signing keys, APK/AAB files,
database dumps, tokens, or production logs.
