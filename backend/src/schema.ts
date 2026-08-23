export const schemaSql = `
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  public_key_base64 TEXT UNIQUE NOT NULL,
  signing_public_key_base64 TEXT NOT NULL,
  token_hash BYTEA NOT NULL,
  token_expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),
  fcm_token TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS registration_challenges (
  device_id TEXT PRIMARY KEY,
  public_key_base64 TEXT NOT NULL,
  signing_public_key_base64 TEXT NOT NULL,
  nonce_base64 TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS call_sessions (
  call_id UUID PRIMARY KEY,
  caller_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  callee_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK (state IN ('ringing', 'active', 'declined', 'ended')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS envelopes (
  envelope_id UUID PRIMARY KEY,
  sender_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  recipient_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('message', 'call')),
  call_id UUID REFERENCES call_sessions(call_id) ON DELETE CASCADE,
  frame_base64 TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  delivered_at TIMESTAMPTZ,
  read_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS envelopes_mailbox_idx
  ON envelopes(recipient_id, created_at) WHERE delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS envelopes_expiry_idx ON envelopes(expires_at);
CREATE INDEX IF NOT EXISTS call_sessions_participants_idx
  ON call_sessions(caller_id, callee_id, updated_at DESC);

ALTER TABLE devices ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;
UPDATE devices SET token_expires_at = NOW() + INTERVAL '30 days' WHERE token_expires_at IS NULL;
ALTER TABLE devices ALTER COLUMN token_expires_at SET DEFAULT (NOW() + INTERVAL '30 days');
ALTER TABLE devices ALTER COLUMN token_expires_at SET NOT NULL;
`;
