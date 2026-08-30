export const schemaSql = `
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  public_key_base64 TEXT UNIQUE NOT NULL,
  signing_public_key_base64 TEXT NOT NULL,
  account_uid TEXT,
  token_hash BYTEA NOT NULL,
  token_expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),
  fcm_token TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT devices_account_uid_bounds
    CHECK (account_uid IS NULL OR char_length(account_uid) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS registration_challenges (
  challenge_id UUID PRIMARY KEY,
  device_id TEXT NOT NULL,
  account_uid TEXT NOT NULL,
  public_key_base64 TEXT NOT NULL,
  signing_public_key_base64 TEXT NOT NULL,
  nonce_base64 TEXT NOT NULL,
  x25519_proof_base64 TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT registration_challenges_account_uid_bounds
    CHECK (char_length(account_uid) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS inbound_routes (
  recipient_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  sender_id TEXT NOT NULL CHECK (sender_id ~ '^[0-9a-f]{64}$'),
  route_token_hash BYTEA NOT NULL CHECK (octet_length(route_token_hash) = 32),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (recipient_id, sender_id),
  CHECK (recipient_id <> sender_id)
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
  read_at TIMESTAMPTZ,
  rejected_at TIMESTAMPTZ
);

ALTER TABLE envelopes ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS account_uid TEXT;
ALTER TABLE registration_challenges ADD COLUMN IF NOT EXISTS account_uid TEXT;
ALTER TABLE registration_challenges ADD COLUMN IF NOT EXISTS x25519_proof_base64 TEXT;
ALTER TABLE registration_challenges ADD COLUMN IF NOT EXISTS challenge_id UUID;
ALTER TABLE registration_challenges ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
UPDATE registration_challenges SET challenge_id = gen_random_uuid() WHERE challenge_id IS NULL;
ALTER TABLE registration_challenges ALTER COLUMN challenge_id SET NOT NULL;

-- Challenges issued before account authentication cannot be upgraded safely.
DELETE FROM registration_challenges WHERE account_uid IS NULL;
ALTER TABLE registration_challenges ALTER COLUMN account_uid SET NOT NULL;

DO $account_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'devices'::regclass AND conname = 'devices_account_uid_bounds'
  ) THEN
    ALTER TABLE devices ADD CONSTRAINT devices_account_uid_bounds
      CHECK (account_uid IS NULL OR char_length(account_uid) BETWEEN 1 AND 128);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'registration_challenges'::regclass
      AND conname = 'registration_challenges_account_uid_bounds'
  ) THEN
    ALTER TABLE registration_challenges
      ADD CONSTRAINT registration_challenges_account_uid_bounds
      CHECK (char_length(account_uid) BETWEEN 1 AND 128);
  END IF;
END
$account_constraints$;

DO $migration$
DECLARE
  legacy_primary_key TEXT;
BEGIN
  SELECT constraint_record.conname INTO legacy_primary_key
  FROM pg_constraint AS constraint_record
  WHERE constraint_record.conrelid = 'registration_challenges'::regclass
    AND constraint_record.contype = 'p'
    AND (
      SELECT array_agg(attribute_record.attname ORDER BY key_column.ordinality)
      FROM unnest(constraint_record.conkey) WITH ORDINALITY AS key_column(attnum, ordinality)
      JOIN pg_attribute AS attribute_record
        ON attribute_record.attrelid = constraint_record.conrelid
       AND attribute_record.attnum = key_column.attnum
    ) = ARRAY['device_id']::name[];
  IF legacy_primary_key IS NOT NULL THEN
    EXECUTE format('ALTER TABLE registration_challenges DROP CONSTRAINT %I', legacy_primary_key);
    ALTER TABLE registration_challenges
      ADD CONSTRAINT registration_challenges_pkey PRIMARY KEY (challenge_id);
  END IF;
END
$migration$;

CREATE INDEX IF NOT EXISTS envelopes_mailbox_idx
  ON envelopes(recipient_id, created_at) WHERE delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS envelopes_pair_pending_idx
  ON envelopes(recipient_id, sender_id, created_at) WHERE delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS envelopes_outbound_status_idx
  ON envelopes(sender_id, created_at DESC) WHERE delivered_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS envelopes_call_idx
  ON envelopes(call_id) WHERE call_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS envelopes_expiry_idx ON envelopes(expires_at);
CREATE INDEX IF NOT EXISTS envelopes_read_cleanup_idx ON envelopes(read_at)
  WHERE read_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS envelopes_rejected_cleanup_idx ON envelopes(rejected_at)
  WHERE rejected_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS call_sessions_participants_idx
  ON call_sessions(caller_id, callee_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS call_sessions_expiry_idx ON call_sessions(expires_at);
UPDATE call_sessions
SET expires_at = NOW() + INTERVAL '120 seconds', updated_at = NOW()
WHERE state = 'active' AND expires_at > NOW() + INTERVAL '120 seconds';
CREATE INDEX IF NOT EXISTS registration_challenges_expiry_idx
  ON registration_challenges(expires_at);
CREATE INDEX IF NOT EXISTS registration_challenges_device_idx
  ON registration_challenges(device_id, created_at);
CREATE INDEX IF NOT EXISTS registration_challenges_account_idx
  ON registration_challenges(account_uid, created_at);
CREATE INDEX IF NOT EXISTS devices_account_uid_idx
  ON devices(account_uid) WHERE account_uid IS NOT NULL;

ALTER TABLE devices ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;
UPDATE devices SET token_expires_at = NOW() + INTERVAL '30 days' WHERE token_expires_at IS NULL;
ALTER TABLE devices ALTER COLUMN token_expires_at SET DEFAULT (NOW() + INTERVAL '30 days');
ALTER TABLE devices ALTER COLUMN token_expires_at SET NOT NULL;
`;
