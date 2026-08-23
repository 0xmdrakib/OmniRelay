import pg from "pg";
import { hashToken, tokenMatches } from "./identity.js";
import { schemaSql } from "./schema.js";

const { Pool } = pg;

export type Device = {
  deviceId: string;
  publicKeyBase64: string;
  tokenHash: Buffer;
  fcmToken: string | null;
};

export type Envelope = {
  envelopeId: string;
  senderId: string;
  recipientId: string;
  kind: "message" | "call";
  callId: string | null;
  frameBase64: string;
  createdAt: string;
};

export type OutboundStatus = {
  envelopeId: string;
  state: "delivered" | "read";
};

export type IdempotentInsertResult = "inserted" | "duplicate" | "conflict";

export class Repository {
  private readonly pool: pg.Pool;

  constructor(databaseUrl: string) {
    this.pool = new Pool({ connectionString: databaseUrl, max: 20 });
  }

  async migrate(): Promise<void> {
    await this.pool.query(schemaSql);
  }

  async health(): Promise<void> {
    await this.pool.query("SELECT 1");
  }

  async saveRegistrationChallenge(
    deviceId: string,
    publicKeyBase64: string,
    signingPublicKeyBase64: string,
    nonceBase64: string
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO registration_challenges(device_id, public_key_base64, signing_public_key_base64, nonce_base64, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + INTERVAL '5 minutes')
       ON CONFLICT (device_id) DO UPDATE SET
         public_key_base64 = EXCLUDED.public_key_base64,
         signing_public_key_base64 = EXCLUDED.signing_public_key_base64,
         nonce_base64 = EXCLUDED.nonce_base64,
         expires_at = EXCLUDED.expires_at`,
      [deviceId, publicKeyBase64, signingPublicKeyBase64, nonceBase64]
    );
  }

  async consumeRegistrationChallenge(deviceId: string): Promise<{
    publicKeyBase64: string;
    signingPublicKeyBase64: string;
    nonceBase64: string;
  } | null> {
    const result = await this.pool.query(
      `DELETE FROM registration_challenges WHERE device_id = $1 AND expires_at > NOW()
       RETURNING public_key_base64, signing_public_key_base64, nonce_base64`,
      [deviceId]
    );
    const row = result.rows[0];
    return row ? {
      publicKeyBase64: row.public_key_base64,
      signingPublicKeyBase64: row.signing_public_key_base64,
      nonceBase64: row.nonce_base64
    } : null;
  }

  async registerOrRotate(
    deviceId: string,
    publicKeyBase64: string,
    signingPublicKeyBase64: string,
    token: string
  ): Promise<boolean> {
    const result = await this.pool.query(
      `INSERT INTO devices(device_id, public_key_base64, signing_public_key_base64, token_hash)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (device_id) DO UPDATE SET
         token_hash = EXCLUDED.token_hash,
         token_expires_at = NOW() + INTERVAL '30 days',
         last_seen_at = NOW()
       WHERE devices.public_key_base64 = EXCLUDED.public_key_base64
         AND devices.signing_public_key_base64 = EXCLUDED.signing_public_key_base64`,
      [deviceId, publicKeyBase64, signingPublicKeyBase64, hashToken(token)]
    );
    return result.rowCount === 1;
  }

  async authenticate(deviceId: string, token: string): Promise<Device | null> {
    const result = await this.pool.query(
      `SELECT device_id, public_key_base64, token_hash, fcm_token
       FROM devices WHERE device_id = $1 AND token_expires_at > NOW()`,
      [deviceId]
    );
    const row = result.rows[0];
    if (!row || !tokenMatches(token, row.token_hash)) return null;
    await this.pool.query("UPDATE devices SET last_seen_at = NOW() WHERE device_id = $1", [deviceId]);
    return {
      deviceId: row.device_id,
      publicKeyBase64: row.public_key_base64,
      tokenHash: row.token_hash,
      fcmToken: row.fcm_token
    };
  }

  async setFcmToken(deviceId: string, fcmToken: string | null): Promise<void> {
    await this.pool.query("UPDATE devices SET fcm_token = $2 WHERE device_id = $1", [deviceId, fcmToken]);
  }

  async fcmTokenFor(deviceId: string): Promise<string | null> {
    const result = await this.pool.query("SELECT fcm_token FROM devices WHERE device_id = $1", [deviceId]);
    return result.rows[0]?.fcm_token ?? null;
  }

  async publicKeyForDevice(deviceId: string): Promise<string | null> {
    const result = await this.pool.query("SELECT public_key_base64 FROM devices WHERE device_id = $1", [deviceId]);
    return result.rows[0]?.public_key_base64 ?? null;
  }

  async signingPublicKeyForDevice(deviceId: string): Promise<string | null> {
    const result = await this.pool.query(
      "SELECT signing_public_key_base64 FROM devices WHERE device_id = $1",
      [deviceId]
    );
    return result.rows[0]?.signing_public_key_base64 ?? null;
  }

  async ensureCall(callId: string, callerId: string, calleeId: string): Promise<IdempotentInsertResult> {
    const result = await this.pool.query(
      `INSERT INTO call_sessions(call_id, caller_id, callee_id, state, expires_at)
       VALUES ($1, $2, $3, 'ringing', NOW() + INTERVAL '2 minutes')
       ON CONFLICT (call_id) DO NOTHING`,
      [callId, callerId, calleeId]
    );
    if (result.rowCount === 1) return "inserted";
    const existing = await this.pool.query(
      "SELECT caller_id, callee_id FROM call_sessions WHERE call_id = $1",
      [callId]
    );
    const row = existing.rows[0];
    return row?.caller_id === callerId && row?.callee_id === calleeId ? "duplicate" : "conflict";
  }

  async transitionCall(
    callId: string,
    actorId: string,
    state: "active" | "declined" | "ended"
  ): Promise<{ otherDeviceId: string; callerId: string; calleeId: string } | null> {
    const result = await this.pool.query(
      `UPDATE call_sessions
       SET state = $3, updated_at = NOW(),
           expires_at = CASE WHEN $3 = 'active' THEN NOW() + INTERVAL '12 hours' ELSE NOW() + INTERVAL '5 minutes' END
       WHERE call_id = $1
         AND (
           ($3 IN ('active', 'declined') AND callee_id = $2 AND state = 'ringing') OR
           ($3 = 'ended' AND (caller_id = $2 OR callee_id = $2) AND state IN ('ringing', 'active'))
         )
       RETURNING caller_id, callee_id`,
      [callId, actorId, state]
    );
    const row = result.rows[0];
    if (!row) {
      const existing = await this.callForParticipant(callId, actorId);
      const idempotent = existing?.state === state && (
        (state === "ended" && (existing.callerId === actorId || existing.calleeId === actorId)) ||
        (state !== "ended" && existing.calleeId === actorId)
      );
      if (!existing || !idempotent) return null;
      return {
        callerId: existing.callerId,
        calleeId: existing.calleeId,
        otherDeviceId: existing.callerId === actorId ? existing.calleeId : existing.callerId
      };
    }
    return {
      callerId: row.caller_id,
      calleeId: row.callee_id,
      otherDeviceId: row.caller_id === actorId ? row.callee_id : row.caller_id
    };
  }

  async callForParticipant(callId: string, deviceId: string): Promise<{
    callerId: string;
    calleeId: string;
    state: string;
  } | null> {
    const result = await this.pool.query(
      `SELECT caller_id, callee_id, state FROM call_sessions
       WHERE call_id = $1 AND (caller_id = $2 OR callee_id = $2) AND expires_at > NOW()`,
      [callId, deviceId]
    );
    const row = result.rows[0];
    return row ? { callerId: row.caller_id, calleeId: row.callee_id, state: row.state } : null;
  }

  async insertEnvelope(
    input: Omit<Envelope, "createdAt">,
    ttlDays: number,
    maxMailbox: number
  ): Promise<IdempotentInsertResult> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [input.recipientId]);
      const existing = await client.query(
        `SELECT sender_id, recipient_id, kind, call_id, frame_base64
         FROM envelopes WHERE envelope_id = $1`,
        [input.envelopeId]
      );
      if (existing.rows[0]) {
        const outcome = this.envelopeMatches(existing.rows[0], input) ? "duplicate" : "conflict";
        await client.query("COMMIT");
        return outcome;
      }
      const count = await client.query(
        `SELECT COUNT(*)::int AS count FROM envelopes
         WHERE recipient_id = $1 AND delivered_at IS NULL AND expires_at > NOW()`,
        [input.recipientId]
      );
      if ((count.rows[0]?.count ?? 0) >= maxMailbox) throw new Error("mailbox_full");
      const result = await client.query(
        `INSERT INTO envelopes(envelope_id, sender_id, recipient_id, kind, call_id, frame_base64, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW() + ($7 || ' days')::interval)
         ON CONFLICT (envelope_id) DO NOTHING`,
        [input.envelopeId, input.senderId, input.recipientId, input.kind, input.callId, input.frameBase64, ttlDays]
      );
      if (result.rowCount === 1) {
        await client.query("COMMIT");
        return "inserted";
      }
      const raced = await client.query(
        `SELECT sender_id, recipient_id, kind, call_id, frame_base64
         FROM envelopes WHERE envelope_id = $1`,
        [input.envelopeId]
      );
      const outcome = raced.rows[0] && this.envelopeMatches(raced.rows[0], input)
        ? "duplicate"
        : "conflict";
      await client.query("COMMIT");
      return outcome;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  private envelopeMatches(row: Record<string, unknown>, input: Omit<Envelope, "createdAt">): boolean {
    return row.sender_id === input.senderId &&
      row.recipient_id === input.recipientId &&
      row.kind === input.kind &&
      (row.call_id ?? null) === (input.callId ?? null) &&
      row.frame_base64 === input.frameBase64;
  }

  async mailbox(recipientId: string, after: string | null, limit: number): Promise<Envelope[]> {
    const result = await this.pool.query(
      `SELECT envelope_id, sender_id, recipient_id, kind, call_id, frame_base64, created_at
       FROM envelopes
       WHERE recipient_id = $1 AND expires_at > NOW() AND delivered_at IS NULL
         AND ($2::timestamptz IS NULL OR created_at > $2::timestamptz)
       ORDER BY created_at ASC LIMIT $3`,
      [recipientId, after, limit]
    );
    return result.rows.map((row) => ({
      envelopeId: row.envelope_id,
      senderId: row.sender_id,
      recipientId: row.recipient_id,
      kind: row.kind,
      callId: row.call_id,
      frameBase64: row.frame_base64,
      createdAt: row.created_at.toISOString()
    }));
  }

  async outboundStatuses(senderId: string, limit: number): Promise<OutboundStatus[]> {
    const result = await this.pool.query(
      `SELECT envelope_id,
              CASE WHEN read_at IS NOT NULL THEN 'read' ELSE 'delivered' END AS state
       FROM envelopes
       WHERE sender_id = $1 AND delivered_at IS NOT NULL
         AND created_at > NOW() - INTERVAL '30 days'
       ORDER BY created_at DESC LIMIT $2`,
      [senderId, limit]
    );
    return result.rows.map((row) => ({ envelopeId: row.envelope_id, state: row.state }));
  }

  async acknowledge(
    recipientId: string,
    envelopeId: string,
    state: "delivered" | "read"
  ): Promise<{ senderId: string; state: "delivered" | "read" } | null> {
    const assignments = state === "read"
      ? "delivered_at = COALESCE(delivered_at, NOW()), read_at = COALESCE(read_at, NOW())"
      : "delivered_at = COALESCE(delivered_at, NOW())";
    const result = await this.pool.query(
      `UPDATE envelopes SET ${assignments}
       WHERE envelope_id = $1 AND recipient_id = $2
       RETURNING sender_id, CASE WHEN read_at IS NOT NULL THEN 'read' ELSE 'delivered' END AS state`,
      [envelopeId, recipientId]
    );
    return result.rows[0] ? { senderId: result.rows[0].sender_id, state: result.rows[0].state } : null;
  }

  async cleanup(): Promise<void> {
    await this.pool.query("DELETE FROM envelopes WHERE expires_at <= NOW() OR read_at < NOW() - INTERVAL '7 days'");
    await this.pool.query("DELETE FROM call_sessions WHERE expires_at <= NOW()");
    await this.pool.query("DELETE FROM registration_challenges WHERE expires_at <= NOW()");
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
