import pg from "pg";
import { hashToken, tokenMatches } from "./identity.js";
import {
  isCanonicalDeviceId,
  MAX_INBOUND_ROUTES,
  routeTokenHashMatches
} from "./route-authorization.js";
import { schemaSql } from "./schema.js";

const { Pool } = pg;
const MAX_ENVELOPE_TTL_SECONDS = 90 * 24 * 60 * 60;
const MAX_CALL_TTL_SECONDS = 300;
export const MIN_ACTIVE_CALL_LEASE_SECONDS = 30;
export const MAX_ACTIVE_CALL_LEASE_SECONDS = 300;
const TERMINAL_CALL_RETENTION_SECONDS = 300;
const MAX_REGISTRATION_CHALLENGES = 16;

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
  state: "delivered" | "read" | "rejected";
};

export type IdempotentInsertResult = "inserted" | "duplicate" | "conflict";
export type CallState = "ringing" | "active" | "declined" | "ended";
export type CallTransitionState = Exclude<CallState, "ringing">;
export type CallRingEnvelopeResult =
  | "inserted"
  | "duplicate"
  | "envelope_conflict"
  | "call_conflict"
  | "expired";
export type CallTransitionEnvelopeResult =
  | { status: "inserted" | "duplicate"; otherDeviceId: string }
  | { status: "envelope_conflict" | "invalid" | "not_found" };

export type InboundRoute = {
  senderId: string;
  routeTokenHash: Buffer;
};

export class UnauthorizedRouteError extends Error {
  constructor() {
    super("unauthorized_route");
    this.name = "UnauthorizedRouteError";
  }
}

export type RepositoryPoolOptions = {
  maxConnections: number;
  idleTimeoutMillis: number;
  connectionTimeoutMillis: number;
  queryTimeoutMillis: number;
  statementTimeoutMillis: number;
  maxUses: number;
  onPoolError?: (error: Error) => void;
};

export type CleanupResult = {
  envelopes: number;
  calls: number;
  challenges: number;
};

const defaultPoolOptions: RepositoryPoolOptions = {
  maxConnections: 4,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  queryTimeoutMillis: 12_000,
  statementTimeoutMillis: 10_000,
  maxUses: 5_000
};

export class Repository {
  private readonly pool: pg.Pool;

  constructor(databaseUrl: string, options: Partial<RepositoryPoolOptions> = {}) {
    const poolOptions = { ...defaultPoolOptions, ...options };
    this.pool = new Pool({
      connectionString: databaseUrl,
      max: poolOptions.maxConnections,
      idleTimeoutMillis: poolOptions.idleTimeoutMillis,
      connectionTimeoutMillis: poolOptions.connectionTimeoutMillis,
      query_timeout: poolOptions.queryTimeoutMillis,
      statement_timeout: poolOptions.statementTimeoutMillis,
      idle_in_transaction_session_timeout: poolOptions.statementTimeoutMillis,
      maxUses: poolOptions.maxUses
    });
    this.pool.on("error", poolOptions.onPoolError ?? ((error) => {
      console.error("Unexpected idle PostgreSQL client error", error);
    }));
  }

  async migrate(): Promise<void> {
    await this.pool.query(schemaSql);
  }

  async health(): Promise<void> {
    await this.pool.query("SELECT 1");
  }

  async saveRegistrationChallenge(
    challengeId: string,
    deviceId: string,
    publicKeyBase64: string,
    signingPublicKeyBase64: string,
    nonceBase64: string,
    x25519ProofBase64: string,
    maxOutstanding: number
  ): Promise<boolean> {
    if (!Number.isInteger(maxOutstanding) || maxOutstanding < 1 ||
        maxOutstanding > MAX_REGISTRATION_CHALLENGES) {
      throw new Error("maxOutstanding registration challenges is outside the supported range");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`registration:${deviceId}`]);
      await client.query(
        "DELETE FROM registration_challenges WHERE device_id = $1 AND expires_at <= NOW()",
        [deviceId]
      );
      const capacity = await client.query(
        "SELECT COUNT(*)::integer AS count FROM registration_challenges WHERE device_id = $1",
        [deviceId]
      );
      if ((capacity.rows[0]?.count ?? maxOutstanding) >= maxOutstanding) {
        await client.query("ROLLBACK");
        return false;
      }
      await client.query(
        `INSERT INTO registration_challenges(
           challenge_id, device_id, public_key_base64, signing_public_key_base64,
           nonce_base64, x25519_proof_base64, expires_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '5 minutes')`,
        [challengeId, deviceId, publicKeyBase64, signingPublicKeyBase64, nonceBase64, x25519ProofBase64]
      );
      await client.query("COMMIT");
      return true;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async registrationChallenge(challengeId: string, deviceId: string): Promise<{
    publicKeyBase64: string;
    signingPublicKeyBase64: string;
    nonceBase64: string;
    x25519ProofBase64: string;
  } | null> {
    const result = await this.pool.query(
      `SELECT public_key_base64, signing_public_key_base64, nonce_base64, x25519_proof_base64
       FROM registration_challenges
       WHERE challenge_id = $1 AND device_id = $2 AND expires_at > NOW()`,
      [challengeId, deviceId]
    );
    const row = result.rows[0];
    return row ? {
      publicKeyBase64: row.public_key_base64,
      signingPublicKeyBase64: row.signing_public_key_base64,
      nonceBase64: row.nonce_base64,
      x25519ProofBase64: row.x25519_proof_base64
    } : null;
  }

  async consumeRegistrationChallenge(challengeId: string, deviceId: string): Promise<boolean> {
    const result = await this.pool.query(
      `DELETE FROM registration_challenges
       WHERE challenge_id = $1 AND device_id = $2 AND expires_at > NOW()`,
      [challengeId, deviceId]
    );
    return result.rowCount === 1;
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
    await this.pool.query(
      `UPDATE devices SET last_seen_at = NOW()
       WHERE device_id = $1 AND last_seen_at < NOW() - INTERVAL '5 minutes'`,
      [deviceId]
    );
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

  async replaceInboundRoutes(recipientId: string, routes: InboundRoute[]): Promise<void> {
    if (!isCanonicalDeviceId(recipientId)) throw new Error("invalid recipient device ID");
    if (routes.length > MAX_INBOUND_ROUTES) throw new Error("too many inbound routes");
    const seen = new Set<string>();
    for (const route of routes) {
      if (!isCanonicalDeviceId(route.senderId) || route.senderId === recipientId) {
        throw new Error("invalid inbound route sender");
      }
      if (route.routeTokenHash.length !== 32) throw new Error("invalid inbound route token hash");
      if (seen.has(route.senderId)) throw new Error("duplicate inbound route sender");
      seen.add(route.senderId);
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await this.lockRecipient(client, recipientId);
      await client.query("DELETE FROM inbound_routes WHERE recipient_id = $1", [recipientId]);
      if (routes.length > 0) {
        const parameters: unknown[] = [recipientId];
        const values = routes.map((route, index) => {
          const senderParameter = index * 2 + 2;
          parameters.push(route.senderId, route.routeTokenHash);
          return `($1, $${senderParameter}, $${senderParameter + 1})`;
        });
        await client.query(
          `INSERT INTO inbound_routes(recipient_id, sender_id, route_token_hash)
           VALUES ${values.join(", ")}`,
          parameters
        );
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async routeAuthorized(senderId: string, recipientId: string, routeTokenHash: Buffer): Promise<boolean> {
    this.validateRouteTokenHash(routeTokenHash);
    const result = await this.pool.query(
      `SELECT route_token_hash FROM inbound_routes
       WHERE recipient_id = $1 AND sender_id = $2`,
      [recipientId, senderId]
    );
    const storedHash = result.rows[0]?.route_token_hash;
    return Buffer.isBuffer(storedHash) && routeTokenHashMatches(storedHash, routeTokenHash);
  }

  async insertEnvelope(
    input: Omit<Envelope, "createdAt">,
    ttlSeconds: number,
    maxMailbox: number,
    maxPendingPerPair: number,
    routeTokenHash: Buffer
  ): Promise<IdempotentInsertResult> {
    if (input.kind !== "message" || input.callId !== null) {
      throw new Error("call envelopes require the transactional call methods");
    }
    this.validateEnvelopeLimits(ttlSeconds, maxMailbox, maxPendingPerPair);
    this.validateRouteTokenHash(routeTokenHash);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await this.lockRecipient(client, input.recipientId);
      await this.requireAuthorizedRoute(client, input.senderId, input.recipientId, routeTokenHash);
      const result = await this.insertEnvelopeLocked(
        client,
        input,
        ttlSeconds,
        maxMailbox,
        maxPendingPerPair
      );
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async createCallWithEnvelope(
    input: Omit<Envelope, "createdAt">,
    ttlSeconds: number,
    maxMailbox: number,
    maxPendingPerPair: number,
    routeTokenHash: Buffer
  ): Promise<CallRingEnvelopeResult> {
    if (input.kind !== "call" || !input.callId) throw new Error("call envelope requires callId");
    this.validateCallTtl(ttlSeconds);
    this.validateEnvelopeLimits(ttlSeconds, maxMailbox, maxPendingPerPair);
    this.validateRouteTokenHash(routeTokenHash);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO call_sessions(call_id, caller_id, callee_id, state, expires_at)
         VALUES ($1, $2, $3, 'ringing', NOW() + ($4 * INTERVAL '1 second'))
         ON CONFLICT (call_id) DO NOTHING`,
        [input.callId, input.senderId, input.recipientId, ttlSeconds]
      );
      const callResult = await client.query(
        `SELECT caller_id, callee_id, state, expires_at > NOW() AS unexpired
         FROM call_sessions WHERE call_id = $1 FOR UPDATE`,
        [input.callId]
      );
      const call = callResult.rows[0];
      if (call?.caller_id !== input.senderId || call?.callee_id !== input.recipientId) {
        await client.query("ROLLBACK");
        return "call_conflict";
      }
      if (call.state !== "ringing" || call.unexpired !== true) {
        await client.query("ROLLBACK");
        return "expired";
      }
      // Every call transaction locks the call row before the recipient mailbox lock.
      await this.lockRecipient(client, input.recipientId);
      await this.requireAuthorizedRoute(client, input.senderId, input.recipientId, routeTokenHash);
      const envelopeResult = await this.insertEnvelopeLocked(
        client,
        input,
        ttlSeconds,
        maxMailbox,
        maxPendingPerPair
      );
      if (envelopeResult === "conflict") {
        await client.query("ROLLBACK");
        return "envelope_conflict";
      }
      await client.query("COMMIT");
      return envelopeResult;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async transitionCallWithEnvelope(
    callId: string,
    actorId: string,
    state: CallTransitionState,
    input: Omit<Envelope, "createdAt">,
    envelopeTtlSeconds: number,
    activeLeaseSeconds: number,
    maxMailbox: number,
    maxPendingPerPair: number,
    routeTokenHash: Buffer
  ): Promise<CallTransitionEnvelopeResult> {
    if (input.kind !== "call" || input.callId !== callId || input.senderId !== actorId) {
      throw new Error("invalid call transition envelope");
    }
    this.validateEnvelopeLimits(envelopeTtlSeconds, maxMailbox, maxPendingPerPair);
    this.validateActiveLease(activeLeaseSeconds);
    this.validateRouteTokenHash(routeTokenHash);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const callResult = await client.query(
        `SELECT caller_id, callee_id, state, expires_at > NOW() AS unexpired
         FROM call_sessions
         WHERE call_id = $1 AND (caller_id = $2 OR callee_id = $2)
         FOR UPDATE`,
        [callId, actorId]
      );
      const call = callResult.rows[0];
      if (!call || call.unexpired !== true) {
        await client.query("ROLLBACK");
        return { status: "not_found" };
      }
      const otherDeviceId = call.caller_id === actorId ? call.callee_id : call.caller_id;
      if (input.recipientId !== otherDeviceId) throw new Error("call transition recipient mismatch");
      // Lock order is invariant: call row first, then the recipient advisory lock.
      await this.lockRecipient(client, otherDeviceId);
      await this.requireAuthorizedRoute(client, actorId, otherDeviceId, routeTokenHash);

      const existingEnvelope = await client.query(
        `SELECT sender_id, recipient_id, kind, call_id, frame_base64
         FROM envelopes WHERE envelope_id = $1`,
        [input.envelopeId]
      );
      if (existingEnvelope.rows[0]) {
        if (!this.envelopeMatches(existingEnvelope.rows[0], input)) {
          await client.query("ROLLBACK");
          return { status: "envelope_conflict" };
        }
        if (call.state === state && this.actorCanSetState(call.callee_id, actorId, state)) {
          await client.query("COMMIT");
          return { status: "duplicate", otherDeviceId };
        }
        await client.query("ROLLBACK");
        return { status: "invalid" };
      }

      if (!this.transitionAllowed(call.state, call.callee_id, actorId, state)) {
        await client.query("ROLLBACK");
        return { status: "invalid" };
      }
      const stateTtlSeconds = state === "active" ? activeLeaseSeconds : TERMINAL_CALL_RETENTION_SECONDS;
      await client.query(
        `UPDATE call_sessions
         SET state = $2, updated_at = NOW(), expires_at = NOW() + ($3 * INTERVAL '1 second')
         WHERE call_id = $1`,
        [callId, state, stateTtlSeconds]
      );
      const envelopeResult = await this.insertEnvelopeLocked(
        client,
        input,
        envelopeTtlSeconds,
        maxMailbox,
        maxPendingPerPair
      );
      if (envelopeResult === "conflict") {
        await client.query("ROLLBACK");
        return { status: "envelope_conflict" };
      }
      await client.query("COMMIT");
      return { status: envelopeResult, otherDeviceId };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async callForParticipant(callId: string, deviceId: string): Promise<{
    callerId: string;
    calleeId: string;
    state: CallState;
    expiresAt: string;
  } | null> {
    const result = await this.pool.query(
      `SELECT caller_id, callee_id, state, expires_at FROM call_sessions
       WHERE call_id = $1 AND (caller_id = $2 OR callee_id = $2) AND expires_at > NOW()`,
      [callId, deviceId]
    );
    const row = result.rows[0];
    return row ? {
      callerId: row.caller_id,
      calleeId: row.callee_id,
      state: row.state,
      expiresAt: new Date(row.expires_at).toISOString()
    } : null;
  }

  async renewCallLease(callId: string, actorId: string, leaseSeconds: number): Promise<string | null> {
    this.validateActiveLease(leaseSeconds);
    const result = await this.pool.query(
      `UPDATE call_sessions
       SET updated_at = NOW(), expires_at = NOW() + ($3 * INTERVAL '1 second')
       WHERE call_id = $1 AND (caller_id = $2 OR callee_id = $2)
         AND state = 'active' AND expires_at > NOW()
       RETURNING expires_at`,
      [callId, actorId, leaseSeconds]
    );
    return result.rows[0] ? new Date(result.rows[0].expires_at).toISOString() : null;
  }

  private validateCallTtl(ttlSeconds: number): void {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > MAX_CALL_TTL_SECONDS) {
      throw new Error("call ttlSeconds is outside the supported range");
    }
  }

  private validateActiveLease(leaseSeconds: number): void {
    if (!Number.isInteger(leaseSeconds) || leaseSeconds < MIN_ACTIVE_CALL_LEASE_SECONDS ||
        leaseSeconds > MAX_ACTIVE_CALL_LEASE_SECONDS) {
      throw new Error("active call lease is outside the supported range");
    }
  }

  private validateEnvelopeLimits(ttlSeconds: number, maxMailbox: number, maxPendingPerPair: number): void {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > MAX_ENVELOPE_TTL_SECONDS) {
      throw new Error("envelope ttlSeconds is outside the supported range");
    }
    if (!Number.isInteger(maxMailbox) || maxMailbox < 1 ||
        !Number.isInteger(maxPendingPerPair) || maxPendingPerPair < 1 ||
        maxPendingPerPair > maxMailbox) {
      throw new Error("mailbox limits are outside the supported range");
    }
  }

  private validateRouteTokenHash(routeTokenHash: Buffer): void {
    if (!Buffer.isBuffer(routeTokenHash) || routeTokenHash.length !== 32) {
      throw new Error("route token hash must be 32 bytes");
    }
  }

  private async lockRecipient(client: pg.PoolClient, recipientId: string): Promise<void> {
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`mailbox:${recipientId}`]);
  }

  private async requireAuthorizedRoute(
    client: pg.PoolClient,
    senderId: string,
    recipientId: string,
    routeTokenHash: Buffer
  ): Promise<void> {
    const route = await client.query(
      `SELECT route_token_hash FROM inbound_routes
       WHERE recipient_id = $1 AND sender_id = $2`,
      [recipientId, senderId]
    );
    const storedHash = route.rows[0]?.route_token_hash;
    if (!Buffer.isBuffer(storedHash) || !routeTokenHashMatches(storedHash, routeTokenHash)) {
      throw new UnauthorizedRouteError();
    }
  }

  private async insertEnvelopeLocked(
    client: pg.PoolClient,
    input: Omit<Envelope, "createdAt">,
    ttlSeconds: number,
    maxMailbox: number,
    maxPendingPerPair: number
  ): Promise<IdempotentInsertResult> {
    const existing = await client.query(
      `SELECT sender_id, recipient_id, kind, call_id, frame_base64
       FROM envelopes WHERE envelope_id = $1`,
      [input.envelopeId]
    );
    if (existing.rows[0]) return this.envelopeMatches(existing.rows[0], input) ? "duplicate" : "conflict";
    const capacity = await client.query(
      `SELECT EXISTS (
         SELECT 1 FROM envelopes
         WHERE recipient_id = $1 AND delivered_at IS NULL AND expires_at > NOW()
         LIMIT 1 OFFSET $2
       ) AS full`,
      [input.recipientId, maxMailbox - 1]
    );
    if (capacity.rows[0]?.full === true) throw new Error("mailbox_full");
    const pairCapacity = await client.query(
      `SELECT EXISTS (
         SELECT 1 FROM envelopes
         WHERE recipient_id = $1 AND sender_id = $2
           AND delivered_at IS NULL AND expires_at > NOW()
         LIMIT 1 OFFSET $3
       ) AS full`,
      [input.recipientId, input.senderId, maxPendingPerPair - 1]
    );
    if (pairCapacity.rows[0]?.full === true) throw new Error("pair_mailbox_full");
    const result = await client.query(
      `INSERT INTO envelopes(envelope_id, sender_id, recipient_id, kind, call_id, frame_base64, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW() + ($7 * INTERVAL '1 second'))
       ON CONFLICT (envelope_id) DO NOTHING`,
      [input.envelopeId, input.senderId, input.recipientId, input.kind, input.callId, input.frameBase64, ttlSeconds]
    );
    if (result.rowCount === 1) return "inserted";
    const raced = await client.query(
      `SELECT sender_id, recipient_id, kind, call_id, frame_base64
       FROM envelopes WHERE envelope_id = $1`,
      [input.envelopeId]
    );
    return raced.rows[0] && this.envelopeMatches(raced.rows[0], input) ? "duplicate" : "conflict";
  }

  private actorCanSetState(calleeId: string, actorId: string, state: CallTransitionState): boolean {
    return state === "ended" || calleeId === actorId;
  }

  private transitionAllowed(
    currentState: CallState,
    calleeId: string,
    actorId: string,
    targetState: CallTransitionState
  ): boolean {
    if (!this.actorCanSetState(calleeId, actorId, targetState)) return false;
    return targetState === "ended"
      ? currentState === "ringing" || currentState === "active"
      : currentState === "ringing";
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
              CASE
                WHEN rejected_at IS NOT NULL THEN 'rejected'
                WHEN read_at IS NOT NULL THEN 'read'
                ELSE 'delivered'
              END AS state
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
    state: "delivered" | "read" | "rejected"
  ): Promise<{ senderId: string; state: "delivered" | "read" | "rejected" } | null> {
    const assignments = state === "read"
      ? "delivered_at = COALESCE(delivered_at, NOW()), read_at = COALESCE(read_at, NOW())"
      : state === "rejected"
        ? "delivered_at = COALESCE(delivered_at, NOW()), rejected_at = COALESCE(rejected_at, NOW())"
        : "delivered_at = COALESCE(delivered_at, NOW())";
    const result = await this.pool.query(
      `UPDATE envelopes SET ${assignments}
       WHERE envelope_id = $1 AND recipient_id = $2
       RETURNING sender_id,
         CASE
           WHEN rejected_at IS NOT NULL THEN 'rejected'
           WHEN read_at IS NOT NULL THEN 'read'
           ELSE 'delivered'
         END AS state`,
      [envelopeId, recipientId]
    );
    return result.rows[0] ? { senderId: result.rows[0].sender_id, state: result.rows[0].state } : null;
  }

  async cleanup(batchSize = 500): Promise<CleanupResult> {
    if (!Number.isInteger(batchSize) || batchSize < 1) {
      throw new Error("cleanup batchSize must be a positive integer");
    }
    const expiredEnvelopes = await this.pool.query(
      `WITH candidates AS (
         SELECT envelope_id FROM envelopes
         WHERE expires_at <= NOW()
         ORDER BY expires_at ASC LIMIT $1
         FOR UPDATE SKIP LOCKED
       )
       DELETE FROM envelopes AS target
       USING candidates
       WHERE target.envelope_id = candidates.envelope_id`,
      [batchSize]
    );
    const remainingEnvelopeCapacity = batchSize - (expiredEnvelopes.rowCount ?? 0);
    const readEnvelopes = remainingEnvelopeCapacity > 0
      ? await this.pool.query(
          `WITH candidates AS (
             SELECT envelope_id FROM envelopes
             WHERE read_at < NOW() - INTERVAL '7 days'
                OR rejected_at < NOW() - INTERVAL '1 day'
             ORDER BY LEAST(
               COALESCE(read_at, 'infinity'::timestamptz),
               COALESCE(rejected_at, 'infinity'::timestamptz)
             ) ASC LIMIT $1
             FOR UPDATE SKIP LOCKED
           )
           DELETE FROM envelopes AS target
           USING candidates
           WHERE target.envelope_id = candidates.envelope_id`,
          [remainingEnvelopeCapacity]
        )
      : null;
    const calls = await this.pool.query(
      `WITH candidates AS (
         SELECT call_id FROM call_sessions
         WHERE expires_at <= NOW()
         ORDER BY expires_at ASC LIMIT $1
         FOR UPDATE SKIP LOCKED
       )
       DELETE FROM call_sessions AS target
       USING candidates
       WHERE target.call_id = candidates.call_id`,
      [batchSize]
    );
    const challenges = await this.pool.query(
      `WITH candidates AS (
         SELECT challenge_id FROM registration_challenges
         WHERE expires_at <= NOW()
         ORDER BY expires_at ASC LIMIT $1
         FOR UPDATE SKIP LOCKED
       )
       DELETE FROM registration_challenges AS target
       USING candidates
       WHERE target.challenge_id = candidates.challenge_id`,
      [batchSize]
    );
    return {
      envelopes: (expiredEnvelopes.rowCount ?? 0) + (readEnvelopes?.rowCount ?? 0),
      calls: calls.rowCount ?? 0,
      challenges: challenges.rowCount ?? 0
    };
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
