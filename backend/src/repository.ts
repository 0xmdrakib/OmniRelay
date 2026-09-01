import pg from "pg";
import { isValidAccountUid, normalizeVerifiedEmail } from "./account-auth.js";
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
const MAX_ACCOUNT_REGISTRATION_CHALLENGES = 64;

export type DeviceRegistrationResult =
  | "registered"
  | "signing_identity_mismatch"
  | "account_mismatch";

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
  | { status: "envelope_conflict" | "invalid" | "not_found" | "participant_busy" };

export type ContactInvitation = {
  invitationId: string;
  direction: "incoming" | "outgoing";
  counterpartAccountUid: string;
  counterpartEmail: string;
  createdAt: string;
  expiresAt: string;
};

export type AccountContact = {
  accountUid: string;
  email: string;
  deviceId: string | null;
  publicKeyBase64: string | null;
};

export type CreateContactInvitationResult =
  | { status: "created"; invitationId: string; recipientDeviceIds: string[]; remainingToday: number }
  | { status: "already_pending"; invitationId: string }
  | { status: "already_contact" | "recipient_unavailable" | "daily_limit" | "contact_limit" | "self" };

export type RespondContactInvitationResult =
  | { status: "accepted" | "declined"; otherDeviceIds: string[] }
  | { status: "not_found" | "expired" | "contact_limit" };

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
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", ["omnirelay-schema-v2"]);
      await client.query(schemaSql);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async health(): Promise<void> {
    await this.pool.query("SELECT 1");
  }

  async saveRegistrationChallenge(
    challengeId: string,
    deviceId: string,
    accountUid: string,
    publicKeyBase64: string,
    signingPublicKeyBase64: string,
    nonceBase64: string,
    x25519ProofBase64: string,
    maxOutstanding: number,
    maxOutstandingForAccount: number
  ): Promise<boolean> {
    if (!isValidAccountUid(accountUid)) throw new Error("invalid account UID");
    if (!Number.isInteger(maxOutstanding) || maxOutstanding < 1 ||
        maxOutstanding > MAX_REGISTRATION_CHALLENGES) {
      throw new Error("maxOutstanding registration challenges is outside the supported range");
    }
    if (!Number.isInteger(maxOutstandingForAccount) || maxOutstandingForAccount < 1 ||
        maxOutstandingForAccount > MAX_ACCOUNT_REGISTRATION_CHALLENGES) {
      throw new Error("maxOutstandingForAccount registration challenges is outside the supported range");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`account-registration:${accountUid}`]);
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`registration:${deviceId}`]);
      await client.query(
        `DELETE FROM registration_challenges
         WHERE (device_id = $1 OR account_uid = $2) AND expires_at <= NOW()`,
        [deviceId, accountUid]
      );
      const capacity = await client.query(
        `SELECT
           COUNT(*) FILTER (WHERE device_id = $1)::integer AS device_count,
           COUNT(*) FILTER (WHERE account_uid = $2)::integer AS account_count
         FROM registration_challenges
         WHERE device_id = $1 OR account_uid = $2`,
        [deviceId, accountUid]
      );
      const row = capacity.rows[0];
      if ((row?.device_count ?? maxOutstanding) >= maxOutstanding ||
          (row?.account_count ?? maxOutstandingForAccount) >= maxOutstandingForAccount) {
        await client.query("ROLLBACK");
        return false;
      }
      await client.query(
        `INSERT INTO registration_challenges(
           challenge_id, device_id, account_uid, public_key_base64, signing_public_key_base64,
           nonce_base64, x25519_proof_base64, expires_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + INTERVAL '5 minutes')`,
        [
          challengeId,
          deviceId,
          accountUid,
          publicKeyBase64,
          signingPublicKeyBase64,
          nonceBase64,
          x25519ProofBase64
        ]
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
    accountUid: string;
    publicKeyBase64: string;
    signingPublicKeyBase64: string;
    nonceBase64: string;
    x25519ProofBase64: string;
  } | null> {
    const result = await this.pool.query(
      `SELECT account_uid, public_key_base64, signing_public_key_base64, nonce_base64, x25519_proof_base64
       FROM registration_challenges
       WHERE challenge_id = $1 AND device_id = $2 AND expires_at > NOW()`,
      [challengeId, deviceId]
    );
    const row = result.rows[0];
    return row ? {
      accountUid: row.account_uid,
      publicKeyBase64: row.public_key_base64,
      signingPublicKeyBase64: row.signing_public_key_base64,
      nonceBase64: row.nonce_base64,
      x25519ProofBase64: row.x25519_proof_base64
    } : null;
  }

  async consumeRegistrationChallenge(
    challengeId: string,
    deviceId: string,
    accountUid: string
  ): Promise<boolean> {
    if (!isValidAccountUid(accountUid)) return false;
    const result = await this.pool.query(
      `DELETE FROM registration_challenges
       WHERE challenge_id = $1 AND device_id = $2 AND account_uid = $3 AND expires_at > NOW()`,
      [challengeId, deviceId, accountUid]
    );
    return result.rowCount === 1;
  }

  async registerOrRotate(
    deviceId: string,
    accountUid: string,
    publicKeyBase64: string,
    signingPublicKeyBase64: string,
    token: string
  ): Promise<DeviceRegistrationResult> {
    if (!isValidAccountUid(accountUid)) throw new Error("invalid account UID");
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`registration:${deviceId}`]);
      const existing = await client.query(
        `SELECT public_key_base64, signing_public_key_base64, account_uid
         FROM devices WHERE device_id = $1 FOR UPDATE`,
        [deviceId]
      );
      const row = existing.rows[0];
      if (!row) {
        await client.query(
          `INSERT INTO devices(
             device_id, account_uid, public_key_base64, signing_public_key_base64, token_hash
           ) VALUES ($1, $2, $3, $4, $5)`,
          [deviceId, accountUid, publicKeyBase64, signingPublicKeyBase64, hashToken(token)]
        );
      } else {
        if (row.public_key_base64 !== publicKeyBase64 ||
            row.signing_public_key_base64 !== signingPublicKeyBase64) {
          await client.query("ROLLBACK");
          return "signing_identity_mismatch";
        }
        if (row.account_uid !== null && row.account_uid !== accountUid) {
          await client.query("ROLLBACK");
          return "account_mismatch";
        }
        await client.query(
          `UPDATE devices SET
             account_uid = COALESCE(account_uid, $2),
             token_hash = $3,
             token_expires_at = NOW() + INTERVAL '30 days',
             last_seen_at = NOW()
           WHERE device_id = $1`,
          [deviceId, accountUid, hashToken(token)]
        );
      }
      await client.query("COMMIT");
      return "registered";
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async accountUidForDevice(deviceId: string): Promise<string | null> {
    const result = await this.pool.query("SELECT account_uid FROM devices WHERE device_id = $1", [deviceId]);
    return result.rows[0]?.account_uid ?? null;
  }

  async upsertAccount(accountUid: string, verifiedEmail: string): Promise<boolean> {
    const email = normalizeVerifiedEmail(verifiedEmail);
    if (!isValidAccountUid(accountUid) || !email) throw new Error("invalid verified account");
    try {
      const result = await this.pool.query(
        `INSERT INTO accounts(account_uid, normalized_email)
         VALUES ($1, $2)
         ON CONFLICT (account_uid) DO UPDATE
           SET normalized_email = EXCLUDED.normalized_email, updated_at = NOW()
           WHERE accounts.normalized_email = EXCLUDED.normalized_email
         RETURNING account_uid`,
        [accountUid, email]
      );
      return result.rowCount === 1;
    } catch (error) {
      if ((error as { code?: unknown })?.code === "23505") return false;
      throw error;
    }
  }

  async createContactInvitation(
    invitationId: string,
    senderAccountUid: string,
    senderDeviceId: string,
    recipientEmail: string,
    dailyLimit: number,
    contactLimit: number
  ): Promise<CreateContactInvitationResult> {
    const email = normalizeVerifiedEmail(recipientEmail);
    if (!isValidAccountUid(senderAccountUid) || !isCanonicalDeviceId(senderDeviceId) || !email) {
      throw new Error("invalid contact invitation input");
    }
    if (!Number.isInteger(dailyLimit) || dailyLimit < 1 ||
        !Number.isInteger(contactLimit) || contactLimit < 1) {
      throw new Error("invalid contact limits");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const recipient = await client.query(
        "SELECT account_uid FROM accounts WHERE normalized_email = $1",
        [email]
      );
      const recipientAccountUid = recipient.rows[0]?.account_uid as string | undefined;
      if (!recipientAccountUid) {
        await client.query("ROLLBACK");
        return { status: "recipient_unavailable" };
      }
      if (recipientAccountUid === senderAccountUid) {
        await client.query("ROLLBACK");
        return { status: "self" };
      }
      const pair = [senderAccountUid, recipientAccountUid].sort();
      for (const accountUid of pair) {
        await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`contacts:${accountUid}`]);
      }
      await client.query(
        `UPDATE contact_invitations SET status = 'cancelled', responded_at = NOW()
         WHERE status = 'pending' AND expires_at <= NOW()
           AND (sender_account_uid = ANY($1::text[]) OR recipient_account_uid = ANY($1::text[]))`,
        [pair]
      );
      const existingContact = await client.query(
        `SELECT 1 FROM account_contacts
         WHERE account_low_uid = $1 AND account_high_uid = $2`,
        pair
      );
      if (existingContact.rowCount) {
        await client.query("ROLLBACK");
        return { status: "already_contact" };
      }
      const existingInvitation = await client.query(
        `SELECT invitation_id FROM contact_invitations
         WHERE status = 'pending' AND expires_at > NOW()
           AND LEAST(sender_account_uid, recipient_account_uid) = $1
           AND GREATEST(sender_account_uid, recipient_account_uid) = $2
         LIMIT 1`,
        pair
      );
      if (existingInvitation.rows[0]) {
        await client.query("COMMIT");
        return {
          status: "already_pending",
          invitationId: existingInvitation.rows[0].invitation_id
        };
      }
      const contactCount = await client.query(
        `SELECT COUNT(*)::integer AS count FROM account_contacts
         WHERE account_low_uid = $1 OR account_high_uid = $1`,
        [senderAccountUid]
      );
      if ((contactCount.rows[0]?.count ?? contactLimit) >= contactLimit) {
        await client.query("ROLLBACK");
        return { status: "contact_limit" };
      }
      const dailyCount = await client.query(
        `SELECT COUNT(*)::integer AS count FROM contact_invitations
         WHERE sender_account_uid = $1
           AND created_at >= date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`,
        [senderAccountUid]
      );
      const sentToday = dailyCount.rows[0]?.count ?? dailyLimit;
      if (sentToday >= dailyLimit) {
        await client.query("ROLLBACK");
        return { status: "daily_limit" };
      }
      const recipientDevices = await client.query(
        `SELECT device_id FROM devices
         WHERE account_uid = $1 AND token_expires_at > NOW()
         ORDER BY last_seen_at DESC LIMIT 8`,
        [recipientAccountUid]
      );
      const recipientDeviceIds = recipientDevices.rows.map((row) => row.device_id as string);
      if (recipientDeviceIds.length === 0) {
        await client.query("ROLLBACK");
        return { status: "recipient_unavailable" };
      }
      await client.query(
        `INSERT INTO contact_invitations(
           invitation_id, sender_account_uid, sender_device_id,
           recipient_account_uid, recipient_device_id
         ) VALUES ($1, $2, $3, $4, $5)`,
        [invitationId, senderAccountUid, senderDeviceId, recipientAccountUid, recipientDeviceIds[0]]
      );
      await client.query("COMMIT");
      return {
        status: "created",
        invitationId,
        recipientDeviceIds,
        remainingToday: Math.max(0, dailyLimit - sentToday - 1)
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async contactInvitations(accountUid: string): Promise<ContactInvitation[]> {
    if (!isValidAccountUid(accountUid)) throw new Error("invalid account UID");
    const result = await this.pool.query(
      `SELECT invitation.invitation_id,
              CASE WHEN invitation.recipient_account_uid = $1 THEN 'incoming' ELSE 'outgoing' END AS direction,
              CASE WHEN invitation.recipient_account_uid = $1
                THEN invitation.sender_account_uid ELSE invitation.recipient_account_uid END AS counterpart_uid,
              account.normalized_email AS counterpart_email,
              invitation.created_at, invitation.expires_at
       FROM contact_invitations AS invitation
       JOIN accounts AS account ON account.account_uid = CASE
         WHEN invitation.recipient_account_uid = $1
           THEN invitation.sender_account_uid ELSE invitation.recipient_account_uid END
       WHERE (invitation.sender_account_uid = $1 OR invitation.recipient_account_uid = $1)
         AND invitation.status = 'pending' AND invitation.expires_at > NOW()
       ORDER BY invitation.created_at DESC
       LIMIT 100`,
      [accountUid]
    );
    return result.rows.map((row) => ({
      invitationId: row.invitation_id,
      direction: row.direction,
      counterpartAccountUid: row.counterpart_uid,
      counterpartEmail: row.counterpart_email,
      createdAt: new Date(row.created_at).toISOString(),
      expiresAt: new Date(row.expires_at).toISOString()
    }));
  }

  async respondContactInvitation(
    invitationId: string,
    recipientAccountUid: string,
    recipientDeviceId: string,
    accept: boolean,
    contactLimit: number
  ): Promise<RespondContactInvitationResult> {
    if (!isValidAccountUid(recipientAccountUid) || !isCanonicalDeviceId(recipientDeviceId) ||
        !Number.isInteger(contactLimit) || contactLimit < 1) {
      throw new Error("invalid invitation response input");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const selected = await client.query(
        `SELECT sender_account_uid, recipient_account_uid, expires_at > NOW() AS unexpired
         FROM contact_invitations
         WHERE invitation_id = $1 AND status = 'pending'
         FOR UPDATE`,
        [invitationId]
      );
      const invitation = selected.rows[0];
      if (!invitation || invitation.recipient_account_uid !== recipientAccountUid) {
        await client.query("ROLLBACK");
        return { status: "not_found" };
      }
      if (invitation.unexpired !== true) {
        await client.query(
          `UPDATE contact_invitations SET status = 'cancelled', responded_at = NOW()
           WHERE invitation_id = $1`,
          [invitationId]
        );
        await client.query("COMMIT");
        return { status: "expired" };
      }
      const pair = [invitation.sender_account_uid as string, recipientAccountUid].sort();
      for (const accountUid of pair) {
        await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`contacts:${accountUid}`]);
      }
      if (accept) {
        const counts = await client.query(
          `SELECT account_uid, COUNT(contact_key)::integer AS count
           FROM (
             SELECT account_low_uid AS account_uid,
                    account_low_uid || ':' || account_high_uid AS contact_key
             FROM account_contacts WHERE account_low_uid = ANY($1::text[])
             UNION ALL
             SELECT account_high_uid AS account_uid,
                    account_low_uid || ':' || account_high_uid AS contact_key
             FROM account_contacts WHERE account_high_uid = ANY($1::text[])
           ) AS contacts
           GROUP BY account_uid`,
          [pair]
        );
        const countByAccount = new Map<string, number>(
          counts.rows.map((row) => [row.account_uid as string, row.count as number])
        );
        if (pair.some((accountUid) => (countByAccount.get(accountUid) ?? 0) >= contactLimit)) {
          await client.query("ROLLBACK");
          return { status: "contact_limit" };
        }
        await client.query(
          `INSERT INTO account_contacts(
             account_low_uid, account_high_uid, invited_by_account_uid
           ) VALUES ($1, $2, $3)
           ON CONFLICT (account_low_uid, account_high_uid) DO NOTHING`,
          [pair[0], pair[1], invitation.sender_account_uid]
        );
      }
      await client.query(
        `UPDATE contact_invitations
         SET status = $2, recipient_device_id = $3, responded_at = NOW()
         WHERE invitation_id = $1`,
        [invitationId, accept ? "accepted" : "declined", recipientDeviceId]
      );
      const devices = await client.query(
        `SELECT device_id FROM devices
         WHERE account_uid = $1 AND token_expires_at > NOW()
         ORDER BY last_seen_at DESC LIMIT 8`,
        [invitation.sender_account_uid]
      );
      await client.query("COMMIT");
      return {
        status: accept ? "accepted" : "declined",
        otherDeviceIds: devices.rows.map((row) => row.device_id as string)
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async accountContacts(accountUid: string): Promise<AccountContact[]> {
    if (!isValidAccountUid(accountUid)) throw new Error("invalid account UID");
    const result = await this.pool.query(
      `SELECT other.account_uid, other.normalized_email,
              device.device_id, device.public_key_base64
       FROM (
         SELECT CASE WHEN account_low_uid = $1 THEN account_high_uid ELSE account_low_uid END AS account_uid,
                created_at
         FROM account_contacts
         WHERE account_low_uid = $1 OR account_high_uid = $1
       ) AS contact
       JOIN accounts AS other ON other.account_uid = contact.account_uid
       LEFT JOIN LATERAL (
         SELECT device_id, public_key_base64
         FROM devices
         WHERE account_uid = other.account_uid AND token_expires_at > NOW()
         ORDER BY last_seen_at DESC LIMIT 1
       ) AS device ON TRUE
       ORDER BY contact.created_at DESC`,
      [accountUid]
    );
    return result.rows.map((row) => ({
      accountUid: row.account_uid,
      email: row.normalized_email,
      deviceId: row.device_id ?? null,
      publicKeyBase64: row.public_key_base64 ?? null
    }));
  }

  async removeAccountContact(accountUid: string, otherAccountUid: string): Promise<boolean> {
    if (!isValidAccountUid(accountUid) || !isValidAccountUid(otherAccountUid) ||
        accountUid === otherAccountUid) return false;
    const pair = [accountUid, otherAccountUid].sort();
    const result = await this.pool.query(
      `DELETE FROM account_contacts WHERE account_low_uid = $1 AND account_high_uid = $2`,
      pair
    );
    return result.rowCount === 1;
  }

  async activeDeviceIdsForAccount(accountUid: string): Promise<string[]> {
    const result = await this.pool.query(
      `SELECT device_id FROM devices
       WHERE account_uid = $1 AND token_expires_at > NOW()
       ORDER BY last_seen_at DESC LIMIT 8`,
      [accountUid]
    );
    return result.rows.map((row) => row.device_id as string);
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

  async revokeSession(deviceId: string): Promise<void> {
    await this.pool.query(
      `UPDATE devices
       SET token_expires_at = NOW(), fcm_token = NULL, last_seen_at = NOW()
       WHERE device_id = $1`,
      [deviceId]
    );
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
      if (state === "active") {
        const participants = [call.caller_id as string, call.callee_id as string].sort();
        for (const participant of participants) {
          await client.query(
            "SELECT pg_advisory_xact_lock(hashtext($1))",
            [`active-call:${participant}`]
          );
        }
        await client.query(
          `DELETE FROM active_call_participants AS participant
           WHERE participant.device_id = ANY($1::text[])
             AND NOT EXISTS (
               SELECT 1 FROM call_sessions AS active_call
               WHERE active_call.call_id = participant.call_id
                 AND active_call.state = 'active' AND active_call.expires_at > NOW()
             )`,
          [participants]
        );
        const reserved = await client.query(
          `INSERT INTO active_call_participants(device_id, call_id)
           VALUES ($1, $3), ($2, $3)
           ON CONFLICT (device_id) DO NOTHING
           RETURNING device_id`,
          [participants[0], participants[1], callId]
        );
        if (reserved.rowCount !== 2) {
          await client.query("ROLLBACK");
          return { status: "participant_busy" };
        }
        const accountRows = await client.query(
          `SELECT account_uid FROM devices
           WHERE device_id = ANY($1::text[]) AND account_uid IS NOT NULL`,
          [participants]
        );
        const accountParticipants = accountRows.rows
          .map((row) => row.account_uid as string)
          .filter((value, index, values) => values.indexOf(value) === index)
          .sort();
        if (accountParticipants.length !== 2) {
          await client.query("ROLLBACK");
          return { status: "invalid" };
        }
        for (const accountUid of accountParticipants) {
          await client.query(
            "SELECT pg_advisory_xact_lock(hashtext($1))",
            [`active-account-call:${accountUid}`]
          );
        }
        await client.query(
          `DELETE FROM active_call_accounts AS participant
           WHERE participant.account_uid = ANY($1::text[])
             AND NOT EXISTS (
               SELECT 1 FROM call_sessions AS active_call
               WHERE active_call.call_id = participant.call_id
                 AND active_call.state = 'active' AND active_call.expires_at > NOW()
             )`,
          [accountParticipants]
        );
        const reservedAccounts = await client.query(
          `INSERT INTO active_call_accounts(account_uid, call_id)
           VALUES ($1, $3), ($2, $3)
           ON CONFLICT (account_uid) DO NOTHING
           RETURNING account_uid`,
          [accountParticipants[0], accountParticipants[1], callId]
        );
        if (reservedAccounts.rowCount !== 2) {
          await client.query("ROLLBACK");
          return { status: "participant_busy" };
        }
      }
      const stateTtlSeconds = state === "active" ? activeLeaseSeconds : TERMINAL_CALL_RETENTION_SECONDS;
      await client.query(
        `UPDATE call_sessions
         SET state = $2, updated_at = NOW(), expires_at = NOW() + ($3 * INTERVAL '1 second')
         WHERE call_id = $1`,
        [callId, state, stateTtlSeconds]
      );
      if (state !== "active") {
        await client.query("DELETE FROM active_call_participants WHERE call_id = $1", [callId]);
        await client.query("DELETE FROM active_call_accounts WHERE call_id = $1", [callId]);
      }
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
