import Fastify, { type FastifyRequest } from "fastify";
import { randomBytes, randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import websocket from "@fastify/websocket";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { AccessToken } from "livekit-server-sdk";
import { z } from "zod";
import {
  createAccountTokenVerifier,
  isValidAccountUid,
  MAX_FIREBASE_ID_TOKEN_LENGTH,
  type AccountTokenVerifier
} from "./account-auth.js";
import { config } from "./config.js";
import { BoundedTaskQueue } from "./bounded-task-queue.js";
import {
  createX25519RegistrationChallenge,
  deviceIdForPublicKey,
  issueDeviceToken,
  verifyRegistrationSignature,
  x25519RegistrationProofMatches
} from "./identity.js";
import { RealtimeHub } from "./hub.js";
import { createPushGateway, InvalidPushTokenError, type PushGateway } from "./push.js";
import { Repository, UnauthorizedRouteError, type Device } from "./repository.js";
import {
  decodeRouteTokenHashBase64,
  DEVICE_ID_PATTERN,
  hashRouteTokenBase64,
  isCanonicalBase64,
  MAX_INBOUND_ROUTES
} from "./route-authorization.js";
import {
  assertFrameBinding,
  parseOmniFrame,
  PayloadType,
  remainingFrameLifetimeSeconds,
  type ParsedOmniFrame
} from "./protocol.js";

function createRepository(): Repository {
  return new Repository(config.DATABASE_URL, {
    maxConnections: config.DATABASE_POOL_MAX,
    idleTimeoutMillis: config.DATABASE_POOL_IDLE_TIMEOUT_MS,
    connectionTimeoutMillis: config.DATABASE_CONNECTION_TIMEOUT_MS,
    queryTimeoutMillis: config.DATABASE_QUERY_TIMEOUT_MS,
    statementTimeoutMillis: config.DATABASE_STATEMENT_TIMEOUT_MS,
    maxUses: config.DATABASE_POOL_MAX_USES
  });
}

const canonicalBase64Bytes = (bytes: number) => z.string().refine(
  (value) => isCanonicalBase64(value, bytes),
  { message: `must be canonical base64 for exactly ${bytes} bytes` }
);
const deviceIdSchema = z.string().regex(DEVICE_ID_PATTERN);
const registerSchema = z.object({
  challengeId: z.uuid(),
  publicKeyBase64: canonicalBase64Bytes(32),
  signingPublicKeyBase64: canonicalBase64Bytes(44),
  nonceBase64: canonicalBase64Bytes(32),
  signatureBase64: canonicalBase64Bytes(64),
  x25519ProofBase64: canonicalBase64Bytes(32),
  fcmToken: z.string().min(10).max(4096).nullable().optional()
}).strict();
const challengeSchema = z.object({
  publicKeyBase64: canonicalBase64Bytes(32),
  signingPublicKeyBase64: canonicalBase64Bytes(44)
}).strict();
const pushTokenSchema = z.object({ fcmToken: z.string().min(10).max(4096).nullable() }).strict();
const envelopeSchema = z.object({
  envelopeId: z.uuid(),
  recipientDeviceId: deviceIdSchema,
  kind: z.enum(["message", "call"]),
  callId: z.uuid().nullable().optional(),
  frameBase64: z.string().min(88).max(88_000),
  routeTokenBase64: canonicalBase64Bytes(32)
}).strict();
const callTransitionSchema = z.object({
  state: z.enum(["active", "declined", "ended"]),
  envelopeId: z.uuid(),
  frameBase64: z.string().min(88).max(16_384),
  routeTokenBase64: canonicalBase64Bytes(32)
}).strict();
const inboundRoutesSchema = z.object({
  routes: z.array(z.object({
    senderDeviceId: deviceIdSchema,
    routeTokenHashBase64: canonicalBase64Bytes(32)
  }).strict()).max(MAX_INBOUND_ROUTES)
}).strict().superRefine((value, context) => {
  const seen = new Set<string>();
  value.routes.forEach((route, index) => {
    if (seen.has(route.senderDeviceId)) {
      context.addIssue({
        code: "custom",
        message: "duplicate senderDeviceId",
        path: ["routes", index, "senderDeviceId"]
      });
    }
    seen.add(route.senderDeviceId);
  });
});
const callLeaseSchema = z.object({}).strict();
const ackSchema = z.object({ state: z.enum(["delivered", "read", "rejected"]) }).strict();

export type BuildServerOptions = {
  logger?: boolean;
  maxInFlightRequests?: number;
  httpMaxConnections?: number;
  maxWebSocketConnections?: number;
  pushConcurrency?: number;
  pushMaxQueued?: number;
  cleanupIntervalMs?: number;
  cleanupBatchSize?: number;
  pushGateway?: PushGateway;
  accountTokenVerifier?: AccountTokenVerifier;
};

function bearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7).trim();
  return token.length > 0 ? token : null;
}

function accountBearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  const match = typeof header === "string" ? /^Bearer ([^\s]+)$/i.exec(header) : null;
  const token = match?.[1];
  return token && token.length <= MAX_FIREBASE_ID_TOKEN_LENGTH ? token : null;
}

async function authenticatedAccountUid(
  request: FastifyRequest,
  verifier: AccountTokenVerifier
): Promise<string | null> {
  const token = accountBearerToken(request);
  if (!token) return null;
  try {
    const uid = await verifier.verifyIdToken(token);
    return isValidAccountUid(uid) ? uid : null;
  } catch {
    // Account tokens and verifier errors are intentionally never logged.
    return null;
  }
}

async function authenticatedDevice(request: FastifyRequest, repository: Repository): Promise<Device | null> {
  const deviceId = request.headers["x-device-id"];
  const token = bearerToken(request);
  if (typeof deviceId !== "string" || !DEVICE_ID_PATTERN.test(deviceId) || !token) return null;
  return repository.authenticate(deviceId, token);
}

export async function buildServer(repository = createRepository(), overrides: BuildServerOptions = {}) {
  const runtime = {
    maxInFlightRequests: overrides.maxInFlightRequests ?? config.MAX_IN_FLIGHT_REQUESTS,
    httpMaxConnections: overrides.httpMaxConnections ?? config.HTTP_MAX_CONNECTIONS,
    maxWebSocketConnections: overrides.maxWebSocketConnections ?? config.WEBSOCKET_MAX_CONNECTIONS,
    pushConcurrency: overrides.pushConcurrency ?? config.PUSH_MAX_CONCURRENCY,
    pushMaxQueued: overrides.pushMaxQueued ?? config.PUSH_MAX_QUEUED,
    cleanupIntervalMs: overrides.cleanupIntervalMs ?? config.CLEANUP_INTERVAL_SECONDS * 1_000,
    cleanupBatchSize: overrides.cleanupBatchSize ?? config.CLEANUP_BATCH_SIZE
  };
  if (!Number.isInteger(runtime.maxInFlightRequests) || runtime.maxInFlightRequests < 1) {
    throw new Error("maxInFlightRequests must be a positive integer");
  }
  if (!Number.isInteger(runtime.cleanupIntervalMs) || runtime.cleanupIntervalMs < 1) {
    throw new Error("cleanupIntervalMs must be a positive integer");
  }
  const app = Fastify({
    logger: overrides.logger ?? true,
    bodyLimit: 100_000,
    requestTimeout: config.HTTP_REQUEST_TIMEOUT_MS,
    handlerTimeout: config.HTTP_REQUEST_TIMEOUT_MS,
    keepAliveTimeout: 10_000,
    maxRequestsPerSocket: 1_000,
    forceCloseConnections: "idle",
    return503OnClosing: true,
    trustProxy: config.TRUST_PROXY
  });
  app.server.maxConnections = runtime.httpMaxConnections;
  const hub = new RealtimeHub(runtime.maxWebSocketConnections);
  const accountTokens = overrides.accountTokenVerifier ??
    createAccountTokenVerifier(config.FIREBASE_SERVICE_ACCOUNT_JSON);
  const push = overrides.pushGateway ?? createPushGateway(config.FIREBASE_SERVICE_ACCOUNT_JSON);
  if (!accountTokens.configured) {
    app.log.warn("Firebase Admin is not configured; new device registration is disabled");
  }
  const pushTasks = new BoundedTaskQueue(
    runtime.pushConcurrency,
    runtime.pushMaxQueued,
    (error) => app.log.error({ error }, "Push task failed")
  );
  let droppedPushTasks = 0;
  let inFlightRequests = 0;
  const releaseRequestSlots = new WeakMap<FastifyRequest, () => void>();
  app.addHook("onRequest", async (request, reply) => {
    if (inFlightRequests >= runtime.maxInFlightRequests) {
      return reply
        .header("Retry-After", "1")
        .header("Connection", "close")
        .code(503)
        .send({ error: "server_busy" });
    }
    inFlightRequests += 1;
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      inFlightRequests -= 1;
      releaseRequestSlots.delete(request);
      reply.raw.off("finish", release);
      reply.raw.off("close", release);
    };
    releaseRequestSlots.set(request, release);
    reply.raw.once("finish", release);
    reply.raw.once("close", release);
  });
  const wakeDevice = async (deviceId: string, envelopeId: string, kind: "message" | "call") => {
    const fcmToken = await repository.fcmTokenFor(deviceId);
    if (!fcmToken) return;
    try {
      await push.sendWake(fcmToken, envelopeId, kind);
    } catch (error) {
      if (error instanceof InvalidPushTokenError) await repository.setFcmToken(deviceId, null);
      app.log.warn({ error, deviceId }, "FCM wake failed");
    }
  };
  const scheduleWake = (deviceId: string, envelopeId: string, kind: "message" | "call") => {
    if (!push.enabled) return;
    if (pushTasks.submit(() => wakeDevice(deviceId, envelopeId, kind))) return;
    droppedPushTasks += 1;
    if (droppedPushTasks === 1 || droppedPushTasks % 100 === 0) {
      app.log.warn({ droppedPushTasks }, "Push queue full; durable mailbox wake was dropped");
    }
  };
  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(rateLimit, { max: 300, timeWindow: "1 minute", cache: 5_000 });
  await app.register(websocket, { options: { maxPayload: 4096 } });

  app.get("/healthz", async (_request, reply) => {
    await repository.health();
    return reply.send({ status: "ok" });
  });

  app.get("/readyz", async (_request, reply) => {
    if (!accountTokens.configured) {
      return reply.code(503).send({ status: "not_ready", registration: "disabled" });
    }
    await repository.health();
    return reply.send({ status: "ready" });
  });

  app.post("/v1/devices/challenge", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (request, reply) => {
    const accountUid = await authenticatedAccountUid(request, accountTokens);
    if (!accountUid) return reply.code(401).send({ error: "invalid_account_token" });
    const parsed = challengeSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_request" });
    let deviceId: string;
    try { deviceId = deviceIdForPublicKey(parsed.data.publicKeyBase64); } catch {
      return reply.code(400).send({ error: "invalid_public_key" });
    }
    const [pinnedSigningKey, boundAccountUid] = await Promise.all([
      repository.signingPublicKeyForDevice(deviceId),
      repository.accountUidForDevice(deviceId)
    ]);
    if (boundAccountUid && boundAccountUid !== accountUid) {
      return reply.code(409).send({ error: "device_account_mismatch" });
    }
    if (pinnedSigningKey && pinnedSigningKey !== parsed.data.signingPublicKeyBase64) {
      return reply.code(409).send({ error: "signing_identity_mismatch" });
    }
    const nonceBase64 = randomBytes(32).toString("base64");
    const x25519Challenge = createX25519RegistrationChallenge(
      parsed.data.publicKeyBase64,
      deviceId,
      nonceBase64,
      parsed.data.signingPublicKeyBase64
    );
    const challengeId = randomUUID();
    const saved = await repository.saveRegistrationChallenge(
      challengeId,
      deviceId,
      accountUid,
      parsed.data.publicKeyBase64,
      parsed.data.signingPublicKeyBase64,
      nonceBase64,
      x25519Challenge.expectedProofBase64,
      config.MAX_REGISTRATION_CHALLENGES_PER_DEVICE,
      config.MAX_REGISTRATION_CHALLENGES_PER_ACCOUNT
    );
    if (!saved) {
      return reply.header("Retry-After", "300").code(429).send({ error: "registration_challenge_limit" });
    }
    return reply.send({
      challengeId,
      deviceId,
      nonceBase64,
      serverEphemeralPublicKeyBase64: x25519Challenge.serverEphemeralPublicKeyBase64
    });
  });

  app.post("/v1/devices/register", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (request, reply) => {
    const accountUid = await authenticatedAccountUid(request, accountTokens);
    if (!accountUid) return reply.code(401).send({ error: "invalid_account_token" });
    const parsed = registerSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_request" });
    let deviceId: string;
    try {
      deviceId = deviceIdForPublicKey(parsed.data.publicKeyBase64);
    } catch {
      return reply.code(400).send({ error: "invalid_public_key" });
    }
    const challenge = await repository.registrationChallenge(parsed.data.challengeId, deviceId);
    if (!challenge || challenge.accountUid !== accountUid ||
        challenge.nonceBase64 !== parsed.data.nonceBase64 ||
        challenge.publicKeyBase64 !== parsed.data.publicKeyBase64 ||
        challenge.signingPublicKeyBase64 !== parsed.data.signingPublicKeyBase64 ||
        !x25519RegistrationProofMatches(
          challenge.x25519ProofBase64,
          parsed.data.x25519ProofBase64
        ) ||
        !verifyRegistrationSignature(
          parsed.data.signingPublicKeyBase64,
          deviceId,
          parsed.data.nonceBase64,
          parsed.data.signatureBase64
        )) {
      return reply.code(401).send({ error: "invalid_registration_proof" });
    }
    const consumed = await repository.consumeRegistrationChallenge(
      parsed.data.challengeId,
      deviceId,
      accountUid
    );
    if (!consumed) return reply.code(401).send({ error: "invalid_registration_proof" });
    const token = issueDeviceToken();
    const registered = await repository.registerOrRotate(
      deviceId,
      accountUid,
      parsed.data.publicKeyBase64,
      parsed.data.signingPublicKeyBase64,
      token
    );
    if (registered === "signing_identity_mismatch") {
      return reply.code(409).send({ error: "signing_identity_mismatch" });
    }
    if (registered === "account_mismatch") {
      return reply.code(409).send({ error: "device_account_mismatch" });
    }
    if (parsed.data.fcmToken) await repository.setFcmToken(deviceId, parsed.data.fcmToken);
    return reply.code(201).send({ deviceId, token });
  });

  app.put("/v1/devices/push-token", async (request, reply) => {
    const device = await authenticatedDevice(request, repository);
    if (!device) return reply.code(401).send({ error: "unauthorized" });
    const parsed = pushTokenSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_request" });
    await repository.setFcmToken(device.deviceId, parsed.data.fcmToken);
    return reply.code(204).send();
  });

  app.delete("/v1/devices/session", async (request, reply) => {
    const device = await authenticatedDevice(request, repository);
    if (!device) return reply.code(401).send({ error: "unauthorized" });
    await repository.revokeSession(device.deviceId);
    hub.disconnectDevice(device.deviceId);
    return reply.code(204).send();
  });

  app.put("/v1/routes/inbound", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } }
  }, async (request, reply) => {
    const device = await authenticatedDevice(request, repository);
    if (!device) return reply.code(401).send({ error: "unauthorized" });
    const parsed = inboundRoutesSchema.safeParse(request.body);
    if (!parsed.success || parsed.data.routes.some((route) => route.senderDeviceId === device.deviceId)) {
      return reply.code(400).send({ error: "invalid_request" });
    }
    const routes = parsed.data.routes.map((route) => ({
      senderId: route.senderDeviceId,
      routeTokenHash: decodeRouteTokenHashBase64(route.routeTokenHashBase64)
    }));
    await repository.replaceInboundRoutes(device.deviceId, routes);
    return reply.code(204).send();
  });

  app.post("/v1/envelopes", async (request, reply) => {
    const device = await authenticatedDevice(request, repository);
    if (!device) return reply.code(401).send({ error: "unauthorized" });
    const parsed = envelopeSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_request" });
    const data = parsed.data;
    const recipientPublicKey = await repository.publicKeyForDevice(data.recipientDeviceId);
    if (!recipientPublicKey) {
      return reply.code(404).send({ error: "recipient_not_registered" });
    }
    if (data.kind === "message" && data.callId) {
      return reply.code(400).send({ error: "call_id_not_allowed" });
    }
    let frame: ParsedOmniFrame;
    try {
      frame = parseOmniFrame(data.frameBase64);
      assertFrameBinding(
        frame,
        device.publicKeyBase64,
        recipientPublicKey,
        data.kind === "message" ? PayloadType.TEXT : PayloadType.CALL_RING
      );
    } catch {
      return reply.code(400).send({ error: "invalid_frame" });
    }
    const routeTokenHash = hashRouteTokenBase64(data.routeTokenBase64);
    const envelopeInput = {
      envelopeId: data.envelopeId,
      senderId: device.deviceId,
      recipientId: data.recipientDeviceId,
      kind: data.kind,
      callId: data.callId ?? null,
      frameBase64: data.frameBase64
    };
    let insertResult: "inserted" | "duplicate";
    if (data.kind === "call") {
      if (!data.callId) return reply.code(400).send({ error: "call_id_required" });
      const remainingCallTtl = remainingFrameLifetimeSeconds(
        frame.timestampMsLow32,
        config.CALL_SIGNAL_TTL_SECONDS,
        config.CALL_MAX_FUTURE_SKEW_SECONDS
      );
      if (remainingCallTtl === null) {
        const authorized = await repository.routeAuthorized(
          device.deviceId,
          data.recipientDeviceId,
          routeTokenHash
        );
        if (!authorized) return reply.code(403).send({ error: "unauthorized_route" });
        return reply.code(200).send({ envelopeId: data.envelopeId, duplicate: false, expired: true });
      }
      try {
        const callResult = await repository.createCallWithEnvelope(
          { ...envelopeInput, kind: "call", callId: data.callId },
          remainingCallTtl,
          config.MAX_MAILBOX_MESSAGES,
          config.MAX_PENDING_MESSAGES_PER_PAIR,
          routeTokenHash
        );
        if (callResult === "call_conflict") return reply.code(409).send({ error: "call_id_conflict" });
        if (callResult === "envelope_conflict") {
          return reply.code(409).send({ error: "envelope_id_conflict" });
        }
        if (callResult === "expired") {
          return reply.code(200).send({ envelopeId: data.envelopeId, duplicate: false, expired: true });
        }
        insertResult = callResult;
      } catch (error) {
        if (error instanceof UnauthorizedRouteError) {
          return reply.code(403).send({ error: "unauthorized_route" });
        }
        if (error instanceof Error && error.message === "mailbox_full") {
          return reply.code(429).send({ error: "recipient_mailbox_full" });
        }
        if (error instanceof Error && error.message === "pair_mailbox_full") {
          return reply.code(429).send({ error: "sender_recipient_queue_full" });
        }
        throw error;
      }
    } else {
      try {
        const messageResult = await repository.insertEnvelope(
          { ...envelopeInput, kind: "message", callId: null },
          config.MESSAGE_TTL_DAYS * 24 * 60 * 60,
          config.MAX_MAILBOX_MESSAGES,
          config.MAX_PENDING_MESSAGES_PER_PAIR,
          routeTokenHash
        );
        if (messageResult === "conflict") {
          return reply.code(409).send({ error: "envelope_id_conflict" });
        }
        insertResult = messageResult;
      } catch (error) {
        if (error instanceof UnauthorizedRouteError) {
          return reply.code(403).send({ error: "unauthorized_route" });
        }
        if (error instanceof Error && error.message === "mailbox_full") {
          return reply.code(429).send({ error: "recipient_mailbox_full" });
        }
        if (error instanceof Error && error.message === "pair_mailbox_full") {
          return reply.code(429).send({ error: "sender_recipient_queue_full" });
        }
        throw error;
      }
    }
    if (insertResult === "inserted") {
      hub.notify(data.recipientDeviceId, data.envelopeId, data.kind);
      scheduleWake(data.recipientDeviceId, data.envelopeId, data.kind);
    }
    return reply.code(insertResult === "inserted" ? 201 : 200).send({
      envelopeId: data.envelopeId,
      duplicate: insertResult === "duplicate"
    });
  });

  app.get("/v1/mailbox", async (request, reply) => {
    const device = await authenticatedDevice(request, repository);
    if (!device) return reply.code(401).send({ error: "unauthorized" });
    const query = z.object({
      after: z.iso.datetime({ offset: true }).nullable().optional(),
      limit: z.coerce.number().int().min(1).max(500).default(100)
    }).safeParse(request.query);
    if (!query.success) return reply.code(400).send({ error: "invalid_query" });
    const [envelopes, outboundStatuses] = await Promise.all([
      repository.mailbox(device.deviceId, query.data.after ?? null, query.data.limit),
      repository.outboundStatuses(device.deviceId, query.data.limit)
    ]);
    return reply.send({ envelopes, outboundStatuses });
  });

  app.post("/v1/envelopes/:envelopeId/ack", async (request, reply) => {
    const device = await authenticatedDevice(request, repository);
    if (!device) return reply.code(401).send({ error: "unauthorized" });
    const params = z.object({ envelopeId: z.uuid() }).safeParse(request.params);
    const body = ackSchema.safeParse(request.body);
    if (!params.success || !body.success) return reply.code(400).send({ error: "invalid_request" });
    const updated = await repository.acknowledge(device.deviceId, params.data.envelopeId, body.data.state);
    if (!updated) return reply.code(404).send({ error: "envelope_not_found" });
    hub.status(updated.senderId, params.data.envelopeId, updated.state);
    return reply.code(204).send();
  });

  app.post("/v1/calls/:callId/state", async (request, reply) => {
    const device = await authenticatedDevice(request, repository);
    if (!device) return reply.code(401).send({ error: "unauthorized" });
    const params = z.object({ callId: z.uuid() }).safeParse(request.params);
    const body = callTransitionSchema.safeParse(request.body);
    if (!params.success || !body.success) return reply.code(400).send({ error: "invalid_request" });
    let transitionFrame: ParsedOmniFrame;
    try {
      transitionFrame = parseOmniFrame(body.data.frameBase64);
    } catch {
      return reply.code(400).send({ error: "invalid_frame" });
    }
    const call = await repository.callForParticipant(params.data.callId, device.deviceId);
    if (!call) return reply.code(404).send({ error: "call_not_found" });
    const otherDeviceId = call.callerId === device.deviceId ? call.calleeId : call.callerId;
    const recipientPublicKey = await repository.publicKeyForDevice(otherDeviceId);
    if (!recipientPublicKey) return reply.code(404).send({ error: "recipient_not_registered" });
    const expectedType = body.data.state === "active"
      ? PayloadType.CALL_ACCEPT
      : body.data.state === "declined" ? PayloadType.CALL_DECLINE : PayloadType.CALL_END;
    try {
      assertFrameBinding(
        transitionFrame,
        device.publicKeyBase64,
        recipientPublicKey,
        expectedType
      );
    } catch {
      return reply.code(400).send({ error: "invalid_frame" });
    }
    const routeTokenHash = hashRouteTokenBase64(body.data.routeTokenBase64);
    const remainingCallTtl = remainingFrameLifetimeSeconds(
      transitionFrame.timestampMsLow32,
      config.CALL_SIGNAL_TTL_SECONDS,
      config.CALL_MAX_FUTURE_SKEW_SECONDS
    );
    if (remainingCallTtl === null) {
      const authorized = await repository.routeAuthorized(device.deviceId, otherDeviceId, routeTokenHash);
      if (!authorized) return reply.code(403).send({ error: "unauthorized_route" });
      return reply.code(204).send();
    }
    let transition: Awaited<ReturnType<Repository["transitionCallWithEnvelope"]>>;
    try {
      transition = await repository.transitionCallWithEnvelope(
        params.data.callId,
        device.deviceId,
        body.data.state,
        {
          envelopeId: body.data.envelopeId,
          senderId: device.deviceId,
          recipientId: otherDeviceId,
          kind: "call",
          callId: params.data.callId,
          frameBase64: body.data.frameBase64
        },
        remainingCallTtl,
        config.CALL_ACTIVE_LEASE_SECONDS,
        config.MAX_MAILBOX_MESSAGES,
        config.MAX_PENDING_MESSAGES_PER_PAIR,
        routeTokenHash
      );
    } catch (error) {
      if (error instanceof UnauthorizedRouteError) {
        return reply.code(403).send({ error: "unauthorized_route" });
      }
      if (error instanceof Error &&
          (error.message === "mailbox_full" || error.message === "pair_mailbox_full")) {
        return reply.code(429).send({ error: "call_signal_queue_full" });
      }
      throw error;
    }
    if (transition.status === "not_found") return reply.code(404).send({ error: "call_not_found" });
    if (transition.status === "invalid") return reply.code(409).send({ error: "invalid_call_transition" });
    if (transition.status === "envelope_conflict") {
      return reply.code(409).send({ error: "envelope_id_conflict" });
    }
    if (transition.status === "inserted") {
      hub.notify(transition.otherDeviceId, body.data.envelopeId, "call");
      scheduleWake(transition.otherDeviceId, body.data.envelopeId, "call");
    }
    return reply.code(204).send();
  });

  app.post("/v1/calls/:callId/lease", {
    config: { rateLimit: { max: 20, timeWindow: "1 minute" } }
  }, async (request, reply) => {
    const device = await authenticatedDevice(request, repository);
    if (!device) return reply.code(401).send({ error: "unauthorized" });
    const params = z.object({ callId: z.uuid() }).safeParse(request.params);
    const body = callLeaseSchema.safeParse(request.body ?? {});
    if (!params.success || !body.success) return reply.code(400).send({ error: "invalid_request" });
    const leaseExpiresAt = await repository.renewCallLease(
      params.data.callId,
      device.deviceId,
      config.CALL_ACTIVE_LEASE_SECONDS
    );
    if (!leaseExpiresAt) return reply.code(404).send({ error: "call_not_available" });
    return reply.send({
      leaseSeconds: config.CALL_ACTIVE_LEASE_SECONDS,
      leaseExpiresAt
    });
  });

  app.post("/v1/calls/:callId/token", async (request, reply) => {
    const device = await authenticatedDevice(request, repository);
    if (!device) return reply.code(401).send({ error: "unauthorized" });
    const params = z.object({ callId: z.uuid() }).safeParse(request.params);
    if (!params.success) return reply.code(400).send({ error: "invalid_call_id" });
    const call = await repository.callForParticipant(params.data.callId, device.deviceId);
    if (!call || call.state !== "active") {
      return reply.code(404).send({ error: "call_not_available" });
    }
    const token = new AccessToken(config.LIVEKIT_API_KEY, config.LIVEKIT_API_SECRET, {
      identity: device.deviceId,
      ttl: `${config.CALL_ACTIVE_LEASE_SECONDS}s`
    });
    token.addGrant({ roomJoin: true, room: params.data.callId, canPublish: true, canSubscribe: true });
    return reply.send({ url: config.LIVEKIT_URL, token: await token.toJwt() });
  });

  app.get("/v1/stream", { websocket: true }, async (socket, request) => {
    let device: Device | null;
    try {
      device = await authenticatedDevice(request, repository);
    } finally {
      releaseRequestSlots.get(request)?.();
    }
    if (!device) {
      socket.close(1008, "unauthorized");
      return;
    }
    if (!hub.add(device.deviceId, socket)) return;
    socket.send(JSON.stringify({ type: "ready" }));
    socket.on("message", (data) => {
      if (data.toString() === "ping") socket.send("pong");
    });
    socket.on("close", () => hub.remove(device.deviceId, socket));
  });

  let cleanupPromise: Promise<void> | null = null;
  let closing = false;
  const runCleanup = () => {
    if (closing) return Promise.resolve();
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = repository.cleanup(runtime.cleanupBatchSize)
      .then((deleted) => {
        if (deleted.envelopes + deleted.calls + deleted.challenges > 0) {
          app.log.info({ deleted }, "Expired records cleaned");
        }
      })
      .catch((error) => app.log.error(error, "Cleanup failed"))
      .finally(() => { cleanupPromise = null; });
    return cleanupPromise;
  };
  const cleanupTimer = setInterval(runCleanup, runtime.cleanupIntervalMs);
  cleanupTimer.unref();
  app.addHook("onClose", async () => {
    closing = true;
    clearInterval(cleanupTimer);
    const pushShutdown = pushTasks.shutdown(true);
    await cleanupPromise;
    await pushShutdown;
    if (droppedPushTasks > 0) {
      app.log.info({ droppedPushTasks }, "Push tasks dropped while protecting server capacity");
    }
    await repository.close();
  });
  return app;
}

export async function startServer() {
  const repository = createRepository();
  let app: Awaited<ReturnType<typeof buildServer>> | null = null;
  try {
    await repository.migrate();
    app = await buildServer(repository);
    await app.listen({ host: config.HOST, port: config.PORT });
  } catch (error) {
    if (app) {
      await app.close().catch(() => undefined);
    } else {
      await repository.close().catch(() => undefined);
    }
    throw error;
  }

  let shutdownPromise: Promise<void> | null = null;
  const shutdown = (signal: NodeJS.Signals) => {
    if (shutdownPromise) return;
    app.log.info({ signal }, "Graceful shutdown started");
    const deadline = setTimeout(() => {
      app.log.error({ signal, timeoutMs: config.SHUTDOWN_TIMEOUT_MS }, "Graceful shutdown deadline exceeded");
      process.exit(1);
    }, config.SHUTDOWN_TIMEOUT_MS);
    deadline.unref();
    shutdownPromise = app.close()
      .then(() => {
        process.exitCode = 0;
      })
      .catch((error) => {
        app.log.error({ error, signal }, "Graceful shutdown failed");
        process.exitCode = 1;
      })
      .finally(() => clearTimeout(deadline));
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
  return app;
}

const entryPoint = process.argv[1];
if (entryPoint && import.meta.url === pathToFileURL(entryPoint).href) {
  await startServer().catch((error) => {
    console.error("OmniRelay backend failed to start", error);
    process.exitCode = 1;
  });
}
