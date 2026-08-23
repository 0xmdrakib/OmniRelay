import Fastify, { type FastifyRequest } from "fastify";
import { randomBytes } from "node:crypto";
import websocket from "@fastify/websocket";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { AccessToken } from "livekit-server-sdk";
import { z } from "zod";
import { config } from "./config.js";
import { deviceIdForPublicKey, issueDeviceToken, verifyRegistrationSignature } from "./identity.js";
import { RealtimeHub } from "./hub.js";
import { createPushGateway, InvalidPushTokenError } from "./push.js";
import { Repository, type Device } from "./repository.js";
import { assertFrameBinding, parseOmniFrame, PayloadType } from "./protocol.js";

const registerSchema = z.object({
  publicKeyBase64: z.string().min(43).max(64),
  signingPublicKeyBase64: z.string().min(40).max(128),
  nonceBase64: z.string().min(16).max(128),
  signatureBase64: z.string().min(64).max(256),
  fcmToken: z.string().min(10).max(4096).nullable().optional()
});
const challengeSchema = z.object({
  publicKeyBase64: z.string().min(43).max(64),
  signingPublicKeyBase64: z.string().min(40).max(128)
});
const pushTokenSchema = z.object({ fcmToken: z.string().min(10).max(4096).nullable() });
const envelopeSchema = z.object({
  envelopeId: z.uuid(),
  recipientDeviceId: z.string().regex(/^[0-9a-f]{64}$/),
  kind: z.enum(["message", "call"]),
  callId: z.uuid().nullable().optional(),
  frameBase64: z.string().min(88).max(88_000)
});
const callTransitionSchema = z.object({
  state: z.enum(["active", "declined", "ended"]),
  envelopeId: z.uuid(),
  frameBase64: z.string().min(88).max(16_384)
});
const ackSchema = z.object({ state: z.enum(["delivered", "read"]) });

function bearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7).trim();
  return token.length > 0 ? token : null;
}

async function authenticatedDevice(request: FastifyRequest, repository: Repository): Promise<Device | null> {
  const deviceId = request.headers["x-device-id"];
  const token = bearerToken(request);
  if (typeof deviceId !== "string" || !token) return null;
  return repository.authenticate(deviceId, token);
}

export async function buildServer(repository = new Repository(config.DATABASE_URL)) {
  const app = Fastify({
    logger: true,
    bodyLimit: 100_000,
    requestTimeout: 15_000,
    trustProxy: config.TRUST_PROXY
  });
  const hub = new RealtimeHub();
  const push = createPushGateway(config.FIREBASE_SERVICE_ACCOUNT_JSON);
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
  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(rateLimit, { max: 300, timeWindow: "1 minute" });
  await app.register(websocket, { options: { maxPayload: 4096 } });

  app.get("/healthz", async (_request, reply) => {
    await repository.health();
    return reply.send({ status: "ok" });
  });

  app.post("/v1/devices/challenge", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (request, reply) => {
    const parsed = challengeSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_request" });
    let deviceId: string;
    try { deviceId = deviceIdForPublicKey(parsed.data.publicKeyBase64); } catch {
      return reply.code(400).send({ error: "invalid_public_key" });
    }
    const pinnedSigningKey = await repository.signingPublicKeyForDevice(deviceId);
    if (pinnedSigningKey && pinnedSigningKey !== parsed.data.signingPublicKeyBase64) {
      return reply.code(409).send({ error: "signing_identity_mismatch" });
    }
    const nonceBase64 = randomBytes(32).toString("base64");
    await repository.saveRegistrationChallenge(
      deviceId,
      parsed.data.publicKeyBase64,
      parsed.data.signingPublicKeyBase64,
      nonceBase64
    );
    return reply.send({ deviceId, nonceBase64 });
  });

  app.post("/v1/devices/register", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (request, reply) => {
    const parsed = registerSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_request" });
    let deviceId: string;
    try {
      deviceId = deviceIdForPublicKey(parsed.data.publicKeyBase64);
    } catch {
      return reply.code(400).send({ error: "invalid_public_key" });
    }
    const challenge = await repository.consumeRegistrationChallenge(deviceId);
    if (!challenge || challenge.nonceBase64 !== parsed.data.nonceBase64 ||
        challenge.publicKeyBase64 !== parsed.data.publicKeyBase64 ||
        challenge.signingPublicKeyBase64 !== parsed.data.signingPublicKeyBase64 ||
        !verifyRegistrationSignature(
          parsed.data.signingPublicKeyBase64,
          deviceId,
          parsed.data.nonceBase64,
          parsed.data.signatureBase64
        )) {
      return reply.code(401).send({ error: "invalid_registration_proof" });
    }
    const token = issueDeviceToken();
    const registered = await repository.registerOrRotate(
      deviceId,
      parsed.data.publicKeyBase64,
      parsed.data.signingPublicKeyBase64,
      token
    );
    if (!registered) return reply.code(409).send({ error: "signing_identity_mismatch" });
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
    try {
      const frame = parseOmniFrame(data.frameBase64);
      assertFrameBinding(
        frame,
        device.publicKeyBase64,
        recipientPublicKey,
        data.kind === "message" ? PayloadType.TEXT : PayloadType.CALL_RING
      );
    } catch {
      return reply.code(400).send({ error: "invalid_frame" });
    }
    if (data.kind === "call") {
      if (!data.callId) return reply.code(400).send({ error: "call_id_required" });
      const callResult = await repository.ensureCall(data.callId, device.deviceId, data.recipientDeviceId);
      if (callResult === "conflict") return reply.code(409).send({ error: "call_id_conflict" });
    }
    let insertResult: "inserted" | "duplicate" | "conflict";
    try {
      insertResult = await repository.insertEnvelope({
        envelopeId: data.envelopeId,
        senderId: device.deviceId,
        recipientId: data.recipientDeviceId,
        kind: data.kind,
        callId: data.callId ?? null,
        frameBase64: data.frameBase64
      }, config.MESSAGE_TTL_DAYS, config.MAX_MAILBOX_MESSAGES);
    } catch (error) {
      if (error instanceof Error && error.message === "mailbox_full") {
        return reply.code(429).send({ error: "recipient_mailbox_full" });
      }
      throw error;
    }
    if (insertResult === "conflict") {
      return reply.code(409).send({ error: "envelope_id_conflict" });
    }
    if (insertResult === "inserted") {
      hub.notify(data.recipientDeviceId, data.envelopeId, data.kind);
      void wakeDevice(data.recipientDeviceId, data.envelopeId, data.kind);
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
        parseOmniFrame(body.data.frameBase64),
        device.publicKeyBase64,
        recipientPublicKey,
        expectedType
      );
    } catch {
      return reply.code(400).send({ error: "invalid_frame" });
    }
    const transition = await repository.transitionCall(params.data.callId, device.deviceId, body.data.state);
    if (!transition) return reply.code(409).send({ error: "invalid_call_transition" });
    const insertResult = await repository.insertEnvelope({
      envelopeId: body.data.envelopeId,
      senderId: device.deviceId,
      recipientId: transition.otherDeviceId,
      kind: "call",
      callId: params.data.callId,
      frameBase64: body.data.frameBase64
    }, 1, config.MAX_MAILBOX_MESSAGES);
    if (insertResult === "conflict") return reply.code(409).send({ error: "envelope_id_conflict" });
    if (insertResult === "inserted") {
      hub.notify(transition.otherDeviceId, body.data.envelopeId, "call");
      void wakeDevice(transition.otherDeviceId, body.data.envelopeId, "call");
    }
    return reply.code(204).send();
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
      ttl: "10m"
    });
    token.addGrant({ roomJoin: true, room: params.data.callId, canPublish: true, canSubscribe: true });
    return reply.send({ url: config.LIVEKIT_URL, token: await token.toJwt() });
  });

  app.get("/v1/stream", { websocket: true }, async (socket, request) => {
    const device = await authenticatedDevice(request, repository);
    if (!device) {
      socket.close(1008, "unauthorized");
      return;
    }
    hub.add(device.deviceId, socket);
    socket.send(JSON.stringify({ type: "ready" }));
    socket.on("message", (data) => {
      if (data.toString() === "ping") socket.send("pong");
    });
    socket.on("close", () => hub.remove(device.deviceId, socket));
  });

  const cleanupTimer = setInterval(() => repository.cleanup().catch((error) => app.log.error(error)), 60 * 60 * 1000);
  cleanupTimer.unref();
  app.addHook("onClose", async () => {
    clearInterval(cleanupTimer);
    await repository.close();
  });
  return app;
}

if (process.env.NODE_ENV !== "test") {
  const repository = new Repository(config.DATABASE_URL);
  await repository.migrate();
  const app = await buildServer(repository);
  await app.listen({ host: config.HOST, port: config.PORT });
  const shutdown = async () => {
    await app.close();
    process.exit(0);
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}
