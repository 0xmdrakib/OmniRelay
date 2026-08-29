import assert from "node:assert/strict";
import {
  createHash,
  createHmac,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomUUID,
  sign,
  type KeyObject
} from "node:crypto";
import test from "node:test";
import WebSocket from "ws";
import { registrationProof, registrationX25519Proof } from "../src/identity.js";

const integrationBaseUrl = process.env.INTEGRATION_BASE_URL;
const baseUrl = integrationBaseUrl ?? "http://127.0.0.1:0";

type RegisteredDevice = {
  deviceId: string;
  token: string;
  publicKeyBase64: string;
  encryptionPrivateKey: KeyObject;
};

function base64UrlToBuffer(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

async function registerDevice(): Promise<RegisteredDevice> {
  const encryption = generateKeyPairSync("x25519");
  const signing = generateKeyPairSync("ed25519");
  const publicKey = encryption.publicKey.export({ format: "jwk" });
  const publicKeyX = publicKey.x;
  if (!publicKeyX) throw new Error("X25519 public JWK is missing x");
  const publicKeyBase64 = base64UrlToBuffer(publicKeyX).toString("base64");
  const signingPublicKeyBase64 = signing.publicKey
    .export({ format: "der", type: "spki" })
    .toString("base64");
  const challengeRequest = () => fetch(`${baseUrl}/v1/devices/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ publicKeyBase64, signingPublicKeyBase64 })
  });
  const challengeResponse = await challengeRequest();
  assert.equal(challengeResponse.status, 200);
  const challenge = await challengeResponse.json() as {
    challengeId: string;
    deviceId: string;
    nonceBase64: string;
    serverEphemeralPublicKeyBase64: string;
  };
  const parallelChallengeResponse = await challengeRequest();
  assert.equal(parallelChallengeResponse.status, 200);
  const parallelChallenge = await parallelChallengeResponse.json() as { challengeId: string };
  assert.notEqual(parallelChallenge.challengeId, challenge.challengeId);
  assert.equal(challenge.deviceId, createHash("sha256").update(Buffer.from(publicKeyBase64, "base64")).digest("hex"));
  const signatureBase64 = sign(
    null,
    registrationProof(challenge.deviceId, challenge.nonceBase64),
    signing.privateKey
  ).toString("base64");
  const serverPublicKey = createPublicKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      x: Buffer.from(challenge.serverEphemeralPublicKeyBase64, "base64").toString("base64url")
    },
    format: "jwk"
  });
  const rawSharedSecret = diffieHellman({
    privateKey: encryption.privateKey,
    publicKey: serverPublicKey
  });
  const pairSharedSecret = Buffer.from(hkdfSync(
    "sha256",
    rawSharedSecret,
    Buffer.alloc(32),
    Buffer.from("OmniRelay/X25519/AES-256-GCM/v1", "utf8"),
    32
  ));
  const x25519ProofBase64 = registrationX25519Proof(
    pairSharedSecret,
    challenge.deviceId,
    challenge.nonceBase64,
    signingPublicKeyBase64
  ).toString("base64");
  const registrationPayload = {
    challengeId: challenge.challengeId,
    publicKeyBase64,
    signingPublicKeyBase64,
    nonceBase64: challenge.nonceBase64,
    signatureBase64,
    x25519ProofBase64
  };
  const invalidProof = await fetch(`${baseUrl}/v1/devices/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ...registrationPayload,
      x25519ProofBase64: Buffer.alloc(32).toString("base64")
    })
  });
  assert.equal(invalidProof.status, 401);
  const response = await fetch(`${baseUrl}/v1/devices/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(registrationPayload)
  });
  assert.equal(response.status, 201);
  const registered = await response.json() as { deviceId: string; token: string };
  return { ...registered, publicKeyBase64, encryptionPrivateKey: encryption.privateKey };
}

function auth(device: RegisteredDevice): Record<string, string> {
  return {
    authorization: `Bearer ${device.token}`,
    "x-device-id": device.deviceId,
    "content-type": "application/json"
  };
}

function backendRouteToken(sender: RegisteredDevice, recipient: RegisteredDevice): string {
  const recipientPublicKey = createPublicKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      x: Buffer.from(recipient.publicKeyBase64, "base64").toString("base64url")
    },
    format: "jwk"
  });
  const pairSharedSecret = Buffer.from(hkdfSync(
    "sha256",
    diffieHellman({ privateKey: sender.encryptionPrivateKey, publicKey: recipientPublicKey }),
    Buffer.alloc(32),
    Buffer.from("OmniRelay/X25519/AES-256-GCM/v1", "utf8"),
    32
  ));
  return createHmac("sha256", pairSharedSecret.subarray(0, 32))
    .update(Buffer.from("OmniRelay/Backend-Route/v1\0", "utf8"))
    .update(Buffer.from(sender.publicKeyBase64, "base64"))
    .update(Buffer.from(recipient.publicKeyBase64, "base64"))
    .digest("base64");
}

async function replaceInboundRoutes(
  recipient: RegisteredDevice,
  routes: Array<{ sender: RegisteredDevice; routeTokenBase64: string }>
): Promise<Response> {
  return fetch(`${baseUrl}/v1/routes/inbound`, {
    method: "PUT",
    headers: auth(recipient),
    body: JSON.stringify({
      routes: routes.map(({ sender, routeTokenBase64 }) => ({
        senderDeviceId: sender.deviceId,
        routeTokenHashBase64: createHash("sha256")
          .update(Buffer.from(routeTokenBase64, "base64"))
          .digest("base64")
      }))
    })
  });
}

async function connectStream(device: RegisteredDevice): Promise<WebSocket> {
  const streamUrl = baseUrl.replace(/^http/, "ws") + "/v1/stream";
  const socket = new WebSocket(streamUrl, { headers: auth(device) });
  await new Promise<void>((resolve, reject) => {
    socket.once("open", resolve);
    socket.once("error", reject);
  });
  return socket;
}

function waitForEvent(socket: WebSocket, type: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.off("message", onMessage);
      reject(new Error(`Timed out waiting for ${type}`));
    }, 5_000);
    const onMessage = (data: WebSocket.RawData) => {
      const event = JSON.parse(data.toString()) as Record<string, unknown>;
      if (event.type !== type) return;
      clearTimeout(timeout);
      socket.off("message", onMessage);
      resolve(event);
    };
    socket.on("message", onMessage);
  });
}

function frame(
  sender: RegisteredDevice,
  recipient: RegisteredDevice,
  payloadType: number,
  timestampMs = Date.now()
): string {
  const payload = Buffer.from(recipient.publicKeyBase64, "base64").subarray(0, 8);
  const bytes = Buffer.alloc(64 + payload.length);
  bytes[0] = 0x2f;
  bytes.writeUInt32BE(timestampMs >>> 0, 8);
  Buffer.from(sender.publicKeyBase64, "base64").copy(bytes, 12);
  bytes.writeUInt16BE(payload.length, 60);
  bytes[62] = payloadType;
  payload.copy(bytes, 64);
  return bytes.toString("base64");
}

test("two devices exchange, acknowledge and obtain LiveKit credentials", { skip: !integrationBaseUrl }, async (t) => {
  const sockets: WebSocket[] = [];
  t.after(() => {
    for (const socket of sockets) socket.terminate();
  });
  const sender = await registerDevice();
  const receiver = await registerDevice();
  const outsider = await registerDevice();
  const senderToReceiverRoute = backendRouteToken(sender, receiver);
  const receiverToSenderRoute = backendRouteToken(receiver, sender);
  const outsiderToReceiverRoute = backendRouteToken(outsider, receiver);
  assert.equal(
    (await replaceInboundRoutes(receiver, [{ sender, routeTokenBase64: senderToReceiverRoute }])).status,
    204
  );
  assert.equal(
    (await replaceInboundRoutes(sender, [{ sender: receiver, routeTokenBase64: receiverToSenderRoute }])).status,
    204
  );
  const tooManyRoutes = await fetch(`${baseUrl}/v1/routes/inbound`, {
    method: "PUT",
    headers: auth(receiver),
    body: JSON.stringify({
      routes: Array.from({ length: 513 }, (_, index) => ({
        senderDeviceId: createHash("sha256").update(`route-${index}`).digest("hex"),
        routeTokenHashBase64: Buffer.alloc(32, index & 0xff).toString("base64")
      }))
    })
  });
  assert.equal(tooManyRoutes.status, 400);
  const nonCanonicalRouteToken = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      envelopeId: randomUUID(),
      recipientDeviceId: receiver.deviceId,
      kind: "message",
      frameBase64: frame(sender, receiver, 0x01),
      routeTokenBase64: senderToReceiverRoute.slice(0, -1)
    })
  });
  assert.equal(nonCanonicalRouteToken.status, 400);
  const replacementSigningKey = generateKeyPairSync("ed25519").publicKey
    .export({ format: "der", type: "spki" })
    .toString("base64");
  const signingKeyReplacement = await fetch(`${baseUrl}/v1/devices/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      publicKeyBase64: sender.publicKeyBase64,
      signingPublicKeyBase64: replacementSigningKey
    })
  });
  assert.equal(signingKeyReplacement.status, 409);
  const senderSocket = await connectStream(sender);
  sockets.push(senderSocket);
  const receiverSocket = await connectStream(receiver);
  sockets.push(receiverSocket);

  const staleCallEnvelopeId = randomUUID();
  const staleCall = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      envelopeId: staleCallEnvelopeId,
      recipientDeviceId: receiver.deviceId,
      kind: "call",
      callId: randomUUID(),
      frameBase64: frame(sender, receiver, 0x04, Date.now() - 10 * 60_000),
      routeTokenBase64: senderToReceiverRoute
    })
  });
  assert.equal(staleCall.status, 200);
  assert.deepEqual(await staleCall.json(), {
    envelopeId: staleCallEnvelopeId,
    duplicate: false,
    expired: true
  });

  const messageId = randomUUID();
  const messageFrame = frame(sender, receiver, 0x01);

  const mailboxChanged = waitForEvent(receiverSocket, "mailbox.changed");
  const sent = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      envelopeId: messageId,
      recipientDeviceId: receiver.deviceId,
      kind: "message",
      frameBase64: messageFrame,
      routeTokenBase64: senderToReceiverRoute
    })
  });
  assert.equal(sent.status, 201);
  assert.equal((await mailboxChanged).envelopeId, messageId);

  const duplicate = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      envelopeId: messageId,
      recipientDeviceId: receiver.deviceId,
      kind: "message",
      frameBase64: messageFrame,
      routeTokenBase64: senderToReceiverRoute
    })
  });
  assert.equal(duplicate.status, 200);

  const conflictingDuplicate = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      envelopeId: messageId,
      recipientDeviceId: receiver.deviceId,
      kind: "message",
      frameBase64: (() => {
        const changed = Buffer.from(messageFrame, "base64");
        changed[44] = 1;
        return changed.toString("base64");
      })(),
      routeTokenBase64: senderToReceiverRoute
    })
  });
  assert.equal(conflictingDuplicate.status, 409);

  const senderSpoof = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      envelopeId: randomUUID(),
      recipientDeviceId: receiver.deviceId,
      kind: "message",
      frameBase64: frame(outsider, receiver, 0x01),
      routeTokenBase64: senderToReceiverRoute
    })
  });
  assert.equal(senderSpoof.status, 400);

  const unauthorizedEnvelopeId = randomUUID();
  const unpairedButCryptographicallyBound = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(outsider),
    body: JSON.stringify({
      envelopeId: unauthorizedEnvelopeId,
      recipientDeviceId: receiver.deviceId,
      kind: "message",
      frameBase64: frame(outsider, receiver, 0x01),
      routeTokenBase64: outsiderToReceiverRoute
    })
  });
  assert.equal(unpairedButCryptographicallyBound.status, 403);
  assert.deepEqual(await unpairedButCryptographicallyBound.json(), { error: "unauthorized_route" });

  const receiverMailboxResponse = await fetch(`${baseUrl}/v1/mailbox`, { headers: auth(receiver) });
  assert.equal(receiverMailboxResponse.status, 200);
  const receiverMailbox = await receiverMailboxResponse.json() as {
    envelopes: Array<{ envelopeId: string }>;
  };
  assert.equal(receiverMailbox.envelopes.some((item) => item.envelopeId === messageId), true);
  assert.equal(receiverMailbox.envelopes.some((item) => item.envelopeId === unauthorizedEnvelopeId), false);
  assert.equal(receiverMailbox.envelopes.some((item) => item.envelopeId === staleCallEnvelopeId), false);

  const statusChanged = waitForEvent(senderSocket, "envelope.status");
  const acknowledged = await fetch(`${baseUrl}/v1/envelopes/${messageId}/ack`, {
    method: "POST",
    headers: auth(receiver),
    body: JSON.stringify({ state: "delivered" })
  });
  assert.equal(acknowledged.status, 204);
  const statusEvent = await statusChanged;
  assert.deepEqual(
    { envelopeId: statusEvent.envelopeId, state: statusEvent.state },
    { envelopeId: messageId, state: "delivered" }
  );

  const senderMailboxResponse = await fetch(`${baseUrl}/v1/mailbox`, { headers: auth(sender) });
  const senderMailbox = await senderMailboxResponse.json() as {
    outboundStatuses: Array<{ envelopeId: string; state: string }>;
  };
  assert.deepEqual(
    senderMailbox.outboundStatuses.find((item) => item.envelopeId === messageId),
    { envelopeId: messageId, state: "delivered" }
  );

  const callId = randomUUID();
  const callRing = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      envelopeId: randomUUID(),
      recipientDeviceId: receiver.deviceId,
      kind: "call",
      callId,
      frameBase64: frame(sender, receiver, 0x04),
      routeTokenBase64: senderToReceiverRoute
    })
  });
  assert.equal(callRing.status, 201);

  const prematureMedia = await fetch(`${baseUrl}/v1/calls/${callId}/token`, {
    method: "POST",
    headers: auth(sender),
    body: "{}"
  });
  assert.equal(prematureMedia.status, 404);

  const callerCannotAccept = await fetch(`${baseUrl}/v1/calls/${callId}/state`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      state: "active",
      envelopeId: randomUUID(),
      frameBase64: frame(sender, receiver, 0x05),
      routeTokenBase64: senderToReceiverRoute
    })
  });
  assert.equal(callerCannotAccept.status, 409);

  const outsiderCannotAccept = await fetch(`${baseUrl}/v1/calls/${callId}/state`, {
    method: "POST",
    headers: auth(outsider),
    body: JSON.stringify({
      state: "active",
      envelopeId: randomUUID(),
      frameBase64: frame(outsider, receiver, 0x05),
      routeTokenBase64: outsiderToReceiverRoute
    })
  });
  assert.equal(outsiderCannotAccept.status, 404);

  const transitionCollisionId = randomUUID();
  const collisionEnvelope = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(receiver),
    body: JSON.stringify({
      envelopeId: transitionCollisionId,
      recipientDeviceId: sender.deviceId,
      kind: "message",
      frameBase64: frame(receiver, sender, 0x01),
      routeTokenBase64: receiverToSenderRoute
    })
  });
  assert.equal(collisionEnvelope.status, 201);
  const conflictingAccept = await fetch(`${baseUrl}/v1/calls/${callId}/state`, {
    method: "POST",
    headers: auth(receiver),
    body: JSON.stringify({
      state: "active",
      envelopeId: transitionCollisionId,
      frameBase64: frame(receiver, sender, 0x05),
      routeTokenBase64: receiverToSenderRoute
    })
  });
  assert.equal(conflictingAccept.status, 409);
  assert.deepEqual(await conflictingAccept.json(), { error: "envelope_id_conflict" });
  const mediaAfterRolledBackConflict = await fetch(`${baseUrl}/v1/calls/${callId}/token`, {
    method: "POST",
    headers: auth(sender),
    body: "{}"
  });
  assert.equal(mediaAfterRolledBackConflict.status, 404);

  const acceptEnvelopeId = randomUUID();
  const acceptFrame = frame(receiver, sender, 0x05);
  const accepted = await fetch(`${baseUrl}/v1/calls/${callId}/state`, {
    method: "POST",
    headers: auth(receiver),
    body: JSON.stringify({
      state: "active",
      envelopeId: acceptEnvelopeId,
      frameBase64: acceptFrame,
      routeTokenBase64: receiverToSenderRoute
    })
  });
  assert.equal(accepted.status, 204);

  const acceptedRetry = await fetch(`${baseUrl}/v1/calls/${callId}/state`, {
    method: "POST",
    headers: auth(receiver),
    body: JSON.stringify({
      state: "active",
      envelopeId: acceptEnvelopeId,
      frameBase64: acceptFrame,
      routeTokenBase64: receiverToSenderRoute
    })
  });
  assert.equal(acceptedRetry.status, 204);

  const malformedLease = await fetch(`${baseUrl}/v1/calls/${callId}/lease`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({ leaseSeconds: 3_600 })
  });
  assert.equal(malformedLease.status, 400);
  const outsiderLease = await fetch(`${baseUrl}/v1/calls/${callId}/lease`, {
    method: "POST",
    headers: auth(outsider),
    body: "{}"
  });
  assert.equal(outsiderLease.status, 404);
  const leaseRenewedAt = Date.now();
  const renewedLease = await fetch(`${baseUrl}/v1/calls/${callId}/lease`, {
    method: "POST",
    headers: auth(sender),
    body: "{}"
  });
  assert.equal(renewedLease.status, 200);
  const lease = await renewedLease.json() as { leaseSeconds: number; leaseExpiresAt: string };
  assert.equal(lease.leaseSeconds, 120);
  const leaseRemainingMs = Date.parse(lease.leaseExpiresAt) - leaseRenewedAt;
  assert.ok(leaseRemainingMs >= 115_000 && leaseRemainingMs <= 125_000);

  const replayedRingEnvelopeId = randomUUID();
  const replayedRing = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      envelopeId: replayedRingEnvelopeId,
      recipientDeviceId: receiver.deviceId,
      kind: "call",
      callId,
      frameBase64: frame(sender, receiver, 0x04),
      routeTokenBase64: senderToReceiverRoute
    })
  });
  assert.equal(replayedRing.status, 200);
  assert.equal((await replayedRing.json() as { expired?: boolean }).expired, true);

  const postReplayMailbox = await fetch(`${baseUrl}/v1/mailbox`, { headers: auth(receiver) });
  const postReplayBody = await postReplayMailbox.json() as { envelopes: Array<{ envelopeId: string }> };
  assert.equal(postReplayBody.envelopes.some((item) => item.envelopeId === replayedRingEnvelopeId), false);

  const mediaResponse = await fetch(`${baseUrl}/v1/calls/${callId}/token`, {
    method: "POST",
    headers: auth(sender),
    body: "{}"
  });
  assert.equal(mediaResponse.status, 200);
  const media = await mediaResponse.json() as { url: string; token: string };
  assert.equal(media.url, process.env.EXPECTED_LIVEKIT_URL ?? media.url);
  assert.match(media.url, /^wss?:\/\//);
  assert.equal(media.token.split(".").length, 3);

  assert.equal((await replaceInboundRoutes(receiver, [])).status, 204);
  const revokedRoute = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      envelopeId: randomUUID(),
      recipientDeviceId: receiver.deviceId,
      kind: "message",
      frameBase64: frame(sender, receiver, 0x01),
      routeTokenBase64: senderToReceiverRoute
    })
  });
  assert.equal(revokedRoute.status, 403);
  assert.deepEqual(await revokedRoute.json(), { error: "unauthorized_route" });
  assert.equal(
    (await replaceInboundRoutes(receiver, [{ sender, routeTokenBase64: senderToReceiverRoute }])).status,
    204
  );

  const quotaCaller = await registerDevice();
  const quotaCallee = await registerDevice();
  const quotaCallerToCallee = backendRouteToken(quotaCaller, quotaCallee);
  const quotaCalleeToCaller = backendRouteToken(quotaCallee, quotaCaller);
  assert.equal(
    (await replaceInboundRoutes(quotaCallee, [{
      sender: quotaCaller,
      routeTokenBase64: quotaCallerToCallee
    }])).status,
    204
  );
  assert.equal(
    (await replaceInboundRoutes(quotaCaller, [{
      sender: quotaCallee,
      routeTokenBase64: quotaCalleeToCaller
    }])).status,
    204
  );

  const quotaFillerEnvelopeIds: string[] = [];
  for (let attempt = 0; attempt < 150; attempt += 1) {
    const envelopeId = randomUUID();
    const response = await fetch(`${baseUrl}/v1/envelopes`, {
      method: "POST",
      headers: auth(quotaCallee),
      body: JSON.stringify({
        envelopeId,
        recipientDeviceId: quotaCaller.deviceId,
        kind: "message",
        frameBase64: frame(quotaCallee, quotaCaller, 0x01),
        routeTokenBase64: quotaCalleeToCaller
      })
    });
    if (response.status === 429) break;
    assert.equal(response.status, 201);
    quotaFillerEnvelopeIds.push(envelopeId);
  }
  assert.equal(quotaFillerEnvelopeIds.length, 100);

  const quotaCallId = randomUUID();
  const quotaRing = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(quotaCaller),
    body: JSON.stringify({
      envelopeId: randomUUID(),
      recipientDeviceId: quotaCallee.deviceId,
      kind: "call",
      callId: quotaCallId,
      frameBase64: frame(quotaCaller, quotaCallee, 0x04),
      routeTokenBase64: quotaCallerToCallee
    })
  });
  assert.equal(quotaRing.status, 201);
  const quotaAcceptEnvelopeId = randomUUID();
  const quotaAcceptFrame = frame(quotaCallee, quotaCaller, 0x05);
  const quotaBlockedAccept = await fetch(`${baseUrl}/v1/calls/${quotaCallId}/state`, {
    method: "POST",
    headers: auth(quotaCallee),
    body: JSON.stringify({
      state: "active",
      envelopeId: quotaAcceptEnvelopeId,
      frameBase64: quotaAcceptFrame,
      routeTokenBase64: quotaCalleeToCaller
    })
  });
  assert.equal(quotaBlockedAccept.status, 429);
  assert.deepEqual(await quotaBlockedAccept.json(), { error: "call_signal_queue_full" });
  const quotaMediaBeforeRetry = await fetch(`${baseUrl}/v1/calls/${quotaCallId}/token`, {
    method: "POST",
    headers: auth(quotaCaller),
    body: "{}"
  });
  assert.equal(quotaMediaBeforeRetry.status, 404);
  const freeQuotaSlot = await fetch(
    `${baseUrl}/v1/envelopes/${quotaFillerEnvelopeIds[0]}/ack`,
    {
      method: "POST",
      headers: auth(quotaCaller),
      body: JSON.stringify({ state: "delivered" })
    }
  );
  assert.equal(freeQuotaSlot.status, 204);
  const quotaAcceptedAfterRetry = await fetch(`${baseUrl}/v1/calls/${quotaCallId}/state`, {
    method: "POST",
    headers: auth(quotaCallee),
    body: JSON.stringify({
      state: "active",
      envelopeId: quotaAcceptEnvelopeId,
      frameBase64: quotaAcceptFrame,
      routeTokenBase64: quotaCalleeToCaller
    })
  });
  assert.equal(quotaAcceptedAfterRetry.status, 204);
  const quotaMediaAfterRetry = await fetch(`${baseUrl}/v1/calls/${quotaCallId}/token`, {
    method: "POST",
    headers: auth(quotaCaller),
    body: "{}"
  });
  assert.equal(quotaMediaAfterRetry.status, 200);

  const limitedEncryption = generateKeyPairSync("x25519");
  const limitedSigning = generateKeyPairSync("ed25519");
  const limitedPublicJwk = limitedEncryption.publicKey.export({ format: "jwk" });
  assert.ok(limitedPublicJwk.x);
  const limitedChallengeBody = {
    publicKeyBase64: Buffer.from(limitedPublicJwk.x, "base64url").toString("base64"),
    signingPublicKeyBase64: limitedSigning.publicKey
      .export({ format: "der", type: "spki" })
      .toString("base64")
  };
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const challenge = await fetch(`${baseUrl}/v1/devices/challenge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(limitedChallengeBody)
    });
    assert.equal(challenge.status, 200);
  }
  const challengeLimit = await fetch(`${baseUrl}/v1/devices/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(limitedChallengeBody)
  });
  assert.equal(challengeLimit.status, 429);
  assert.equal(challengeLimit.headers.get("retry-after"), "300");
});
