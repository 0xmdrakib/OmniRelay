import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import test from "node:test";
import WebSocket from "ws";
import { registrationProof } from "../src/identity.js";

const integrationBaseUrl = process.env.INTEGRATION_BASE_URL;
const baseUrl = integrationBaseUrl ?? "http://127.0.0.1:0";

type RegisteredDevice = {
  deviceId: string;
  token: string;
  publicKeyBase64: string;
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
  const challengeResponse = await fetch(`${baseUrl}/v1/devices/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ publicKeyBase64, signingPublicKeyBase64 })
  });
  assert.equal(challengeResponse.status, 200);
  const challenge = await challengeResponse.json() as { deviceId: string; nonceBase64: string };
  assert.equal(challenge.deviceId, createHash("sha256").update(Buffer.from(publicKeyBase64, "base64")).digest("hex"));
  const signatureBase64 = sign(
    null,
    registrationProof(challenge.deviceId, challenge.nonceBase64),
    signing.privateKey
  ).toString("base64");
  const response = await fetch(`${baseUrl}/v1/devices/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      publicKeyBase64,
      signingPublicKeyBase64,
      nonceBase64: challenge.nonceBase64,
      signatureBase64
    })
  });
  assert.equal(response.status, 201);
  const registered = await response.json() as Omit<RegisteredDevice, "publicKeyBase64">;
  return { ...registered, publicKeyBase64 };
}

function auth(device: RegisteredDevice): Record<string, string> {
  return {
    authorization: `Bearer ${device.token}`,
    "x-device-id": device.deviceId,
    "content-type": "application/json"
  };
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

function frame(sender: RegisteredDevice, recipient: RegisteredDevice, payloadType: number): string {
  const payload = Buffer.from(recipient.publicKeyBase64, "base64").subarray(0, 8);
  const bytes = Buffer.alloc(64 + payload.length);
  bytes[0] = 0x1f;
  Buffer.from(sender.publicKeyBase64, "base64").copy(bytes, 12);
  bytes.writeUInt16BE(payload.length, 60);
  bytes[62] = payloadType;
  payload.copy(bytes, 64);
  return bytes.toString("base64");
}

test("two devices exchange, acknowledge and obtain LiveKit credentials", { skip: !integrationBaseUrl }, async () => {
  const sender = await registerDevice();
  const receiver = await registerDevice();
  const outsider = await registerDevice();
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
  const receiverSocket = await connectStream(receiver);
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
      frameBase64: messageFrame
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
      frameBase64: messageFrame
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
      })()
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
      frameBase64: frame(outsider, receiver, 0x01)
    })
  });
  assert.equal(senderSpoof.status, 400);

  const receiverMailboxResponse = await fetch(`${baseUrl}/v1/mailbox`, { headers: auth(receiver) });
  assert.equal(receiverMailboxResponse.status, 200);
  const receiverMailbox = await receiverMailboxResponse.json() as {
    envelopes: Array<{ envelopeId: string }>;
  };
  assert.equal(receiverMailbox.envelopes.some((item) => item.envelopeId === messageId), true);

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
      frameBase64: frame(sender, receiver, 0x04)
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
      frameBase64: frame(sender, receiver, 0x05)
    })
  });
  assert.equal(callerCannotAccept.status, 409);

  const outsiderCannotAccept = await fetch(`${baseUrl}/v1/calls/${callId}/state`, {
    method: "POST",
    headers: auth(outsider),
    body: JSON.stringify({
      state: "active",
      envelopeId: randomUUID(),
      frameBase64: frame(outsider, receiver, 0x05)
    })
  });
  assert.equal(outsiderCannotAccept.status, 404);

  const acceptEnvelopeId = randomUUID();
  const accepted = await fetch(`${baseUrl}/v1/calls/${callId}/state`, {
    method: "POST",
    headers: auth(receiver),
    body: JSON.stringify({
      state: "active",
      envelopeId: acceptEnvelopeId,
      frameBase64: frame(receiver, sender, 0x05)
    })
  });
  assert.equal(accepted.status, 204);

  const acceptedRetry = await fetch(`${baseUrl}/v1/calls/${callId}/state`, {
    method: "POST",
    headers: auth(receiver),
    body: JSON.stringify({
      state: "active",
      envelopeId: acceptEnvelopeId,
      frameBase64: frame(receiver, sender, 0x05)
    })
  });
  assert.equal(acceptedRetry.status, 204);

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
  senderSocket.close();
  receiverSocket.close();
});
