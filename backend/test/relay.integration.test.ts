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
import pg from "pg";
import WebSocket from "ws";
import type { AccountTokenVerifier, VerifiedAccount } from "../src/account-auth.js";
import { hashToken, registrationProof, registrationX25519Proof } from "../src/identity.js";
import type { PushGateway } from "../src/push.js";
import { Repository } from "../src/repository.js";
import { buildServer } from "../src/server.js";

const integrationBaseUrl = process.env.INTEGRATION_BASE_URL;
let baseUrl = "http://127.0.0.1:0";
const { Pool } = pg;

const accountAUid = "integration-account-a";
const accountBUid = "integration-account-b";
const accountCUid = "integration-account-c";
const accountAToken = "firebase-test-id-token-for-integration-account-a";
const accountBToken = "firebase-test-id-token-for-integration-account-b";
const accountCToken = "firebase-test-id-token-for-integration-account-c";
const accountByToken = new Map([
  [accountAToken, accountAUid],
  [accountBToken, accountBUid],
  [accountCToken, accountCUid]
]);

const integrationAccountVerifier: AccountTokenVerifier = {
  configured: true,
  async verifyIdToken(token: string): Promise<VerifiedAccount> {
    const uid = accountByToken.get(token);
    if (!uid) throw new Error("invalid injected integration token");
    return { uid, email: `${uid}@example.test` };
  }
};

const disabledPush: PushGateway = {
  enabled: false,
  async sendWake() {}
};

type DeviceIdentity = {
  publicKeyBase64: string;
  encryptionPrivateKey: KeyObject;
  signingPublicKeyBase64: string;
  signingPrivateKey: KeyObject;
};

type RegisteredDevice = DeviceIdentity & {
  deviceId: string;
  token: string;
};

type RegistrationChallenge = {
  challengeId: string;
  deviceId: string;
  nonceBase64: string;
  serverEphemeralPublicKeyBase64: string;
};

function base64UrlToBuffer(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function createDeviceIdentity(): DeviceIdentity {
  const encryption = generateKeyPairSync("x25519");
  const signing = generateKeyPairSync("ed25519");
  const publicKey = encryption.publicKey.export({ format: "jwk" });
  const publicKeyX = publicKey.x;
  if (!publicKeyX) throw new Error("X25519 public JWK is missing x");
  const publicKeyBase64 = base64UrlToBuffer(publicKeyX).toString("base64");
  const signingPublicKeyBase64 = signing.publicKey
    .export({ format: "der", type: "spki" })
    .toString("base64");
  return {
    publicKeyBase64,
    encryptionPrivateKey: encryption.privateKey,
    signingPublicKeyBase64,
    signingPrivateKey: signing.privateKey
  };
}

function accountHeaders(accountToken: string): Record<string, string> {
  return {
    authorization: `Bearer ${accountToken}`,
    "content-type": "application/json"
  };
}

function requestChallenge(identity: DeviceIdentity, accountToken: string): Promise<Response> {
  return fetch(`${baseUrl}/v1/devices/challenge`, {
    method: "POST",
    headers: accountHeaders(accountToken),
    body: JSON.stringify({
      publicKeyBase64: identity.publicKeyBase64,
      signingPublicKeyBase64: identity.signingPublicKeyBase64
    })
  });
}

function registrationPayload(identity: DeviceIdentity, challenge: RegistrationChallenge) {
  const signatureBase64 = sign(
    null,
    registrationProof(challenge.deviceId, challenge.nonceBase64),
    identity.signingPrivateKey
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
    privateKey: identity.encryptionPrivateKey,
    publicKey: serverPublicKey
  });
  const pairSharedSecret = Buffer.from(hkdfSync(
    "sha256",
    rawSharedSecret,
    Buffer.alloc(32),
    Buffer.from("OmniRelay/X25519/AES-256-GCM/v1", "utf8"),
    32
  ));
  return {
    challengeId: challenge.challengeId,
    publicKeyBase64: identity.publicKeyBase64,
    signingPublicKeyBase64: identity.signingPublicKeyBase64,
    nonceBase64: challenge.nonceBase64,
    signatureBase64,
    x25519ProofBase64: registrationX25519Proof(
      pairSharedSecret,
      challenge.deviceId,
      challenge.nonceBase64,
      identity.signingPublicKeyBase64
    ).toString("base64")
  };
}

async function registerIdentity(
  identity: DeviceIdentity,
  accountToken: string,
  exerciseProofRejection = false
): Promise<RegisteredDevice> {
  const challengeResponse = await requestChallenge(identity, accountToken);
  assert.equal(challengeResponse.status, 200);
  const challenge = await challengeResponse.json() as RegistrationChallenge;
  assert.equal(
    challenge.deviceId,
    createHash("sha256").update(Buffer.from(identity.publicKeyBase64, "base64")).digest("hex")
  );
  const payload = registrationPayload(identity, challenge);
  if (exerciseProofRejection) {
    const parallelChallengeResponse = await requestChallenge(identity, accountToken);
    assert.equal(parallelChallengeResponse.status, 200);
    const parallelChallenge = await parallelChallengeResponse.json() as { challengeId: string };
    assert.notEqual(parallelChallenge.challengeId, challenge.challengeId);
    const invalidProof = await fetch(`${baseUrl}/v1/devices/register`, {
      method: "POST",
      headers: accountHeaders(accountToken),
      body: JSON.stringify({
        ...payload,
        x25519ProofBase64: Buffer.alloc(32).toString("base64")
      })
    });
    assert.equal(invalidProof.status, 401);
  }
  const response = await fetch(`${baseUrl}/v1/devices/register`, {
    method: "POST",
    headers: accountHeaders(accountToken),
    body: JSON.stringify(payload)
  });
  assert.equal(response.status, 201);
  const registered = await response.json() as { deviceId: string; token: string };
  return { ...identity, ...registered };
}

async function registerDevice(
  accountToken: string,
  exerciseProofRejection = false
): Promise<RegisteredDevice> {
  return registerIdentity(createDeviceIdentity(), accountToken, exerciseProofRejection);
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
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is required for integration tests");
  const repository = new Repository(databaseUrl);
  await repository.migrate();
  const app = await buildServer(repository, {
    logger: false,
    cleanupIntervalMs: 60_000,
    pushGateway: disabledPush,
    accountTokenVerifier: integrationAccountVerifier
  });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const address = app.server.address();
  if (!address || typeof address === "string") throw new Error("integration server did not bind a TCP port");
  baseUrl = `http://127.0.0.1:${address.port}`;
  const database = new Pool({ connectionString: databaseUrl, max: 1 });
  const sockets: WebSocket[] = [];
  t.after(async () => {
    for (const socket of sockets) socket.terminate();
    await database.end();
    await app.close();
  });

  const authProbeIdentity = createDeviceIdentity();
  const missingAccountToken = await fetch(`${baseUrl}/v1/devices/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      publicKeyBase64: authProbeIdentity.publicKeyBase64,
      signingPublicKeyBase64: authProbeIdentity.signingPublicKeyBase64
    })
  });
  assert.equal(missingAccountToken.status, 401);
  const invalidAccountToken = await requestChallenge(authProbeIdentity, "invalid-firebase-id-token");
  assert.equal(invalidAccountToken.status, 401);

  const sender = await registerDevice(accountAToken, true);
  const receiver = await registerDevice(accountBToken);
  const outsider = await registerDevice(accountCToken);

  const inviteResponse = await fetch(`${baseUrl}/v1/contacts/invitations`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({ email: `${accountBUid}@example.test` })
  });
  assert.equal(inviteResponse.status, 201);
  const invitation = await inviteResponse.json() as { invitationId: string; status: string };
  assert.equal(invitation.status, "created");
  const incomingInvites = await fetch(`${baseUrl}/v1/contacts/invitations`, {
    headers: auth(receiver)
  });
  assert.equal(incomingInvites.status, 200);
  const invitationList = await incomingInvites.json() as {
    invitations: Array<{ invitationId: string; direction: string; counterpartEmail: string }>;
  };
  const incomingInvitation = invitationList.invitations.find(
    (item) => item.invitationId === invitation.invitationId
  );
  assert.equal(incomingInvitation?.direction, "incoming");
  assert.equal(incomingInvitation?.counterpartEmail, `${accountAUid}@example.test`);
  const acceptedInvitation = await fetch(
    `${baseUrl}/v1/contacts/invitations/${invitation.invitationId}/respond`,
    {
      method: "POST",
      headers: auth(receiver),
      body: JSON.stringify({ action: "accept" })
    }
  );
  assert.equal(acceptedInvitation.status, 200);
  assert.deepEqual(await acceptedInvitation.json(), { status: "accepted" });
  const senderContactsResponse = await fetch(`${baseUrl}/v1/contacts`, { headers: auth(sender) });
  assert.equal(senderContactsResponse.status, 200);
  const senderContacts = await senderContactsResponse.json() as {
    contacts: Array<{ accountUid: string; email: string; deviceId: string; publicKeyBase64: string }>;
    contactLimit: number;
    dailyInvitationLimit: number;
  };
  assert.equal(senderContacts.contactLimit, 20);
  assert.equal(senderContacts.dailyInvitationLimit, 5);
  assert.deepEqual(
    senderContacts.contacts.find((contact) => contact.accountUid === accountBUid),
    {
      accountUid: accountBUid,
      email: `${accountBUid}@example.test`,
      deviceId: receiver.deviceId,
      publicKeyBase64: receiver.publicKeyBase64
    }
  );

  const invitationQuotaTargets: string[] = [];
  for (let index = 0; index < 5; index += 1) {
    const accountUid = `integration-invite-quota-${index}`;
    const email = `${accountUid}@example.test`;
    const deviceId = createHash("sha256").update(`invite-device-${index}`).digest("hex");
    invitationQuotaTargets.push(accountUid);
    await database.query(
      `INSERT INTO accounts(account_uid, normalized_email) VALUES ($1, $2)
       ON CONFLICT (account_uid) DO NOTHING`,
      [accountUid, email]
    );
    await database.query(
      `INSERT INTO devices(
         device_id, public_key_base64, signing_public_key_base64,
         account_uid, token_hash, token_expires_at
       ) VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '1 day')
       ON CONFLICT (device_id) DO NOTHING`,
      [
        deviceId,
        Buffer.alloc(32, index + 21).toString("base64"),
        Buffer.alloc(44, index + 31).toString("base64"),
        accountUid,
        Buffer.alloc(32, index + 41)
      ]
    );
    const quotaResult = await repository.createContactInvitation(
      randomUUID(),
      accountAUid,
      sender.deviceId,
      email,
      5,
      20
    );
    if (index < 4) assert.equal(quotaResult.status, "created");
    else assert.equal(quotaResult.status, "daily_limit");
  }

  const seededContactUids = [...invitationQuotaTargets.slice(0, 4)];
  while (seededContactUids.length < 19) {
    const index = seededContactUids.length;
    const accountUid = `integration-contact-cap-${index}`;
    seededContactUids.push(accountUid);
    await database.query(
      `INSERT INTO accounts(account_uid, normalized_email) VALUES ($1, $2)
       ON CONFLICT (account_uid) DO NOTHING`,
      [accountUid, `${accountUid}@example.test`]
    );
  }
  for (const otherUid of seededContactUids) {
    const pair = [accountAUid, otherUid].sort();
    await database.query(
      `INSERT INTO account_contacts(account_low_uid, account_high_uid, invited_by_account_uid)
       VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
      [pair[0], pair[1], accountAUid]
    );
  }
  const contactCapResult = await repository.createContactInvitation(
    randomUUID(),
    accountAUid,
    sender.deviceId,
    `${accountCUid}@example.test`,
    5,
    20
  );
  assert.equal(contactCapResult.status, "contact_limit");

  const oldSenderSessionToken = sender.token;
  const rotationChallengeResponse = await requestChallenge(sender, accountAToken);
  assert.equal(rotationChallengeResponse.status, 200);
  const rotationChallenge = await rotationChallengeResponse.json() as RegistrationChallenge;
  const rotationPayload = registrationPayload(sender, rotationChallenge);
  const wrongAccountCompletion = await fetch(`${baseUrl}/v1/devices/register`, {
    method: "POST",
    headers: accountHeaders(accountBToken),
    body: JSON.stringify(rotationPayload)
  });
  assert.equal(wrongAccountCompletion.status, 401);
  const rotationResponse = await fetch(`${baseUrl}/v1/devices/register`, {
    method: "POST",
    headers: accountHeaders(accountAToken),
    body: JSON.stringify(rotationPayload)
  });
  assert.equal(rotationResponse.status, 201);
  const rotated = await rotationResponse.json() as { deviceId: string; token: string };
  assert.equal(rotated.deviceId, sender.deviceId);
  assert.notEqual(rotated.token, oldSenderSessionToken);
  sender.token = rotated.token;
  const oldSessionRejected = await fetch(`${baseUrl}/v1/devices/push-token`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${oldSenderSessionToken}`,
      "x-device-id": sender.deviceId,
      "content-type": "application/json"
    },
    body: JSON.stringify({ fcmToken: null })
  });
  assert.equal(oldSessionRejected.status, 401);
  const rotatedSessionAccepted = await fetch(`${baseUrl}/v1/devices/push-token`, {
    method: "PUT",
    headers: auth(sender),
    body: JSON.stringify({ fcmToken: null })
  });
  assert.equal(rotatedSessionAccepted.status, 204);

  const crossAccountTakeover = await requestChallenge(sender, accountBToken);
  assert.equal(crossAccountTakeover.status, 409);
  assert.deepEqual(await crossAccountTakeover.json(), { error: "device_account_mismatch" });
  const senderBinding = await database.query(
    "SELECT account_uid FROM devices WHERE device_id = $1",
    [sender.deviceId]
  );
  assert.equal(senderBinding.rows[0]?.account_uid, accountAUid);

  const legacyIdentity = createDeviceIdentity();
  const legacyDeviceId = createHash("sha256")
    .update(Buffer.from(legacyIdentity.publicKeyBase64, "base64"))
    .digest("hex");
  await database.query(
    `INSERT INTO devices(
       device_id, public_key_base64, signing_public_key_base64, token_hash, account_uid
     ) VALUES ($1, $2, $3, $4, NULL)`,
    [
      legacyDeviceId,
      legacyIdentity.publicKeyBase64,
      legacyIdentity.signingPublicKeyBase64,
      hashToken("legacy-device-session-token")
    ]
  );
  const migratedLegacyDevice = await registerIdentity(legacyIdentity, accountCToken);
  assert.equal(migratedLegacyDevice.deviceId, legacyDeviceId);
  const migratedBinding = await database.query(
    "SELECT account_uid FROM devices WHERE device_id = $1",
    [legacyDeviceId]
  );
  assert.equal(migratedBinding.rows[0]?.account_uid, accountCUid);

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
    headers: accountHeaders(accountAToken),
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

  const sameAccountReceiver = await registerDevice(accountBToken);
  const outsiderToSameAccountRoute = backendRouteToken(outsider, sameAccountReceiver);
  const sameAccountToOutsiderRoute = backendRouteToken(sameAccountReceiver, outsider);
  assert.equal(
    (await replaceInboundRoutes(sameAccountReceiver, [
      { sender: outsider, routeTokenBase64: outsiderToSameAccountRoute }
    ])).status,
    204
  );
  assert.equal(
    (await replaceInboundRoutes(outsider, [
      { sender: sameAccountReceiver, routeTokenBase64: sameAccountToOutsiderRoute }
    ])).status,
    204
  );
  const waitingCallId = randomUUID();
  const waitingRing = await fetch(`${baseUrl}/v1/envelopes`, {
    method: "POST",
    headers: auth(outsider),
    body: JSON.stringify({
      envelopeId: randomUUID(),
      recipientDeviceId: sameAccountReceiver.deviceId,
      kind: "call",
      callId: waitingCallId,
      frameBase64: frame(outsider, sameAccountReceiver, 0x04),
      routeTokenBase64: outsiderToSameAccountRoute
    })
  });
  assert.equal(waitingRing.status, 201);
  const blockedWaitingAccept = await fetch(`${baseUrl}/v1/calls/${waitingCallId}/state`, {
    method: "POST",
    headers: auth(sameAccountReceiver),
    body: JSON.stringify({
      state: "active",
      envelopeId: randomUUID(),
      frameBase64: frame(sameAccountReceiver, outsider, 0x05),
      routeTokenBase64: sameAccountToOutsiderRoute
    })
  });
  assert.equal(blockedWaitingAccept.status, 409);
  assert.deepEqual(await blockedWaitingAccept.json(), { error: "participant_busy" });

  const endedActiveCall = await fetch(`${baseUrl}/v1/calls/${callId}/state`, {
    method: "POST",
    headers: auth(sender),
    body: JSON.stringify({
      state: "ended",
      envelopeId: randomUUID(),
      frameBase64: frame(sender, receiver, 0x07),
      routeTokenBase64: senderToReceiverRoute
    })
  });
  assert.equal(endedActiveCall.status, 204);

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

  const quotaCaller = await registerDevice(accountAToken);
  const quotaCallee = await registerDevice(accountBToken);
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
      headers: accountHeaders(accountCToken),
      body: JSON.stringify(limitedChallengeBody)
    });
    assert.equal(challenge.status, 200);
  }
  const challengeLimit = await fetch(`${baseUrl}/v1/devices/challenge`, {
    method: "POST",
    headers: accountHeaders(accountCToken),
    body: JSON.stringify(limitedChallengeBody)
  });
  assert.equal(challengeLimit.status, 429);
  assert.equal(challengeLimit.headers.get("retry-after"), "300");

  const revokeOutsider = await fetch(`${baseUrl}/v1/devices/session`, {
    method: "DELETE",
    headers: {
      authorization: `Bearer ${outsider.token}`,
      "x-device-id": outsider.deviceId
    }
  });
  assert.equal(revokeOutsider.status, 204);
  const revokedSessionRequest = await fetch(`${baseUrl}/v1/mailbox?limit=1`, {
    headers: auth(outsider)
  });
  assert.equal(revokedSessionRequest.status, 401);
  const revokedRow = await database.query(
    `SELECT token_expires_at <= NOW() AS expired, fcm_token
     FROM devices WHERE device_id = $1`,
    [outsider.deviceId]
  );
  assert.equal(revokedRow.rows[0]?.expired, true);
  assert.equal(revokedRow.rows[0]?.fcm_token, null);
});
