import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import WebSocket from "ws";
import { buildServer } from "../src/server.js";
import type { PushGateway } from "../src/push.js";
import type { CleanupResult, Device, Repository } from "../src/repository.js";

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

const disabledPush: PushGateway = {
  enabled: false,
  async sendWake() {}
};

class FakeRepository {
  healthCalls = 0;
  cleanupCalls = 0;
  closeCalls = 0;
  readonly callTtls: number[] = [];
  readonly envelopeTtls: number[] = [];
  readonly revokedDeviceIds: string[] = [];
  readonly senderPublicKey = Buffer.alloc(32, 7).toString("base64");
  readonly recipientPublicKey = Buffer.alloc(32, 9).toString("base64");
  healthHandler: () => Promise<void> = async () => undefined;
  cleanupHandler: (batchSize: number) => Promise<CleanupResult> = async () => ({
    envelopes: 0,
    calls: 0,
    challenges: 0
  });

  async health(): Promise<void> {
    this.healthCalls += 1;
    await this.healthHandler();
  }

  async cleanup(batchSize: number): Promise<CleanupResult> {
    this.cleanupCalls += 1;
    return this.cleanupHandler(batchSize);
  }

  async close(): Promise<void> {
    this.closeCalls += 1;
  }

  async authenticate(deviceId: string): Promise<Device> {
    return {
      deviceId,
      publicKeyBase64: this.senderPublicKey,
      tokenHash: Buffer.alloc(32),
      fcmToken: null
    };
  }

  async publicKeyForDevice(): Promise<string> {
    return this.recipientPublicKey;
  }

  async routeAuthorized(): Promise<boolean> {
    return true;
  }

  async revokeSession(deviceId: string): Promise<void> {
    this.revokedDeviceIds.push(deviceId);
  }

  async createCallWithEnvelope(_input: unknown, ttlSeconds: number) {
    this.callTtls.push(ttlSeconds);
    this.envelopeTtls.push(ttlSeconds);
    return "inserted" as const;
  }
}

const repository = (fake: FakeRepository) => fake as unknown as Repository;
const nextTurn = () => new Promise<void>((resolve) => setImmediate(resolve));

function callFrame(senderPublicKey: string, recipientPublicKey: string, timestampMs: number): string {
  const recipientPrefix = Buffer.from(recipientPublicKey, "base64").subarray(0, 8);
  const bytes = Buffer.alloc(64 + recipientPrefix.length);
  bytes[0] = 0x2f;
  bytes.writeUInt32BE(timestampMs >>> 0, 8);
  Buffer.from(senderPublicKey, "base64").copy(bytes, 12);
  bytes.writeUInt16BE(recipientPrefix.length, 60);
  bytes[62] = 0x04;
  recipientPrefix.copy(bytes, 64);
  return bytes.toString("base64");
}

test("overload returns retryable 503 and releases the request slot", async () => {
  const fake = new FakeRepository();
  const firstHealthStarted = deferred();
  const releaseFirstHealth = deferred();
  fake.healthHandler = async () => {
    if (fake.healthCalls === 1) {
      firstHealthStarted.resolve();
      await releaseFirstHealth.promise;
    }
  };
  const app = await buildServer(repository(fake), {
    logger: false,
    maxInFlightRequests: 1,
    cleanupIntervalMs: 60_000,
    pushGateway: disabledPush
  });

  const first = app.inject({ method: "GET", url: "/healthz" });
  await firstHealthStarted.promise;
  const overloaded = await app.inject({ method: "GET", url: "/healthz" });
  assert.equal(overloaded.statusCode, 503);
  assert.equal(overloaded.headers["retry-after"], "1");
  assert.deepEqual(overloaded.json(), { error: "server_busy" });

  releaseFirstHealth.resolve();
  assert.equal((await first).statusCode, 200);
  assert.equal((await app.inject({ method: "GET", url: "/healthz" })).statusCode, 200);
  await app.close();
  assert.equal(fake.closeCalls, 1);
});

test("authenticated sign-out revokes the server-side device session", async () => {
  const fake = new FakeRepository();
  const app = await buildServer(repository(fake), {
    logger: false,
    cleanupIntervalMs: 60_000,
    pushGateway: disabledPush
  });
  const deviceId = "a".repeat(64);
  const response = await app.inject({
    method: "DELETE",
    url: "/v1/devices/session",
    headers: { authorization: "Bearer test", "x-device-id": deviceId }
  });
  assert.equal(response.statusCode, 204);
  assert.deepEqual(fake.revokedDeviceIds, [deviceId]);
  await app.close();
});

test("cleanup never overlaps and shutdown waits before closing PostgreSQL", async () => {
  const fake = new FakeRepository();
  const cleanupStarted = deferred();
  const releaseCleanup = deferred();
  fake.cleanupHandler = async () => {
    cleanupStarted.resolve();
    await releaseCleanup.promise;
    return { envelopes: 1, calls: 0, challenges: 0 };
  };
  const app = await buildServer(repository(fake), {
    logger: false,
    cleanupIntervalMs: 5,
    cleanupBatchSize: 17,
    pushGateway: disabledPush
  });

  await cleanupStarted.promise;
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(fake.cleanupCalls, 1);

  let closed = false;
  const closing = app.close().then(() => { closed = true; });
  await nextTurn();
  assert.equal(closed, false);
  assert.equal(fake.closeCalls, 0);
  releaseCleanup.resolve();
  await closing;
  assert.equal(fake.cleanupCalls, 1);
  assert.equal(fake.closeCalls, 1);
});

test("stale call retries terminate without a ghost ring and fresh rings keep only remaining TTL", async () => {
  const fake = new FakeRepository();
  const app = await buildServer(repository(fake), {
    logger: false,
    cleanupIntervalMs: 60_000,
    pushGateway: disabledPush
  });
  const recipientDeviceId = "b".repeat(64);
  const senderDeviceId = "a".repeat(64);
  const routeTokenBase64 = Buffer.alloc(32, 11).toString("base64");
  const request = (timestampMs: number) => app.inject({
    method: "POST",
    url: "/v1/envelopes",
    headers: { authorization: "Bearer test", "x-device-id": senderDeviceId },
    payload: {
      envelopeId: randomUUID(),
      recipientDeviceId,
      kind: "call",
      callId: randomUUID(),
      frameBase64: callFrame(fake.senderPublicKey, fake.recipientPublicKey, timestampMs),
      routeTokenBase64
    }
  });

  const stale = await request(Date.now() - 10 * 60_000);
  assert.equal(stale.statusCode, 200);
  assert.equal(stale.json().expired, true);
  assert.deepEqual(fake.callTtls, []);
  assert.deepEqual(fake.envelopeTtls, []);

  const fresh = await request(Date.now() - 10_000);
  assert.equal(fresh.statusCode, 201);
  assert.equal(fake.callTtls.length, 1);
  assert.equal(fake.envelopeTtls.length, 1);
  assert.ok(fake.callTtls[0]! >= 49 && fake.callTtls[0]! <= 50);
  assert.equal(fake.envelopeTtls[0], fake.callTtls[0]);
  await app.close();
});

test("WebSocket upgrade releases HTTP in-flight capacity", async () => {
  const fake = new FakeRepository();
  const app = await buildServer(repository(fake), {
    logger: false,
    maxInFlightRequests: 1,
    maxWebSocketConnections: 2,
    cleanupIntervalMs: 60_000,
    pushGateway: disabledPush
  });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const address = app.server.address();
  if (!address || typeof address === "string") throw new Error("test server did not bind a TCP port");

  const socket = new WebSocket(`ws://127.0.0.1:${address.port}/v1/stream`, {
    headers: { authorization: "Bearer test", "x-device-id": "d".repeat(64) }
  });
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("WebSocket did not become ready")), 2_000);
    socket.once("message", (data) => {
      if (JSON.parse(data.toString()).type !== "ready") return;
      clearTimeout(timeout);
      resolve();
    });
    socket.once("error", reject);
  });

  const response = await fetch(`http://127.0.0.1:${address.port}/healthz`);
  assert.equal(response.status, 200);
  socket.close();
  await app.close();
  assert.equal(fake.closeCalls, 1);
});
