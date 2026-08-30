import assert from "node:assert/strict";
import test from "node:test";
import type { AccountTokenVerifier } from "../src/account-auth.js";
import type { PushGateway } from "../src/push.js";
import type { CleanupResult, Repository } from "../src/repository.js";
import { buildServer } from "../src/server.js";

const validAccountToken = "firebase-id-token-valid-for-unit-testing-only";
const challengePayload = {
  publicKeyBase64: Buffer.alloc(32, 7).toString("base64"),
  signingPublicKeyBase64: Buffer.alloc(44, 9).toString("base64")
};

const disabledPush: PushGateway = {
  enabled: false,
  async sendWake() {}
};

class NoDatabaseRepository {
  databaseCalls = 0;

  async health(): Promise<void> { this.databaseCalls += 1; }
  async cleanup(): Promise<CleanupResult> {
    this.databaseCalls += 1;
    return { envelopes: 0, calls: 0, challenges: 0 };
  }
  async close(): Promise<void> {}
}

class UnitAccountVerifier implements AccountTokenVerifier {
  readonly configured = true;
  readonly receivedTokens: string[] = [];

  constructor(private readonly uid: string = "unit-account-uid") {}

  async verifyIdToken(token: string): Promise<string> {
    this.receivedTokens.push(token);
    if (token !== validAccountToken) throw new Error("invalid test token");
    return this.uid;
  }
}

test("registration endpoints return 401 before database work for missing or invalid account tokens", async () => {
  const repository = new NoDatabaseRepository();
  const verifier = new UnitAccountVerifier();
  const app = await buildServer(repository as unknown as Repository, {
    logger: false,
    cleanupIntervalMs: 60_000,
    pushGateway: disabledPush,
    accountTokenVerifier: verifier
  });

  const missingChallengeToken = await app.inject({
    method: "POST",
    url: "/v1/devices/challenge",
    payload: challengePayload
  });
  assert.equal(missingChallengeToken.statusCode, 401);
  assert.deepEqual(missingChallengeToken.json(), { error: "invalid_account_token" });

  const invalidChallengeToken = await app.inject({
    method: "POST",
    url: "/v1/devices/challenge",
    headers: { authorization: "Bearer invalid-firebase-token" },
    payload: challengePayload
  });
  assert.equal(invalidChallengeToken.statusCode, 401);

  const missingRegistrationToken = await app.inject({
    method: "POST",
    url: "/v1/devices/register",
    payload: {}
  });
  assert.equal(missingRegistrationToken.statusCode, 401);

  const oversizedToken = await app.inject({
    method: "POST",
    url: "/v1/devices/register",
    headers: { authorization: `Bearer ${"x".repeat(16_385)}` },
    payload: {}
  });
  assert.equal(oversizedToken.statusCode, 401);
  assert.deepEqual(verifier.receivedTokens, ["invalid-firebase-token"]);
  assert.equal(repository.databaseCalls, 0);
  await app.close();
});

test("a verifier returning an invalid UID is rejected before database work", async () => {
  const repository = new NoDatabaseRepository();
  const app = await buildServer(repository as unknown as Repository, {
    logger: false,
    cleanupIntervalMs: 60_000,
    pushGateway: disabledPush,
    accountTokenVerifier: new UnitAccountVerifier("")
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/devices/challenge",
    headers: { authorization: `Bearer ${validAccountToken}` },
    payload: challengePayload
  });
  assert.equal(response.statusCode, 401);
  assert.equal(repository.databaseCalls, 0);
  await app.close();
});

test("readiness fails closed without Firebase Admin and succeeds with an account verifier", async () => {
  const unavailableRepository = new NoDatabaseRepository();
  const unavailable = await buildServer(unavailableRepository as unknown as Repository, {
    logger: false,
    cleanupIntervalMs: 60_000,
    pushGateway: disabledPush,
    accountTokenVerifier: {
      configured: false,
      async verifyIdToken(): Promise<string> { throw new Error("disabled"); }
    }
  });
  const notReady = await unavailable.inject({ method: "GET", url: "/readyz" });
  assert.equal(notReady.statusCode, 503);
  assert.deepEqual(notReady.json(), { status: "not_ready", registration: "disabled" });
  assert.equal(unavailableRepository.databaseCalls, 0);
  await unavailable.close();

  const readyRepository = new NoDatabaseRepository();
  const ready = await buildServer(readyRepository as unknown as Repository, {
    logger: false,
    cleanupIntervalMs: 60_000,
    pushGateway: disabledPush,
    accountTokenVerifier: new UnitAccountVerifier()
  });
  const response = await ready.inject({ method: "GET", url: "/readyz" });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { status: "ready" });
  assert.equal(readyRepository.databaseCalls, 1);
  await ready.close();
});
