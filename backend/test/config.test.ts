import assert from "node:assert/strict";
import test from "node:test";
import { parseConfig } from "../src/config.js";

const testDatabaseUrl = "postgres://test:test@127.0.0.1:5432/omnirelay_test";
const productionNeonEnvironment = {
  NODE_ENV: "production",
  DATABASE_URL: "postgresql://role:password@ep-omnirelay-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require",
  DATABASE_MIGRATION_URL: "postgresql://role:password@ep-omnirelay.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
} satisfies NodeJS.ProcessEnv;

function parseTestConfig(overrides: NodeJS.ProcessEnv = {}) {
  return parseConfig({ NODE_ENV: "test", DATABASE_URL: testDatabaseUrl, ...overrides });
}

test("resource controls use conservative defaults", () => {
  const parsed = parseTestConfig();
  assert.equal(parsed.DATABASE_POOL_MAX, 4);
  assert.equal(parsed.DATABASE_MIGRATION_URL, undefined);
  assert.equal(parsed.DATABASE_POOL_IDLE_TIMEOUT_MS, 30_000);
  assert.equal(parsed.DATABASE_CONNECTION_TIMEOUT_MS, 5_000);
  assert.equal(parsed.DATABASE_QUERY_TIMEOUT_MS, 12_000);
  assert.equal(parsed.DATABASE_STATEMENT_TIMEOUT_MS, 10_000);
  assert.equal(parsed.MAX_IN_FLIGHT_REQUESTS, 64);
  assert.equal(parsed.HTTP_MAX_CONNECTIONS, 768);
  assert.equal(parsed.WEBSOCKET_MAX_CONNECTIONS, 512);
  assert.equal(parsed.PUSH_MAX_CONCURRENCY, 4);
  assert.equal(parsed.PUSH_MAX_QUEUED, 256);
  assert.equal(parsed.SHUTDOWN_TIMEOUT_MS, 25_000);
  assert.equal(parsed.CLEANUP_BATCH_SIZE, 500);
  assert.equal(parsed.CLEANUP_INTERVAL_SECONDS, 900);
  assert.equal(parsed.CALL_SIGNAL_TTL_SECONDS, 60);
  assert.equal(parsed.CALL_ACTIVE_LEASE_SECONDS, 120);
  assert.equal(parsed.MAX_REGISTRATION_CHALLENGES_PER_DEVICE, 4);
  assert.equal(parsed.MAX_REGISTRATION_CHALLENGES_PER_ACCOUNT, 16);
  assert.equal(parsed.FIREBASE_SERVICE_ACCOUNT_JSON, undefined);
  assert.equal(parsed.GOOGLE_APPLICATION_CREDENTIALS, undefined);
  assert.equal(parsed.FIREBASE_PROJECT_ID, undefined);
  assert.equal(parsed.MAX_PENDING_MESSAGES_PER_PAIR, 100);
  assert.equal(parsed.CALL_MAX_FUTURE_SKEW_SECONDS, 15);
});

test("resource controls accept bounded overrides", () => {
  const parsed = parseTestConfig({
    DATABASE_POOL_MAX: "8",
    DATABASE_QUERY_TIMEOUT_MS: "20000",
    DATABASE_STATEMENT_TIMEOUT_MS: "15000",
    HTTP_REQUEST_TIMEOUT_MS: "25000",
    MAX_IN_FLIGHT_REQUESTS: "128",
    HTTP_MAX_CONNECTIONS: "1200",
    WEBSOCKET_MAX_CONNECTIONS: "900",
    PUSH_MAX_CONCURRENCY: "8",
    PUSH_MAX_QUEUED: "512",
    CALL_SIGNAL_TTL_SECONDS: "90",
    CALL_ACTIVE_LEASE_SECONDS: "180",
    MAX_REGISTRATION_CHALLENGES_PER_DEVICE: "8",
    MAX_REGISTRATION_CHALLENGES_PER_ACCOUNT: "24",
    MAX_PENDING_MESSAGES_PER_PAIR: "250",
    CLEANUP_BATCH_SIZE: "1000"
  });
  assert.equal(parsed.DATABASE_POOL_MAX, 8);
  assert.equal(parsed.DATABASE_QUERY_TIMEOUT_MS, 20_000);
  assert.equal(parsed.MAX_IN_FLIGHT_REQUESTS, 128);
  assert.equal(parsed.WEBSOCKET_MAX_CONNECTIONS, 900);
  assert.equal(parsed.PUSH_MAX_CONCURRENCY, 8);
  assert.equal(parsed.CALL_SIGNAL_TTL_SECONDS, 90);
  assert.equal(parsed.CALL_ACTIVE_LEASE_SECONDS, 180);
  assert.equal(parsed.MAX_REGISTRATION_CHALLENGES_PER_DEVICE, 8);
  assert.equal(parsed.MAX_REGISTRATION_CHALLENGES_PER_ACCOUNT, 24);
  assert.equal(parsed.MAX_PENDING_MESSAGES_PER_PAIR, 250);
  assert.equal(parsed.CLEANUP_BATCH_SIZE, 1_000);
});

test("unsafe resource relationships are rejected", () => {
  assert.throws(
    () => parseConfig({
      NODE_ENV: "test",
      DATABASE_URL: testDatabaseUrl,
      DATABASE_QUERY_TIMEOUT_MS: "5000",
      DATABASE_STATEMENT_TIMEOUT_MS: "6000"
    }),
    /DATABASE_QUERY_TIMEOUT_MS/
  );
  assert.throws(
    () => parseConfig({
      NODE_ENV: "test",
      DATABASE_URL: testDatabaseUrl,
      DATABASE_POOL_MAX: "16",
      MAX_IN_FLIGHT_REQUESTS: "8"
    }),
    /MAX_IN_FLIGHT_REQUESTS/
  );
  assert.throws(
    () => parseConfig({
      NODE_ENV: "test",
      DATABASE_URL: testDatabaseUrl,
      MAX_IN_FLIGHT_REQUESTS: "64",
      WEBSOCKET_MAX_CONNECTIONS: "512",
      HTTP_MAX_CONNECTIONS: "575"
    }),
    /HTTP_MAX_CONNECTIONS/
  );
  assert.throws(
    () => parseConfig({
      NODE_ENV: "test",
      DATABASE_URL: testDatabaseUrl,
      CALL_SIGNAL_TTL_SECONDS: "15",
      CALL_MAX_FUTURE_SKEW_SECONDS: "16"
    }),
    /CALL_MAX_FUTURE_SKEW_SECONDS/
  );
  assert.throws(
    () => parseConfig({
      NODE_ENV: "test",
      DATABASE_URL: testDatabaseUrl,
      MAX_MAILBOX_MESSAGES: "100",
      MAX_PENDING_MESSAGES_PER_PAIR: "101"
    }),
    /MAX_PENDING_MESSAGES_PER_PAIR/
  );
  assert.throws(
    () => parseTestConfig({ CALL_ACTIVE_LEASE_SECONDS: "301" }),
    /CALL_ACTIVE_LEASE_SECONDS/
  );
  assert.throws(
    () => parseTestConfig({ MAX_REGISTRATION_CHALLENGES_PER_DEVICE: "17" }),
    /MAX_REGISTRATION_CHALLENGES_PER_DEVICE/
  );
  assert.throws(
    () => parseTestConfig({ MAX_REGISTRATION_CHALLENGES_PER_ACCOUNT: "65" }),
    /MAX_REGISTRATION_CHALLENGES_PER_ACCOUNT/
  );
  assert.throws(
    () => parseTestConfig({ FIREBASE_SERVICE_ACCOUNT_JSON: "x".repeat(65_537) }),
    /FIREBASE_SERVICE_ACCOUNT_JSON/
  );
  assert.throws(
    () => parseTestConfig({ GOOGLE_APPLICATION_CREDENTIALS: "x".repeat(4_097) }),
    /GOOGLE_APPLICATION_CREDENTIALS/
  );
  assert.throws(
    () => parseTestConfig({ FIREBASE_PROJECT_ID: "Not a valid project id" }),
    /FIREBASE_PROJECT_ID/
  );
  assert.throws(
    () => parseTestConfig({ DATABASE_URL: "https://not-postgres.example" }),
    /PostgreSQL connection URL/
  );
});

test("production still rejects development credentials", () => {
  assert.throws(
    () => parseConfig(productionNeonEnvironment),
    /Production requires non-default LiveKit credentials/
  );
});

test("database URL is always explicit", () => {
  assert.throws(() => parseConfig({ NODE_ENV: "test" }), /DATABASE_URL/);
});

test("production accepts only a matching hardened Neon endpoint pair", () => {
  const liveKit = {
    LIVEKIT_API_KEY: "production-key",
    LIVEKIT_API_SECRET: "production-secret-at-least-32-characters"
  };
  assert.doesNotThrow(() => parseConfig({ ...productionNeonEnvironment, ...liveKit }));
  assert.throws(
    () => parseConfig({
      ...productionNeonEnvironment,
      ...liveKit,
      DATABASE_URL: testDatabaseUrl,
      DATABASE_MIGRATION_URL: testDatabaseUrl
    }),
    /official Neon pooled endpoint/
  );
  assert.throws(
    () => parseConfig({
      ...productionNeonEnvironment,
      ...liveKit,
      DATABASE_MIGRATION_URL: productionNeonEnvironment.DATABASE_URL
    }),
    /official Neon direct endpoint/
  );
});
