import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  HOST: z.string().default("0.0.0.0"),
  DATABASE_URL: z.string().min(1).default("postgres://omnirelay:omnirelay@localhost:5432/omnirelay"),
  DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(32).default(4),
  DATABASE_POOL_IDLE_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(300_000).default(30_000),
  DATABASE_CONNECTION_TIMEOUT_MS: z.coerce.number().int().min(250).max(30_000).default(5_000),
  DATABASE_QUERY_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(120_000).default(12_000),
  DATABASE_STATEMENT_TIMEOUT_MS: z.coerce.number().int().min(500).max(120_000).default(10_000),
  DATABASE_POOL_MAX_USES: z.coerce.number().int().min(100).max(100_000).default(5_000),
  LIVEKIT_URL: z.string().url().default("ws://localhost:7880"),
  LIVEKIT_API_KEY: z.string().min(3).default("devkey"),
  LIVEKIT_API_SECRET: z.string().min(32).default("devsecret-change-me-at-least-32-bytes"),
  TRUST_PROXY: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  FIREBASE_SERVICE_ACCOUNT_JSON: z.string().optional(),
  MESSAGE_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(30),
  CALL_SIGNAL_TTL_SECONDS: z.coerce.number().int().min(15).max(300).default(60),
  CALL_MAX_FUTURE_SKEW_SECONDS: z.coerce.number().int().min(0).max(60).default(15),
  CALL_ACTIVE_LEASE_SECONDS: z.coerce.number().int().min(30).max(300).default(120),
  MAX_REGISTRATION_CHALLENGES_PER_DEVICE: z.coerce.number().int().min(1).max(16).default(4),
  MAX_MAILBOX_MESSAGES: z.coerce.number().int().min(100).max(100_000).default(10_000),
  MAX_PENDING_MESSAGES_PER_PAIR: z.coerce.number().int().min(10).max(10_000).default(100),
  HTTP_REQUEST_TIMEOUT_MS: z.coerce.number().int().min(2_000).max(120_000).default(15_000),
  MAX_IN_FLIGHT_REQUESTS: z.coerce.number().int().min(8).max(4_096).default(64),
  HTTP_MAX_CONNECTIONS: z.coerce.number().int().min(16).max(100_000).default(768),
  WEBSOCKET_MAX_CONNECTIONS: z.coerce.number().int().min(1).max(50_000).default(512),
  PUSH_MAX_CONCURRENCY: z.coerce.number().int().min(1).max(32).default(4),
  PUSH_MAX_QUEUED: z.coerce.number().int().min(0).max(10_000).default(256),
  SHUTDOWN_TIMEOUT_MS: z.coerce.number().int().min(5_000).max(120_000).default(25_000),
  CLEANUP_INTERVAL_SECONDS: z.coerce.number().int().min(60).max(86_400).default(900),
  CLEANUP_BATCH_SIZE: z.coerce.number().int().min(10).max(10_000).default(500)
});

export type AppConfig = z.infer<typeof schema>;

export function parseConfig(environment: NodeJS.ProcessEnv): AppConfig {
  const parsed = schema.parse(environment);
  if (parsed.DATABASE_QUERY_TIMEOUT_MS < parsed.DATABASE_STATEMENT_TIMEOUT_MS) {
    throw new Error("DATABASE_QUERY_TIMEOUT_MS must be greater than or equal to DATABASE_STATEMENT_TIMEOUT_MS");
  }
  if (parsed.HTTP_REQUEST_TIMEOUT_MS < parsed.DATABASE_QUERY_TIMEOUT_MS) {
    throw new Error("HTTP_REQUEST_TIMEOUT_MS must be greater than or equal to DATABASE_QUERY_TIMEOUT_MS");
  }
  if (parsed.MAX_IN_FLIGHT_REQUESTS < parsed.DATABASE_POOL_MAX) {
    throw new Error("MAX_IN_FLIGHT_REQUESTS must be greater than or equal to DATABASE_POOL_MAX");
  }
  if (parsed.HTTP_MAX_CONNECTIONS < parsed.WEBSOCKET_MAX_CONNECTIONS + parsed.MAX_IN_FLIGHT_REQUESTS) {
    throw new Error(
      "HTTP_MAX_CONNECTIONS must reserve room for WEBSOCKET_MAX_CONNECTIONS and MAX_IN_FLIGHT_REQUESTS"
    );
  }
  if (parsed.CALL_MAX_FUTURE_SKEW_SECONDS > parsed.CALL_SIGNAL_TTL_SECONDS) {
    throw new Error("CALL_MAX_FUTURE_SKEW_SECONDS must not exceed CALL_SIGNAL_TTL_SECONDS");
  }
  if (parsed.MAX_PENDING_MESSAGES_PER_PAIR > parsed.MAX_MAILBOX_MESSAGES) {
    throw new Error("MAX_PENDING_MESSAGES_PER_PAIR must not exceed MAX_MAILBOX_MESSAGES");
  }
  if (parsed.NODE_ENV === "production") {
    if (parsed.LIVEKIT_API_KEY === "devkey" || parsed.LIVEKIT_API_SECRET.startsWith("devsecret-")) {
      throw new Error("Production requires non-default LiveKit credentials");
    }
    if (parsed.DATABASE_URL.includes("omnirelay:omnirelay@localhost")) {
      throw new Error("Production requires an explicit database password and URL");
    }
  }
  return parsed;
}

export const config: AppConfig = parseConfig(process.env);
