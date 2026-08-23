import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  HOST: z.string().default("0.0.0.0"),
  DATABASE_URL: z.string().min(1).default("postgres://omnirelay:omnirelay@localhost:5432/omnirelay"),
  LIVEKIT_URL: z.string().url().default("ws://localhost:7880"),
  LIVEKIT_API_KEY: z.string().min(3).default("devkey"),
  LIVEKIT_API_SECRET: z.string().min(32).default("devsecret-change-me-at-least-32-bytes"),
  TRUST_PROXY: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  FIREBASE_SERVICE_ACCOUNT_JSON: z.string().optional(),
  MESSAGE_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(30),
  MAX_MAILBOX_MESSAGES: z.coerce.number().int().min(100).max(100000).default(10000)
});

export type AppConfig = z.infer<typeof schema>;
const parsed = schema.parse(process.env);
if (parsed.NODE_ENV === "production") {
  if (parsed.LIVEKIT_API_KEY === "devkey" || parsed.LIVEKIT_API_SECRET.startsWith("devsecret-")) {
    throw new Error("Production requires non-default LiveKit credentials");
  }
  if (parsed.DATABASE_URL.includes("omnirelay:omnirelay@localhost")) {
    throw new Error("Production requires an explicit database password and URL");
  }
}
export const config: AppConfig = parsed;
