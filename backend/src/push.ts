import type { App } from "firebase-admin/app";
import { getMessaging } from "firebase-admin/messaging";
import { getOrCreateFirebaseAdminApp } from "./firebase-admin.js";

export interface PushGateway {
  readonly enabled: boolean;
  sendWake(token: string, envelopeId: string, kind: "message" | "call"): Promise<void>;
}

export class InvalidPushTokenError extends Error {
  constructor() {
    super("Push target is no longer valid");
    this.name = "InvalidPushTokenError";
  }
}

class DisabledPushGateway implements PushGateway {
  readonly enabled = false;

  async sendWake(): Promise<void> {
    // Existing device sessions can still poll while valid; new account-bound
    // registrations fail closed when the shared Firebase Admin app is absent.
  }
}

class FirebasePushGateway implements PushGateway {
  readonly enabled = true;

  constructor(private readonly app: App) {}

  async sendWake(token: string, envelopeId: string, kind: "message" | "call"): Promise<void> {
    try {
      await getMessaging(this.app).send({
        token,
        data: { type: "mailbox_changed", envelope_id: envelopeId, kind },
        android: {
          priority: "high",
          ttl: kind === "call" ? 60_000 : 24 * 60 * 60 * 1000
        }
      });
    } catch (error) {
      const code = (error as { code?: unknown })?.code;
      if (code === "messaging/registration-token-not-registered" ||
          code === "messaging/invalid-registration-token") {
        throw new InvalidPushTokenError();
      }
      throw error;
    }
  }
}

export function createPushGateway(serviceAccountJson?: string): PushGateway {
  const app = getOrCreateFirebaseAdminApp(serviceAccountJson);
  return app ? new FirebasePushGateway(app) : new DisabledPushGateway();
}
