import { cert, getApps, initializeApp } from "firebase-admin/app";
import { getMessaging } from "firebase-admin/messaging";

export interface PushGateway {
  sendWake(token: string, envelopeId: string, kind: "message" | "call"): Promise<void>;
}

export class InvalidPushTokenError extends Error {
  constructor() {
    super("Push target is no longer valid");
    this.name = "InvalidPushTokenError";
  }
}

class DisabledPushGateway implements PushGateway {
  async sendWake(): Promise<void> {
    // WebSocket and mailbox polling remain fully functional without Firebase.
  }
}

class FirebasePushGateway implements PushGateway {
  constructor(serviceAccountJson: string) {
    if (getApps().length === 0) {
      const serviceAccount = JSON.parse(serviceAccountJson);
      initializeApp({ credential: cert(serviceAccount) });
    }
  }

  async sendWake(token: string, envelopeId: string, kind: "message" | "call"): Promise<void> {
    try {
      await getMessaging().send({
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
  return serviceAccountJson ? new FirebasePushGateway(serviceAccountJson) : new DisabledPushGateway();
}
