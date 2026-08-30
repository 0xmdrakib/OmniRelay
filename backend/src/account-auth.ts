import type { App } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getOrCreateFirebaseAdminApp } from "./firebase-admin.js";

export const MAX_ACCOUNT_UID_LENGTH = 128;
export const MAX_FIREBASE_ID_TOKEN_LENGTH = 16_384;

export function isValidAccountUid(value: unknown): value is string {
  return typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_ACCOUNT_UID_LENGTH &&
    !value.includes("\0");
}

export class AccountTokenVerificationError extends Error {
  constructor() {
    super("Account token verification failed");
    this.name = "AccountTokenVerificationError";
  }
}

export interface AccountTokenVerifier {
  readonly configured: boolean;
  verifyIdToken(token: string): Promise<string>;
}

class RejectingAccountTokenVerifier implements AccountTokenVerifier {
  readonly configured = false;

  async verifyIdToken(): Promise<string> {
    throw new AccountTokenVerificationError();
  }
}

class FirebaseAccountTokenVerifier implements AccountTokenVerifier {
  readonly configured = true;

  constructor(private readonly app: App) {}

  async verifyIdToken(token: string): Promise<string> {
    if (token.length < 1 || token.length > MAX_FIREBASE_ID_TOKEN_LENGTH) {
      throw new AccountTokenVerificationError();
    }
    try {
      const decoded = await getAuth(this.app).verifyIdToken(token, true);
      if (!isValidAccountUid(decoded.uid)) throw new AccountTokenVerificationError();
      return decoded.uid;
    } catch {
      // Firebase errors are deliberately collapsed so callers cannot leak token details.
      throw new AccountTokenVerificationError();
    }
  }
}

/** Missing Admin configuration always yields a rejecting verifier, including in production. */
export function createAccountTokenVerifier(serviceAccountJson?: string): AccountTokenVerifier {
  const app = getOrCreateFirebaseAdminApp(serviceAccountJson);
  return app ? new FirebaseAccountTokenVerifier(app) : new RejectingAccountTokenVerifier();
}
