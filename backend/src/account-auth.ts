import type { App } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getOrCreateFirebaseAdminApp } from "./firebase-admin.js";

export const MAX_ACCOUNT_UID_LENGTH = 128;
export const MAX_FIREBASE_ID_TOKEN_LENGTH = 16_384;
export const MAX_ACCOUNT_EMAIL_LENGTH = 320;

export type VerifiedAccount = {
  uid: string;
  email: string;
};

export function isValidAccountUid(value: unknown): value is string {
  return typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_ACCOUNT_UID_LENGTH &&
    !value.includes("\0");
}

export function normalizeVerifiedEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > MAX_ACCOUNT_EMAIL_LENGTH ||
      normalized.includes("\0") || !normalized.includes("@")) return null;
  return normalized;
}

export class AccountTokenVerificationError extends Error {
  constructor() {
    super("Account token verification failed");
    this.name = "AccountTokenVerificationError";
  }
}

export interface AccountTokenVerifier {
  readonly configured: boolean;
  verifyIdToken(token: string): Promise<VerifiedAccount>;
}

class RejectingAccountTokenVerifier implements AccountTokenVerifier {
  readonly configured = false;

  async verifyIdToken(): Promise<VerifiedAccount> {
    throw new AccountTokenVerificationError();
  }
}

class FirebaseAccountTokenVerifier implements AccountTokenVerifier {
  readonly configured = true;

  constructor(private readonly app: App) {}

  async verifyIdToken(token: string): Promise<VerifiedAccount> {
    if (token.length < 1 || token.length > MAX_FIREBASE_ID_TOKEN_LENGTH) {
      throw new AccountTokenVerificationError();
    }
    try {
      const decoded = await getAuth(this.app).verifyIdToken(token, true);
      const email = decoded.email_verified === true
        ? normalizeVerifiedEmail(decoded.email)
        : null;
      if (!isValidAccountUid(decoded.uid) || !email) throw new AccountTokenVerificationError();
      return { uid: decoded.uid, email };
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
