import {
  applicationDefault,
  cert,
  getApps,
  initializeApp,
  type App,
  type ServiceAccount
} from "firebase-admin/app";

const MAX_SERVICE_ACCOUNT_JSON_LENGTH = 65_536;

function serviceAccountFromJson(serviceAccountJson: string): ServiceAccount {
  if (serviceAccountJson.length > MAX_SERVICE_ACCOUNT_JSON_LENGTH) {
    throw new Error("Invalid Firebase Admin service account configuration");
  }
  try {
    const value = JSON.parse(serviceAccountJson) as Record<string, unknown>;
    const projectId = value.project_id ?? value.projectId;
    const clientEmail = value.client_email ?? value.clientEmail;
    const privateKey = value.private_key ?? value.privateKey;
    if (typeof projectId !== "string" || projectId.length < 1 || projectId.length > 256 ||
        typeof clientEmail !== "string" || clientEmail.length < 3 || clientEmail.length > 512 ||
        typeof privateKey !== "string" || privateKey.length < 64 || privateKey.length > 32_768) {
      throw new Error("invalid service account fields");
    }
    return { projectId, clientEmail, privateKey };
  } catch {
    // Do not attach the parse error: Firebase configuration can contain private key material.
    throw new Error("Invalid Firebase Admin service account configuration");
  }
}

/**
 * Returns the process-wide Firebase Admin app. Both authentication and push use
 * this function so a service account is parsed and initialized at most once.
 */
export function getOrCreateFirebaseAdminApp(serviceAccountJson?: string): App | null {
  const existing = getApps()[0];
  if (existing) return existing;
  const applicationCredentialsPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (!serviceAccountJson && !applicationCredentialsPath) return null;
  try {
    return initializeApp({
      credential: serviceAccountJson
        ? cert(serviceAccountFromJson(serviceAccountJson))
        : applicationDefault(),
      projectId: process.env.FIREBASE_PROJECT_ID
    });
  } catch {
    throw new Error("Invalid Firebase Admin service account configuration");
  }
}
