import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from "node:crypto";

export function decodePublicKey(publicKeyBase64: string): Buffer {
  const key = Buffer.from(publicKeyBase64, "base64");
  if (key.length !== 32) throw new Error("publicKey must be a raw 32-byte X25519 key");
  return key;
}

export function deviceIdForPublicKey(publicKeyBase64: string): string {
  return createHash("sha256").update(decodePublicKey(publicKeyBase64)).digest("hex");
}

export function issueDeviceToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashToken(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

export function tokenMatches(token: string, expectedHash: Buffer): boolean {
  const actual = hashToken(token);
  return actual.length === expectedHash.length && timingSafeEqual(actual, expectedHash);
}

export function registrationProof(deviceId: string, nonceBase64: string): Buffer {
  return Buffer.from(`OmniRelay/Register/v1\n${deviceId}\n${nonceBase64}`, "utf8");
}

export function verifyRegistrationSignature(
  signingPublicKeyBase64: string,
  deviceId: string,
  nonceBase64: string,
  signatureBase64: string
): boolean {
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(signingPublicKeyBase64, "base64"),
      format: "der",
      type: "spki"
    });
    return verify(null, registrationProof(deviceId, nonceBase64), publicKey, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}
