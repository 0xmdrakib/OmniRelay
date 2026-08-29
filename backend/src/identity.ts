import {
  createHash,
  createHmac,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
  verify
} from "node:crypto";
import { decodeCanonicalBase64, isCanonicalDeviceId } from "./route-authorization.js";

const pairHkdfInfo = Buffer.from("OmniRelay/X25519/AES-256-GCM/v1", "utf8");
const registrationX25519Domain = Buffer.from("OmniRelay/Register-X25519/v2\0", "utf8");

export function decodePublicKey(publicKeyBase64: string): Buffer {
  return decodeCanonicalBase64(publicKeyBase64, 32, "publicKey");
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
  if (!isCanonicalDeviceId(deviceId)) throw new Error("deviceId must be lowercase SHA-256 hex");
  const nonce = decodeCanonicalBase64(nonceBase64, 32, "registration nonce");
  nonce.fill(0);
  return Buffer.from(`OmniRelay/Register/v2\n${deviceId}\n${nonceBase64}`, "utf8");
}

export type X25519RegistrationChallenge = {
  serverEphemeralPublicKeyBase64: string;
  expectedProofBase64: string;
};

export function createX25519RegistrationChallenge(
  clientPublicKeyBase64: string,
  deviceId: string,
  nonceBase64: string,
  signingPublicKeyBase64: string
): X25519RegistrationChallenge {
  const clientRaw = decodePublicKey(clientPublicKeyBase64);
  const signingPublic = decodeCanonicalBase64(signingPublicKeyBase64, 44, "signing public key");
  signingPublic.fill(0);
  const clientPublicKey = createPublicKey({
    key: { kty: "OKP", crv: "X25519", x: clientRaw.toString("base64url") },
    format: "jwk"
  });
  const server = generateKeyPairSync("x25519");
  const rawSharedSecret = diffieHellman({ privateKey: server.privateKey, publicKey: clientPublicKey });
  const pairSharedSecret = Buffer.from(
    hkdfSync("sha256", rawSharedSecret, Buffer.alloc(32), pairHkdfInfo, 32)
  );
  const expectedProof = registrationX25519Proof(
    pairSharedSecret,
    deviceId,
    nonceBase64,
    signingPublicKeyBase64
  );
  const publicJwk = server.publicKey.export({ format: "jwk" });
  if (!publicJwk.x) throw new Error("server X25519 key is missing raw public material");
  return {
    serverEphemeralPublicKeyBase64: Buffer.from(publicJwk.x, "base64url").toString("base64"),
    expectedProofBase64: expectedProof.toString("base64")
  };
}

export function registrationX25519Proof(
  pairSharedSecret: Buffer,
  deviceId: string,
  nonceBase64: string,
  signingPublicKeyBase64: string
): Buffer {
  if (pairSharedSecret.length !== 32) throw new Error("pair shared secret must be 32 bytes");
  if (!isCanonicalDeviceId(deviceId)) throw new Error("deviceId must be lowercase SHA-256 hex");
  const nonce = decodeCanonicalBase64(nonceBase64, 32, "registration nonce");
  const signingPublic = decodeCanonicalBase64(signingPublicKeyBase64, 44, "signing public key");
  nonce.fill(0);
  signingPublic.fill(0);
  return createHmac("sha256", pairSharedSecret)
    .update(registrationX25519Domain)
    .update(deviceId, "utf8")
    .update("\0", "utf8")
    .update(nonceBase64, "utf8")
    .update("\0", "utf8")
    .update(signingPublicKeyBase64, "utf8")
    .digest();
}

export function x25519RegistrationProofMatches(expectedBase64: string, suppliedBase64: string): boolean {
  try {
    const expected = decodeCanonicalBase64(expectedBase64, 32, "expected registration proof");
    const supplied = decodeCanonicalBase64(suppliedBase64, 32, "registration proof");
    return timingSafeEqual(expected, supplied);
  } catch {
    return false;
  }
}

export function verifyRegistrationSignature(
  signingPublicKeyBase64: string,
  deviceId: string,
  nonceBase64: string,
  signatureBase64: string
): boolean {
  try {
    const signingPublicKey = decodeCanonicalBase64(signingPublicKeyBase64, 44, "signing public key");
    const signature = decodeCanonicalBase64(signatureBase64, 64, "registration signature");
    const publicKey = createPublicKey({
      key: signingPublicKey,
      format: "der",
      type: "spki"
    });
    if (publicKey.asymmetricKeyType !== "ed25519") return false;
    return verify(null, registrationProof(deviceId, nonceBase64), publicKey, signature);
  } catch {
    return false;
  }
}
