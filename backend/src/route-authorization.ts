import { createHash, timingSafeEqual } from "node:crypto";

export const DEVICE_ID_PATTERN = /^[0-9a-f]{64}$/;
export const ROUTE_TOKEN_BYTES = 32;
export const ROUTE_TOKEN_HASH_BYTES = 32;
export const MAX_INBOUND_ROUTES = 512;

const canonicalBase64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function decodeCanonicalBase64(value: string, expectedBytes: number, label = "value"): Buffer {
  if (!Number.isInteger(expectedBytes) || expectedBytes < 1) {
    throw new Error("expectedBytes must be a positive integer");
  }
  if (!canonicalBase64Pattern.test(value)) throw new Error(`${label} must use canonical base64`);
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== expectedBytes || decoded.toString("base64") !== value) {
    decoded.fill(0);
    throw new Error(`${label} must be canonical base64 for exactly ${expectedBytes} bytes`);
  }
  return decoded;
}

export function isCanonicalBase64(value: string, expectedBytes: number): boolean {
  try {
    const decoded = decodeCanonicalBase64(value, expectedBytes);
    decoded.fill(0);
    return true;
  } catch {
    return false;
  }
}

export function isCanonicalDeviceId(value: string): boolean {
  return DEVICE_ID_PATTERN.test(value);
}

/** Hashes a raw route token for lookup and clears the temporary decoded bytes. */
export function hashRouteTokenBase64(routeTokenBase64: string): Buffer {
  const token = decodeCanonicalBase64(routeTokenBase64, ROUTE_TOKEN_BYTES, "route token");
  try {
    return createHash("sha256").update(token).digest();
  } finally {
    token.fill(0);
  }
}

export function decodeRouteTokenHashBase64(routeTokenHashBase64: string): Buffer {
  return decodeCanonicalBase64(routeTokenHashBase64, ROUTE_TOKEN_HASH_BYTES, "route token hash");
}

export function routeTokenHashMatches(expectedHash: Buffer, presentedHash: Buffer): boolean {
  return expectedHash.length === ROUTE_TOKEN_HASH_BYTES &&
    presentedHash.length === ROUTE_TOKEN_HASH_BYTES &&
    timingSafeEqual(expectedHash, presentedHash);
}
