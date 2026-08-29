import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import test from "node:test";
import {
  decodeCanonicalBase64,
  decodeRouteTokenHashBase64,
  hashRouteTokenBase64,
  isCanonicalBase64,
  isCanonicalDeviceId,
  routeTokenHashMatches
} from "../src/route-authorization.js";

test("route tokens and hashes require canonical standard base64 for exactly 32 bytes", () => {
  const bytes = Buffer.alloc(32, 0xfb);
  const canonical = bytes.toString("base64");
  assert.equal(isCanonicalBase64(canonical, 32), true);
  assert.deepEqual(decodeCanonicalBase64(canonical, 32), bytes);
  assert.deepEqual(decodeRouteTokenHashBase64(canonical), bytes);

  assert.equal(isCanonicalBase64(canonical.replace(/\+/g, "-").replace(/\//g, "_"), 32), false);
  assert.equal(isCanonicalBase64(canonical.slice(0, -1), 32), false);
  assert.equal(isCanonicalBase64(Buffer.alloc(31).toString("base64"), 32), false);
  assert.equal(isCanonicalBase64("A".repeat(42) + "B=", 32), false);
});

test("route token hashing is SHA-256 and never aliases malformed encodings", () => {
  const raw = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  const encoded = raw.toString("base64");
  assert.deepEqual(hashRouteTokenBase64(encoded), createHash("sha256").update(raw).digest());
  assert.throws(() => hashRouteTokenBase64(encoded.slice(0, -1)), /canonical base64/);
});

test("backend route-token wire contract matches the Android HMAC-SHA256 vector", () => {
  const pairSharedSecret = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  const senderPublicKey = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 32));
  const recipientPublicKey = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 64));
  const routeToken = createHmac("sha256", pairSharedSecret.subarray(0, 32))
    .update(Buffer.from("OmniRelay/Backend-Route/v1\0", "utf8"))
    .update(senderPublicKey)
    .update(recipientPublicKey)
    .digest();

  assert.equal(routeToken.toString("hex"), "7dd82dddd93c7dde1962c2fb68a48e10f7e802b85df6cbf51de6bc0badbdeec1");
  assert.equal(routeToken.toString("base64"), "fdgt3dk8fd4ZYsL7aKSOEPfoArhd9sv1Hea8C6297sE=");
  assert.equal(
    hashRouteTokenBase64(routeToken.toString("base64")).toString("hex"),
    "266ff8c024899c1c0e861adedd405907b4ae71b939762b0e3622f7be38d1fca4"
  );
});

test("device IDs are canonical lowercase SHA-256 hex", () => {
  assert.equal(isCanonicalDeviceId("a".repeat(64)), true);
  assert.equal(isCanonicalDeviceId("A".repeat(64)), false);
  assert.equal(isCanonicalDeviceId("a".repeat(63)), false);
  assert.equal(isCanonicalDeviceId("g".repeat(64)), false);
});

test("stored route-token hashes compare only as fixed 32-byte digests", () => {
  const expected = Buffer.alloc(32, 7);
  assert.equal(routeTokenHashMatches(expected, Buffer.alloc(32, 7)), true);
  assert.equal(routeTokenHashMatches(expected, Buffer.alloc(32, 8)), false);
  assert.equal(routeTokenHashMatches(expected, Buffer.alloc(31, 7)), false);
});
