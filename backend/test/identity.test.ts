import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  deviceIdForPublicKey,
  hashToken,
  issueDeviceToken,
  registrationProof,
  tokenMatches,
  verifyRegistrationSignature
} from "../src/identity.js";

test("device IDs are stable SHA-256 identifiers for raw X25519 keys", () => {
  const key = Buffer.alloc(32, 7).toString("base64");
  assert.equal(deviceIdForPublicKey(key), deviceIdForPublicKey(key));
  assert.equal(deviceIdForPublicKey(key).length, 64);
});

test("registration tokens are random and constant-time comparable", () => {
  const first = issueDeviceToken();
  const second = issueDeviceToken();
  assert.notEqual(first, second);
  assert.equal(tokenMatches(first, hashToken(first)), true);
  assert.equal(tokenMatches(second, hashToken(first)), false);
});

test("malformed public keys are rejected", () => {
  assert.throws(() => deviceIdForPublicKey(Buffer.alloc(31).toString("base64")));
});

test("registration proof requires the matching Ed25519 private key", () => {
  const pair = generateKeyPairSync("ed25519");
  const attacker = generateKeyPairSync("ed25519");
  const deviceId = "a".repeat(64);
  const nonce = Buffer.alloc(32, 9).toString("base64");
  const signature = sign(null, registrationProof(deviceId, nonce), pair.privateKey).toString("base64");
  const publicDer = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const attackerDer = attacker.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  assert.equal(verifyRegistrationSignature(publicDer, deviceId, nonce, signature), true);
  assert.equal(verifyRegistrationSignature(attackerDer, deviceId, nonce, signature), false);
});
