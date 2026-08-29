import assert from "node:assert/strict";
import test from "node:test";
import { createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, sign } from "node:crypto";
import {
  createX25519RegistrationChallenge,
  deviceIdForPublicKey,
  hashToken,
  issueDeviceToken,
  registrationProof,
  registrationX25519Proof,
  tokenMatches,
  verifyRegistrationSignature,
  x25519RegistrationProofMatches
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

test("relay registration additionally proves possession of the X25519 private key", () => {
  const device = generateKeyPairSync("x25519");
  const attacker = generateKeyPairSync("x25519");
  const rawPublic = (device.publicKey.export({ format: "jwk" }).x);
  assert.ok(rawPublic);
  const publicKeyBase64 = Buffer.from(rawPublic, "base64url").toString("base64");
  const deviceId = deviceIdForPublicKey(publicKeyBase64);
  const nonce = Buffer.alloc(32, 3).toString("base64");
  const signingPublic = Buffer.alloc(44, 4).toString("base64");
  const challenge = createX25519RegistrationChallenge(
    publicKeyBase64,
    deviceId,
    nonce,
    signingPublic
  );
  const serverPublic = createPublicKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      x: Buffer.from(challenge.serverEphemeralPublicKeyBase64, "base64").toString("base64url")
    },
    format: "jwk"
  });
  const derivePairSecret = (privateKey: typeof device.privateKey) => Buffer.from(hkdfSync(
    "sha256",
    diffieHellman({ privateKey, publicKey: serverPublic }),
    Buffer.alloc(32),
    Buffer.from("OmniRelay/X25519/AES-256-GCM/v1", "utf8"),
    32
  ));
  const legitimate = registrationX25519Proof(
    derivePairSecret(device.privateKey),
    deviceId,
    nonce,
    signingPublic
  ).toString("base64");
  const forged = registrationX25519Proof(
    derivePairSecret(attacker.privateKey),
    deviceId,
    nonce,
    signingPublic
  ).toString("base64");

  assert.equal(x25519RegistrationProofMatches(challenge.expectedProofBase64, legitimate), true);
  assert.equal(x25519RegistrationProofMatches(challenge.expectedProofBase64, forged), false);
});

test("registration proof matches the shared Android RFC 7748 vector", () => {
  const pairSharedSecret = Buffer.from(
    "16ae601d94730e7b0322af739e023360d9591cb220aeee08dded040daadc8cbc",
    "hex"
  );
  const proof = registrationX25519Proof(
    pairSharedSecret,
    "300c9c9603b92a4b39ed3958bf9240114804db4fd373012c0ca47432d63425ae",
    "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
    "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="
  );
  assert.equal(
    proof.toString("hex"),
    "f1c18162243627d49a07b0b517b319c7307834eaa356d5e53ed7156451570345"
  );
});
