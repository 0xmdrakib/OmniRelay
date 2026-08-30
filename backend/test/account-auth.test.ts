import assert from "node:assert/strict";
import test from "node:test";
import {
  AccountTokenVerificationError,
  createAccountTokenVerifier,
  isValidAccountUid,
  MAX_ACCOUNT_UID_LENGTH
} from "../src/account-auth.js";

test("Firebase account UIDs are bounded without normalization", () => {
  assert.equal(isValidAccountUid("firebase-uid-123"), true);
  assert.equal(isValidAccountUid("ü".repeat(MAX_ACCOUNT_UID_LENGTH)), true);
  assert.equal(isValidAccountUid(""), false);
  assert.equal(isValidAccountUid("x".repeat(MAX_ACCOUNT_UID_LENGTH + 1)), false);
  assert.equal(isValidAccountUid("uid\0suffix"), false);
  assert.equal(isValidAccountUid(null), false);
});

test("missing Firebase Admin configuration fails account verification closed", async () => {
  const verifier = createAccountTokenVerifier(undefined);
  assert.equal(verifier.configured, false);
  await assert.rejects(
    verifier.verifyIdToken("a-token-that-must-never-be-accepted"),
    AccountTokenVerificationError
  );
});
