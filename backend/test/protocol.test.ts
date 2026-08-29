import assert from "node:assert/strict";
import test from "node:test";
import {
  assertFrameBinding,
  frameAgeMilliseconds,
  parseOmniFrame,
  PayloadType,
  remainingFrameLifetimeSeconds
} from "../src/protocol.js";

function validFrame(): { encoded: string; sender: string; recipient: string } {
  const senderBytes = Buffer.alloc(32, 0x11);
  const recipientBytes = Buffer.alloc(32, 0x22);
  const payload = recipientBytes.subarray(0, 8);
  const bytes = Buffer.alloc(64 + payload.length);
  bytes[0] = 0x2f;
  bytes.writeUInt32BE(Date.now() >>> 0, 8);
  senderBytes.copy(bytes, 12);
  bytes.writeUInt16BE(payload.length, 60);
  bytes[62] = PayloadType.TEXT;
  payload.copy(bytes, 64);
  return {
    encoded: bytes.toString("base64"),
    sender: senderBytes.toString("base64"),
    recipient: recipientBytes.toString("base64")
  };
}

test("strict OmniFrame validation binds sender, recipient and payload type", () => {
  const candidate = validFrame();
  const parsed = parseOmniFrame(candidate.encoded);
  assert.doesNotThrow(() => assertFrameBinding(parsed, candidate.sender, candidate.recipient, PayloadType.TEXT));
  assert.throws(() => assertFrameBinding(parsed, Buffer.alloc(32).toString("base64"), candidate.recipient, PayloadType.TEXT));
  assert.throws(() => assertFrameBinding(parsed, candidate.sender, Buffer.alloc(32).toString("base64"), PayloadType.TEXT));
  assert.throws(() => assertFrameBinding(parsed, candidate.sender, candidate.recipient, PayloadType.CALL_RING));
});

test("call freshness is bounded, clock-skew tolerant and wrap-safe", () => {
  const modulus = 0x1_0000_0000;
  const now = modulus + 1_000;
  const timestamp = (now - 500) % modulus;
  assert.equal(frameAgeMilliseconds(timestamp, now), 500);
  assert.equal(remainingFrameLifetimeSeconds(timestamp, 60, 15, now), 60);

  const ordinaryNow = 1_800_000_000_000;
  const low32 = (value: number) => value % modulus;
  assert.equal(remainingFrameLifetimeSeconds(low32(ordinaryNow - 1_500), 60, 15, ordinaryNow), 59);
  assert.equal(remainingFrameLifetimeSeconds(low32(ordinaryNow - 60_000), 60, 15, ordinaryNow), null);
  assert.equal(remainingFrameLifetimeSeconds(low32(ordinaryNow + 15_000), 60, 15, ordinaryNow), 60);
  assert.equal(remainingFrameLifetimeSeconds(low32(ordinaryNow + 15_001), 60, 15, ordinaryNow), null);
});

test("malformed base64, versions and payload lengths are rejected", () => {
  const candidate = validFrame();
  assert.throws(() => parseOmniFrame(`${candidate.encoded}\n`));

  const wrongVersion = Buffer.from(candidate.encoded, "base64");
  wrongVersion[0] = 0x1f;
  assert.throws(() => parseOmniFrame(wrongVersion.toString("base64")));

  const wrongLength = Buffer.from(candidate.encoded, "base64");
  wrongLength.writeUInt16BE(9, 60);
  assert.throws(() => parseOmniFrame(wrongLength.toString("base64")));
});
