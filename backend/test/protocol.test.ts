import assert from "node:assert/strict";
import test from "node:test";
import { assertFrameBinding, parseOmniFrame, PayloadType } from "../src/protocol.js";

function validFrame(): { encoded: string; sender: string; recipient: string } {
  const senderBytes = Buffer.alloc(32, 0x11);
  const recipientBytes = Buffer.alloc(32, 0x22);
  const payload = recipientBytes.subarray(0, 8);
  const bytes = Buffer.alloc(64 + payload.length);
  bytes[0] = 0x1f;
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

test("malformed base64, versions and payload lengths are rejected", () => {
  const candidate = validFrame();
  assert.throws(() => parseOmniFrame(`${candidate.encoded}\n`));

  const wrongVersion = Buffer.from(candidate.encoded, "base64");
  wrongVersion[0] = 0x2f;
  assert.throws(() => parseOmniFrame(wrongVersion.toString("base64")));

  const wrongLength = Buffer.from(candidate.encoded, "base64");
  wrongLength.writeUInt16BE(9, 60);
  assert.throws(() => parseOmniFrame(wrongLength.toString("base64")));
});
