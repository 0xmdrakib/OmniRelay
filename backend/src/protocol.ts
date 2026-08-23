const HEADER_SIZE = 64;
const MAX_PAYLOAD_SIZE = 0xffff;
const PUBLIC_KEY_OFFSET = 12;
const PUBLIC_KEY_SIZE = 32;
const PAYLOAD_LENGTH_OFFSET = 60;
const PAYLOAD_TYPE_OFFSET = 62;
const RECIPIENT_PREFIX_SIZE = 8;

export const PayloadType = {
  TEXT: 0x01,
  VOICE: 0x02,
  HANDSHAKE: 0x03,
  CALL_RING: 0x04,
  CALL_ACCEPT: 0x05,
  CALL_DECLINE: 0x06,
  CALL_END: 0x07,
  PRESENCE: 0x08
} as const;

const knownPayloadTypes = new Set<number>(Object.values(PayloadType));
const strictBase64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export type ParsedOmniFrame = {
  bytes: Buffer;
  payloadType: number;
  senderPublicKey: Buffer;
  recipientPrefix: Buffer;
};

/** Validates only public framing metadata; encrypted content remains opaque. */
export function parseOmniFrame(frameBase64: string): ParsedOmniFrame {
  if (!strictBase64.test(frameBase64)) throw new Error("invalid_base64");
  const bytes = Buffer.from(frameBase64, "base64");
  if (bytes.length < HEADER_SIZE || bytes.length > HEADER_SIZE + MAX_PAYLOAD_SIZE) {
    throw new Error("invalid_frame_size");
  }
  const version = (bytes[0]! >>> 4) & 0x0f;
  if (version !== 1) throw new Error("unsupported_frame_version");
  const payloadLength = bytes.readUInt16BE(PAYLOAD_LENGTH_OFFSET);
  if (bytes.length !== HEADER_SIZE + payloadLength) throw new Error("payload_length_mismatch");
  const payloadType = bytes[PAYLOAD_TYPE_OFFSET]!;
  if (!knownPayloadTypes.has(payloadType)) throw new Error("unknown_payload_type");
  return {
    bytes,
    payloadType,
    senderPublicKey: bytes.subarray(PUBLIC_KEY_OFFSET, PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE),
    recipientPrefix: bytes.subarray(HEADER_SIZE, HEADER_SIZE + Math.min(payloadLength, RECIPIENT_PREFIX_SIZE))
  };
}

export function assertFrameBinding(
  frame: ParsedOmniFrame,
  senderPublicKeyBase64: string,
  recipientPublicKeyBase64: string,
  expectedPayloadType: number
): void {
  const senderPublicKey = Buffer.from(senderPublicKeyBase64, "base64");
  const recipientPublicKey = Buffer.from(recipientPublicKeyBase64, "base64");
  if (senderPublicKey.length !== PUBLIC_KEY_SIZE || !frame.senderPublicKey.equals(senderPublicKey)) {
    throw new Error("sender_key_mismatch");
  }
  if (frame.recipientPrefix.length !== RECIPIENT_PREFIX_SIZE ||
      !frame.recipientPrefix.equals(recipientPublicKey.subarray(0, RECIPIENT_PREFIX_SIZE))) {
    throw new Error("recipient_key_mismatch");
  }
  if (frame.payloadType !== expectedPayloadType) throw new Error("payload_type_mismatch");
}
