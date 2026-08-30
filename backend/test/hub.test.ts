import assert from "node:assert/strict";
import test from "node:test";
import type WebSocket from "ws";
import { RealtimeHub } from "../src/hub.js";

class FakeSocket {
  readonly OPEN = 1;
  readyState = 1;
  bufferedAmount = 0;
  readonly sent: string[] = [];
  readonly closed: Array<{ code: number; reason: string }> = [];
  terminated = false;

  send(message: string): void {
    this.sent.push(message);
  }

  close(code: number, reason: string): void {
    this.readyState = 3;
    this.closed.push({ code, reason });
  }

  terminate(): void {
    this.terminated = true;
    this.readyState = 3;
  }
}

const socket = () => new FakeSocket();
const asWebSocket = (value: FakeSocket) => value as unknown as WebSocket;

test("hub caps total sockets and releases capacity exactly once", () => {
  const hub = new RealtimeHub(2, 2, 64);
  const first = socket();
  const second = socket();
  const rejected = socket();
  assert.equal(hub.add("a", asWebSocket(first)), true);
  assert.equal(hub.add("b", asWebSocket(second)), true);
  assert.equal(hub.add("c", asWebSocket(rejected)), false);
  assert.equal(hub.size(), 2);
  assert.equal(rejected.closed[0]?.code, 1013);

  hub.remove("a", asWebSocket(first));
  hub.remove("a", asWebSocket(first));
  assert.equal(hub.size(), 1);
  assert.equal(hub.add("c", asWebSocket(socket())), true);
  assert.equal(hub.size(), 2);
});

test("hub evicts old per-device sessions and slow consumers", () => {
  const hub = new RealtimeHub(4, 2, 1_024);
  const oldest = socket();
  const second = socket();
  const newest = socket();
  hub.add("device", asWebSocket(oldest));
  hub.add("device", asWebSocket(second));
  assert.equal(hub.add("device", asWebSocket(newest)), true);
  assert.equal(oldest.closed[0]?.code, 1008);
  assert.equal(hub.size(), 2);

  second.bufferedAmount = 1_000;
  hub.notify("device", "envelope", "message");
  assert.equal(second.closed[0]?.code, 1013);
  assert.equal(hub.size(), 1);
  assert.equal(newest.sent.length, 1);
});

test("disconnecting a device closes every socket and releases global capacity once", () => {
  const hub = new RealtimeHub(2, 2, 1_024);
  const first = socket();
  const second = socket();
  hub.add("device", asWebSocket(first));
  hub.add("device", asWebSocket(second));

  hub.disconnectDevice("device");
  assert.equal(first.closed[0]?.code, 1000);
  assert.equal(second.closed[0]?.reason, "session revoked");
  assert.equal(hub.size(), 0);

  hub.remove("device", asWebSocket(first));
  assert.equal(hub.size(), 0);
  assert.equal(hub.add("new-a", asWebSocket(socket())), true);
  assert.equal(hub.add("new-b", asWebSocket(socket())), true);
  assert.equal(hub.size(), 2);
});
