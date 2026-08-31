import type WebSocket from "ws";

export class RealtimeHub {
  private readonly sockets = new Map<string, Set<WebSocket>>();
  private totalSockets = 0;

  constructor(
    private readonly maxTotalSockets = 512,
    private readonly maxSocketsPerDevice = 5,
    private readonly maxBufferedBytesPerSocket = 64 * 1024
  ) {
    if (!Number.isInteger(maxTotalSockets) || maxTotalSockets < 1) {
      throw new Error("maxTotalSockets must be a positive integer");
    }
    if (!Number.isInteger(maxSocketsPerDevice) || maxSocketsPerDevice < 1) {
      throw new Error("maxSocketsPerDevice must be a positive integer");
    }
    if (!Number.isInteger(maxBufferedBytesPerSocket) || maxBufferedBytesPerSocket < 1) {
      throw new Error("maxBufferedBytesPerSocket must be a positive integer");
    }
  }

  add(deviceId: string, socket: WebSocket): boolean {
    const set = this.sockets.get(deviceId) ?? new Set<WebSocket>();
    if (set.has(socket)) return true;
    while (set.size >= this.maxSocketsPerDevice) {
      const oldest = set.values().next().value as WebSocket | undefined;
      if (!oldest) break;
      this.remove(deviceId, oldest);
      this.closeSocket(oldest, 1008, "too many sessions");
    }
    if (this.totalSockets >= this.maxTotalSockets) {
      this.closeSocket(socket, 1013, "server connection capacity reached");
      return false;
    }
    set.add(socket);
    this.sockets.set(deviceId, set);
    this.totalSockets += 1;
    return true;
  }

  remove(deviceId: string, socket: WebSocket): void {
    const set = this.sockets.get(deviceId);
    if (set?.delete(socket)) this.totalSockets -= 1;
    if (set?.size === 0) this.sockets.delete(deviceId);
  }

  disconnectDevice(deviceId: string): void {
    const sockets = this.sockets.get(deviceId);
    if (!sockets) return;
    this.sockets.delete(deviceId);
    this.totalSockets = Math.max(0, this.totalSockets - sockets.size);
    for (const socket of sockets) this.closeSocket(socket, 1000, "session revoked");
  }

  size(): number {
    return this.totalSockets;
  }

  notify(deviceId: string, envelopeId: string, kind: "message" | "call" | "invite"): void {
    this.send(deviceId, { type: "mailbox.changed", envelopeId, kind });
  }

  status(deviceId: string, envelopeId: string, state: "delivered" | "read" | "rejected"): void {
    this.send(deviceId, { type: "envelope.status", envelopeId, state });
  }

  private send(deviceId: string, event: object): void {
    const message = JSON.stringify(event);
    for (const socket of [...(this.sockets.get(deviceId) ?? [])]) {
      if (socket.readyState !== socket.OPEN) {
        this.remove(deviceId, socket);
        continue;
      }
      if (socket.bufferedAmount + Buffer.byteLength(message) > this.maxBufferedBytesPerSocket) {
        this.remove(deviceId, socket);
        this.closeSocket(socket, 1013, "client is not consuming events");
        continue;
      }
      try {
        socket.send(message);
      } catch {
        this.remove(deviceId, socket);
        this.closeSocket(socket, 1011, "event delivery failed");
      }
    }
  }

  private closeSocket(socket: WebSocket, code: number, reason: string): void {
    try {
      socket.close(code, reason);
    } catch {
      try {
        socket.terminate();
      } catch {
        // The socket is already unusable and has been removed from accounting.
      }
    }
  }
}
