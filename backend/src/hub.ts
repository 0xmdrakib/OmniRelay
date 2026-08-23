import type WebSocket from "ws";

export class RealtimeHub {
  private static readonly MAX_SOCKETS_PER_DEVICE = 5;
  private readonly sockets = new Map<string, Set<WebSocket>>();

  add(deviceId: string, socket: WebSocket): void {
    const set = this.sockets.get(deviceId) ?? new Set<WebSocket>();
    while (set.size >= RealtimeHub.MAX_SOCKETS_PER_DEVICE) {
      const oldest = set.values().next().value as WebSocket | undefined;
      if (!oldest) break;
      set.delete(oldest);
      oldest.close(1008, "too many sessions");
    }
    set.add(socket);
    this.sockets.set(deviceId, set);
  }

  remove(deviceId: string, socket: WebSocket): void {
    const set = this.sockets.get(deviceId);
    set?.delete(socket);
    if (set?.size === 0) this.sockets.delete(deviceId);
  }

  notify(deviceId: string, envelopeId: string, kind: "message" | "call"): void {
    this.send(deviceId, { type: "mailbox.changed", envelopeId, kind });
  }

  status(deviceId: string, envelopeId: string, state: "delivered" | "read"): void {
    this.send(deviceId, { type: "envelope.status", envelopeId, state });
  }

  private send(deviceId: string, event: object): void {
    const message = JSON.stringify(event);
    for (const socket of this.sockets.get(deviceId) ?? []) {
      if (socket.readyState === socket.OPEN) socket.send(message);
    }
  }
}
