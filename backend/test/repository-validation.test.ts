import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Repository } from "../src/repository.js";

test("repository rejects unsafe lease, route, and challenge bounds before database I/O", async (t) => {
  const repository = new Repository("postgres://invalid:invalid@127.0.0.1:1/invalid");
  t.after(() => repository.close());
  const deviceId = "a".repeat(64);

  await assert.rejects(repository.renewCallLease(randomUUID(), deviceId, 29), /active call lease/);
  await assert.rejects(repository.renewCallLease(randomUUID(), deviceId, 301), /active call lease/);
  await assert.rejects(
    repository.replaceInboundRoutes(
      deviceId,
      Array.from({ length: 513 }, (_, index) => ({
        senderId: index.toString(16).padStart(64, "0"),
        routeTokenHash: Buffer.alloc(32, index & 0xff)
      }))
    ),
    /too many inbound routes/
  );
  await assert.rejects(
    repository.saveRegistrationChallenge(
      randomUUID(),
      deviceId,
      Buffer.alloc(32).toString("base64"),
      Buffer.alloc(44).toString("base64"),
      Buffer.alloc(32).toString("base64"),
      Buffer.alloc(32).toString("base64"),
      17
    ),
    /maxOutstanding registration challenges/
  );
});
