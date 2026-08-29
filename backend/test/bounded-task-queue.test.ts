import assert from "node:assert/strict";
import test from "node:test";
import { BoundedTaskQueue } from "../src/bounded-task-queue.js";

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

const nextTurn = () => new Promise<void>((resolve) => setImmediate(resolve));

test("task queue strictly bounds active and queued work", async () => {
  const gates = [deferred(), deferred(), deferred(), deferred()];
  const started: number[] = [];
  const queue = new BoundedTaskQueue(2, 2);
  const submit = (index: number) => queue.submit(async () => {
    started.push(index);
    await gates[index]!.promise;
  });

  assert.equal(submit(0), true);
  assert.equal(submit(1), true);
  assert.equal(submit(2), true);
  assert.equal(submit(3), true);
  assert.equal(queue.submit(async () => undefined), false);
  await nextTurn();
  assert.deepEqual(queue.stats(), { active: 2, queued: 2, accepting: true });
  assert.deepEqual(started, [0, 1]);

  gates[0]!.resolve();
  await nextTurn();
  assert.deepEqual(queue.stats(), { active: 2, queued: 1, accepting: true });
  assert.deepEqual(started, [0, 1, 2]);

  const stopped = queue.shutdown(true);
  assert.deepEqual(queue.stats(), { active: 2, queued: 0, accepting: false });
  assert.equal(queue.submit(async () => undefined), false);
  gates[1]!.resolve();
  gates[2]!.resolve();
  await stopped;
  assert.deepEqual(queue.stats(), { active: 0, queued: 0, accepting: false });
  assert.deepEqual(started, [0, 1, 2]);
});

test("task failures are contained and do not stop later work", async () => {
  const errors: unknown[] = [];
  const completed: string[] = [];
  const queue = new BoundedTaskQueue(1, 1, (error) => errors.push(error));
  queue.submit(async () => { throw new Error("expected failure"); });
  queue.submit(async () => { completed.push("second"); });
  await queue.shutdown(false);
  assert.equal((errors[0] as Error).message, "expected failure");
  assert.deepEqual(completed, ["second"]);
});
