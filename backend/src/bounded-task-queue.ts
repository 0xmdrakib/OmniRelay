export type BoundedTaskQueueStats = {
  active: number;
  queued: number;
  accepting: boolean;
};

export class BoundedTaskQueue {
  private readonly pending: Array<() => Promise<void>> = [];
  private active = 0;
  private accepting = true;
  private idlePromise: Promise<void> | null = null;
  private resolveIdle: (() => void) | null = null;

  constructor(
    private readonly concurrency: number,
    private readonly maxQueued: number,
    private readonly onTaskError: (error: unknown) => void = () => undefined
  ) {
    if (!Number.isInteger(concurrency) || concurrency < 1) {
      throw new Error("concurrency must be a positive integer");
    }
    if (!Number.isInteger(maxQueued) || maxQueued < 0) {
      throw new Error("maxQueued must be a non-negative integer");
    }
  }

  submit(task: () => Promise<void>): boolean {
    if (!this.accepting) return false;
    if (this.active < this.concurrency) {
      this.start(task);
      return true;
    }
    if (this.pending.length >= this.maxQueued) return false;
    this.pending.push(task);
    return true;
  }

  stats(): BoundedTaskQueueStats {
    return {
      active: this.active,
      queued: this.pending.length,
      accepting: this.accepting
    };
  }

  async shutdown(discardQueued = true): Promise<void> {
    this.accepting = false;
    if (discardQueued) this.pending.length = 0;
    await this.waitForIdle();
  }

  private start(task: () => Promise<void>): void {
    this.active += 1;
    void Promise.resolve()
      .then(task)
      .catch((error) => {
        try {
          this.onTaskError(error);
        } catch {
          // Error reporting must never stall queue progress.
        }
      })
      .finally(() => {
        this.active -= 1;
        const next = this.pending.shift();
        if (next) {
          this.start(next);
        } else if (this.active === 0) {
          this.resolveIdle?.();
          this.idlePromise = null;
          this.resolveIdle = null;
        }
      });
  }

  private waitForIdle(): Promise<void> {
    if (this.active === 0 && this.pending.length === 0) return Promise.resolve();
    if (!this.idlePromise) {
      this.idlePromise = new Promise<void>((resolve) => {
        this.resolveIdle = resolve;
      });
    }
    return this.idlePromise;
  }
}
