/**
 * Async utilities
 * Replaces Node.js process.nextTick with Web-standard queueMicrotask
 */

/**
 * Schedule a callback to run in the next microtask.
 * This is the Web-standard replacement for process.nextTick().
 */
export function nextTick(callback: () => void): void {
  queueMicrotask(callback);
}

/**
 * Schedule a callback with arguments to run in the next microtask.
 */
export function nextTickWith<T extends unknown[]>(
  callback: (...args: T) => void,
  ...args: T
): void {
  queueMicrotask(() => callback(...args));
}

/**
 * Create a deferred promise that can be resolved/rejected externally.
 */
export interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
}

/** Create a {@link Deferred} promise that can be resolved or rejected externally. */
export function deferred<T>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;

  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
}

/**
 * Sleep for the given number of milliseconds.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Create a timeout promise that rejects after the given time.
 */
export function timeout<T>(ms: number, message?: string): Promise<T> {
  return new Promise((_, reject) => {
    setTimeout(() => {
      reject(new Error(message ?? `Timeout after ${ms}ms`));
    }, ms);
  });
}

/**
 * Race a promise against a timeout.
 */
export async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  message?: string,
): Promise<T> {
  return Promise.race([promise, timeout<T>(ms, message)]);
}
