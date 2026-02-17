/**
 * Tests for utility modules
 */

import { assertEquals, assertRejects, assertThrows } from '@std/assert';
import {
  allocBytes,
  compareBytes,
  concatBytes,
  copyBytes,
  EMPTY_BYTES,
  equalsBytes,
  fillBytes,
  fromArray,
  fromBase64,
  fromHex,
  fromString,
  isBytes,
  readInt32BE,
  readUInt16BE,
  readUInt32BE,
  readUInt64BE,
  readUInt8,
  sliceBytes,
  toBase64,
  toHex,
  toUtf8,
  viewBytes,
  writeInt32BE,
  writeUInt16BE,
  writeUInt32BE,
  writeUInt64BE,
  writeUInt8,
} from '../src/utils/binary.ts';
import { EventEmitter, listenerCount } from '../src/utils/events.ts';
import {
  deferred,
  nextTick,
  nextTickWith,
  sleep,
  timeout,
  withTimeout,
} from '../src/utils/async.ts';

// Binary utilities tests
Deno.test('allocBytes creates zero-filled array', () => {
  const bytes = allocBytes(10);
  assertEquals(bytes.length, 10);
  assertEquals(bytes.every((b) => b === 0), true);
});

Deno.test('fromString encodes UTF-8', () => {
  const bytes = fromString('hello');
  assertEquals(toUtf8(bytes), 'hello');
});

Deno.test('fromHex decodes hex string', () => {
  const bytes = fromHex('48656c6c6f');
  assertEquals(toUtf8(bytes), 'Hello');
});

Deno.test('fromBase64 decodes base64 string', () => {
  const bytes = fromBase64('SGVsbG8=');
  assertEquals(toUtf8(bytes), 'Hello');
});

Deno.test('toHex encodes to hex string', () => {
  const bytes = fromString('Hello');
  assertEquals(toHex(bytes), '48656c6c6f');
});

Deno.test('toBase64 encodes to base64 string', () => {
  const bytes = fromString('Hello');
  assertEquals(toBase64(bytes), 'SGVsbG8=');
});

Deno.test('concatBytes concatenates arrays', () => {
  const a = fromString('Hello');
  const b = fromString(' ');
  const c = fromString('World');
  const result = concatBytes([a, b, c]);
  assertEquals(toUtf8(result), 'Hello World');
});

Deno.test('isBytes detects Uint8Array', () => {
  assertEquals(isBytes(new Uint8Array(5)), true);
  assertEquals(isBytes([1, 2, 3]), false);
  assertEquals(isBytes('string'), false);
  assertEquals(isBytes(null), false);
});

Deno.test('readUInt32BE and writeUInt32BE work correctly', () => {
  const buf = allocBytes(4);
  writeUInt32BE(buf, 0x12345678, 0);
  assertEquals(readUInt32BE(buf, 0), 0x12345678);
});

Deno.test('EMPTY_BYTES is empty', () => {
  assertEquals(EMPTY_BYTES.length, 0);
});

// EventEmitter tests
Deno.test('EventEmitter emits events', () => {
  interface TestEvents {
    data: [string];
    count: [number];
  }
  const emitter = new EventEmitter<TestEvents>();
  let received = '';

  emitter.on('data', (value) => {
    received = value;
  });

  emitter.emit('data', 'hello');
  assertEquals(received, 'hello');
});

Deno.test('EventEmitter once listener fires once', () => {
  interface TestEvents {
    ping: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  let count = 0;

  emitter.once('ping', () => {
    count++;
  });

  emitter.emit('ping');
  emitter.emit('ping');
  assertEquals(count, 1);
});

Deno.test('EventEmitter removeListener works', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  let count = 0;

  const listener = () => {
    count++;
  };

  emitter.on('test', listener);
  emitter.emit('test');
  assertEquals(count, 1);

  emitter.removeListener('test', listener);
  emitter.emit('test');
  assertEquals(count, 1);
});

Deno.test('EventEmitter listenerCount works', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();

  assertEquals(emitter.listenerCount('test'), 0);
  emitter.on('test', () => {});
  assertEquals(emitter.listenerCount('test'), 1);
  emitter.on('test', () => {});
  assertEquals(emitter.listenerCount('test'), 2);
});

// Async utilities tests
Deno.test('nextTick schedules callback', async () => {
  let executed = false;
  nextTick(() => {
    executed = true;
  });
  assertEquals(executed, false);
  await Promise.resolve(); // Wait for microtask
  assertEquals(executed, true);
});

Deno.test('deferred creates resolvable promise', async () => {
  const d = deferred<number>();
  setTimeout(() => d.resolve(42), 10);
  const result = await d.promise;
  assertEquals(result, 42);
});

Deno.test('sleep waits for specified time', async () => {
  const start = Date.now();
  await sleep(50);
  const elapsed = Date.now() - start;
  assertEquals(elapsed >= 45, true); // Allow some tolerance
});

// =============================================================================
// Additional Binary utilities tests
// =============================================================================

Deno.test('fromArray creates Uint8Array from number array', () => {
  const bytes = fromArray([1, 2, 3, 4]);
  assertEquals(bytes.length, 4);
  assertEquals(bytes[0], 1);
  assertEquals(bytes[3], 4);
});

Deno.test('readUInt64BE and writeUInt64BE work correctly', () => {
  const buf = allocBytes(8);
  writeUInt64BE(buf, 0x123456789ABCDEFn, 0);
  assertEquals(readUInt64BE(buf, 0), 0x123456789ABCDEFn);
});

Deno.test('readUInt64BE handles zero', () => {
  const buf = allocBytes(8);
  writeUInt64BE(buf, 0n, 0);
  assertEquals(readUInt64BE(buf, 0), 0n);
});

Deno.test('readInt32BE and writeInt32BE handle positive values', () => {
  const buf = allocBytes(4);
  writeInt32BE(buf, 12345, 0);
  assertEquals(readInt32BE(buf, 0), 12345);
});

Deno.test('readInt32BE and writeInt32BE handle negative values', () => {
  const buf = allocBytes(4);
  writeInt32BE(buf, -1, 0);
  assertEquals(readInt32BE(buf, 0), -1);
});

Deno.test('readInt32BE and writeInt32BE handle min/max', () => {
  const buf = allocBytes(8);
  writeInt32BE(buf, 0x7FFFFFFF, 0);
  assertEquals(readInt32BE(buf, 0), 0x7FFFFFFF);
  writeInt32BE(buf, -0x80000000, 4);
  assertEquals(readInt32BE(buf, 4), -0x80000000);
});

Deno.test('readUInt16BE and writeUInt16BE work correctly', () => {
  const buf = allocBytes(2);
  writeUInt16BE(buf, 0xBEEF, 0);
  assertEquals(readUInt16BE(buf, 0), 0xBEEF);
});

Deno.test('readUInt8 and writeUInt8 work correctly', () => {
  const buf = allocBytes(1);
  writeUInt8(buf, 0xAB, 0);
  assertEquals(readUInt8(buf, 0), 0xAB);
});

Deno.test('sliceBytes creates a subarray', () => {
  const buf = fromArray([1, 2, 3, 4, 5]);
  const slice = sliceBytes(buf, 1, 4);
  assertEquals(slice.length, 3);
  assertEquals(slice[0], 2);
  assertEquals(slice[2], 4);
});

Deno.test('copyBytes copies data between arrays', () => {
  const src = fromArray([10, 20, 30, 40]);
  const dst = allocBytes(6);
  const copied = copyBytes(src, dst, 1, 0, 3);
  assertEquals(copied, 3);
  assertEquals(dst[0], 0);
  assertEquals(dst[1], 10);
  assertEquals(dst[2], 20);
  assertEquals(dst[3], 30);
  assertEquals(dst[4], 0);
});

Deno.test('copyBytes without sourceEnd copies from sourceStart to end', () => {
  const src = fromArray([1, 2, 3]);
  const dst = allocBytes(4);
  const copied = copyBytes(src, dst, 0, 1);
  assertEquals(copied, 2);
  assertEquals(dst[0], 2);
  assertEquals(dst[1], 3);
});

Deno.test('equalsBytes returns true for equal arrays', () => {
  assertEquals(equalsBytes(fromArray([1, 2, 3]), fromArray([1, 2, 3])), true);
});

Deno.test('equalsBytes returns false for different arrays', () => {
  assertEquals(equalsBytes(fromArray([1, 2, 3]), fromArray([1, 2, 4])), false);
});

Deno.test('equalsBytes returns false for different lengths', () => {
  assertEquals(equalsBytes(fromArray([1, 2]), fromArray([1, 2, 3])), false);
});

Deno.test('compareBytes returns 0 for equal arrays', () => {
  assertEquals(compareBytes(fromArray([1, 2, 3]), fromArray([1, 2, 3])), 0);
});

Deno.test('compareBytes returns -1 when first is less', () => {
  assertEquals(compareBytes(fromArray([1, 2, 3]), fromArray([1, 2, 4])), -1);
});

Deno.test('compareBytes returns 1 when first is greater', () => {
  assertEquals(compareBytes(fromArray([1, 3, 3]), fromArray([1, 2, 3])), 1);
});

Deno.test('compareBytes handles different lengths', () => {
  assertEquals(compareBytes(fromArray([1, 2]), fromArray([1, 2, 3])), -1);
  assertEquals(compareBytes(fromArray([1, 2, 3]), fromArray([1, 2])), 1);
});

Deno.test('fillBytes fills with value', () => {
  const buf = allocBytes(5);
  fillBytes(buf, 0xFF);
  assertEquals(buf.every((b) => b === 0xFF), true);
});

Deno.test('fillBytes respects start and end', () => {
  const buf = allocBytes(5);
  fillBytes(buf, 0xAA, 1, 4);
  assertEquals(buf[0], 0);
  assertEquals(buf[1], 0xAA);
  assertEquals(buf[3], 0xAA);
  assertEquals(buf[4], 0);
});

Deno.test('viewBytes creates view over ArrayBuffer', () => {
  const buf = fromArray([1, 2, 3, 4, 5]);
  const view = viewBytes(buf.buffer as ArrayBuffer, 1, 3);
  assertEquals(view.length, 3);
  assertEquals(view[0], 2);
});

Deno.test('concatBytes handles empty array', () => {
  const result = concatBytes([]);
  assertEquals(result.length, 0);
});

Deno.test('concatBytes handles single array', () => {
  const a = fromArray([1, 2, 3]);
  const result = concatBytes([a]);
  assertEquals(result.length, 3);
  assertEquals(toHex(result), toHex(a));
});

// =============================================================================
// Additional EventEmitter tests
// =============================================================================

Deno.test('EventEmitter emit returns false when no listeners', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  assertEquals(emitter.emit('test'), false);
});

Deno.test('EventEmitter emit returns true when listeners exist', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  emitter.on('test', () => {});
  assertEquals(emitter.emit('test'), true);
});

Deno.test('EventEmitter removeAllListeners for specific event', () => {
  interface TestEvents {
    a: [];
    b: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  emitter.on('a', () => {});
  emitter.on('a', () => {});
  emitter.on('b', () => {});

  emitter.removeAllListeners('a');
  assertEquals(emitter.listenerCount('a'), 0);
  assertEquals(emitter.listenerCount('b'), 1);
});

Deno.test('EventEmitter removeAllListeners for all events', () => {
  interface TestEvents {
    a: [];
    b: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  emitter.on('a', () => {});
  emitter.on('b', () => {});

  emitter.removeAllListeners();
  assertEquals(emitter.listenerCount('a'), 0);
  assertEquals(emitter.listenerCount('b'), 0);
});

Deno.test('EventEmitter listeners returns listener functions', () => {
  interface TestEvents {
    test: [number];
  }
  const emitter = new EventEmitter<TestEvents>();
  const fn1 = (_n: number) => {};
  const fn2 = (_n: number) => {};

  emitter.on('test', fn1);
  emitter.on('test', fn2);

  const listeners = emitter.listeners('test');
  assertEquals(listeners.length, 2);
  assertEquals(listeners[0], fn1);
  assertEquals(listeners[1], fn2);
});

Deno.test('EventEmitter eventNames returns registered events', () => {
  interface TestEvents {
    a: [];
    b: [];
    c: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  emitter.on('a', () => {});
  emitter.on('c', () => {});

  const names = emitter.eventNames();
  assertEquals(names.includes('a'), true);
  assertEquals(names.includes('c'), true);
  assertEquals(names.includes('b'), false);
});

Deno.test('EventEmitter prependListener adds to front', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  const order: number[] = [];

  emitter.on('test', () => order.push(1));
  emitter.prependListener('test', () => order.push(0));

  emitter.emit('test');
  assertEquals(order, [0, 1]);
});

Deno.test('EventEmitter prependOnceListener fires once at front', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  const order: number[] = [];

  emitter.on('test', () => order.push(1));
  emitter.prependOnceListener('test', () => order.push(0));

  emitter.emit('test');
  emitter.emit('test');
  assertEquals(order, [0, 1, 1]);
});

Deno.test('EventEmitter getMaxListeners and setMaxListeners', () => {
  const emitter = new EventEmitter();
  assertEquals(emitter.getMaxListeners(), 10);
  emitter.setMaxListeners(20);
  assertEquals(emitter.getMaxListeners(), 20);
});

Deno.test('EventEmitter off is alias for removeListener', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  let count = 0;
  const fn = () => count++;

  emitter.on('test', fn);
  emitter.emit('test');
  assertEquals(count, 1);

  emitter.off('test', fn);
  emitter.emit('test');
  assertEquals(count, 1);
});

Deno.test('EventEmitter removeListener on nonexistent event is safe', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  emitter.removeListener('test', () => {});
  assertEquals(emitter.listenerCount('test'), 0);
});

Deno.test('EventEmitter error in listener emits error event', () => {
  interface TestEvents {
    data: [];
    error: [Error];
  }
  const emitter = new EventEmitter<TestEvents>();
  let caughtError: Error | null = null;

  emitter.on('error', (err) => {
    caughtError = err;
  });
  emitter.on('data', () => {
    throw new Error('test error');
  });

  emitter.emit('data');
  assertEquals(caughtError!.message, 'test error');
});

Deno.test('EventEmitter error in listener without error handler throws', () => {
  interface TestEvents {
    data: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  emitter.on('data', () => {
    throw new Error('unhandled');
  });

  assertThrows(() => emitter.emit('data'), Error, 'unhandled');
});

Deno.test('EventEmitter rawListeners returns same as listeners', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  const fn = () => {};
  emitter.on('test', fn);

  assertEquals(emitter.rawListeners('test'), emitter.listeners('test'));
});

Deno.test('listenerCount static function works', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  emitter.on('test', () => {});
  emitter.on('test', () => {});
  assertEquals(listenerCount(emitter, 'test'), 2);
});

Deno.test('EventEmitter removeListener cleans up empty event map', () => {
  interface TestEvents {
    test: [];
  }
  const emitter = new EventEmitter<TestEvents>();
  const fn = () => {};
  emitter.on('test', fn);
  assertEquals(emitter.eventNames().length, 1);
  emitter.removeListener('test', fn);
  assertEquals(emitter.eventNames().length, 0);
});

// =============================================================================
// Additional Async utilities tests
// =============================================================================

Deno.test('nextTickWith passes arguments', async () => {
  let result = '';
  nextTickWith(
    (a: string, b: string) => {
      result = a + b;
    },
    'hello',
    ' world',
  );
  await Promise.resolve();
  assertEquals(result, 'hello world');
});

Deno.test('deferred can be rejected', async () => {
  const d = deferred<number>();
  d.reject(new Error('test reject'));
  await assertRejects(() => d.promise, Error, 'test reject');
});

Deno.test('timeout rejects after delay', async () => {
  await assertRejects(() => timeout(10, 'timed out'), Error, 'timed out');
});

Deno.test('timeout uses default message', async () => {
  await assertRejects(() => timeout(10), Error, 'Timeout after 10ms');
});

Deno.test({
  name: 'withTimeout resolves if fast enough',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const result = await withTimeout(Promise.resolve(42), 1000);
    assertEquals(result, 42);
  },
});

Deno.test({
  name: 'withTimeout rejects if too slow',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    await assertRejects(
      () => withTimeout(new Promise(() => {}), 10, 'too slow'),
      Error,
      'too slow',
    );
  },
});
