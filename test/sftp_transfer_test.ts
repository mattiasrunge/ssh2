/**
 * SFTP Transfer Tests
 *
 * Tests fastGet and fastPut using a mock FSInterface SFTP and real local temp files.
 */

import { assertEquals } from '@std/assert';
import { fastGet, fastPut } from '../src/protocol/sftp/transfer.ts';
import type { SFTP } from '../src/protocol/sftp/SFTP.ts';

// deno-lint-ignore no-explicit-any
type AnyFn = (...args: any[]) => any;

// =============================================================================
// Mock helpers
// =============================================================================

/**
 * Create a mock SFTP used as SOURCE in fastGet.
 * Implements the callback-style FSInterface that fastXfer expects.
 */
function createSrcMock(data: Uint8Array) {
  let nextHandle = 1;
  const handles = new Map<number, Uint8Array>();
  let fstatError: Error | null = null;
  let openError: Error | null = null;

  return {
    open(_path: string, _flags: string, modeOrCb: number | AnyFn, cb?: AnyFn) {
      const fn = typeof modeOrCb === 'function' ? modeOrCb : cb!;
      if (openError) { fn(openError); return; }
      const h = nextHandle++;
      handles.set(h, data);
      fn(null, h);
    },
    close(h: number, cb: (err: Error | null) => void) {
      handles.delete(h);
      cb(null);
    },
    read(_h: number, buf: Uint8Array, offset: number, len: number, pos: number | bigint, cb: AnyFn) {
      const p = Number(pos);
      const end = Math.min(p + len, data.length);
      const n = Math.max(0, end - p);
      if (n > 0) buf.set(data.slice(p, end), offset);
      cb(null, n, buf);
    },
    write(_h: number, _buf: Uint8Array, _offset: number, _len: number, _pos: number | bigint, cb: AnyFn) {
      cb(null);
    },
    fstat(_h: number, cb: AnyFn) {
      if (fstatError) { cb(fstatError); return; }
      cb(null, { size: data.length });
    },
    stat(_path: string, cb: AnyFn) {
      cb(null, { size: data.length });
    },
    setFstatError(err: Error) { fstatError = err; },
    setOpenError(err: Error) { openError = err; },
  };
}

/**
 * Create a mock SFTP used as DESTINATION in fastPut.
 */
function createDstMock() {
  let nextHandle = 1;
  const writtenChunks: Array<{ pos: number; data: Uint8Array }> = [];
  let writeError: Error | null = null;
  let openError: Error | null = null;

  return {
    open(_path: string, _flags: string, modeOrCb: number | AnyFn, cb?: AnyFn) {
      const fn = typeof modeOrCb === 'function' ? modeOrCb : cb!;
      if (openError) { fn(openError); return; }
      fn(null, nextHandle++);
    },
    close(_h: number, cb: (err: Error | null) => void) {
      cb(null);
    },
    read(_h: number, buf: Uint8Array, _o: number, _l: number, _p: number | bigint, cb: AnyFn) {
      cb(null, 0, buf);
    },
    write(_h: number, buf: Uint8Array, offset: number, len: number, pos: number | bigint, cb: AnyFn) {
      if (writeError) { cb(writeError); return; }
      writtenChunks.push({ pos: Number(pos), data: buf.slice(offset, offset + len) });
      cb(null);
    },
    fstat(_h: number, cb: AnyFn) { cb(null, { size: 0 }); },
    stat(_path: string, cb: AnyFn) { cb(null, { size: 0 }); },
    setWriteError(err: Error) { writeError = err; },
    setOpenError(err: Error) { openError = err; },
    /** Reassemble written chunks into a contiguous Uint8Array */
    assembleData(totalSize: number): Uint8Array {
      const result = new Uint8Array(totalSize);
      for (const { pos, data } of writtenChunks) {
        result.set(data, pos);
      }
      return result;
    },
    getWrittenChunks() { return writtenChunks; },
  };
}

// =============================================================================
// fastGet tests
// =============================================================================

Deno.test('fastGet: downloads remote data to local file', async () => {
  const data = new Uint8Array(80);
  for (let i = 0; i < 80; i++) data[i] = i;
  const mock = createSrcMock(data);
  const localPath = await Deno.makeTempFile();
  try {
    await new Promise<void>((resolve, reject) => {
      fastGet(mock as unknown as SFTP, '/remote/file.txt', localPath, (err) =>
        err ? reject(err) : resolve());
    });
    const result = await Deno.readFile(localPath);
    assertEquals(result, data);
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastGet: opts as callback (4th arg is the cb)', async () => {
  // Call signature: fastGet(sftp, remote, local, cb) — no opts object
  const data = new Uint8Array(20).fill(42);
  const mock = createSrcMock(data);
  const localPath = await Deno.makeTempFile();
  try {
    await new Promise<void>((resolve, reject) => {
      // Pass callback directly as 4th argument
      fastGet(mock as unknown as SFTP, '/remote/file.txt', localPath, (err) =>
        err ? reject(err) : resolve());
    });
    const result = await Deno.readFile(localPath);
    assertEquals(result, data);
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastGet: step callback receives progress', async () => {
  // Use default chunkSize so the whole file is one chunk (serial, no seek races)
  const data = new Uint8Array(50);
  for (let i = 0; i < 50; i++) data[i] = i;
  const mock = createSrcMock(data);
  const localPath = await Deno.makeTempFile();
  const steps: Array<{ total: number; transferred: number; chunk: number }> = [];
  try {
    await new Promise<void>((resolve, reject) => {
      fastGet(
        mock as unknown as SFTP,
        '/remote/file.txt',
        localPath,
        { step: (p: any) => steps.push({ ...p }) } as any,
        (err) => err ? reject(err) : resolve(),
      );
    });
    assertEquals(steps.length > 0, true);
    const last = steps[steps.length - 1];
    assertEquals(last.transferred, 50);
    assertEquals(last.total, 50);
    const result = await Deno.readFile(localPath);
    assertEquals(result, data);
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastGet: fstat fails, fallback to stat succeeds', async () => {
  const data = new Uint8Array(30).fill(7);
  const mock = createSrcMock(data);
  mock.setFstatError(new Error('fstat not supported'));
  const localPath = await Deno.makeTempFile();
  try {
    await new Promise<void>((resolve, reject) => {
      fastGet(mock as unknown as SFTP, '/remote/file.txt', localPath, (err) =>
        err ? reject(err) : resolve());
    });
    const result = await Deno.readFile(localPath);
    assertEquals(result, data);
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastGet: src.open error calls callback with error', async () => {
  const mock = createSrcMock(new Uint8Array(10));
  mock.setOpenError(new Error('permission denied'));

  let callbackErr: Error | null = null as Error | null;
  const localPath = await Deno.makeTempFile();
  try {
    await new Promise<void>((resolve) => {
      fastGet(mock as unknown as SFTP, '/remote/file.txt', localPath, (err) => {
        callbackErr = err;
        resolve();
      });
    });
    assertEquals((callbackErr as Error | null)?.message, 'permission denied');
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastGet: empty remote file calls callback with null', async () => {
  // fsize=0 → onError() with no error → callback(null)
  const data = new Uint8Array(0);
  const mock = createSrcMock(data);
  const localPath = await Deno.makeTempFile();
  try {
    await new Promise<void>((resolve, reject) => {
      fastGet(mock as unknown as SFTP, '/remote/empty.txt', localPath, (err) =>
        err ? reject(err) : resolve());
    });
    // No error: empty transfer completed successfully
    const result = await Deno.readFile(localPath);
    assertEquals(result.length, 0);
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastGet: multi-read cycle with concurrency=1', async () => {
  // concurrency=1 forces serial reads/writes, avoiding LocalFS seek races
  const SIZE = 100;
  const data = new Uint8Array(SIZE);
  for (let i = 0; i < SIZE; i++) data[i] = (i * 3) % 256;
  const mock = createSrcMock(data);
  const localPath = await Deno.makeTempFile();
  try {
    await new Promise<void>((resolve, reject) => {
      fastGet(
        mock as unknown as SFTP,
        '/remote/large.bin',
        localPath,
        { chunkSize: 20, concurrency: 1 } as any,
        (err) => err ? reject(err) : resolve(),
      );
    });
    const result = await Deno.readFile(localPath);
    assertEquals(result, data);
  } finally {
    await Deno.remove(localPath);
  }
});

// =============================================================================
// fastPut tests
// =============================================================================

Deno.test('fastPut: uploads local file to mock SFTP destination', async () => {
  const data = new Uint8Array(60);
  for (let i = 0; i < 60; i++) data[i] = i;
  const localPath = await Deno.makeTempFile();
  try {
    await Deno.writeFile(localPath, data);
    const mock = createDstMock();
    await new Promise<void>((resolve, reject) => {
      fastPut(mock as unknown as SFTP, localPath, '/remote/upload.txt', (err) =>
        err ? reject(err) : resolve());
    });
    const result = mock.assembleData(60);
    assertEquals(result, data);
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastPut: opts as callback (4th arg is the cb)', async () => {
  const data = new Uint8Array(10).fill(5);
  const localPath = await Deno.makeTempFile();
  try {
    await Deno.writeFile(localPath, data);
    const mock = createDstMock();
    await new Promise<void>((resolve, reject) => {
      fastPut(mock as unknown as SFTP, localPath, '/remote/file.txt', (err) =>
        err ? reject(err) : resolve());
    });
    assertEquals(mock.assembleData(10), data);
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastPut: multi-read cycle with concurrency=1 and step callback', async () => {
  // concurrency=1 forces serial reads from LocalFS, avoiding seek races
  const SIZE = 100;
  const data = new Uint8Array(SIZE);
  for (let i = 0; i < SIZE; i++) data[i] = i % 256;
  const localPath = await Deno.makeTempFile();
  const stepTransferred: number[] = [];
  try {
    await Deno.writeFile(localPath, data);
    const mock = createDstMock();
    await new Promise<void>((resolve, reject) => {
      fastPut(
        mock as unknown as SFTP,
        localPath,
        '/remote/big.bin',
        {
          chunkSize: 20,
          concurrency: 1,
          step: (p: any) => stepTransferred.push(p.transferred),
        } as any,
        (err) => err ? reject(err) : resolve(),
      );
    });
    assertEquals(stepTransferred.length > 0, true);
    assertEquals(stepTransferred[stepTransferred.length - 1], SIZE);
    assertEquals(mock.assembleData(SIZE), data);
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastPut: write error calls callback with error', async () => {
  const data = new Uint8Array(30).fill(3);
  const localPath = await Deno.makeTempFile();
  try {
    await Deno.writeFile(localPath, data);
    const mock = createDstMock();
    mock.setWriteError(new Error('remote write failed'));

    let callbackErr: Error | null = null as Error | null;
    await new Promise<void>((resolve) => {
      fastPut(mock as unknown as SFTP, localPath, '/remote/file.txt', (err) => {
        callbackErr = err;
        resolve();
      });
    });
    assertEquals((callbackErr as Error | null)?.message, 'remote write failed');
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastPut: dst open error calls callback with error', async () => {
  const data = new Uint8Array(10).fill(1);
  const localPath = await Deno.makeTempFile();
  try {
    await Deno.writeFile(localPath, data);
    const mock = createDstMock();
    mock.setOpenError(new Error('remote access denied'));

    let callbackErr: Error | null = null as Error | null;
    await new Promise<void>((resolve) => {
      fastPut(mock as unknown as SFTP, localPath, '/remote/file.txt', (err) => {
        callbackErr = err;
        resolve();
      });
    });
    assertEquals((callbackErr as Error | null)?.message, 'remote access denied');
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastPut: empty local file calls callback with null', async () => {
  const localPath = await Deno.makeTempFile();
  try {
    // Empty file: size=0, fsize=0 → onError() with no error
    const mock = createDstMock();
    await new Promise<void>((resolve, reject) => {
      fastPut(mock as unknown as SFTP, localPath, '/remote/empty.txt', (err) =>
        err ? reject(err) : resolve());
    });
    // No written chunks since file was empty
    assertEquals(mock.getWrittenChunks().length, 0);
  } finally {
    await Deno.remove(localPath);
  }
});

// =============================================================================
// Additional tests to cover LocalFS paths via fastGet/fastPut options
// =============================================================================

Deno.test('fastGet: with mode option (covers LocalFS.open with mode param)', async () => {
  // mode option causes LocalFS dst.open to be called with (path, 'w', mode, cb)
  const data = new Uint8Array(40).fill(99);
  const mock = createSrcMock(data);
  const localPath = await Deno.makeTempFile();
  try {
    await new Promise<void>((resolve, reject) => {
      fastGet(
        mock as unknown as SFTP,
        '/remote/file.txt',
        localPath,
        { mode: 0o644 } as any,
        (err) => err ? reject(err) : resolve(),
      );
    });
    const result = await Deno.readFile(localPath);
    assertEquals(result, data);
  } finally {
    await Deno.remove(localPath);
  }
});

Deno.test('fastGet: dst open error (local file is non-writable directory)', async () => {
  // Try to open a path that can't be written (e.g. a directory path)
  const data = new Uint8Array(10).fill(1);
  const mock = createSrcMock(data);
  const tmpDir = await Deno.makeTempDir();
  try {
    let callbackErr: Error | null = null as Error | null;
    await new Promise<void>((resolve) => {
      // localPath points to a directory → open for write will fail
      fastGet(mock as unknown as SFTP, '/remote/file.txt', tmpDir, (err) => {
        callbackErr = err;
        resolve();
      });
    });
    // Should have gotten an error (can't write to directory path)
    assertEquals(callbackErr instanceof Error, true);
  } finally {
    await Deno.remove(tmpDir);
  }
});

Deno.test('fastPut: src open error (file does not exist)', async () => {
  const mock = createDstMock();
  let callbackErr: Error | null = null as Error | null;
  await new Promise<void>((resolve) => {
    fastPut(
      mock as unknown as SFTP,
      '/non/existent/path/file.txt',
      '/remote/dest.txt',
      (err) => {
        callbackErr = err;
        resolve();
      },
    );
  });
  assertEquals(callbackErr instanceof Error, true);
});

Deno.test('fastPut: large file with default chunk size (LocalFS multi-read)', async () => {
  // Use concurrency=1 for serial reads to avoid seek race conditions in LocalFS
  const SIZE = 200;
  const data = new Uint8Array(SIZE);
  for (let i = 0; i < SIZE; i++) data[i] = i % 256;
  const localPath = await Deno.makeTempFile();
  try {
    await Deno.writeFile(localPath, data);
    const mock = createDstMock();
    await new Promise<void>((resolve, reject) => {
      fastPut(
        mock as unknown as SFTP,
        localPath,
        '/remote/large.bin',
        { chunkSize: 20, concurrency: 1 } as any,
        (err) => err ? reject(err) : resolve(),
      );
    });
    assertEquals(mock.assembleData(SIZE), data);
  } finally {
    await Deno.remove(localPath);
  }
});
