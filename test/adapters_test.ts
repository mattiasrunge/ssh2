/**
 * Tests for Deno Transport Adapters
 */

import { assertEquals, assertExists, assertRejects } from '@std/assert';
import {
  connect,
  DenoListener,
  DenoTransport,
  DenoTransportFactory,
  denoTransport,
  listen,
} from '../src/adapters/deno.ts';

// Helper: start a local listener and return [listener, port]
async function startListener(): Promise<[Deno.Listener, number]> {
  const listener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  return [listener, port];
}

// ============================================================
// DenoTransport
// ============================================================

Deno.test('DenoTransport: remoteAddress/remotePort/localAddress/localPort', async () => {
  const [rawListener, port] = await startListener();

  // Accept connection in background
  const serverConnPromise = rawListener.accept();
  const clientConn = await Deno.connect({ hostname: '127.0.0.1', port });
  const serverConn = await serverConnPromise;

  const transport = new DenoTransport(clientConn);

  assertEquals(transport.remoteAddress, '127.0.0.1');
  assertEquals(transport.remotePort, port);
  assertExists(transport.localAddress);
  assertExists(transport.localPort);
  assertEquals(typeof transport.localPort, 'number');

  transport.close();
  serverConn.close();
  rawListener.close();
});

Deno.test('DenoTransport: readable and writable are streams', async () => {
  const [rawListener, port] = await startListener();

  const serverConnPromise = rawListener.accept();
  const clientConn = await Deno.connect({ hostname: '127.0.0.1', port });
  const serverConn = await serverConnPromise;

  const transport = new DenoTransport(clientConn);

  assertExists(transport.readable);
  assertExists(transport.writable);

  transport.close();
  serverConn.close();
  rawListener.close();
});

Deno.test('DenoTransport: conn getter returns underlying Deno.Conn', async () => {
  const [rawListener, port] = await startListener();

  const serverConnPromise = rawListener.accept();
  const clientConn = await Deno.connect({ hostname: '127.0.0.1', port });
  const serverConn = await serverConnPromise;

  const transport = new DenoTransport(clientConn);

  assertEquals(transport.conn, clientConn);

  transport.close();
  serverConn.close();
  rawListener.close();
});

Deno.test('DenoTransport: closed starts false, becomes true after close()', async () => {
  const [rawListener, port] = await startListener();

  const serverConnPromise = rawListener.accept();
  const clientConn = await Deno.connect({ hostname: '127.0.0.1', port });
  const serverConn = await serverConnPromise;

  const transport = new DenoTransport(clientConn);

  assertEquals(transport.closed, false);
  transport.close();
  assertEquals(transport.closed, true);

  // Double close is safe
  transport.close();
  assertEquals(transport.closed, true);

  serverConn.close();
  rawListener.close();
});

Deno.test('DenoTransport: close() on already-closed underlying conn does not throw', async () => {
  const [rawListener, port] = await startListener();

  const serverConnPromise = rawListener.accept();
  const clientConn = await Deno.connect({ hostname: '127.0.0.1', port });
  const serverConn = await serverConnPromise;

  const transport = new DenoTransport(clientConn);

  // Close the underlying conn first
  clientConn.close();
  // Now close the transport - should not throw
  transport.close();
  assertEquals(transport.closed, true);

  serverConn.close();
  rawListener.close();
});

// ============================================================
// DenoListener
// ============================================================

Deno.test('DenoListener: address/port/addr getters', async () => {
  const rawListener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const denoListener = new DenoListener(rawListener);

  assertEquals(denoListener.address, '127.0.0.1');
  assertEquals(typeof denoListener.port, 'number');
  assertEquals(denoListener.port > 0, true);

  const addr = denoListener.addr;
  assertEquals(addr.hostname, '127.0.0.1');
  assertEquals(addr.port, denoListener.port);

  denoListener.close();
});

Deno.test('DenoListener: listener getter returns underlying Deno.Listener', async () => {
  const rawListener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const denoListener = new DenoListener(rawListener);

  assertEquals(denoListener.listener, rawListener);

  denoListener.close();
});

Deno.test('DenoListener: accept() yields DenoTransport for each connection', async () => {
  const rawListener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const denoListener = new DenoListener(rawListener);
  const port = denoListener.port;

  const received: DenoTransport[] = [];

  // Accept 2 connections in background
  const acceptTask = (async () => {
    for await (const transport of denoListener) {
      received.push(transport as DenoTransport);
      transport.close();
      if (received.length >= 2) break;
    }
  })();

  // Make 2 client connections
  const c1 = await Deno.connect({ hostname: '127.0.0.1', port });
  const c2 = await Deno.connect({ hostname: '127.0.0.1', port });

  await acceptTask;

  assertEquals(received.length, 2);
  assertExists(received[0]);
  assertExists(received[1]);

  c1.close();
  c2.close();
  denoListener.close();
});

Deno.test('DenoListener: close() stops accept loop cleanly', async () => {
  const rawListener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const denoListener = new DenoListener(rawListener);

  const acceptTask = (async () => {
    // deno-lint-ignore no-empty
    for await (const _transport of denoListener) {
      // close immediately
    }
  })();

  // Close listener - the accept loop should terminate without throwing
  denoListener.close();
  await acceptTask; // should resolve, not reject

  // Double close is safe
  denoListener.close();
});

Deno.test('DenoListener: accept() via Symbol.asyncIterator', async () => {
  const rawListener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const denoListener = new DenoListener(rawListener);
  const port = denoListener.port;

  let count = 0;
  const iter = denoListener[Symbol.asyncIterator]();

  // Connect, then get one from iterator
  const clientConn = Deno.connect({ hostname: '127.0.0.1', port });
  const result = await iter.next();

  if (!result.done) {
    count++;
    (result.value as DenoTransport).close();
  }

  (await clientConn).close();
  denoListener.close();
  // Drain the iterator
  await iter.next();

  assertEquals(count, 1);
});

// ============================================================
// DenoTransportFactory
// ============================================================

Deno.test('DenoTransportFactory: connect() without timeout', async () => {
  const rawListener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const port = (rawListener.addr as Deno.NetAddr).port;

  const serverConnPromise = rawListener.accept();
  const factory = new DenoTransportFactory();
  const transport = await factory.connect({ host: '127.0.0.1', port });

  const serverConn = await serverConnPromise;

  assertExists(transport);
  assertEquals(transport.remotePort, port);

  transport.close();
  serverConn.close();
  rawListener.close();
});

Deno.test('DenoTransportFactory: connect() with timeout (succeeds within timeout)', async () => {
  const rawListener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const port = (rawListener.addr as Deno.NetAddr).port;

  const serverConnPromise = rawListener.accept();
  const factory = new DenoTransportFactory();
  const transport = await factory.connect({ host: '127.0.0.1', port, timeout: 5000 });

  const serverConn = await serverConnPromise;

  assertExists(transport);
  assertEquals(transport.remotePort, port);

  transport.close();
  serverConn.close();
  rawListener.close();
});

Deno.test('DenoTransportFactory: listen() returns DenoListener', async () => {
  const factory = new DenoTransportFactory();
  const listener = await factory.listen({ port: 0, hostname: '127.0.0.1' });

  assertExists(listener);
  assertEquals(listener instanceof DenoListener, true);

  listener.close();
});

Deno.test('DenoTransportFactory: listen() with host option', async () => {
  const factory = new DenoTransportFactory();
  const listener = await factory.listen({ port: 0, host: '127.0.0.1' });

  assertExists(listener);
  listener.close();
});

Deno.test('DenoTransportFactory: listen() with no host uses 0.0.0.0', async () => {
  const factory = new DenoTransportFactory();
  const listener = await factory.listen({ port: 0 });

  assertExists(listener);
  listener.close();
});

// ============================================================
// Default denoTransport singleton
// ============================================================

Deno.test('denoTransport singleton: connect and listen work', async () => {
  const rawListener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const port = (rawListener.addr as Deno.NetAddr).port;

  const serverConnPromise = rawListener.accept();
  const transport = await denoTransport.connect({ host: '127.0.0.1', port });
  const serverConn = await serverConnPromise;

  assertExists(transport);
  transport.close();
  serverConn.close();
  rawListener.close();
});

// ============================================================
// Convenience functions
// ============================================================

Deno.test('connect() convenience function returns a Transport', async () => {
  const rawListener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const port = (rawListener.addr as Deno.NetAddr).port;

  const serverConnPromise = rawListener.accept();
  const transport = await connect('127.0.0.1', port);
  const serverConn = await serverConnPromise;

  assertExists(transport);
  assertEquals(transport.remotePort, port);

  transport.close();
  serverConn.close();
  rawListener.close();
});

Deno.test('connect() with timeout option', async () => {
  const rawListener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const port = (rawListener.addr as Deno.NetAddr).port;

  const serverConnPromise = rawListener.accept();
  const transport = await connect('127.0.0.1', port, 5000);
  const serverConn = await serverConnPromise;

  assertExists(transport);

  transport.close();
  serverConn.close();
  rawListener.close();
});

Deno.test('listen() convenience function returns a TransportListener', async () => {
  const listener = await listen(0, '127.0.0.1');

  assertExists(listener);
  assertEquals(listener instanceof DenoListener, true);

  listener.close();
});

Deno.test('listen() without host uses default', async () => {
  const listener = await listen(0);

  assertExists(listener);
  listener.close();
});

// ============================================================
// Mock non-TCP address coverage
// ============================================================

// Helper: create a mock Deno.Conn with a non-TCP address type
function makeMockConn(transport: string): Deno.Conn {
  const fakeAddr = { transport, path: '/tmp/fake.sock' } as unknown as Deno.Addr;
  return {
    remoteAddr: fakeAddr,
    localAddr: fakeAddr,
    readable: new ReadableStream<Uint8Array>(),
    writable: new WritableStream<Uint8Array>(),
    close: () => {},
    ref: () => {},
    unref: () => {},
    rid: 0,
  } as unknown as Deno.Conn;
}

// Helper: create a mock Deno.Listener with a non-TCP address type
function makeMockListener(transport: string): Deno.Listener {
  const fakeAddr = { transport, path: '/tmp/fake.sock' } as unknown as Deno.Addr;
  return {
    addr: fakeAddr,
    rid: 0,
    close: () => {},
    accept: () => Promise.reject(new Error('mock listener closed')),
    [Symbol.asyncIterator](): AsyncIterableIterator<Deno.Conn> {
      return {
        next: () => Promise.reject(new Error('mock listener closed')),
        [Symbol.asyncIterator]() {
          return this;
        },
      };
    },
    ref: () => {},
    unref: () => {},
  } as unknown as Deno.Listener;
}

Deno.test('DenoTransport: non-TCP address returns undefined for all address getters', () => {
  const mockConn = makeMockConn('unix');
  const transport = new DenoTransport(mockConn);

  assertEquals(transport.remoteAddress, undefined);
  assertEquals(transport.remotePort, undefined);
  assertEquals(transport.localAddress, undefined);
  assertEquals(transport.localPort, undefined);
});

Deno.test('DenoListener: non-TCP address returns empty string and 0 for address getters', () => {
  const mockListener = makeMockListener('unix');
  const listener = new DenoListener(mockListener);

  assertEquals(listener.address, '');
  assertEquals(listener.port, 0);
  assertEquals(listener.addr.hostname, '');
  assertEquals(listener.addr.port, 0);
});

Deno.test('DenoListener: accept() propagates error when listener not closed by us', async () => {
  // Deno's real listener.close() causes for-await to end normally (not throw).
  // To cover the !this._closed throw branch, use a mock listener whose iterator throws,
  // simulating an unexpected OS-level socket error.
  const fakeAddr = { transport: 'tcp', hostname: '127.0.0.1', port: 9999 } as unknown as Deno.Addr;
  const throwingMockListener = {
    addr: fakeAddr,
    rid: 0,
    close: () => {},
    accept: () => Promise.reject(new Error('socket error')),
    [Symbol.asyncIterator](): AsyncIterableIterator<Deno.Conn> {
      return {
        next: () => Promise.reject(new Error('socket error')),
        [Symbol.asyncIterator]() {
          return this;
        },
      };
    },
    ref: () => {},
    unref: () => {},
  } as unknown as Deno.Listener;

  // _closed starts false — error from the iterator should propagate
  const denoListener = new DenoListener(throwingMockListener);
  await assertRejects(
    async () => {
      for await (const _transport of denoListener) {
        // should not yield
      }
    },
    Error,
    'socket error',
  );
});

Deno.test('DenoTransportFactory: connect() with timeout fails on refused port', async () => {
  // Find a port that is not listening by creating a listener, getting the port, closing it
  const tmp = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const port = (tmp.addr as Deno.NetAddr).port;
  tmp.close();

  // Now connect to a closed port with a timeout — should fail quickly
  const factory = new DenoTransportFactory();
  await assertRejects(
    () => factory.connect({ host: '127.0.0.1', port, timeout: 5000 }),
  );
});
