/**
 * Server Host Keys Tests
 *
 * Tests for various host key types and multiple host key selection.
 * Converted from test/test-server-hostkeys.js
 */

import { assertEquals } from '@std/assert';

import { Client } from '../src/client.ts';
import { type Connection, Server, type ServerAuthContext } from '../src/server.ts';
import {
  clearMustCallChecks,
  generateTestHostKeyECDSA,
  generateTestHostKeyEd25519,
  generateTestHostKeyRSA,
  mustCall,
  verifyMustCallChecks,
} from './integration_helpers.ts';

const DEBUG = false;
const FIXTURES_DIR = new URL('./fixtures/', import.meta.url).pathname;

// =============================================================================
// Tests
// =============================================================================

// Test RSA host key
Deno.test({
  name: 'hostkeys: RSA host key',
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    clearMustCallChecks();

    const hostKey = await generateTestHostKeyRSA();
    const privateKey = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
    const username = 'KeyUser';

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    if (!DEBUG) {
      server.on('error', () => {});
      client.on('error', () => {});
    }

    await server.listen(0, '127.0.0.1');
    const addr = server.address()!;

    try {
      const serverDone = new Promise<void>((resolve) => {
        server.on(
          'connection',
          mustCall((conn: Connection) => {
            conn.on(
              'authentication',
              mustCall((authCtx: ServerAuthContext) => {
                assertEquals(authCtx.username, username);
                authCtx.accept();
              }),
            );

            conn.on(
              'ready',
              mustCall(() => {
                conn.end();
                resolve();
              }),
            );
          }),
        );
      });

      const clientDone = new Promise<void>((resolve) => {
        client.on(
          'handshake',
          mustCall((info: unknown) => {
            const hi = info as { serverHostKey: string };
            assertEquals(hi.serverHostKey, 'rsa-sha2-512');
          }),
        );

        client.on(
          'close',
          mustCall(() => {
            resolve();
          }),
        );
      });

      await client.connect({
        host: addr.hostname,
        port: addr.port,
        username,
        privateKey,
        debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
      });

      await Promise.all([serverDone, clientDone]);
    } finally {
      try {
        client.end();
      } catch { /* ignore */ }
      try {
        await server.close();
      } catch { /* ignore */ }
      verifyMustCallChecks();
    }
  },
});

// Test ECDSA host key
Deno.test({
  name: 'hostkeys: ECDSA host key',
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    clearMustCallChecks();

    const hostKey = await generateTestHostKeyECDSA();
    const privateKey = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
    const username = 'KeyUser';

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    if (!DEBUG) {
      server.on('error', () => {});
      client.on('error', () => {});
    }

    await server.listen(0, '127.0.0.1');
    const addr = server.address()!;

    try {
      const serverDone = new Promise<void>((resolve) => {
        server.on(
          'connection',
          mustCall((conn: Connection) => {
            conn.on(
              'authentication',
              mustCall((authCtx: ServerAuthContext) => {
                assertEquals(authCtx.username, username);
                authCtx.accept();
              }),
            );

            conn.on(
              'ready',
              mustCall(() => {
                conn.end();
                resolve();
              }),
            );
          }),
        );
      });

      const clientDone = new Promise<void>((resolve) => {
        client.on(
          'handshake',
          mustCall((info: unknown) => {
            const hi = info as { serverHostKey: string };
            assertEquals(hi.serverHostKey, 'ecdsa-sha2-nistp256');
          }),
        );

        client.on(
          'close',
          mustCall(() => {
            resolve();
          }),
        );
      });

      await client.connect({
        host: addr.hostname,
        port: addr.port,
        username,
        privateKey,
        debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
      });

      await Promise.all([serverDone, clientDone]);
    } finally {
      try {
        client.end();
      } catch { /* ignore */ }
      try {
        await server.close();
      } catch { /* ignore */ }
      verifyMustCallChecks();
    }
  },
});

// Test Ed25519 host key
Deno.test({
  name: 'hostkeys: Ed25519 host key',
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    clearMustCallChecks();

    const hostKey = await generateTestHostKeyEd25519();
    const privateKey = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
    const username = 'KeyUser';

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    if (!DEBUG) {
      server.on('error', () => {});
      client.on('error', () => {});
    }

    await server.listen(0, '127.0.0.1');
    const addr = server.address()!;

    try {
      const serverDone = new Promise<void>((resolve) => {
        server.on(
          'connection',
          mustCall((conn: Connection) => {
            conn.on(
              'authentication',
              mustCall((authCtx: ServerAuthContext) => {
                assertEquals(authCtx.username, username);
                authCtx.accept();
              }),
            );

            conn.on(
              'ready',
              mustCall(() => {
                conn.end();
                resolve();
              }),
            );
          }),
        );
      });

      const clientDone = new Promise<void>((resolve) => {
        client.on(
          'handshake',
          mustCall((info: unknown) => {
            const hi = info as { serverHostKey: string };
            assertEquals(hi.serverHostKey, 'ssh-ed25519');
          }),
        );

        client.on(
          'close',
          mustCall(() => {
            resolve();
          }),
        );
      });

      await client.connect({
        host: addr.hostname,
        port: addr.port,
        username,
        privateKey,
        debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
      });

      await Promise.all([serverDone, clientDone]);
    } finally {
      try {
        client.end();
      } catch { /* ignore */ }
      try {
        await server.close();
      } catch { /* ignore */ }
      verifyMustCallChecks();
    }
  },
});

// Test multiple host keys with selection
Deno.test({
  name: 'hostkeys: Multiple host keys (select RSA)',
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    clearMustCallChecks();

    const rsaKey = await generateTestHostKeyRSA();
    const ecdsaKey = await generateTestHostKeyECDSA();
    const privateKey = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
    const username = 'KeyUser';

    const server = new Server({
      hostKeys: [rsaKey.parsedKey, ecdsaKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    if (!DEBUG) {
      server.on('error', () => {});
      client.on('error', () => {});
    }

    await server.listen(0, '127.0.0.1');
    const addr = server.address()!;

    try {
      const serverDone = new Promise<void>((resolve) => {
        server.on(
          'connection',
          mustCall((conn: Connection) => {
            conn.on(
              'authentication',
              mustCall((authCtx: ServerAuthContext) => {
                assertEquals(authCtx.username, username);
                authCtx.accept();
              }),
            );

            conn.on(
              'ready',
              mustCall(() => {
                conn.end();
                resolve();
              }),
            );
          }),
        );
      });

      const clientDone = new Promise<void>((resolve) => {
        client.on(
          'handshake',
          mustCall((info: unknown) => {
            const hi = info as { serverHostKey: string };
            // Client prefers RSA when available
            assertEquals(hi.serverHostKey, 'rsa-sha2-512');
          }),
        );

        client.on(
          'close',
          mustCall(() => {
            resolve();
          }),
        );
      });

      await client.connect({
        host: addr.hostname,
        port: addr.port,
        username,
        privateKey,
        algorithms: {
          serverHostKey: ['rsa-sha2-512', 'rsa-sha2-256'],
        },
        debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
      });

      await Promise.all([serverDone, clientDone]);
    } finally {
      try {
        client.end();
      } catch { /* ignore */ }
      try {
        await server.close();
      } catch { /* ignore */ }
      verifyMustCallChecks();
    }
  },
});
