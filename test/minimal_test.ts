/**
 * Minimal SSH Client/Server Integration Test
 *
 * A simple test that verifies basic client/server connectivity with password auth.
 */

import { assertEquals } from '@std/assert';
import { Client } from '../src/client.ts';
import {
  type Connection,
  type PwdAuthContext,
  Server,
  type ServerAuthContext,
} from '../src/server.ts';
import { generateTestHostKeyRSA } from './integration_helpers.ts';

const DEBUG = false;

Deno.test({
  name: 'Minimal client/server connection with password auth',
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const hostKey = await generateTestHostKeyRSA();

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    let authAttempts = 0;
    let serverReady = false;
    let clientReady = false;

    server.on('connection', (conn: Connection) => {
      conn.on('authentication', (ctx: ServerAuthContext) => {
        authAttempts++;
        if (ctx.method === 'none') {
          ctx.reject(['password']);
        } else if (ctx.method === 'password') {
          assertEquals((ctx as PwdAuthContext).password, 'testpass');
          ctx.accept();
        }
      });
      conn.on('ready', () => {
        serverReady = true;
        // Small delay to ensure client receives USERAUTH_SUCCESS before disconnect
        // (ChaCha20-Poly1305 sends encrypted packets in multiple TCP writes)
        setTimeout(() => conn.end(), 50);
      });
      conn.on('close', () => {
        server.close();
      });
      conn.on('error', () => {
        // Ignore errors during close
      });
    });

    await server.listen(0, 'localhost');
    const addr = server.address()!;

    const clientClosedPromise = new Promise<void>((resolve) => {
      client.on('ready', () => {
        clientReady = true;
      });
      client.on('close', () => resolve());
      client.on('error', () => {
        // Ignore errors during close
      });
    });

    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'testuser',
      password: 'testpass',
      debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
    });

    // Wait for client to close (triggered by server ending connection)
    await Promise.race([
      clientClosedPromise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Test timeout')), 5000)),
    ]);

    client.end();
    server.close();

    // Verify the test worked
    assertEquals(authAttempts, 2, 'Expected 2 auth attempts (none + password)');
    assertEquals(serverReady, true, 'Server should have become ready');
    assertEquals(clientReady, true, 'Client should have become ready');
  },
});
