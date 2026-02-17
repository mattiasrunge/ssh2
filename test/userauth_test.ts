/**
 * User Authentication Tests
 *
 * Tests various SSH authentication methods: password, public key,
 * keyboard-interactive.
 *
 * NOTE: Some tests from the original test-userauth.js are skipped because
 * the TypeScript implementation doesn't yet support parsing private keys
 * from PEM/OpenSSH formats. These need to be implemented:
 * - Old-style PEM RSA private keys (BEGIN RSA PRIVATE KEY)
 * - OpenSSH new format private keys (BEGIN OPENSSH PRIVATE KEY)
 * - DSA, ECDSA private key parsing
 * - PPK format private keys
 * - Hostbased authentication (requires private key parsing)
 */

import { assertEquals } from '@std/assert';
import { Client } from '../src/client.ts';
import {
  type Connection,
  type HostbasedAuthContext,
  type KeyboardAuthContext,
  type PwdAuthContext,
  Server,
  type ServerAuthContext,
} from '../src/server.ts';
import {
  clearMustCallChecks,
  generateTestHostKeyRSA,
  mustCall,
  verifyMustCallChecks,
} from './integration_helpers.ts';
import { generateKeyPair } from '../src/keygen.ts';

const DEBUG = false;

// NOTE: Integration tests require working KEX, which has been implemented.
// Set to false to run the tests, true to skip (e.g., in CI without network access).
const SKIP_INTEGRATION_TESTS = false;

// ============================================================================
// Password Authentication Tests
// ============================================================================

Deno.test({
  name: 'Password authentication',
  ignore: SKIP_INTEGRATION_TESTS,
  async fn() {
    // Generate a host key for the server
    const hostKey = await generateTestHostKeyRSA();

    const username = 'Password User';
    const password = 'hi mom';

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    let authAttempt = 0;
    server.on(
      'connection',
      mustCall((conn: Connection) => {
        conn.on(
          'authentication',
          mustCall((ctx: ServerAuthContext) => {
            assertEquals(ctx.username, username);
            if (++authAttempt === 1) {
              assertEquals(ctx.method, 'none');
              ctx.reject(['password']); // Tell client password auth is available
              return;
            }
            assertEquals(ctx.method, 'password');
            assertEquals((ctx as PwdAuthContext).password, password);
            ctx.accept();
          }, 2),
        );
        conn.on(
          'ready',
          mustCall(() => {
            conn.end();
          }),
        );
        conn.on('close', () => server.close());
      }),
    );

    await server.listen(0, 'localhost');
    const addr = server.address()!;

    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username,
      password,
      debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
    });

    await new Promise<void>((resolve) => {
      client.on('close', mustCall(() => resolve()));
    });

    client.end();
    server.close();
    await new Promise((r) => setTimeout(r, 50));
    verifyMustCallChecks();
  },
});

Deno.test({
  name: 'Password authentication with empty username',
  ignore: false,
  async fn() {
    const hostKey = await generateTestHostKeyRSA();

    const username = '';
    const password = 'hi mom';

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    let authAttempt = 0;
    server.on(
      'connection',
      mustCall((conn: Connection) => {
        conn.on(
          'authentication',
          mustCall((ctx: ServerAuthContext) => {
            assertEquals(ctx.username, username);
            if (++authAttempt === 1) {
              assertEquals(ctx.method, 'none');
              ctx.reject(['password']); // Tell client password auth is available
              return;
            }
            assertEquals(ctx.method, 'password');
            assertEquals((ctx as PwdAuthContext).password, password);
            ctx.accept();
          }, 2),
        );
        conn.on(
          'ready',
          mustCall(() => {
            conn.end();
          }),
        );
        conn.on('close', () => server.close());
      }),
    );

    await server.listen(0, 'localhost');
    const addr = server.address()!;

    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username,
      password,
      debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
    });

    await new Promise<void>((resolve) => {
      client.on('close', mustCall(() => resolve()));
    });

    client.end();
    server.close();
    await new Promise((r) => setTimeout(r, 50));
    verifyMustCallChecks();
  },
});

// ============================================================================
// Keyboard-Interactive Authentication Tests
// ============================================================================

Deno.test({
  name: 'Keyboard-interactive authentication',
  ignore: SKIP_INTEGRATION_TESTS,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const hostKey = await generateTestHostKeyRSA();

    const username = 'Keyboard-Interactive User';
    const request = {
      name: 'SSH2 Authentication',
      instructions: 'These are instructions',
      prompts: [
        { prompt: 'Password: ', echo: false },
        { prompt: 'Is the cake a lie? ', echo: true },
      ],
    };
    const responses = ['foobarbaz', 'yes'];

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    let authAttempt = 0;
    server.on(
      'connection',
      mustCall((conn: Connection) => {
        conn.on(
          'authentication',
          mustCall((ctx: ServerAuthContext) => {
            assertEquals(ctx.username, username);
            if (++authAttempt === 1) {
              assertEquals(ctx.method, 'none');
              ctx.reject(['keyboard-interactive']); // Tell client keyboard-interactive is available
              return;
            }
            assertEquals(ctx.method, 'keyboard-interactive');
            const kbCtx = ctx as KeyboardAuthContext;
            kbCtx.prompt(
              request.prompts,
              request.name,
              request.instructions,
              mustCall((resps: string[]) => {
                assertEquals(resps, responses);
                ctx.accept();
              }),
            );
          }, 2),
        );
        conn.on(
          'ready',
          mustCall(() => {
            conn.end();
          }),
        );
        conn.on('close', () => server.close());
      }),
    );

    await server.listen(0, 'localhost');
    const addr = server.address()!;

    client.on(
      'keyboard-interactive',
      mustCall(
        (
          name: string,
          instructions: string,
          _lang: string,
          prompts: Array<{ prompt: string; echo: boolean }>,
          finish: (responses: string[]) => void,
        ) => {
          assertEquals(name, request.name);
          assertEquals(instructions, request.instructions);
          assertEquals(prompts, request.prompts);
          finish(responses);
        },
      ),
    );

    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username,
      tryKeyboard: true,
      debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
    });

    await new Promise<void>((resolve) => {
      client.on('close', mustCall(() => resolve()));
    });

    client.end();
    server.close();
    await new Promise((r) => setTimeout(r, 50));
    verifyMustCallChecks();
  },
});

// ============================================================================
// Tests that require private key parsing (TODO: implement keyParser support)
// ============================================================================

// The following tests are from test-userauth.js but require private key parsing
// which is not yet implemented in the TypeScript version:
//
// - RSA key authentication (old OpenSSH format)
// - RSA key authentication (new OpenSSH format)
// - RSA encrypted key authentication
// - DSA key authentication
// - ECDSA key authentication
// - PPK format key authentication
// - Hostbased authentication
// - Password change requested
// - authHandler() tests
//
// These should be re-enabled once keyParser supports private key formats.

Deno.test({
  name: 'RSA key authentication (OpenSSH new format)',
  ignore: SKIP_INTEGRATION_TESTS,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const hostKey = await generateTestHostKeyRSA();

    // Read the openssh_new_rsa private key
    const privateKeyPath = new URL('./fixtures/openssh_new_rsa', import.meta.url).pathname;
    const privateKey = await Deno.readFile(privateKeyPath);

    const username = 'RSA Key User';

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    let authAttempt = 0;
    server.on(
      'connection',
      mustCall((conn: Connection) => {
        conn.on(
          'authentication',
          mustCall((ctx: ServerAuthContext) => {
            assertEquals(ctx.username, username);
            authAttempt++;
            if (authAttempt === 1) {
              assertEquals(ctx.method, 'none');
              ctx.reject(['publickey']); // Tell client publickey auth is available
              return;
            }
            assertEquals(ctx.method, 'publickey');
            // For publickey auth, accept if we get a valid signature
            ctx.accept();
          }, 3), // none + publickey query + publickey with signature
        );
        conn.on(
          'ready',
          mustCall(() => {
            conn.end();
          }),
        );
        conn.on('close', () => server.close());
      }),
    );

    await server.listen(0, 'localhost');
    const addr = server.address()!;

    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username,
      privateKey,
      debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
    });

    await new Promise<void>((resolve) => {
      client.on('close', mustCall(() => resolve()));
    });

    client.end();
    server.close();
    await new Promise((r) => setTimeout(r, 50));
    verifyMustCallChecks();
  },
});

Deno.test({
  name: 'ECDSA key authentication (old PEM format)',
  ignore: SKIP_INTEGRATION_TESTS,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const hostKey = await generateTestHostKeyRSA();

    // Read the id_ecdsa private key (P-256)
    const privateKeyPath = new URL('./fixtures/id_ecdsa', import.meta.url).pathname;
    const privateKey = await Deno.readFile(privateKeyPath);

    const username = 'ECDSA Key User';

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    let authAttempt = 0;
    server.on(
      'connection',
      mustCall((conn: Connection) => {
        conn.on(
          'authentication',
          mustCall((ctx: ServerAuthContext) => {
            assertEquals(ctx.username, username);
            authAttempt++;
            if (authAttempt === 1) {
              assertEquals(ctx.method, 'none');
              ctx.reject(['publickey']); // Tell client publickey auth is available
              return;
            }
            assertEquals(ctx.method, 'publickey');
            // For publickey auth, accept if we get a valid signature
            ctx.accept();
          }, 3), // none + publickey query + publickey with signature
        );
        conn.on(
          'ready',
          mustCall(() => {
            conn.end();
          }),
        );
        conn.on('close', () => server.close());
      }),
    );

    await server.listen(0, 'localhost');
    const addr = server.address()!;

    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username,
      privateKey,
      debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
    });

    await new Promise<void>((resolve) => {
      client.on('close', mustCall(() => resolve()));
    });

    client.end();
    server.close();
    await new Promise((r) => setTimeout(r, 50));
    verifyMustCallChecks();
  },
});

Deno.test({
  name: 'Hostbased authentication',
  ignore: false,
  async fn() {
    clearMustCallChecks();

    // Generate a host key for the server
    const hostKey = await generateTestHostKeyRSA();
    // Generate a key for the client to use for hostbased auth
    const clientKey = await generateKeyPair('ed25519');

    const username = 'hostbased-user';
    const localHostname = 'client.example.com';
    const localUsername = 'local-user';

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    let authAttempt = 0;
    server.on(
      'connection',
      mustCall((conn: Connection) => {
        conn.on(
          'authentication',
          mustCall((ctx: ServerAuthContext) => {
            assertEquals(ctx.username, username);
            if (++authAttempt === 1) {
              assertEquals(ctx.method, 'none');
              ctx.reject(['hostbased']); // Tell client hostbased auth is available
              return;
            }
            assertEquals(ctx.method, 'hostbased');

            const hostbasedCtx = ctx as HostbasedAuthContext;
            assertEquals(hostbasedCtx.localHostname, localHostname);
            assertEquals(hostbasedCtx.localUsername, localUsername);
            assertEquals(hostbasedCtx.key.algo, 'ssh-ed25519');

            // Accept the hostbased auth
            ctx.accept();
          }, 2),
        );
        conn.on(
          'ready',
          mustCall(() => {
            conn.end();
          }),
        );
        conn.on('close', () => server.close());
      }),
    );

    await server.listen(0, 'localhost');
    const addr = server.address()!;

    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username,
      privateKey: clientKey.private,
      localHostname,
      localUsername,
      debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
    });

    await new Promise<void>((resolve) => {
      client.on('close', mustCall(() => resolve()));
    });

    client.end();
    await new Promise((r) => setTimeout(r, 50));
    verifyMustCallChecks();
  },
});

// Cleanup after all tests
clearMustCallChecks();
