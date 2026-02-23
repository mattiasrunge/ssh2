/**
 * Shell Tests
 *
 * Tests for interactive shell functionality over SSH.
 * Converted from test/test-shell.js
 */

import { assertEquals, assertExists } from '@std/assert';

import type { Channel } from '../src/Channel.ts';
import { Client } from '../src/client.ts';
import { type Connection, Server, type ServerAuthContext, type Session } from '../src/server.ts';
import {
  clearMustCallChecks,
  generateTestHostKeyEd25519,
  mustCall,
  verifyMustCallChecks,
} from './integration_helpers.ts';

const DEBUG = false;
const decoder = new TextDecoder();

interface TestContext {
  client: Client;
  server: Server;
  conn?: Connection;
  cleanup: () => Promise<void>;
}

/**
 * Create a test context with client and server
 */
async function createTestContext(title: string): Promise<TestContext> {
  const hostKey = await generateTestHostKeyEd25519();

  const server = new Server({
    hostKeys: [hostKey.parsedKey],
    debug: DEBUG ? (msg: string) => console.log(`[${title}][SERVER]`, msg) : undefined,
  });

  const client = new Client();

  if (!DEBUG) {
    server.on('error', () => {});
    client.on('error', () => {});
  }

  await server.listen(0, '127.0.0.1');

  const cleanup = async () => {
    try {
      client.end();
    } catch { /* ignore */ }
    try {
      await server.close();
    } catch { /* ignore */ }
    verifyMustCallChecks();
  };

  return { client, server, cleanup };
}

/**
 * Connect client to server with password auth
 * Returns when both client and server are ready
 */
async function connectWithPasswordAuth(
  ctx: TestContext,
  title: string,
): Promise<Connection> {
  const { client, server } = ctx;
  const addr = server.address()!;

  return new Promise<Connection>((resolve, reject) => {
    let connReady = false;
    let clientReady = false;
    let conn: Connection | undefined;

    const checkBothReady = () => {
      if (connReady && clientReady && conn) {
        resolve(conn);
      }
    };

    server.on(
      'connection',
      mustCall((c: Connection) => {
        conn = c;
        ctx.conn = c;
        c.on(
          'authentication',
          mustCall((authCtx: ServerAuthContext) => {
            authCtx.accept();
          }),
        );
        c.on(
          'ready',
          mustCall(() => {
            connReady = true;
            checkBothReady();
          }),
        );
      }),
    );

    // Set up client ready BEFORE connecting
    client.on(
      'ready',
      mustCall(() => {
        clientReady = true;
        checkBothReady();
      }),
    );

    client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'test',
      password: 'test',
      debug: DEBUG ? (msg: string) => console.log(`[${title}][CLIENT]`, msg) : undefined,
    }).catch(reject);
  });
}

// =============================================================================
// Tests
// =============================================================================

Deno.test('shell: Simple shell()', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('Simple shell()');

  try {
    const OUTPUT = 'shell output!\n';

    const conn = await connectWithPasswordAuth(ctx, 'Simple shell()');

    // Server side: handle session and shell
    const shellDone = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((accept: () => Session | undefined) => {
          const session = accept();
          assertExists(session);

          session!.on(
            'pty',
            mustCall((
              acceptPty: (() => void) | undefined,
              _reject: (() => void) | undefined,
              _info: Record<string, unknown>,
            ) => {
              if (acceptPty) acceptPty();

              session!.on(
                'shell',
                mustCall((
                  acceptShell: () => Channel | undefined,
                  _rejectShell: (() => void) | undefined,
                ) => {
                  const stream = acceptShell();
                  assertExists(stream);

                  // Server sends output
                  stream!.write(OUTPUT);

                  // Server reads input from stdin until 'exit\n'
                  // Use ReadableStream API instead of events
                  (async () => {
                    const reader = stream!.stdout.getReader();
                    let input = '';
                    try {
                      while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        if (value) {
                          input += decoder.decode(value);
                          if (input === 'exit\n') {
                            stream!.end();
                            resolve();
                            break;
                          }
                        }
                      }
                    } finally {
                      reader.releaseLock();
                    }
                  })();
                }),
              );
            }),
          );
        }),
      );
    });

    // Client side: request shell
    const clientDone = (async () => {
      const stream = await ctx.client.shell();

      // Client sends exit command
      stream.write('exit\n');

      // Client reads server output
      (async () => {
        const reader = stream.stdout.getReader();
        let output = '';
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) {
              output += decoder.decode(value);
            }
          }
        } finally {
          reader.releaseLock();
        }
        assertEquals(output, OUTPUT);
      })();

      await new Promise<void>((resolve) => {
        stream.on(
          'close',
          mustCall(() => {
            conn.end();
            resolve();
          }),
        );
      });
    })();

    await Promise.all([shellDone, clientDone]);
  } finally {
    await ctx.cleanup();
  }
});

Deno.test({
  name: 'shell: Shell with environment set',
  ignore: false,
  fn: async () => {
    // Test environment variable passing with shell
    clearMustCallChecks();
    const ctx = await createTestContext('Shell with environment set');

    try {
      const OUTPUT = 'shell output!\n';
      const clientEnv = { SSH2NODETEST: 'foo' };

      const conn = await connectWithPasswordAuth(ctx, 'Shell with environment set');

      const shellDone = new Promise<void>((resolve) => {
        conn.on(
          'session',
          mustCall((accept: () => Session | undefined) => {
            const session = accept();
            assertExists(session);

            let sawPty = false;
            let sawEnv = false;

            session!.on(
              'pty',
              mustCall((
                acceptPty: (() => void) | undefined,
                _reject: (() => void) | undefined,
                _info: Record<string, unknown>,
              ) => {
                if (acceptPty) acceptPty();
                sawPty = true;
              }),
            );

            session!.on(
              'env',
              mustCall((
                acceptEnv: (() => void) | undefined,
                _reject: (() => void) | undefined,
                info: { key: string; val: string },
              ) => {
                if (acceptEnv) acceptEnv();
                sawEnv = true;
                assertEquals(info.key, Object.keys(clientEnv)[0]);
                assertEquals(info.val, Object.values(clientEnv)[0]);
              }),
            );

            session!.on(
              'shell',
              mustCall((
                acceptShell: () => Channel | undefined,
                _rejectShell: (() => void) | undefined,
              ) => {
                assertEquals(sawPty, true, 'Expected pty before shell');
                assertEquals(sawEnv, true, 'Expected env before shell');

                const stream = acceptShell();
                assertExists(stream);

                stream!.write(OUTPUT);

                // Use ReadableStream API to read input from client
                (async () => {
                  const reader = stream!.stdout.getReader();
                  let input = '';
                  try {
                    while (true) {
                      const { done, value } = await reader.read();
                      if (done) break;
                      if (value) {
                        input += decoder.decode(value);
                        if (input === 'exit\n') {
                          stream!.end();
                          resolve();
                          break;
                        }
                      }
                    }
                  } finally {
                    reader.releaseLock();
                  }
                })();
              }),
            );
          }),
        );
      });

      const clientDone = (async () => {
        const stream = await ctx.client.shell({ env: clientEnv });

        stream.write('exit\n');

        // Use ReadableStream API to read output from server
        (async () => {
          const reader = stream.stdout.getReader();
          let output = '';
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              if (value) {
                output += decoder.decode(value);
              }
            }
          } finally {
            reader.releaseLock();
          }
          assertEquals(output, OUTPUT);
        })();

        await new Promise<void>((resolve) => {
          stream.on(
            'close',
            mustCall(() => {
              conn.end();
              resolve();
            }),
          );
        });
      })();

      await Promise.all([shellDone, clientDone]);
    } finally {
      await ctx.cleanup();
    }
  },
});
