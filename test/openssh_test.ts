/**
 * OpenSSH-specific Tests
 *
 * Tests for OpenSSH-specific features like:
 * - Agent forwarding
 * - UNIX socket forwarding
 * - Port 0 binding workaround
 *
 * Converted from test/test-openssh.js
 */

import { assertEquals, assertExists } from '@std/assert';

import { Client } from '../src/client.ts';
import { type Connection, Server, type ServerAuthContext, type Session } from '../src/server.ts';
import type { Channel } from '../src/Channel.ts';
import {
  clearMustCallChecks,
  generateTestHostKeyEd25519,
  mustCall,
  verifyMustCallChecks,
} from './integration_helpers.ts';

const DEBUG = false;

// =============================================================================
// Helper functions
// =============================================================================

interface TestContext {
  client: Client;
  server: Server;
  conn?: Connection;
  cleanup: () => Promise<void>;
}

async function createTestContext(
  title: string,
  serverIdent?: string,
  debug = DEBUG,
): Promise<TestContext> {
  const hostKey = await generateTestHostKeyEd25519();

  const server = new Server({
    hostKeys: [hostKey.parsedKey],
    ident: serverIdent,
    debug: debug ? (msg: string) => console.log(`[${title}][SERVER]`, msg) : undefined,
  });

  const client = new Client();

  if (!debug) {
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

async function connectWithPasswordAuth(
  ctx: TestContext,
  title: string,
  debug = DEBUG,
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
      username: 'foo',
      password: 'bar',
      debug: debug ? (msg: string) => console.log(`[${title}][CLIENT]`, msg) : undefined,
    }).catch(reject);
  });
}

// =============================================================================
// Tests
// =============================================================================

// Test: Exec with OpenSSH agent forwarding
Deno.test({
  name: 'openssh: Exec with agent forwarding',
  ignore: false,
  fn: async () => {
    clearMustCallChecks();
    const ctx = await createTestContext('Agent forwarding');

    try {
      const conn = await connectWithPasswordAuth(ctx, 'Agent forwarding');

      // Server handles session with auth-agent
      conn.on(
        'session',
        mustCall((accept: () => Session | undefined) => {
          const session = accept();
          assertExists(session);

          let sawAuthAgent = false;

          session!.on(
            'auth-agent',
            mustCall((
              acceptAgent: (() => void) | undefined,
              _reject: (() => void) | undefined,
            ) => {
              sawAuthAgent = true;
              if (acceptAgent) acceptAgent();
            }),
          );

          session!.on(
            'exec',
            mustCall((
              acceptExec: () => Channel | undefined,
              _reject: (() => void) | undefined,
              info: { command: string },
            ) => {
              assertEquals(sawAuthAgent, true, 'Expected auth-agent before exec');
              assertEquals(info.command, 'foo --bar');

              const stream = acceptExec();
              assertExists(stream);
              stream!.exit(100);
              stream!.end();
              // Wait for stream to close before ending connection
              stream!.on('close', () => {
                conn.end();
              });
            }),
          );
        }),
      );

      // Client executes with agentForward
      const execDone = (async () => {
        const stream = await ctx.client.exec('foo --bar', { agentForward: true });
        // Consume stdout
        (async () => {
          const reader = stream.stdout.getReader();
          try {
            while (true) {
              const { done } = await reader.read();
              if (done) break;
            }
          } finally {
            reader.releaseLock();
          }
        })();
        await new Promise<void>((resolve) => {
          stream.on('close', () => resolve());
        });
      })();

      await execDone;
    } finally {
      await ctx.cleanup();
    }
  },
});

// Test: OpenSSH forwarded UNIX socket connection
Deno.test({
  name: 'openssh: Forwarded UNIX socket connection',
  ignore: false,
  fn: async () => {
    clearMustCallChecks();
    const ctx = await createTestContext('Forwarded UNIX socket', 'OpenSSH_7.1');
    const decoder = new TextDecoder();
    const DEBUG_TEST = false;

    try {
      const socketPath = '/foo';
      const conn = await connectWithPasswordAuth(ctx, 'Forwarded UNIX socket');
      if (DEBUG_TEST) console.log('[TEST] Connection established');

      // Server handles the streamlocal-forward request and opens a forwarded channel
      const serverDone = new Promise<void>((resolve) => {
        let requestCount = 0;

        conn.on('request', (
          accept: (() => void) | undefined,
          _reject: (() => void) | undefined,
          name: string,
          info: unknown,
        ) => {
          requestCount++;
          if (DEBUG_TEST) console.log(`[TEST] Server received request #${requestCount}:`, name);
          const streamInfo = info as { socketPath: string };

          if (name === 'streamlocal-forward@openssh.com') {
            assertEquals(streamInfo.socketPath, socketPath);

            // Accept the forward request
            if (DEBUG_TEST) console.log('[TEST] Accepting forward request');
            if (accept) accept();

            // Wait for the client to receive the success response before opening channel
            setTimeout(() => {
              // Server opens a forwarded-streamlocal channel back to client
              if (DEBUG_TEST) console.log('[TEST] Opening forwarded-streamlocal channel');
              conn.openssh_forwardOutStreamLocal(socketPath, (err?: Error, ch?: Channel) => {
                if (DEBUG_TEST) {
                  console.log('[TEST] Forwarded-streamlocal channel callback, err:', err);
                }
                assertEquals(err, undefined);
                assertExists(ch);

                // Server sends data
                if (DEBUG_TEST) {
                  console.log('[TEST] Server sending data');
                }
                ch!.write('server-data');

                // Read client response
                (async () => {
                  const reader = ch!.stdout.getReader();
                  let data = '';
                  try {
                    while (true) {
                      const { done, value } = await reader.read();
                      if (done) break;
                      if (value) data += decoder.decode(value);
                      if (data.includes('client-data')) {
                        ch!.end();
                        break;
                      }
                    }
                  } finally {
                    reader.releaseLock();
                  }
                  assertEquals(data, 'client-data');
                })();
              });
            }, 100); // Increased timeout for the client to be ready
          } else if (name === 'cancel-streamlocal-forward@openssh.com') {
            assertEquals(streamInfo.socketPath, socketPath);
            if (accept) accept();
            conn.end();
            resolve();
          }
        });
      });

      // Client requests forwarding
      if (DEBUG_TEST) console.log('[TEST] Client requesting forward');
      const clientDone = (async () => {
        // Set up unix connection handler BEFORE requesting forward
        if (DEBUG_TEST) console.log('[TEST] Setting up unix connection handler');
        ctx.client.on('unix connection', (
          info: unknown,
          accept: () => Channel,
          _reject: () => void,
        ) => {
          if (DEBUG_TEST) console.log('[TEST] Received unix connection event');
          const streamInfo = info as { socketPath: string };
          assertEquals(streamInfo.socketPath, socketPath);

          const stream = accept();
          assertExists(stream);

          // Read server data
          (async () => {
            const reader = stream.stdout.getReader();
            let data = '';
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (value) data += decoder.decode(value);
                if (data.includes('server-data')) {
                  // Send response and close
                  stream.write('client-data');
                  break;
                }
              }
            } finally {
              reader.releaseLock();
            }
            assertEquals(data, 'server-data');
          })();

          stream.on('close', () => {
            // Cancel forwarding (may fail during cleanup, that's ok)
            ctx.client.openssh_unforwardInStreamLocal(socketPath).catch(() => {});
          });
        });

        if (DEBUG_TEST) console.log('[TEST] Calling openssh_forwardInStreamLocal');
        await ctx.client.openssh_forwardInStreamLocal(socketPath);
        if (DEBUG_TEST) console.log('[TEST] openssh_forwardInStreamLocal resolved');

        await new Promise<void>((resolve) => {
          ctx.client.on('close', () => resolve());
        });
      })();

      await Promise.all([serverDone, clientDone]);
    } finally {
      await ctx.cleanup();
    }
  },
});

// Test: OpenSSH direct UNIX socket connection
Deno.test({
  name: 'openssh: Direct UNIX socket connection',
  ignore: false,
  fn: async () => {
    clearMustCallChecks();
    const ctx = await createTestContext('Direct UNIX socket', 'OpenSSH_8.0');
    const decoder = new TextDecoder();

    try {
      const socketPath = '/foo/bar/baz';
      const response = 'Hello World';

      const conn = await connectWithPasswordAuth(ctx, 'Direct UNIX socket');

      // Server handles direct streamlocal connection
      const serverDone = new Promise<void>((resolve) => {
        conn.on(
          'openssh.streamlocal',
          mustCall((
            accept: () => Channel | undefined,
            _reject: () => void,
            info: { socketPath: string },
          ) => {
            assertEquals(info.socketPath, socketPath);

            const stream = accept();
            assertExists(stream);

            // Send response and close
            stream!.write(response);
            stream!.end();

            stream!.on('close', () => {
              conn.end();
              resolve();
            });
          }),
        );
      });

      // Client opens direct streamlocal connection
      const clientDone = (async () => {
        const stream = await ctx.client.openssh_forwardOutStreamLocal(socketPath);
        assertExists(stream);

        // Read response
        (async () => {
          const reader = stream.stdout.getReader();
          let data = '';
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              if (value) data += decoder.decode(value);
            }
          } finally {
            reader.releaseLock();
          }
          assertEquals(data, response);
        })();

        await new Promise<void>((resolve) => {
          stream.on('close', () => resolve());
        });
      })();

      await Promise.all([serverDone, clientDone]);
    } finally {
      await ctx.cleanup();
    }
  },
});

// Test: OpenSSH 5.x workaround for binding on port 0
Deno.test({
  name: 'openssh: Port 0 binding with callback port',
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    clearMustCallChecks();
    const ctx = await createTestContext('Port 0 binding', 'OpenSSH_5.3');

    try {
      const conn = await connectWithPasswordAuth(ctx, 'Port 0 binding');

      const boundAddr = 'good';
      const boundPort = 1337;
      const tcpInfo = {
        destIP: boundAddr,
        destPort: boundPort,
        srcIP: 'remote',
        srcPort: 12345,
      };

      // Server handles request
      const serverDone = new Promise<void>((resolve) => {
        conn.on(
          'request',
          mustCall((
            accept: ((port?: number) => void) | undefined,
            _reject: (() => void) | undefined,
            name: string,
            info: unknown,
          ) => {
            const reqInfo = info as { bindAddr?: string; bindPort?: number };
            assertEquals(name, 'tcpip-forward');
            assertEquals(reqInfo.bindAddr, boundAddr);
            assertEquals(reqInfo.bindPort, 0);

            // Accept with bound port
            if (accept) accept(boundPort);

            // Initiate forwarded connection
            conn.forwardOut(
              boundAddr,
              0, // Use 0 for port since OpenSSH 5.x doesn't return real port in forwardOut
              tcpInfo.srcIP,
              tcpInfo.srcPort,
              mustCall((err: Error | undefined, _ch: Channel | undefined) => {
                assertEquals(err, undefined);
                ctx.client.end();
                resolve();
              }),
            );
          }),
        );
      });

      // Client requests forwarding
      const clientDone = (async () => {
        // Set up event handlers before the forwarding call
        ctx.client.on(
          'tcp connection',
          mustCall((
            details: unknown,
            accept: () => Channel,
            _reject: () => void,
          ) => {
            const tcpDetails = details as {
              destIP: string;
              destPort: number;
              srcIP: string;
              srcPort: number;
            };
            assertEquals(tcpDetails.destIP, tcpInfo.destIP);
            assertEquals(tcpDetails.srcIP, tcpInfo.srcIP);
            assertEquals(tcpDetails.srcPort, tcpInfo.srcPort);
            accept();
          }),
        );

        const port = await ctx.client.forwardIn(boundAddr, 0);
        assertEquals(port, boundPort);

        await new Promise<void>((resolve) => {
          ctx.client.on(
            'close',
            mustCall(() => {
              resolve();
            }),
          );
        });
      })();

      await Promise.all([serverDone, clientDone]);
    } finally {
      await ctx.cleanup();
    }
  },
});
