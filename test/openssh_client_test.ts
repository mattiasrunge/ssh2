/**
 * Test SSH server with real OpenSSH client
 *
 * This script starts an SSH server and attempts to connect using the system's
 * OpenSSH client to verify cipher switching works correctly.
 */

import { type Connection, Server, type ServerAuthContext, type Session } from '../src/server.ts';
import { generateKeyPair } from '../src/keygen.ts';
import { parseKey } from '../src/protocol/keyParser.ts';

const DEBUG = true;

async function main() {
  console.log('Generating host key...');

  // Generate an Ed25519 host key
  const keyPair = await generateKeyPair('ed25519');
  const parsedKey = parseKey(keyPair.private);
  if (parsedKey instanceof Error) {
    throw parsedKey;
  }

  console.log('Starting SSH server...');

  const server = new Server({
    hostKeys: [parsedKey],
    debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
  });

  server.on('connection', (conn: Connection) => {
    console.log('Client connected!');

    conn.on('authentication', (ctx: ServerAuthContext) => {
      console.log(`Auth attempt: method=${ctx.method}, user=${ctx.username}`);
      if (ctx.method === 'none') {
        // Reject 'none' but indicate password is acceptable
        ctx.reject(['password', 'publickey']);
      } else if (ctx.method === 'password') {
        // Accept any password for testing
        console.log('Accepting password authentication');
        ctx.accept();
      } else if (ctx.method === 'publickey') {
        // Accept any public key for testing
        console.log('Accepting publickey authentication');
        ctx.accept();
      } else {
        ctx.reject();
      }
    });

    conn.on('ready', () => {
      console.log('Client authenticated and ready!');
    });

    conn.on('session', (accept: () => Session | undefined) => {
      const session = accept();
      if (!session) return;

      console.log('Session opened');

      session.on('exec', (
        acceptExec: () => import('../src/Channel.ts').Channel | undefined,
        _reject: (() => void) | undefined,
        info: { command: string },
      ) => {
        console.log(`Exec request: ${info.command}`);
        const channel = acceptExec();
        if (channel) {
          // Echo back the command
          channel.write(`You ran: ${info.command}\n`);
          channel.exit(0);
          channel.end();
        }
      });

      session.on('shell', (
        acceptShell: () => import('../src/Channel.ts').Channel | undefined,
        _reject: (() => void) | undefined,
      ) => {
        console.log('Shell request');
        const channel = acceptShell();
        if (channel) {
          channel.write('Welcome to the test SSH server!\r\n');
          channel.exit(0);
          channel.end();
        }
      });
    });

    conn.on('close', () => {
      console.log('Client disconnected');
    });

    conn.on('error', (err: Error) => {
      console.error('Connection error:', err.message);
    });
  });

  await server.listen(0, '127.0.0.1');
  const addr = server.address()!;
  console.log(`\nSSH Server listening on ${addr.hostname}:${addr.port}`);
  console.log('\nTo test, run in another terminal:');
  console.log(
    `  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p ${addr.port} testuser@127.0.0.1`,
  );
  console.log('\nOr with a specific cipher:');
  console.log(
    `  ssh -c chacha20-poly1305@openssh.com -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p ${addr.port} testuser@127.0.0.1`,
  );
  console.log('\nOr run a command:');
  console.log(
    `  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p ${addr.port} testuser@127.0.0.1 "echo hello"`,
  );
  console.log('\nPress Ctrl+C to stop the server.\n');

  // Keep the server running
  await new Promise(() => {});
}

main().catch(console.error);
