/**
 * Client robustness: the ready timeout, auth that gives up instead of looping,
 * password providers, RSA user keys signed with SHA-2, and refused channel
 * requests.
 */

import { assert, assertEquals, assertRejects } from '@std/assert';
import { Client } from '../src/client.ts';
import { generateKeyPair } from '../src/keygen.ts';
import {
  type Connection,
  type PKAuthContext,
  type PwdAuthContext,
  Server,
  type ServerAuthContext,
  type Session,
} from '../src/server.ts';
import { generateTestHostKeyRSA } from './integration_helpers.ts';

type AuthHandler = (ctx: ServerAuthContext) => void;

async function startServer(onAuth: AuthHandler, onReady?: (conn: Connection) => void) {
  const hostKey = await generateTestHostKeyRSA();
  const server = new Server({ hostKeys: [hostKey.parsedKey] });
  server.on('connection', (conn: Connection) => {
    conn.on('authentication', onAuth);
    conn.on('ready', () => onReady?.(conn));
    conn.on('error', () => {});
  });
  await server.listen(0, 'localhost');
  const addr = server.address()!;
  return { server, host: addr.hostname, port: addr.port };
}

function authError(err: unknown): string | undefined {
  return (err as { level?: string }).level;
}

Deno.test('client: readyTimeout fires when the server never speaks', async () => {
  const listener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const accepted: Deno.Conn[] = [];
  (async () => {
    for await (const conn of listener) accepted.push(conn);
  })();

  const client = new Client();
  const started = Date.now();
  const err = await assertRejects(() =>
    client.connect({
      host: '127.0.0.1',
      port: (listener.addr as Deno.NetAddr).port,
      username: 'anna',
      password: 'x',
      readyTimeout: 300,
      hostVerifier: () => true,
    })
  );
  assertEquals(authError(err), 'client-timeout');
  assert(Date.now() - started < 3000, 'timed out promptly');

  client.end();
  for (const conn of accepted) {
    try {
      conn.close();
    } catch { /* already closed */ }
  }
  listener.close();
});

Deno.test('client: a wrong password is tried once, then auth fails', async () => {
  let passwordAttempts = 0;
  const { server, host, port } = await startServer((ctx) => {
    if (ctx.method === 'password') passwordAttempts++;
    ctx.reject(['password', 'publickey']);
  });

  const client = new Client();
  const err = await assertRejects(() =>
    client.connect({ host, port, username: 'anna', password: 'wrong', hostVerifier: () => true })
  );
  assertEquals(authError(err), 'client-authentication');
  assertEquals(passwordAttempts, 1);

  client.end();
  server.close();
});

Deno.test('client: a password provider is asked again after a rejection', async () => {
  const seen: string[] = [];
  const { server, host, port } = await startServer((ctx) => {
    if (ctx.method !== 'password') return ctx.reject(['password']);
    const pw = (ctx as PwdAuthContext).password;
    seen.push(pw);
    if (pw === 'right') ctx.accept();
    else ctx.reject(['password']);
  }, (conn) => conn.end());

  const attempts: number[] = [];
  const client = new Client();
  await client.connect({
    host,
    port,
    username: 'anna',
    password: (attempt) => {
      attempts.push(attempt);
      return attempt === 1 ? 'wrong' : 'right';
    },
    hostVerifier: () => true,
  });
  assertEquals(attempts, [1, 2]);
  assertEquals(seen, ['wrong', 'right']);

  client.end();
  server.close();
});

Deno.test('client: a password provider gives up after passwordAttempts', async () => {
  let passwordAttempts = 0;
  const { server, host, port } = await startServer((ctx) => {
    if (ctx.method === 'password') passwordAttempts++;
    ctx.reject(['password']);
  });

  const client = new Client();
  const err = await assertRejects(() =>
    client.connect({
      host,
      port,
      username: 'anna',
      password: () => 'wrong',
      passwordAttempts: 2,
      hostVerifier: () => true,
    })
  );
  assertEquals(authError(err), 'client-authentication');
  assertEquals(passwordAttempts, 2);

  client.end();
  server.close();
});

Deno.test('client: a password provider returning false skips password auth', async () => {
  let passwordAttempts = 0;
  const { server, host, port } = await startServer((ctx) => {
    if (ctx.method === 'password') passwordAttempts++;
    ctx.reject(['password']);
  });

  const client = new Client();
  const err = await assertRejects(() =>
    client.connect({
      host,
      port,
      username: 'anna',
      password: () => false,
      hostVerifier: () => true,
    })
  );
  assertEquals(authError(err), 'client-authentication');
  assertEquals(passwordAttempts, 0);

  client.end();
  server.close();
});

Deno.test('client: a rejected key falls through to the password', async () => {
  const key = await generateKeyPair('ed25519');
  const methods: string[] = [];
  const { server, host, port } = await startServer((ctx) => {
    methods.push(ctx.method);
    if (ctx.method === 'password') return ctx.accept();
    ctx.reject(['publickey', 'password']);
  }, (conn) => conn.end());

  const client = new Client();
  await client.connect({
    host,
    port,
    username: 'anna',
    privateKey: key.private,
    password: 'secret',
    hostVerifier: () => true,
  });
  assertEquals(methods, ['none', 'publickey', 'password']);

  client.end();
  server.close();
});

Deno.test('client: an RSA user key signs with rsa-sha2-512 when the server offers it', async () => {
  const key = await generateKeyPair('rsa', { bits: 2048 });
  const algos: string[] = [];
  const { server, host, port } = await startServer((ctx) => {
    if (ctx.method !== 'publickey') return ctx.reject(['publickey']);
    const pk = ctx as PKAuthContext;
    algos.push(`${pk.key.algo}/${pk.hashAlgo}`);
    ctx.accept(); // answers the query with PK_OK, then the signed request
  }, (conn) => conn.end());

  const client = new Client();
  await client.connect({
    host,
    port,
    username: 'anna',
    privateKey: key.private,
    hostVerifier: () => true,
  });
  assert(algos.length > 0);
  for (const algo of algos) assertEquals(algo, 'ssh-rsa/sha512');

  client.end();
  server.close();
});

Deno.test('client: a refused exec request settles accepted=false and closes', async () => {
  const { server, host, port } = await startServer((ctx) => ctx.accept(), (conn) => {
    conn.on('session', (accept: () => Session | undefined) => {
      const session = accept()!;
      session.on('exec', (_accept, reject) => reject?.());
    });
  });

  const client = new Client();
  await client.connect({ host, port, username: 'anna', password: 'x', hostVerifier: () => true });
  const channel = await client.exec('true');
  const closed = new Promise<void>((resolve) => channel.on('close', () => resolve()));
  assertEquals(await channel.accepted, false);
  await closed;

  client.end();
  server.close();
});

Deno.test('client: an accepted exec request settles accepted=true', async () => {
  const { server, host, port } = await startServer((ctx) => ctx.accept(), (conn) => {
    conn.on('session', (accept: () => Session | undefined) => {
      const session = accept()!;
      session.on('exec', (acceptExec) => {
        const stream = acceptExec()!;
        stream.exit(0);
        stream.end();
      });
    });
  });

  const client = new Client();
  await client.connect({ host, port, username: 'anna', password: 'x', hostVerifier: () => true });
  const channel = await client.exec('true');
  const closed = new Promise<void>((resolve) => channel.on('close', () => resolve()));
  assertEquals(await channel.accepted, true);
  await closed;

  client.end();
  server.close();
});
