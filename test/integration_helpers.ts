/**
 * Integration Test Helpers
 *
 * Deno equivalent of common.js - provides utilities for client/server integration tests.
 */

import { fail } from '@std/assert';
import { Client } from '../src/client.ts';
import { type Connection, Server, type ServerAuthContext } from '../src/server.ts';
import {
  type ParsedKey,
  parseKey,
  SYM_DECRYPTED,
  SYM_HASH_ALGO,
  SYM_PRIV_PEM,
  SYM_PUB_PEM,
  SYM_PUB_SSH,
} from '../src/protocol/keyParser.ts';
import { allocBytes, toBase64, writeUInt32BE } from '../src/utils/binary.ts';

export const FIXTURES_PATH = new URL('./fixtures', import.meta.url).pathname;

const DEFAULT_TEST_TIMEOUT = 30 * 1000;

// ============================================================================
// Test Host Key Generation
// ============================================================================

/**
 * Generate a test host key that can be used with the Server.
 * This creates a ParsedKey-compatible object with working sign/verify methods.
 *
 * This is needed because parseKey() doesn't support parsing private keys
 * from OpenSSH format (BEGIN OPENSSH PRIVATE KEY).
 */
export interface TestHostKey {
  parsedKey: ParsedKey;
  privateKeyPem: string;
  publicKeyPem: string;
  publicKeySSH: Uint8Array;
}

/**
 * Create PEM-formatted string from binary data
 */
function makePEM(type: string, data: Uint8Array): string {
  const b64 = toBase64(data);
  let formatted = b64.replace(/.{64}/g, '$&\n');
  if (b64.length % 64 !== 0) {
    formatted += '\n';
  }
  return `-----BEGIN ${type} KEY-----\n${formatted}-----END ${type} KEY-----`;
}

/**
 * Generate RSA test host key
 */
export async function generateTestHostKeyRSA(bits = 2048): Promise<TestHostKey> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;

  const pubSpki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const privPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  // Extract RSA public key components from SPKI for SSH format
  // SPKI format: SEQUENCE { AlgorithmIdentifier, BIT STRING { SEQUENCE { n, e } } }
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

  // Base64url decode n and e
  const n = base64urlToBytes(jwk.n!);
  const e = base64urlToBytes(jwk.e!);

  // Create SSH format public key: length + "ssh-rsa" + length + e + length + n
  const publicKeySSH = allocBytes(4 + 7 + 4 + e.length + 4 + n.length);
  const encoder = new TextEncoder();

  writeUInt32BE(publicKeySSH, 7, 0);
  publicKeySSH.set(encoder.encode('ssh-rsa'), 4);

  let offset = 4 + 7;
  writeUInt32BE(publicKeySSH, e.length, offset);
  publicKeySSH.set(e, offset + 4);

  offset += 4 + e.length;
  writeUInt32BE(publicKeySSH, n.length, offset);
  publicKeySSH.set(n, offset + 4);

  const privateKeyPem = makePEM('PRIVATE', privPkcs8);
  const publicKeyPem = makePEM('PUBLIC', pubSpki);

  const parsedKey: ParsedKey = {
    type: 'ssh-rsa',
    comment: '',
    async sign(data: Uint8Array, algo?: string): Promise<Uint8Array | Error> {
      try {
        // Determine hash algorithm
        let hash = 'SHA-256';
        if (algo === 'sha1' || algo === 'ssh-rsa') hash = 'SHA-1';
        else if (algo === 'sha512' || algo === 'rsa-sha2-512') hash = 'SHA-512';

        // Re-import with correct hash
        const key = await crypto.subtle.importKey(
          'pkcs8',
          privPkcs8 as BufferSource,
          { name: 'RSASSA-PKCS1-v1_5', hash },
          false,
          ['sign'],
        );
        const signature = await crypto.subtle.sign(
          'RSASSA-PKCS1-v1_5',
          key,
          data as BufferSource,
        );
        return new Uint8Array(signature);
      } catch (err) {
        return err as Error;
      }
    },
    async verify(data: Uint8Array, signature: Uint8Array, algo?: string): Promise<boolean | Error> {
      try {
        let hash = 'SHA-256';
        if (algo === 'sha1' || algo === 'ssh-rsa') hash = 'SHA-1';
        else if (algo === 'sha512' || algo === 'rsa-sha2-512') hash = 'SHA-512';

        const key = await crypto.subtle.importKey(
          'spki',
          pubSpki as BufferSource,
          { name: 'RSASSA-PKCS1-v1_5', hash },
          false,
          ['verify'],
        );
        return await crypto.subtle.verify(
          'RSASSA-PKCS1-v1_5',
          key,
          signature as BufferSource,
          data as BufferSource,
        );
      } catch (err) {
        return err as Error;
      }
    },
    isPrivateKey(): boolean {
      return true;
    },
    getPrivatePEM(): string | null {
      return privateKeyPem;
    },
    getPublicPEM(): string | null {
      return publicKeyPem;
    },
    getPublicSSH(): Uint8Array | null {
      return publicKeySSH;
    },
    equals(_key: ParsedKey | string | Uint8Array): boolean {
      return false; // Simplified for tests
    },
    [SYM_HASH_ALGO]: 'sha256',
    [SYM_PRIV_PEM]: privateKeyPem,
    [SYM_PUB_PEM]: publicKeyPem,
    [SYM_PUB_SSH]: publicKeySSH,
    [SYM_DECRYPTED]: true,
  };

  return { parsedKey, privateKeyPem, publicKeyPem, publicKeySSH };
}

/**
 * Generate Ed25519 test host key
 */
export async function generateTestHostKeyEd25519(): Promise<TestHostKey> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;

  const pubSpki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const privPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  // Extract public key bytes from SPKI (last 32 bytes for Ed25519)
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));

  // Create SSH format public key: length + "ssh-ed25519" + length + pub
  const publicKeySSH = allocBytes(4 + 11 + 4 + pubRaw.length);
  const encoder = new TextEncoder();

  writeUInt32BE(publicKeySSH, 11, 0);
  publicKeySSH.set(encoder.encode('ssh-ed25519'), 4);

  writeUInt32BE(publicKeySSH, pubRaw.length, 15);
  publicKeySSH.set(pubRaw, 19);

  const privateKeyPem = makePEM('PRIVATE', privPkcs8);
  const publicKeyPem = makePEM('PUBLIC', pubSpki);

  // Store references to keys for closures
  const privKey = keyPair.privateKey;
  const pubKey = keyPair.publicKey;

  const parsedKey: ParsedKey = {
    type: 'ssh-ed25519',
    comment: '',
    async sign(data: Uint8Array): Promise<Uint8Array | Error> {
      try {
        const signature = await crypto.subtle.sign(
          'Ed25519',
          privKey,
          data as BufferSource,
        );
        return new Uint8Array(signature);
      } catch (err) {
        return err as Error;
      }
    },
    async verify(data: Uint8Array, signature: Uint8Array): Promise<boolean | Error> {
      try {
        return await crypto.subtle.verify(
          'Ed25519',
          pubKey,
          signature as BufferSource,
          data as BufferSource,
        );
      } catch (err) {
        return err as Error;
      }
    },
    isPrivateKey(): boolean {
      return true;
    },
    getPrivatePEM(): string | null {
      return privateKeyPem;
    },
    getPublicPEM(): string | null {
      return publicKeyPem;
    },
    getPublicSSH(): Uint8Array | null {
      return publicKeySSH;
    },
    equals(_key: ParsedKey | string | Uint8Array): boolean {
      return false; // Simplified for tests
    },
    [SYM_HASH_ALGO]: null,
    [SYM_PRIV_PEM]: privateKeyPem,
    [SYM_PUB_PEM]: publicKeyPem,
    [SYM_PUB_SSH]: publicKeySSH,
    [SYM_DECRYPTED]: true,
  };

  return { parsedKey, privateKeyPem, publicKeyPem, publicKeySSH };
}

/**
 * Generate ECDSA test host key (P-256)
 */
export async function generateTestHostKeyECDSA(): Promise<TestHostKey> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;

  const pubSpki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const privPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  // Get raw public key for SSH format
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));

  // Create SSH format public key: length + "ecdsa-sha2-nistp256" + length + "nistp256" + length + point
  const keyType = 'ecdsa-sha2-nistp256';
  const curveName = 'nistp256';
  const encoder = new TextEncoder();

  const publicKeySSH = allocBytes(4 + keyType.length + 4 + curveName.length + 4 + rawPub.length);
  let offset = 0;

  writeUInt32BE(publicKeySSH, keyType.length, offset);
  publicKeySSH.set(encoder.encode(keyType), offset + 4);
  offset += 4 + keyType.length;

  writeUInt32BE(publicKeySSH, curveName.length, offset);
  publicKeySSH.set(encoder.encode(curveName), offset + 4);
  offset += 4 + curveName.length;

  writeUInt32BE(publicKeySSH, rawPub.length, offset);
  publicKeySSH.set(rawPub, offset + 4);

  const privateKeyPem = makePEM('PRIVATE', privPkcs8);
  const publicKeyPem = makePEM('PUBLIC', pubSpki);

  // Store references to keys for closures
  const privKey = keyPair.privateKey;
  const pubKey = keyPair.publicKey;

  const parsedKey: ParsedKey = {
    type: 'ecdsa-sha2-nistp256',
    comment: '',
    async sign(data: Uint8Array): Promise<Uint8Array | Error> {
      try {
        const signature = await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          privKey,
          data as BufferSource,
        );
        // Convert from WebCrypto format (r||s) to SSH format (length + r + length + s)
        const sigBytes = new Uint8Array(signature);
        const r = sigBytes.slice(0, 32);
        const s = sigBytes.slice(32);

        // Add leading zero if MSB is set (to make it positive in SSH format)
        const rPad = r[0] >= 0x80 ? 1 : 0;
        const sPad = s[0] >= 0x80 ? 1 : 0;

        const sshSig = allocBytes(4 + rPad + r.length + 4 + sPad + s.length);
        let off = 0;

        writeUInt32BE(sshSig, rPad + r.length, off);
        if (rPad) sshSig[off + 4] = 0;
        sshSig.set(r, off + 4 + rPad);
        off += 4 + rPad + r.length;

        writeUInt32BE(sshSig, sPad + s.length, off);
        if (sPad) sshSig[off + 4] = 0;
        sshSig.set(s, off + 4 + sPad);

        return sshSig;
      } catch (err) {
        return err as Error;
      }
    },
    async verify(data: Uint8Array, signature: Uint8Array): Promise<boolean | Error> {
      try {
        // Convert from SSH format to WebCrypto format
        // SSH format: length + r + length + s
        // WebCrypto format: r || s (64 bytes for P-256)
        const view = new DataView(signature.buffer, signature.byteOffset);
        const rLen = view.getUint32(0);
        const rStart = 4;
        const sLenOffset = 4 + rLen;
        const sLen = view.getUint32(sLenOffset);
        const sStart = sLenOffset + 4;

        let r = signature.slice(rStart, rStart + rLen);
        let s = signature.slice(sStart, sStart + sLen);

        // Remove leading zeros if present
        if (r.length > 32 && r[0] === 0) r = r.slice(1);
        if (s.length > 32 && s[0] === 0) s = s.slice(1);

        // Pad to 32 bytes if needed
        if (r.length < 32) {
          const padded = new Uint8Array(32);
          padded.set(r, 32 - r.length);
          r = padded;
        }
        if (s.length < 32) {
          const padded = new Uint8Array(32);
          padded.set(s, 32 - s.length);
          s = padded;
        }

        const webCryptoSig = new Uint8Array(64);
        webCryptoSig.set(r, 0);
        webCryptoSig.set(s, 32);

        return await crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          pubKey,
          webCryptoSig as BufferSource,
          data as BufferSource,
        );
      } catch (err) {
        return err as Error;
      }
    },
    isPrivateKey(): boolean {
      return true;
    },
    getPrivatePEM(): string | null {
      return privateKeyPem;
    },
    getPublicPEM(): string | null {
      return publicKeyPem;
    },
    getPublicSSH(): Uint8Array | null {
      return publicKeySSH;
    },
    equals(_key: ParsedKey | string | Uint8Array): boolean {
      return false; // Simplified for tests
    },
    [SYM_HASH_ALGO]: 'sha256',
    [SYM_PRIV_PEM]: privateKeyPem,
    [SYM_PUB_PEM]: publicKeyPem,
    [SYM_PUB_SSH]: publicKeySSH,
    [SYM_DECRYPTED]: true,
  };

  return { parsedKey, privateKeyPem, publicKeyPem, publicKeySSH };
}

/**
 * Helper to convert base64url to Uint8Array
 */
function base64urlToBytes(b64url: string): Uint8Array {
  // Convert base64url to base64
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  while (b64.length % 4) b64 += '=';

  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  // For RSA parameters, we may need to add leading zero byte for positive integers
  if (bytes[0] >= 0x80) {
    const padded = new Uint8Array(bytes.length + 1);
    padded[0] = 0;
    padded.set(bytes, 1);
    return padded;
  }

  return bytes;
}

// Track must-call checks for cleanup
interface MustCallContext {
  name: string;
  expected: number;
  minimum?: number;
  actual: number;
  stack: string;
}

const mustCallChecks: MustCallContext[] = [];

/**
 * Clear all must-call checks (call at end of each test)
 */
export function clearMustCallChecks(): void {
  mustCallChecks.length = 0;
}

/**
 * Verify all must-call checks passed
 */
export function verifyMustCallChecks(): void {
  const failed = mustCallChecks.filter((ctx) => {
    if (ctx.minimum !== undefined) {
      return ctx.actual < ctx.minimum;
    }
    return ctx.actual !== ctx.expected;
  });

  if (failed.length > 0) {
    const messages = failed.map((ctx) => {
      const expectedStr = ctx.minimum !== undefined
        ? `at least ${ctx.minimum}`
        : `exactly ${ctx.expected}`;
      return `Function "${ctx.name}" was called ${ctx.actual} times, expected ${expectedStr}.\n${ctx.stack}`;
    });
    fail(messages.join('\n\n'));
  }

  clearMustCallChecks();
}

/**
 * Wrap a function to verify it gets called exactly `count` times
 */
// deno-lint-ignore no-explicit-any
export function mustCall<T extends (...args: any[]) => any>(
  fn?: T,
  count = 1,
): T {
  const actualFn = fn ?? (() => {}) as T;

  const ctx: MustCallContext = {
    name: actualFn.name || '<anonymous>',
    expected: count,
    actual: 0,
    stack: new Error().stack ?? '',
  };

  mustCallChecks.push(ctx);

  const wrapped = ((...args: Parameters<T>) => {
    ctx.actual++;
    return actualFn(...args);
  }) as T;

  return wrapped;
}

/**
 * Wrap a function to verify it gets called at least `min` times
 */
// deno-lint-ignore no-explicit-any
export function mustCallAtLeast<T extends (...args: any[]) => any>(
  fn?: T,
  min = 1,
): T {
  const actualFn = fn ?? (() => {}) as T;

  const ctx: MustCallContext = {
    name: actualFn.name || '<anonymous>',
    expected: min,
    minimum: min,
    actual: 0,
    stack: new Error().stack ?? '',
  };

  mustCallChecks.push(ctx);

  const wrapped = ((...args: Parameters<T>) => {
    ctx.actual++;
    return actualFn(...args);
  }) as T;

  return wrapped;
}

/**
 * Create a function that should never be called
 */
export function mustNotCall(msg?: string): (...args: unknown[]) => never {
  const stack = new Error().stack ?? '';
  return (...args: unknown[]) => {
    const argsInfo = args.length > 0 ? `\nCalled with arguments: ${JSON.stringify(args)}` : '';
    fail(`${msg || 'Function should not have been called'} at ${stack}${argsInfo}`);
  };
}

/**
 * Fixture key cache
 */
const fixtureKeyCache = new Map<string, { key: ParsedKey; raw: Uint8Array; fullPath: string }>();

/**
 * Read a fixture file
 */
export function fixture(file: string): Uint8Array {
  const fullPath = `${FIXTURES_PATH}/${file}`;
  return Deno.readFileSync(fullPath);
}

/**
 * Load and parse a key fixture
 */
export function fixtureKey(
  file: string,
  passphrase?: string,
  bypass = false,
): { key: ParsedKey; raw: Uint8Array; fullPath: string } {
  if (!bypass) {
    const cached = fixtureKeyCache.get(file);
    if (cached) return cached;
  }

  const fullPath = `${FIXTURES_PATH}/${file}`;
  const raw = fixture(file);
  const keyResult = parseKey(raw, passphrase);

  if (keyResult instanceof Error) {
    throw keyResult;
  }

  const key: ParsedKey = Array.isArray(keyResult) ? keyResult[0] : keyResult;

  const result = { key, raw, fullPath };
  fixtureKeyCache.set(file, result);
  return result;
}

/**
 * Setup configuration
 */
export interface SetupConfig {
  client?: {
    username?: string;
    password?: string;
    privateKey?: Uint8Array | string;
    passphrase?: string;
    tryKeyboard?: boolean;
    localUsername?: string;
    localHostname?: string;
    agent?: string;
    authHandler?: unknown;
  };
  server?: {
    hostKeys: (Uint8Array | string)[];
    ident?: string;
  };
  allReady?: () => void;
  timeout?: number;
  debug?: boolean;
  noForceClientReady?: boolean;
  noForceServerReady?: boolean;
  noClientError?: boolean;
  noServerError?: boolean;
}

/**
 * Setup result
 */
export interface SetupResult {
  client: Client;
  server: Server;
  cleanup: () => Promise<void>;
}

/**
 * Create a client/server test environment
 */
export async function setup(
  title: string,
  configs: SetupConfig,
): Promise<SetupResult> {
  const {
    client: clientCfg,
    server: serverCfg,
    allReady,
    timeout: timeout_ = DEFAULT_TEST_TIMEOUT,
    debug,
    noForceClientReady,
    noForceServerReady,
    noClientError,
    noServerError,
  } = configs;

  let clientReady = false;
  let serverReady = false;
  let clientClosed = false;
  let serverClosed = false;

  const msg = (text: string) => `${title}: ${text}`;

  // Create deferred promises for ready states
  const clientReadyPromise = Promise.withResolvers<void>();
  const serverReadyPromise = Promise.withResolvers<void>();
  const allClosedPromise = Promise.withResolvers<void>();

  // Timeout handling
  let timeoutId: number | undefined;
  if (timeout_ > 0) {
    timeoutId = setTimeout(() => {
      fail(msg('Test timed out'));
    }, timeout_);
  }

  const clearTimeoutIfSet = () => {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
      timeoutId = undefined;
    }
  };

  // Track cleanup
  const cleanupFns: (() => void | Promise<void> | Server)[] = [];

  // Create server
  if (!serverCfg) {
    throw new Error('Server config is required');
  }

  const server = new Server({
    hostKeys: serverCfg.hostKeys,
    ident: serverCfg.ident,
    debug: debug ? (msg: string) => console.log(`[${title}][SERVER]`, msg) : undefined,
  });

  cleanupFns.push(() => server.close());

  if (!noServerError) {
    server.on('error', (err) => {
      fail(msg(`Unexpected server error: ${err.stack}`));
    });
  }

  // Create client
  if (!clientCfg) {
    throw new Error('Client config is required');
  }

  const client = new Client();

  cleanupFns.push(() => client.end());

  if (!noClientError) {
    client.on('error', (err) => {
      fail(msg(`Unexpected client error: ${err.stack}`));
    });
  }

  // Track ready events
  const onClientReady = () => {
    if (clientReady) {
      fail(msg('Received multiple ready events for client'));
    }
    clientReady = true;
    clientReadyPromise.resolve();
    if (clientReady && serverReady && allReady) {
      allReady();
    }
  };

  const onServerReady = () => {
    if (serverReady) {
      fail(msg('Received multiple ready events for server'));
    }
    serverReady = true;
    serverReadyPromise.resolve();
    if (clientReady && serverReady && allReady) {
      allReady();
    }
  };

  // Track close events
  const onClientClose = () => {
    if (clientClosed) {
      fail(msg('Received multiple close events for client'));
    }
    clientClosed = true;
    if (clientClosed && serverClosed) {
      clearTimeoutIfSet();
      allClosedPromise.resolve();
    }
  };

  const onServerClose = () => {
    if (serverClosed) {
      fail(msg('Received multiple close events for server'));
    }
    serverClosed = true;
    if (clientClosed && serverClosed) {
      clearTimeoutIfSet();
      allClosedPromise.resolve();
    }
  };

  // Set up client events
  if (noForceClientReady) {
    client.on('ready', onClientReady);
  } else {
    client.on('ready', mustCall(onClientReady));
  }
  client.on('close', mustCall(onClientClose));

  // Set up server connection handling
  server.on(
    'connection',
    mustCall((conn: Connection) => {
      if (!noServerError) {
        conn.on('error', (err) => {
          fail(msg(`Unexpected connection error: ${err.stack}`));
        });
      }

      if (noForceServerReady) {
        conn.on('ready', onServerReady);
      } else {
        conn.on('ready', mustCall(onServerReady));
      }

      // Server close when connection ends
      conn.on('close', () => {
        server.close();
      });
    }),
  );

  server.on('close', mustCall(onServerClose));

  // Start server
  await server.listen(0, 'localhost');
  const addr = server.address();
  if (!addr) {
    throw new Error('Server failed to get address');
  }

  // Connect client
  try {
    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username: clientCfg.username ?? 'test',
      password: clientCfg.password,
      privateKey: clientCfg.privateKey,
      passphrase: clientCfg.passphrase,
      tryKeyboard: clientCfg.tryKeyboard,
      localUsername: clientCfg.localUsername,
      localHostname: clientCfg.localHostname,
      agent: clientCfg.agent,
      debug: debug ? (msg: string) => console.log(`[${title}][CLIENT]`, msg) : undefined,
    });
  } catch (ex) {
    const err = ex as Error;
    err.message = msg(err.message);
    throw err;
  }

  const cleanup = async () => {
    clearTimeoutIfSet();
    for (const fn of cleanupFns) {
      try {
        await fn();
      } catch {
        // Ignore cleanup errors
      }
    }
    verifyMustCallChecks();
  };

  return { client, server, cleanup };
}

/**
 * Simple setup with password authentication
 */
export async function setupSimple(
  title: string,
  debug = false,
): Promise<SetupResult & { conn: Connection }> {
  const hostKey = fixtureKey('ssh_host_rsa_key');
  let connRef: Connection | undefined;

  const result = await setup(title, {
    client: { username: 'Password User', password: '12345' },
    server: { hostKeys: [hostKey.raw] },
    debug,
  });

  // Set up simple authentication handler
  return new Promise((resolve) => {
    result.server.on(
      'connection',
      mustCall((conn: Connection) => {
        connRef = conn;
        conn.on(
          'authentication',
          mustCall((ctx: ServerAuthContext) => {
            ctx.accept();
          }),
        );
        conn.on('ready', () => {
          resolve({ ...result, conn: connRef! });
        });
      }),
    );
  });
}

/**
 * Wait for an event with timeout
 */
export function waitForEvent<T>(
  emitter: { on: (event: string, cb: (...args: unknown[]) => void) => void },
  event: string,
  timeout = 5000,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Timeout waiting for event: ${event}`));
    }, timeout);

    emitter.on(event, (...args: unknown[]) => {
      clearTimeout(timer);
      resolve(args[0] as T);
    });
  });
}

/**
 * Collect data from a stream until it ends
 */
export async function collectData(
  stream: ReadableStream<Uint8Array>,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  const reader = stream.getReader();

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  // Concatenate all chunks
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result;
}

/**
 * Write data to a writable stream
 */
export async function writeData(
  stream: WritableStream<Uint8Array>,
  data: Uint8Array | string,
): Promise<void> {
  const writer = stream.getWriter();
  try {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    await writer.write(bytes);
  } finally {
    writer.releaseLock();
  }
}
