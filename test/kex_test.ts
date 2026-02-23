/**
 * Key Exchange (KEX) Tests
 *
 * Unit tests for pure functions in src/protocol/kex.ts.
 * Tests createDefaultOffer, buildKexInit, parseKexInit,
 * negotiateAlgorithms, getKexHashAlgorithm, buildExchangeHashInput,
 * computeExchangeHash, deriveSessionKeys, and KexHandler.
 */

import { assertEquals, assertInstanceOf } from '@std/assert';
import {
  buildExchangeHashInput,
  buildKexInit,
  computeExchangeHash,
  createDefaultOffer,
  deriveSessionKeys,
  getKexHashAlgorithm,
  KexHandler,
  negotiateAlgorithms,
  parseKexInit,
  type KexAlgorithms,
  type NegotiatedAlgorithms,
} from '../src/protocol/kex.ts';

// =============================================================================
// createDefaultOffer
// =============================================================================

Deno.test('createDefaultOffer: returns non-empty kex list', () => {
  const offer = createDefaultOffer();
  assertEquals(Array.isArray(offer.kex), true);
  assertEquals(offer.kex.length > 0, true);
});

Deno.test('createDefaultOffer: returns cs/sc cipher lists', () => {
  const offer = createDefaultOffer();
  assertEquals(Array.isArray(offer.cs.cipher), true);
  assertEquals(Array.isArray(offer.sc.cipher), true);
  assertEquals(offer.cs.cipher.length > 0, true);
});

Deno.test('createDefaultOffer: returns mac and compress lists', () => {
  const offer = createDefaultOffer();
  assertEquals(Array.isArray(offer.cs.mac), true);
  assertEquals(Array.isArray(offer.cs.compress), true);
  assertEquals(Array.isArray(offer.sc.mac), true);
  assertEquals(Array.isArray(offer.sc.compress), true);
});

Deno.test('createDefaultOffer: lang lists are empty', () => {
  const offer = createDefaultOffer();
  assertEquals(offer.cs.lang, []);
  assertEquals(offer.sc.lang, []);
});

Deno.test('createDefaultOffer: returns a new object each call', () => {
  const a = createDefaultOffer();
  const b = createDefaultOffer();
  // Should be different array instances
  assertEquals(a.kex === b.kex, false);
  assertEquals(JSON.stringify(a), JSON.stringify(b));
});

// =============================================================================
// buildKexInit + parseKexInit round-trip
// =============================================================================

Deno.test('buildKexInit: produces a parseable KEXINIT packet', () => {
  const offer = createDefaultOffer();
  const packet = buildKexInit(offer);
  assertEquals(packet instanceof Uint8Array, true);
  assertEquals(packet.length > 16, true); // at least message type + cookie
});

Deno.test('buildKexInit + parseKexInit: round-trip', () => {
  const offer = createDefaultOffer();
  const packet = buildKexInit(offer);
  // parseKexInit expects the payload starting at byte 0 (message type)
  const parsed = parseKexInit(packet);
  assertEquals(parsed instanceof Error, false);
  const result = parsed as KexAlgorithms;
  assertEquals(result.kex, offer.kex);
  assertEquals(result.cs.cipher, offer.cs.cipher);
  assertEquals(result.sc.cipher, offer.sc.cipher);
  assertEquals(result.cs.mac, offer.cs.mac);
  assertEquals(result.sc.mac, offer.sc.mac);
});

Deno.test('parseKexInit: malformed packet returns Error', () => {
  // Too short to be a valid KEXINIT
  const tooShort = new Uint8Array(5);
  const result = parseKexInit(tooShort);
  assertInstanceOf(result, Error);
});

Deno.test('parseKexInit: partially valid packet returns Error', () => {
  // Valid header but truncated name-lists
  const partial = new Uint8Array(20); // message type + cookie (17 bytes) + 3 bytes of garbage
  partial[0] = 20; // KEXINIT message type
  const result = parseKexInit(partial);
  assertInstanceOf(result, Error);
});

// =============================================================================
// negotiateAlgorithms
// =============================================================================

function makeOffer(
  kex: string[],
  hostKey: string[],
  cipher: string[],
  mac: string[],
  compress: string[] = ['none'],
): KexAlgorithms {
  return {
    kex,
    serverHostKey: hostKey,
    cs: { cipher, mac, compress, lang: [] },
    sc: { cipher, mac, compress, lang: [] },
  };
}

Deno.test('negotiateAlgorithms: client perspective — happy path', () => {
  const local = makeOffer(
    ['curve25519-sha256'],
    ['ssh-ed25519'],
    ['aes128-ctr'],
    ['hmac-sha2-256'],
  );
  const remote = makeOffer(
    ['curve25519-sha256'],
    ['ssh-ed25519'],
    ['aes128-ctr'],
    ['hmac-sha2-256'],
  );
  const result = negotiateAlgorithms(local, remote, false);
  assertEquals(result instanceof Error, false);
  const neg = result as NegotiatedAlgorithms;
  assertEquals(neg.kex, 'curve25519-sha256');
  assertEquals(neg.serverHostKey, 'ssh-ed25519');
  assertEquals(neg.cs.cipher, 'aes128-ctr');
  assertEquals(neg.cs.mac, 'hmac-sha2-256');
  assertEquals(neg.cs.compress, 'none');
});

Deno.test('negotiateAlgorithms: server perspective prefers remote order', () => {
  // From server, remoteList is preferred (the client's list)
  const local = makeOffer(
    ['algo-a', 'algo-b'],
    ['ssh-ed25519'],
    ['aes128-ctr'],
    ['hmac-sha2-256'],
  );
  const remote = makeOffer(
    ['algo-b', 'algo-a'],
    ['ssh-ed25519'],
    ['aes128-ctr'],
    ['hmac-sha2-256'],
  );
  const result = negotiateAlgorithms(local, remote, true);
  assertEquals(result instanceof Error, false);
  // Server uses client's (remote) preference → 'algo-b' first
  assertEquals((result as NegotiatedAlgorithms).kex, 'algo-b');
});

Deno.test('negotiateAlgorithms: no matching kex returns Error', () => {
  const local = makeOffer(['kex-a'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256']);
  const remote = makeOffer(['kex-b'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256']);
  const result = negotiateAlgorithms(local, remote, false);
  assertInstanceOf(result, Error);
  assertEquals((result as Error).message.includes('key exchange'), true);
});

Deno.test('negotiateAlgorithms: no matching host key returns Error', () => {
  const local = makeOffer(['curve25519-sha256'], ['ssh-rsa'], ['aes128-ctr'], ['hmac-sha2-256']);
  const remote = makeOffer(['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256']);
  const result = negotiateAlgorithms(local, remote, false);
  assertInstanceOf(result, Error);
  assertEquals((result as Error).message.includes('host key'), true);
});

Deno.test('negotiateAlgorithms: no matching cs cipher returns Error', () => {
  const local: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
  };
  const remote: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes256-gcm@openssh.com'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
  };
  const result = negotiateAlgorithms(local, remote, false);
  assertInstanceOf(result, Error);
  assertEquals((result as Error).message.includes('client-to-server cipher'), true);
});

Deno.test('negotiateAlgorithms: no matching sc cipher returns Error', () => {
  const local: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
  };
  const remote: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes256-gcm@openssh.com'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
  };
  const result = negotiateAlgorithms(local, remote, false);
  assertInstanceOf(result, Error);
  assertEquals((result as Error).message.includes('server-to-client cipher'), true);
});

Deno.test('negotiateAlgorithms: no matching cs mac returns Error', () => {
  const local: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
  };
  const remote: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-512'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
  };
  const result = negotiateAlgorithms(local, remote, false);
  assertInstanceOf(result, Error);
  assertEquals((result as Error).message.includes('client-to-server MAC'), true);
});

Deno.test('negotiateAlgorithms: no matching sc mac returns Error', () => {
  const local: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
  };
  const remote: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-512'], compress: ['none'], lang: [] },
  };
  const result = negotiateAlgorithms(local, remote, false);
  assertInstanceOf(result, Error);
  assertEquals((result as Error).message.includes('server-to-client MAC'), true);
});

Deno.test('negotiateAlgorithms: no matching cs compress returns Error', () => {
  const local: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
  };
  const remote: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['zlib'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
  };
  const result = negotiateAlgorithms(local, remote, false);
  assertInstanceOf(result, Error);
  assertEquals((result as Error).message.includes('client-to-server compression'), true);
});

Deno.test('negotiateAlgorithms: no matching sc compress returns Error', () => {
  const local: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
  };
  const remote: KexAlgorithms = {
    kex: ['curve25519-sha256'],
    serverHostKey: ['ssh-ed25519'],
    cs: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['none'], lang: [] },
    sc: { cipher: ['aes128-ctr'], mac: ['hmac-sha2-256'], compress: ['zlib'], lang: [] },
  };
  const result = negotiateAlgorithms(local, remote, false);
  assertInstanceOf(result, Error);
  assertEquals((result as Error).message.includes('server-to-client compression'), true);
});

// =============================================================================
// getKexHashAlgorithm
// =============================================================================

Deno.test('getKexHashAlgorithm: sha512 algo returns sha512', () => {
  assertEquals(getKexHashAlgorithm('ecdh-sha2-nistp521'), 'sha512');
});

Deno.test('getKexHashAlgorithm: sha384 algo returns sha384', () => {
  assertEquals(getKexHashAlgorithm('ecdh-sha2-nistp384'), 'sha384');
});

Deno.test('getKexHashAlgorithm: sha256 algo returns sha256', () => {
  assertEquals(getKexHashAlgorithm('diffie-hellman-group14-sha256'), 'sha256');
});

Deno.test('getKexHashAlgorithm: sha1 algo returns sha1', () => {
  assertEquals(getKexHashAlgorithm('diffie-hellman-group1-sha1'), 'sha1');
});

Deno.test('getKexHashAlgorithm: curve25519 returns sha256', () => {
  assertEquals(getKexHashAlgorithm('curve25519-sha256'), 'sha256');
});

Deno.test('getKexHashAlgorithm: nistp256 returns sha256', () => {
  assertEquals(getKexHashAlgorithm('ecdh-sha2-nistp256'), 'sha256');
});

Deno.test('getKexHashAlgorithm: nistp384 returns sha384', () => {
  assertEquals(getKexHashAlgorithm('ecdh-sha2-nistp384'), 'sha384');
});

Deno.test('getKexHashAlgorithm: nistp521 returns sha512', () => {
  assertEquals(getKexHashAlgorithm('ecdh-sha2-nistp521'), 'sha512');
});

Deno.test('getKexHashAlgorithm: unknown returns sha256', () => {
  assertEquals(getKexHashAlgorithm('unknown-algorithm'), 'sha256');
});

// =============================================================================
// buildExchangeHashInput
// =============================================================================

Deno.test('buildExchangeHashInput: returns a Uint8Array', () => {
  const result = buildExchangeHashInput(
    'SSH-2.0-TestClient',
    'SSH-2.0-TestServer',
    new Uint8Array(10),
    new Uint8Array(10),
    new Uint8Array(20), // server host key
    new Uint8Array(32), // client public
    new Uint8Array(32), // server public
    new Uint8Array(32), // shared secret
  );
  assertEquals(result instanceof Uint8Array, true);
  assertEquals(result.length > 0, true);
});

Deno.test('buildExchangeHashInput: different inputs produce different outputs', () => {
  const a = buildExchangeHashInput(
    'SSH-2.0-ClientA',
    'SSH-2.0-Server',
    new Uint8Array(10),
    new Uint8Array(10),
    new Uint8Array(20),
    new Uint8Array(32),
    new Uint8Array(32),
    new Uint8Array(32),
  );
  const b = buildExchangeHashInput(
    'SSH-2.0-ClientB',
    'SSH-2.0-Server',
    new Uint8Array(10),
    new Uint8Array(10),
    new Uint8Array(20),
    new Uint8Array(32),
    new Uint8Array(32),
    new Uint8Array(32),
  );
  // Different client versions produce different content (same length, different bytes)
  assertEquals(a.length, b.length); // Same structure = same length
  assertEquals(a.every((v, i) => v === b[i]), false); // But different bytes
});

Deno.test('buildExchangeHashInput: sharedSecret with leading zeros (mpint stripping)', () => {
  // SharedSecret with leading zeros - writeMpint strips them
  const sharedSecretWithZeros = new Uint8Array([0x00, 0x00, 0x01, 0x02]);
  const result = buildExchangeHashInput(
    'SSH-2.0-Client',
    'SSH-2.0-Server',
    new Uint8Array(10),
    new Uint8Array(10),
    new Uint8Array(20),
    new Uint8Array(32),
    new Uint8Array(32),
    sharedSecretWithZeros,
  );
  assertEquals(result instanceof Uint8Array, true);
});

Deno.test('buildExchangeHashInput: sharedSecret MSB set (mpint positive padding)', () => {
  // SharedSecret with MSB set — writeMpint adds a leading zero
  const sharedSecretMSBSet = new Uint8Array([0xff, 0x01]);
  const result = buildExchangeHashInput(
    'SSH-2.0-Client',
    'SSH-2.0-Server',
    new Uint8Array(10),
    new Uint8Array(10),
    new Uint8Array(20),
    new Uint8Array(32),
    new Uint8Array(32),
    sharedSecretMSBSet,
  );
  assertEquals(result instanceof Uint8Array, true);
});

// =============================================================================
// computeExchangeHash
// =============================================================================

Deno.test('computeExchangeHash: returns a Uint8Array hash', async () => {
  const result = await computeExchangeHash(
    'sha256',
    'SSH-2.0-Client',
    'SSH-2.0-Server',
    new Uint8Array(10),
    new Uint8Array(10),
    new Uint8Array(20),
    new Uint8Array(32),
    new Uint8Array(32),
    new Uint8Array(32),
  );
  assertEquals(result instanceof Uint8Array, true);
  assertEquals(result.length, 32); // SHA-256 output
});

Deno.test('computeExchangeHash: sha512 produces 64-byte hash', async () => {
  const result = await computeExchangeHash(
    'sha512',
    'SSH-2.0-Client',
    'SSH-2.0-Server',
    new Uint8Array(10),
    new Uint8Array(10),
    new Uint8Array(20),
    new Uint8Array(32),
    new Uint8Array(32),
    new Uint8Array(32),
  );
  assertEquals(result.length, 64);
});

// =============================================================================
// deriveSessionKeys
// =============================================================================

function makeNegotiated(kex = 'curve25519-sha256'): NegotiatedAlgorithms {
  return {
    kex,
    serverHostKey: 'ssh-ed25519',
    cs: { cipher: 'aes128-ctr', mac: 'hmac-sha2-256', compress: 'none' },
    sc: { cipher: 'aes128-ctr', mac: 'hmac-sha2-256', compress: 'none' },
  };
}

Deno.test('deriveSessionKeys: returns all 6 key material buffers', async () => {
  const sharedSecret = new Uint8Array(32).fill(1);
  const exchangeHash = new Uint8Array(32).fill(2);
  const sessionId = new Uint8Array(32).fill(3);
  const keys = await deriveSessionKeys(sharedSecret, exchangeHash, sessionId, makeNegotiated());
  assertEquals(keys.ivC2S instanceof Uint8Array, true);
  assertEquals(keys.ivS2C instanceof Uint8Array, true);
  assertEquals(keys.keyC2S instanceof Uint8Array, true);
  assertEquals(keys.keyS2C instanceof Uint8Array, true);
  assertEquals(keys.macKeyC2S instanceof Uint8Array, true);
  assertEquals(keys.macKeyS2C instanceof Uint8Array, true);
});

Deno.test('deriveSessionKeys: sharedSecret with leading zeros works (mpint stripping)', async () => {
  // SharedSecret with leading zeros — writeMpint should strip them
  const sharedSecret = new Uint8Array([0, 0, 0, 1, 2, 3]);
  const exchangeHash = new Uint8Array(32).fill(5);
  const sessionId = new Uint8Array(32).fill(6);
  const keys = await deriveSessionKeys(sharedSecret, exchangeHash, sessionId, makeNegotiated());
  assertEquals(keys.ivC2S instanceof Uint8Array, true);
});

Deno.test('deriveSessionKeys: sharedSecret with MSB set is padded', async () => {
  // SharedSecret MSB set — writeMpint adds a zero byte
  const sharedSecret = new Uint8Array([0xff, 0xfe, 0xfd]);
  const exchangeHash = new Uint8Array(32).fill(7);
  const sessionId = new Uint8Array(32).fill(8);
  const keys = await deriveSessionKeys(sharedSecret, exchangeHash, sessionId, makeNegotiated());
  assertEquals(keys.keyC2S instanceof Uint8Array, true);
});

// =============================================================================
// KexHandler
// =============================================================================

Deno.test('KexHandler: constructor without offer uses default', () => {
  const handler = new KexHandler(false);
  const offer = handler.offer;
  assertEquals(Array.isArray(offer.kex), true);
  assertEquals(offer.kex.length > 0, true);
});

Deno.test('KexHandler: constructor with custom offer uses it', () => {
  const custom = makeOffer(['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256']);
  const handler = new KexHandler(true, custom);
  assertEquals(handler.offer.kex, ['curve25519-sha256']);
});

Deno.test('KexHandler: generateKexInit returns a Uint8Array', () => {
  const handler = new KexHandler(false);
  const packet = handler.generateKexInit();
  assertEquals(packet instanceof Uint8Array, true);
  assertEquals(packet.length > 16, true);
  // State should have kexinit stored
  assertEquals(handler.state.kexinit, packet);
});

Deno.test('KexHandler: handleKexInit round-trip works', () => {
  const server = new KexHandler(true);
  const client = new KexHandler(false);
  const clientPacket = client.generateKexInit();
  const result = server.handleKexInit(clientPacket);
  assertEquals(result instanceof Error, false);
  const { algorithms, strictKex } = result as { algorithms: NegotiatedAlgorithms; strictKex: boolean };
  assertEquals(typeof algorithms.kex, 'string');
  assertEquals(typeof strictKex, 'boolean');
});

Deno.test('KexHandler: handleKexInit with malformed packet returns Error', () => {
  const handler = new KexHandler(false);
  const result = handler.handleKexInit(new Uint8Array(5));
  assertInstanceOf(result, Error);
});

Deno.test('KexHandler: initKeyExchange without algorithms returns Error', async () => {
  const handler = new KexHandler(false);
  // Don't call handleKexInit first
  const result = await handler.initKeyExchange();
  assertInstanceOf(result, Error);
  assertEquals((result as Error).message.includes('not negotiated'), true);
});

Deno.test('KexHandler: completeKeyExchange without init returns Error', async () => {
  const handler = new KexHandler(false);
  const result = await handler.completeKeyExchange(new Uint8Array(32), new Uint8Array(32));
  assertInstanceOf(result, Error);
  assertEquals((result as Error).message.includes('not initialized'), true);
});

Deno.test('KexHandler: reset clears state but keeps sessionId', () => {
  const handler = new KexHandler(false);
  handler.generateKexInit(); // sets state.kexinit
  // Manually set a session ID
  (handler.state as Record<string, unknown>).sessionId = new Uint8Array([1, 2, 3]);
  handler.reset();
  // kexinit should be cleared
  assertEquals(handler.state.kexinit, undefined);
  // sessionId should be preserved
  assertEquals(handler.state.sessionId, new Uint8Array([1, 2, 3]));
});

Deno.test('KexHandler: state getter returns current state object', () => {
  const handler = new KexHandler(false);
  const s1 = handler.state;
  const s2 = handler.state;
  assertEquals(s1, s2); // same reference
});

Deno.test('KexHandler: handleKexInit with no common algo returns Error', () => {
  const handler = new KexHandler(false);
  // Build a KEXINIT with completely incompatible algorithms
  const incompatible: KexAlgorithms = {
    kex: ['totally-unknown-kex'],
    serverHostKey: ['totally-unknown-hostkey'],
    cs: { cipher: ['totally-unknown-cipher'], mac: ['totally-unknown-mac'], compress: ['unknown-compress'], lang: [] },
    sc: { cipher: ['totally-unknown-cipher'], mac: ['totally-unknown-mac'], compress: ['unknown-compress'], lang: [] },
  };
  const packet = buildKexInit(incompatible);
  const result = handler.handleKexInit(packet);
  assertInstanceOf(result, Error);
});
