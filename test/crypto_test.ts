/**
 * Tests for crypto module
 */

import { assertEquals } from '@std/assert';
import {
  hash,
  hashLength,
  hmac,
  hmacVerify,
  randomBytes,
  randomFill,
  timingSafeEqual,
  xorBytes,
} from '../src/crypto/mod.ts';
import { toHex } from '../src/utils/binary.ts';

// Random tests
Deno.test('randomBytes generates correct length', () => {
  const bytes = randomBytes(32);
  assertEquals(bytes.length, 32);
});

Deno.test('randomBytes generates different values', () => {
  const a = randomBytes(16);
  const b = randomBytes(16);
  assertEquals(toHex(a) !== toHex(b), true);
});

Deno.test('randomFill fills buffer with random data', () => {
  const buf = new Uint8Array(16);
  randomFill(buf);
  assertEquals(buf.some((b) => b !== 0), true);
});

Deno.test('randomFill respects offset and size', () => {
  const buf = new Uint8Array(16);
  buf.fill(0);
  randomFill(buf, 4, 8);
  // First 4 bytes should still be zero
  assertEquals(buf.slice(0, 4).every((b) => b === 0), true);
  // Last 4 bytes should still be zero
  assertEquals(buf.slice(12).every((b) => b === 0), true);
  // Middle 8 bytes should have some non-zero values (statistically)
});

// Hash tests
Deno.test('hash SHA-256 produces correct output', async () => {
  const data = new TextEncoder().encode('hello');
  const result = await hash('sha256', data);
  assertEquals(result.length, 32);
  // Known SHA-256 hash of 'hello'
  assertEquals(
    toHex(result),
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
  );
});

Deno.test('hash SHA-1 produces correct output', async () => {
  const data = new TextEncoder().encode('hello');
  const result = await hash('sha1', data);
  assertEquals(result.length, 20);
  assertEquals(toHex(result), 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d');
});

Deno.test('hash SHA-512 produces correct output', async () => {
  const data = new TextEncoder().encode('hello');
  const result = await hash('sha512', data);
  assertEquals(result.length, 64);
});

Deno.test('hashLength returns correct values', () => {
  assertEquals(hashLength('sha1'), 20);
  assertEquals(hashLength('sha256'), 32);
  assertEquals(hashLength('sha384'), 48);
  assertEquals(hashLength('sha512'), 64);
});

// HMAC tests
Deno.test('hmac produces correct output', async () => {
  const key = new TextEncoder().encode('secret');
  const data = new TextEncoder().encode('hello');
  const result = await hmac('sha256', key, data);
  assertEquals(result.length, 32);
});

Deno.test('hmacVerify validates correctly', async () => {
  const key = new TextEncoder().encode('secret');
  const data = new TextEncoder().encode('hello');
  const sig = await hmac('sha256', key, data);

  assertEquals(await hmacVerify('sha256', key, data, sig), true);

  // Tamper with signature
  sig[0] ^= 0xff;
  assertEquals(await hmacVerify('sha256', key, data, sig), false);
});

// Utility tests
Deno.test('timingSafeEqual returns true for equal arrays', () => {
  const a = new Uint8Array([1, 2, 3, 4, 5]);
  const b = new Uint8Array([1, 2, 3, 4, 5]);
  assertEquals(timingSafeEqual(a, b), true);
});

Deno.test('timingSafeEqual returns false for different arrays', () => {
  const a = new Uint8Array([1, 2, 3, 4, 5]);
  const b = new Uint8Array([1, 2, 3, 4, 6]);
  assertEquals(timingSafeEqual(a, b), false);
});

Deno.test('timingSafeEqual returns false for different lengths', () => {
  const a = new Uint8Array([1, 2, 3, 4, 5]);
  const b = new Uint8Array([1, 2, 3, 4]);
  assertEquals(timingSafeEqual(a, b), false);
});

Deno.test('xorBytes XORs correctly', () => {
  const a = new Uint8Array([0xff, 0x00, 0xaa]);
  const b = new Uint8Array([0xff, 0xff, 0x55]);
  const result = xorBytes(a, b);
  assertEquals(result, new Uint8Array([0x00, 0xff, 0xff]));
});

// Key Exchange tests
import {
  createKeyExchange,
  DHExchange,
  ECDHExchange,
  SUPPORTED_KEX_ALGORITHMS,
  toMpint,
  X25519Exchange,
} from '../src/crypto/kex.ts';

Deno.test('toMpint strips leading zeros', () => {
  const input = new Uint8Array([0, 0, 0, 0x7f, 0x80]);
  const result = toMpint(input);
  assertEquals(result, new Uint8Array([0x7f, 0x80]));
});

Deno.test('toMpint adds zero prefix for negative-looking numbers', () => {
  const input = new Uint8Array([0x80, 0x00]);
  const result = toMpint(input);
  assertEquals(result, new Uint8Array([0x00, 0x80, 0x00]));
});

Deno.test('X25519Exchange generates valid key pair', async () => {
  const kex = new X25519Exchange();
  const result = await kex.generateKeyPair();

  assertEquals(result.publicKey.length, 32);
  assertEquals(typeof result.computeSecret, 'function');
});

Deno.test('X25519Exchange computes shared secret', async () => {
  const alice = new X25519Exchange();
  const bob = new X25519Exchange();

  const aliceResult = await alice.generateKeyPair();
  const bobResult = await bob.generateKeyPair();

  const aliceSecret = await aliceResult.computeSecret(bobResult.publicKey);
  const bobSecret = await bobResult.computeSecret(aliceResult.publicKey);

  assertEquals(toHex(aliceSecret), toHex(bobSecret));
});

Deno.test('ECDHExchange P-256 generates valid key pair', async () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp256', 'nistp256', 'sha256');
  const result = await kex.generateKeyPair();

  // P-256 uncompressed public key is 65 bytes (0x04 || x || y)
  assertEquals(result.publicKey.length, 65);
  assertEquals(result.publicKey[0], 0x04);
});

Deno.test('ECDHExchange P-256 computes shared secret', async () => {
  const aliceKex = new ECDHExchange('ecdh-sha2-nistp256', 'nistp256', 'sha256');
  const bobKex = new ECDHExchange('ecdh-sha2-nistp256', 'nistp256', 'sha256');

  const aliceResult = await aliceKex.generateKeyPair();
  const bobResult = await bobKex.generateKeyPair();

  const aliceSecret = await aliceResult.computeSecret(bobResult.publicKey);
  const bobSecret = await bobResult.computeSecret(aliceResult.publicKey);

  assertEquals(toHex(aliceSecret), toHex(bobSecret));
});

Deno.test('DHExchange modp14 generates valid key pair', async () => {
  const kex = new DHExchange('diffie-hellman-group14-sha256', 'modp14', 'sha256');
  const result = await kex.generateKeyPair();

  // MODP14 is 2048-bit, so public key should be reasonable size
  assertEquals(result.publicKey.length > 200, true);
  assertEquals(typeof result.computeSecret, 'function');
});

Deno.test('DHExchange modp14 computes shared secret', async () => {
  const aliceKex = new DHExchange('diffie-hellman-group14-sha256', 'modp14', 'sha256');
  const bobKex = new DHExchange('diffie-hellman-group14-sha256', 'modp14', 'sha256');

  const aliceResult = await aliceKex.generateKeyPair();
  const bobResult = await bobKex.generateKeyPair();

  const aliceSecret = await aliceResult.computeSecret(bobResult.publicKey);
  const bobSecret = await bobResult.computeSecret(aliceResult.publicKey);

  assertEquals(toHex(aliceSecret), toHex(bobSecret));
});

Deno.test('createKeyExchange creates correct exchange type', () => {
  const x25519 = createKeyExchange('curve25519-sha256');
  assertEquals(x25519 instanceof X25519Exchange, true);

  const ecdh = createKeyExchange('ecdh-sha2-nistp256');
  assertEquals(ecdh instanceof ECDHExchange, true);

  const dh = createKeyExchange('diffie-hellman-group14-sha256');
  assertEquals(dh instanceof DHExchange, true);
});

Deno.test('SUPPORTED_KEX_ALGORITHMS contains expected algorithms', () => {
  assertEquals(SUPPORTED_KEX_ALGORITHMS.includes('curve25519-sha256'), true);
  assertEquals(SUPPORTED_KEX_ALGORITHMS.includes('ecdh-sha2-nistp256'), true);
  assertEquals(SUPPORTED_KEX_ALGORITHMS.includes('diffie-hellman-group14-sha256'), true);
});
