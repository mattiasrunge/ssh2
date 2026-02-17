/**
 * Tests for key generation
 *
 * Note: Full parsing/verification tests require private key parser
 * which is not yet implemented. These tests verify key generation works
 * and produces valid OpenSSH format output.
 */

import { assertEquals, assertExists, assertRejects } from '@std/assert';
import { generateKeyPair } from '../src/keygen.ts';

Deno.test('generateKeyPair RSA 2048', async () => {
  const keys = await generateKeyPair('rsa', { bits: 2048 });

  assertExists(keys.private);
  assertExists(keys.public);

  // Verify OpenSSH format
  assertEquals(keys.private.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'), true);
  assertEquals(keys.private.includes('-----END OPENSSH PRIVATE KEY-----'), true);
  assertEquals(keys.public.startsWith('ssh-rsa '), true);
});

Deno.test('generateKeyPair ECDSA nistp256', async () => {
  const keys = await generateKeyPair('ecdsa', { bits: 256 });

  assertExists(keys.private);
  assertExists(keys.public);

  assertEquals(keys.private.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'), true);
  assertEquals(keys.public.startsWith('ecdsa-sha2-nistp256 '), true);
});

Deno.test('generateKeyPair ECDSA nistp384', async () => {
  const keys = await generateKeyPair('ecdsa', { bits: 384 });

  assertExists(keys.private);
  assertExists(keys.public);

  assertEquals(keys.private.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'), true);
  assertEquals(keys.public.startsWith('ecdsa-sha2-nistp384 '), true);
});

Deno.test('generateKeyPair Ed25519', async () => {
  const keys = await generateKeyPair('ed25519');

  assertExists(keys.private);
  assertExists(keys.public);

  assertEquals(keys.private.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'), true);
  assertEquals(keys.public.startsWith('ssh-ed25519 '), true);
});

Deno.test('generateKeyPair with comment', async () => {
  const comment = 'test-key@example.com';
  const keys = await generateKeyPair('ed25519', { comment });

  assertExists(keys.private);
  assertExists(keys.public);

  // Check that public key contains comment
  assertEquals(keys.public.includes(comment), true);
});

Deno.test('generateKeyPair RSA encrypted with passphrase', async () => {
  const passphrase = 'test-password-123';
  const keys = await generateKeyPair('rsa', {
    bits: 2048,
    passphrase,
    cipher: 'aes256-cbc',
  });

  assertExists(keys.private);
  assertExists(keys.public);

  // Should still be valid OpenSSH format
  assertEquals(keys.private.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'), true);
  assertEquals(keys.public.startsWith('ssh-rsa '), true);
});

Deno.test('generateKeyPair rejects invalid key type', async () => {
  await assertRejects(
    async () => {
      await generateKeyPair('invalid-type');
    },
    Error,
    'Unsupported key type',
  );
});

Deno.test('generateKeyPair RSA rejects missing bits', async () => {
  await assertRejects(
    async () => {
      await generateKeyPair('rsa');
    },
    TypeError,
    'Missing bits option',
  );
});

Deno.test('generateKeyPair ECDSA rejects invalid bits', async () => {
  await assertRejects(
    async () => {
      await generateKeyPair('ecdsa', { bits: 128 });
    },
    Error,
    'bits must be 256, 384, or 521',
  );
});
