/**
 * Tests for SSH Key Parser
 *
 * Tests public and private key parsing, sign, and verify functionality.
 */

import { assertEquals, assertExists } from '@std/assert';
import { parseKey } from '../src/protocol/keyParser.ts';
import {
  KEY_PARSER_FIXTURES_PATH,
  keyToDetails,
  listDir,
  readFixture,
  readFixtureJson,
} from './helpers.ts';

interface ExpectedResult {
  type: string;
  comment: string;
  public: string | null;
  publicSSH: string | null;
  private: string | null;
}

// Test all public key fixtures
Deno.test('keyParser parses all OpenSSH public key fixtures', async () => {
  const files = await listDir(KEY_PARSER_FIXTURES_PATH);

  // Filter to just .pub files (not .pub.result)
  const pubFiles = files.filter((f) =>
    f.endsWith('.pub') &&
    !f.endsWith('.result')
  );

  for (const name of pubFiles) {
    const keyPath = `${KEY_PARSER_FIXTURES_PATH}/${name}`;
    const resultPath = `${keyPath}.result`;

    // Read key and expected result
    const keyData = await readFixture(keyPath);
    let expected: ExpectedResult | string;
    try {
      expected = await readFixtureJson<ExpectedResult>(resultPath);
    } catch {
      // Skip if no result file
      continue;
    }

    // Parse key
    const result = parseKey(keyData);

    // Check if expected is an error string
    if (typeof expected === 'string') {
      assertEquals(
        result instanceof Error,
        true,
        `${name}: Expected error but got success`,
      );
      assertEquals(
        (result as Error).message,
        expected,
        `${name}: Error message mismatch`,
      );
    } else {
      // Expected success
      if (result instanceof Error) {
        throw new Error(`${name}: Unexpected error: ${result.message}`);
      }

      const details = keyToDetails(result);

      assertEquals(details.type, expected.type, `${name}: type mismatch`);
      assertEquals(details.comment, expected.comment, `${name}: comment mismatch`);
      assertEquals(details.public, expected.public, `${name}: public PEM mismatch`);
      assertEquals(details.publicSSH, expected.publicSSH, `${name}: publicSSH mismatch`);
      assertEquals(
        details.private,
        expected.private,
        `${name}: private should be null for public key`,
      );
    }
  }
});

// Test specific public key types
Deno.test('keyParser parses RSA public key', async () => {
  const keyPath = `${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.pub`;
  const keyData = await readFixture(keyPath);

  const result = parseKey(keyData);
  assertEquals(result instanceof Error, false);

  if (!(result instanceof Error)) {
    assertEquals(result.type, 'ssh-rsa');
    assertExists(result.getPublicPEM());
    assertExists(result.getPublicSSH());
    assertEquals(result.isPrivateKey(), false);
    assertEquals(result.getPrivatePEM(), null);
  }
});

Deno.test('keyParser parses ECDSA public key', async () => {
  const keyPath = `${KEY_PARSER_FIXTURES_PATH}/openssh_new_ecdsa.pub`;
  const keyData = await readFixture(keyPath);

  const result = parseKey(keyData);
  assertEquals(result instanceof Error, false);

  if (!(result instanceof Error)) {
    assertEquals(result.type, 'ecdsa-sha2-nistp256');
    assertExists(result.getPublicPEM());
    assertExists(result.getPublicSSH());
    assertEquals(result.isPrivateKey(), false);
  }
});

Deno.test('keyParser parses Ed25519 public key', async () => {
  const keyPath = `${KEY_PARSER_FIXTURES_PATH}/openssh_new_ed25519.pub`;
  const keyData = await readFixture(keyPath);

  const result = parseKey(keyData);
  assertEquals(result instanceof Error, false);

  if (!(result instanceof Error)) {
    assertEquals(result.type, 'ssh-ed25519');
    assertExists(result.getPublicPEM());
    assertExists(result.getPublicSSH());
    assertEquals(result.isPrivateKey(), false);
  }
});

// Test equals() method
Deno.test('keyParser equals() returns true for same key', async () => {
  const keyPath = `${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.pub`;
  const keyData = await readFixture(keyPath);

  const result1 = parseKey(keyData);
  const result2 = parseKey(keyData);

  assertEquals(result1 instanceof Error, false);
  assertEquals(result2 instanceof Error, false);

  if (!(result1 instanceof Error) && !(result2 instanceof Error)) {
    assertEquals(result1.equals(result2), true);
  }
});

Deno.test('keyParser equals() returns false for different keys', async () => {
  const keyPath1 = `${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.pub`;
  const keyPath2 = `${KEY_PARSER_FIXTURES_PATH}/openssh_new_ecdsa.pub`;

  const keyData1 = await readFixture(keyPath1);
  const keyData2 = await readFixture(keyPath2);

  const result1 = parseKey(keyData1);
  const result2 = parseKey(keyData2);

  assertEquals(result1 instanceof Error, false);
  assertEquals(result2 instanceof Error, false);

  if (!(result1 instanceof Error) && !(result2 instanceof Error)) {
    assertEquals(result1.equals(result2), false);
  }
});

// Test error handling
Deno.test('keyParser returns error for invalid key data', () => {
  const result = parseKey('not a valid key');
  assertEquals(result instanceof Error, true);
});

Deno.test('keyParser returns error for empty string', () => {
  const result = parseKey('');
  assertEquals(result instanceof Error, true);
});

Deno.test('keyParser returns error for invalid buffer', () => {
  const result = parseKey(new Uint8Array([0x00, 0x01, 0x02]));
  assertEquals(result instanceof Error, true);
});

// Test string input
Deno.test('keyParser accepts string input', async () => {
  const keyPath = `${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.pub`;
  const keyData = await Deno.readTextFile(keyPath);

  const result = parseKey(keyData);
  assertEquals(result instanceof Error, false);

  if (!(result instanceof Error)) {
    assertEquals(result.type, 'ssh-rsa');
  }
});

// Test that parseKey returns itself when passed a ParsedKey
Deno.test('keyParser returns same key when passed ParsedKey', async () => {
  const keyPath = `${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.pub`;
  const keyData = await readFixture(keyPath);

  const result1 = parseKey(keyData);
  assertEquals(result1 instanceof Error, false);

  if (!(result1 instanceof Error)) {
    const result2 = parseKey(result1);
    assertEquals(result1, result2);
  }
});

// =============================================================================
// Private key parsing
// =============================================================================

Deno.test('keyParser parses new OpenSSH RSA private key', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa`);
  const expected = await readFixtureJson<{ type: string; comment: string; private: string }>(
    `${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.result`,
  );

  const result = parseKey(keyData);
  assertEquals(result instanceof Error, false);
  if (result instanceof Error) return;

  assertEquals(result.type, expected.type);
  assertEquals(result.comment, expected.comment);
  assertEquals(result.isPrivateKey(), true);
  assertExists(result.getPrivatePEM());
  assertExists(result.getPublicPEM());
  assertExists(result.getPublicSSH());
});

Deno.test('keyParser parses new OpenSSH ECDSA private key', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_ecdsa`);
  const expected = await readFixtureJson<{ type: string }>(
    `${KEY_PARSER_FIXTURES_PATH}/openssh_new_ecdsa.result`,
  );

  const result = parseKey(keyData);
  assertEquals(result instanceof Error, false);
  if (result instanceof Error) return;

  assertEquals(result.type, expected.type);
  assertEquals(result.isPrivateKey(), true);
  assertExists(result.getPrivatePEM());
  assertExists(result.getPublicSSH());
});

Deno.test('keyParser parses new OpenSSH Ed25519 private key', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_ed25519`);

  const result = parseKey(keyData);
  assertEquals(result instanceof Error, false);
  if (result instanceof Error) return;

  assertEquals(result.type, 'ssh-ed25519');
  assertEquals(result.isPrivateKey(), true);
  assertExists(result.getPublicSSH());
  assertExists(result.getPublicPEM());
});

Deno.test('keyParser parses old PEM RSA private key', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_old_rsa`);
  const expected = await readFixtureJson<{ type: string }>(
    `${KEY_PARSER_FIXTURES_PATH}/openssh_old_rsa.result`,
  );

  const result = parseKey(keyData);
  assertEquals(result instanceof Error, false);
  if (result instanceof Error) return;

  assertEquals(result.type, expected.type);
  assertEquals(result.isPrivateKey(), true);
  assertExists(result.getPrivatePEM());
});

Deno.test('keyParser parses old PEM ECDSA private key', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_old_ecdsa`);

  const result = parseKey(keyData);
  assertEquals(result instanceof Error, false);
  if (result instanceof Error) return;

  assertEquals(result.isPrivateKey(), true);
  assertExists(result.getPrivatePEM());
  assertExists(result.getPublicSSH());
});

Deno.test('keyParser parses unencrypted PPK RSA key', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/ppk_rsa`);
  const expected = await readFixtureJson<ExpectedResult>(
    `${KEY_PARSER_FIXTURES_PATH}/ppk_rsa.result`,
  );

  // PPK requires async parsing (MAC verification)
  const result = await parseKey(keyData, '');
  assertEquals(
    result instanceof Error,
    false,
    `Unexpected error: ${result instanceof Error ? result.message : ''}`,
  );
  if (result instanceof Error) return;

  const details = keyToDetails(result);
  assertEquals(details.type, expected.type);
  assertEquals(details.comment, expected.comment);
  assertEquals(result.isPrivateKey(), true);
  assertExists(result.getPrivatePEM());
  assertExists(result.getPublicPEM());
  assertExists(result.getPublicSSH());
});

// =============================================================================
// Sign and verify
// =============================================================================

Deno.test('keyParser RSA private key sign and verify', async () => {
  const privData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa`);
  const pubData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.pub`);

  const privKey = parseKey(privData);
  const pubKey = parseKey(pubData);

  assertEquals(privKey instanceof Error, false);
  assertEquals(pubKey instanceof Error, false);
  if (privKey instanceof Error || pubKey instanceof Error) return;

  const data = new TextEncoder().encode('test data to sign');
  const signature = await privKey.sign(data);

  assertEquals(signature instanceof Error, false);
  if (signature instanceof Error) return;
  assertEquals(signature instanceof Uint8Array, true);
  assertEquals(signature.length > 0, true);

  const valid = await pubKey.verify(data, signature);
  assertEquals(valid, true);
});

Deno.test('keyParser ECDSA private key sign produces Uint8Array', async () => {
  const privData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_ecdsa`);

  const privKey = parseKey(privData);

  assertEquals(privKey instanceof Error, false);
  if (privKey instanceof Error) return;

  const data = new TextEncoder().encode('ecdsa test message');
  const signature = await privKey.sign(data);

  assertEquals(signature instanceof Error, false);
  if (signature instanceof Error) return;
  assertEquals(signature instanceof Uint8Array, true);
  assertEquals(signature.length > 0, true);
});

Deno.test('keyParser Ed25519 private key sign and verify', async () => {
  const privData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_ed25519`);
  const pubData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_ed25519.pub`);

  const privKey = parseKey(privData);
  const pubKey = parseKey(pubData);

  assertEquals(privKey instanceof Error, false);
  assertEquals(pubKey instanceof Error, false);
  if (privKey instanceof Error || pubKey instanceof Error) return;

  const data = new TextEncoder().encode('ed25519 test');
  const signature = await privKey.sign(data);

  assertEquals(signature instanceof Error, false);
  if (signature instanceof Error) return;
  assertEquals(signature instanceof Uint8Array, true);

  const valid = await pubKey.verify(data, signature);
  assertEquals(valid, true);
});

Deno.test('keyParser RSA sign with rsa-sha2-256 algo produces signature', async () => {
  const privData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa`);
  const privKey = parseKey(privData);
  if (privKey instanceof Error) return;

  const data = new TextEncoder().encode('sha256 test');
  const signature = await privKey.sign(data, 'rsa-sha2-256');
  // Sign should succeed (rsa-sha2-256 uses sha256 hash)
  assertEquals(signature instanceof Uint8Array, true);
  if (signature instanceof Uint8Array) {
    assertEquals(signature.length > 0, true);
  }
});

Deno.test('keyParser RSA sign with rsa-sha2-512 algo produces signature', async () => {
  const privData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa`);
  const privKey = parseKey(privData);
  if (privKey instanceof Error) return;

  const data = new TextEncoder().encode('sha512 test');
  const signature = await privKey.sign(data, 'rsa-sha2-512');
  // Sign should succeed (rsa-sha2-512 uses sha512 hash)
  assertEquals(signature instanceof Uint8Array, true);
  if (signature instanceof Uint8Array) {
    assertEquals(signature.length > 0, true);
  }
});

Deno.test('keyParser verify returns false for invalid signature', async () => {
  const privData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa`);
  const pubData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.pub`);

  const privKey = parseKey(privData);
  const pubKey = parseKey(pubData);
  if (privKey instanceof Error || pubKey instanceof Error) return;

  const data = new TextEncoder().encode('original data');
  const signature = await privKey.sign(data);
  if (signature instanceof Error) return;

  // Tamper with the signature
  const badSig = new Uint8Array(signature);
  badSig[badSig.length - 1] ^= 0xff;

  const valid = await pubKey.verify(data, badSig);
  assertEquals(valid, false);
});

Deno.test('keyParser sign on public key returns error', async () => {
  const pubData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.pub`);
  const pubKey = parseKey(pubData);
  if (pubKey instanceof Error) return;

  // Public key has no private PEM, so sign should return an Error
  const result = await pubKey.sign(new TextEncoder().encode('test'));
  assertEquals(result instanceof Error, true);
});

Deno.test('keyParser equals with Uint8Array public SSH bytes', async () => {
  const pubData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.pub`);
  const result = parseKey(pubData);
  if (result instanceof Error) return;

  const pubSSH = result.getPublicSSH();
  assertExists(pubSSH);

  // equals() when passed raw Uint8Array public key
  assertEquals(result.equals(pubSSH!), true);
});

Deno.test('keyParser equals with different public SSH bytes returns false', async () => {
  const pubData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa.pub`);
  const result = parseKey(pubData);
  if (result instanceof Error) return;

  const wrongBytes = new Uint8Array([1, 2, 3, 4]);
  assertEquals(result.equals(wrongBytes), false);
});

Deno.test('keyParser parses all private key fixtures without error', async () => {
  const privateFixtures = [
    'openssh_new_rsa',
    'openssh_new_ecdsa',
    'openssh_new_ed25519',
    'openssh_old_rsa',
    'openssh_old_ecdsa',
  ];

  for (const name of privateFixtures) {
    const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/${name}`);
    const result = parseKey(keyData);
    assertEquals(
      result instanceof Error,
      false,
      `${name}: Expected success but got error: ${result instanceof Error ? result.message : ''}`,
    );
  }
});

// =============================================================================
// Encrypted key parsing
// =============================================================================

const PASSPHRASE = 'password';
const PPK_PASSPHRASE = 'node.js';

Deno.test('keyParser parses encrypted OpenSSH RSA key (aes256-ctr)', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa_enc`);
  const expected = await readFixtureJson<ExpectedResult>(
    `${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa_enc.result`,
  );

  const result = await parseKey(keyData, PASSPHRASE);
  assertEquals(
    result instanceof Error,
    false,
    `Error: ${result instanceof Error ? result.message : ''}`,
  );
  if (result instanceof Error) return;

  const details = keyToDetails(result);
  assertEquals(details.type, expected.type);
  assertEquals(details.comment, expected.comment);
  assertEquals(result.isPrivateKey(), true);
  assertExists(result.getPrivatePEM());
  assertExists(result.getPublicPEM());
});

Deno.test('keyParser parses encrypted OpenSSH RSA key (aes128-gcm)', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa_enc_gcm`);
  const expected = await readFixtureJson<ExpectedResult>(
    `${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa_enc_gcm.result`,
  );

  const result = await parseKey(keyData, PASSPHRASE);
  assertEquals(
    result instanceof Error,
    false,
    `Error: ${result instanceof Error ? result.message : ''}`,
  );
  if (result instanceof Error) return;

  const details = keyToDetails(result);
  assertEquals(details.type, expected.type);
  assertEquals(details.comment, expected.comment);
  assertEquals(result.isPrivateKey(), true);
});

Deno.test('keyParser parses encrypted OpenSSH ECDSA key (aes256-ctr)', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_ecdsa_enc`);
  const expected = await readFixtureJson<ExpectedResult>(
    `${KEY_PARSER_FIXTURES_PATH}/openssh_new_ecdsa_enc.result`,
  );

  const result = await parseKey(keyData, PASSPHRASE);
  assertEquals(
    result instanceof Error,
    false,
    `Error: ${result instanceof Error ? result.message : ''}`,
  );
  if (result instanceof Error) return;

  assertEquals(result.type, expected.type);
  assertEquals(result.isPrivateKey(), true);
});

Deno.test('keyParser parses encrypted OpenSSH ECDSA key (aes128-gcm)', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_ecdsa_enc_gcm`);
  const expected = await readFixtureJson<ExpectedResult>(
    `${KEY_PARSER_FIXTURES_PATH}/openssh_new_ecdsa_enc_gcm.result`,
  );

  const result = await parseKey(keyData, PASSPHRASE);
  assertEquals(
    result instanceof Error,
    false,
    `Error: ${result instanceof Error ? result.message : ''}`,
  );
  if (result instanceof Error) return;

  assertEquals(result.type, expected.type);
  assertEquals(result.isPrivateKey(), true);
});

Deno.test('keyParser returns error for encrypted old PEM key (unsupported)', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_old_rsa_enc`);

  // With passphrase: returns error explaining old PEM encryption is not supported
  const resultAsync = await parseKey(keyData, PASSPHRASE);
  assertEquals(resultAsync instanceof Error, true);
  assertEquals(
    (resultAsync as Error).message.includes('old-style PEM'),
    true,
    `Expected old-style PEM error, got: ${(resultAsync as Error).message}`,
  );
  assertEquals(
    (resultAsync as Error).message.includes('ssh-keygen'),
    true,
    'Error should suggest ssh-keygen conversion',
  );

  // Without passphrase: also returns error
  const resultSync = parseKey(keyData);
  assertEquals(resultSync instanceof Error, true);
  assertEquals(
    (resultSync as Error).message.includes('old-style PEM'),
    true,
    `Expected old-style PEM error, got: ${(resultSync as Error).message}`,
  );
});

Deno.test('keyParser parses encrypted PPK RSA key', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/ppk_rsa_enc`);
  const expected = await readFixtureJson<ExpectedResult>(
    `${KEY_PARSER_FIXTURES_PATH}/ppk_rsa_enc.result`,
  );

  const result = await parseKey(keyData, PPK_PASSPHRASE);
  assertEquals(
    result instanceof Error,
    false,
    `Error: ${result instanceof Error ? result.message : ''}`,
  );
  if (result instanceof Error) return;

  assertEquals(result.type, expected.type);
  assertEquals(result.comment, expected.comment);
  assertEquals(result.isPrivateKey(), true);
});

Deno.test('keyParser returns error for encrypted key without passphrase', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa_enc`);
  const result = parseKey(keyData);
  assertEquals(result instanceof Error, true);
  assertEquals(
    (result as Error).message.includes('passphrase'),
    true,
    `Expected passphrase error, got: ${(result as Error).message}`,
  );
});

Deno.test('keyParser returns error for wrong passphrase', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/openssh_new_rsa_enc`);
  const result = await parseKey(keyData, 'wrong-passphrase');
  assertEquals(result instanceof Error, true);
});

// =============================================================================
// RFC4716 public key parsing
// =============================================================================

Deno.test('keyParser parses RFC4716 public key', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/rfc4716_rsa.pub`);
  const expected = await readFixtureJson<ExpectedResult>(
    `${KEY_PARSER_FIXTURES_PATH}/rfc4716_rsa.pub.result`,
  );

  const result = parseKey(keyData);
  assertEquals(
    result instanceof Error,
    false,
    `Error: ${result instanceof Error ? result.message : ''}`,
  );
  if (result instanceof Error) return;

  const details = keyToDetails(result);
  assertEquals(details.type, expected.type);
  assertEquals(details.comment, expected.comment);
  assertEquals(details.public, expected.public);
  assertEquals(details.publicSSH, expected.publicSSH);
  assertEquals(result.isPrivateKey(), false);
});

Deno.test('keyParser parses RFC4716 public key with multi-line comment', async () => {
  const keyData = await readFixture(`${KEY_PARSER_FIXTURES_PATH}/rfc4716_rsa3.pub`);
  const expected = await readFixtureJson<ExpectedResult>(
    `${KEY_PARSER_FIXTURES_PATH}/rfc4716_rsa3.pub.result`,
  );

  const result = parseKey(keyData);
  assertEquals(
    result instanceof Error,
    false,
    `Error: ${result instanceof Error ? result.message : ''}`,
  );
  if (result instanceof Error) return;

  const details = keyToDetails(result);
  assertEquals(details.type, expected.type);
  assertEquals(details.comment, expected.comment);
});

Deno.test('keyParser parses all RFC4716 public key fixtures', async () => {
  const files = await listDir(KEY_PARSER_FIXTURES_PATH);
  const rfc4716Files = files.filter((f) =>
    f.startsWith('rfc4716_') && f.endsWith('.pub') && !f.endsWith('.result')
  );

  for (const name of rfc4716Files) {
    const keyPath = `${KEY_PARSER_FIXTURES_PATH}/${name}`;
    const resultPath = `${keyPath}.result`;

    const keyData = await readFixture(keyPath);
    const expected = await readFixtureJson<ExpectedResult>(resultPath);

    const result = parseKey(keyData);
    if (result instanceof Error) {
      throw new Error(`${name}: Unexpected error: ${result.message}`);
    }

    const details = keyToDetails(result);
    assertEquals(details.type, expected.type, `${name}: type mismatch`);
    assertEquals(details.comment, expected.comment, `${name}: comment mismatch`);
    assertEquals(details.public, expected.public, `${name}: public PEM mismatch`);
    assertEquals(details.publicSSH, expected.publicSSH, `${name}: publicSSH mismatch`);
  }
});
