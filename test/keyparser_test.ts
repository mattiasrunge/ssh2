/**
 * Tests for SSH Key Parser
 *
 * Currently tests public key parsing functionality.
 * Private key parsing tests will be added when that feature is implemented.
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

  // Filter to just .pub files (not .pub.result), excluding RFC4716 format (not yet supported)
  const pubFiles = files.filter((f) =>
    f.endsWith('.pub') &&
    !f.endsWith('.result') &&
    !f.startsWith('rfc4716_') // RFC4716 format not yet implemented
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
