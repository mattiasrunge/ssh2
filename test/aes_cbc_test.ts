/**
 * Tests for unpadded AES-CBC over Web Crypto (src/crypto/aes-cbc.ts)
 *
 * Cross-checks against @noble/ciphers' raw CBC implementation, which was the
 * previous provider for these code paths.
 */

import { assertEquals, assertRejects } from '@std/assert';
import { cbc } from '@noble/ciphers/aes';
import { decryptNoPad, encryptNoPad, importCbcKey } from '../src/crypto/aes-cbc.ts';
import { randomBytes } from '../src/crypto/random.ts';
import { toHex } from '../src/utils/binary.ts';

const KEY_SIZES = [16, 24, 32]; // AES-128, AES-192, AES-256
const DATA_SIZES = [16, 32, 48, 256, 1024];

Deno.test('aes-cbc encryptNoPad matches @noble/ciphers raw CBC', async () => {
  for (const keySize of KEY_SIZES) {
    const keyRaw = randomBytes(keySize);
    const key = await importCbcKey(keyRaw);
    for (const dataSize of DATA_SIZES) {
      const iv = randomBytes(16);
      const data = randomBytes(dataSize);
      const ours = await encryptNoPad(key, iv, data);
      const noble = cbc(keyRaw, iv, { disablePadding: true }).encrypt(data);
      assertEquals(toHex(ours), toHex(noble), `encrypt key=${keySize} data=${dataSize}`);
    }
  }
});

Deno.test('aes-cbc decryptNoPad matches @noble/ciphers raw CBC', async () => {
  for (const keySize of KEY_SIZES) {
    const keyRaw = randomBytes(keySize);
    const key = await importCbcKey(keyRaw);
    for (const dataSize of DATA_SIZES) {
      const iv = randomBytes(16);
      const ciphertext = randomBytes(dataSize);
      const ours = await decryptNoPad(key, iv, ciphertext);
      const noble = cbc(keyRaw, iv, { disablePadding: true }).decrypt(ciphertext);
      assertEquals(toHex(ours), toHex(noble), `decrypt key=${keySize} data=${dataSize}`);
    }
  }
});

Deno.test('aes-cbc round-trip', async () => {
  const key = await importCbcKey(randomBytes(32));
  const iv = randomBytes(16);
  const data = randomBytes(160);
  const encrypted = await encryptNoPad(key, iv, data);
  const decrypted = await decryptNoPad(key, iv, encrypted);
  assertEquals(toHex(decrypted), toHex(data));
});

Deno.test('aes-cbc rejects non-block-aligned data', async () => {
  const key = await importCbcKey(randomBytes(32));
  const iv = randomBytes(16);
  await assertRejects(() => encryptNoPad(key, iv, randomBytes(17)));
  await assertRejects(() => decryptNoPad(key, iv, randomBytes(17)));
});

Deno.test('aes-cbc decryptNoPad handles empty input', async () => {
  const key = await importCbcKey(randomBytes(32));
  const result = await decryptNoPad(key, randomBytes(16), new Uint8Array(0));
  assertEquals(result.length, 0);
});
