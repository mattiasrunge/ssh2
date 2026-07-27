/**
 * Tests for unpadded AES-CBC over Web Crypto (src/crypto/aes-cbc.ts)
 *
 * Known-answer vectors are from NIST SP 800-38A (F.2.1, F.2.3, F.2.5),
 * covering AES-128/192/256-CBC.
 */

import { assertEquals, assertRejects } from '@std/assert';
import { decryptNoPad, encryptNoPad, importCbcKey } from '../src/crypto/aes-cbc.ts';
import { randomBytes } from '../src/crypto/random.ts';
import { fromHex, toHex } from '../src/utils/binary.ts';

// NIST SP 800-38A: common plaintext and IV for all CBC examples
const NIST_PT = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51' +
  '30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710';
const NIST_IV = '000102030405060708090a0b0c0d0e0f';

const NIST_VECTORS = [
  {
    name: 'AES-128-CBC (F.2.1)',
    key: '2b7e151628aed2a6abf7158809cf4f3c',
    ct: '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2' +
      '73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7',
  },
  {
    name: 'AES-192-CBC (F.2.3)',
    key: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
    ct: '4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a' +
      '571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd',
  },
  {
    name: 'AES-256-CBC (F.2.5)',
    key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
    ct: 'f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d' +
      '39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b',
  },
];

Deno.test('aes-cbc encryptNoPad matches NIST SP 800-38A vectors', async () => {
  for (const { name, key, ct } of NIST_VECTORS) {
    const cryptoKey = await importCbcKey(fromHex(key));
    const encrypted = await encryptNoPad(cryptoKey, fromHex(NIST_IV), fromHex(NIST_PT));
    assertEquals(toHex(encrypted), ct, name);
  }
});

Deno.test('aes-cbc decryptNoPad matches NIST SP 800-38A vectors', async () => {
  for (const { name, key, ct } of NIST_VECTORS) {
    const cryptoKey = await importCbcKey(fromHex(key));
    const decrypted = await decryptNoPad(cryptoKey, fromHex(NIST_IV), fromHex(ct));
    assertEquals(toHex(decrypted), NIST_PT, name);
  }
});

Deno.test('aes-cbc round-trip for all key sizes and data sizes', async () => {
  for (const keySize of [16, 24, 32]) {
    const key = await importCbcKey(randomBytes(keySize));
    for (const dataSize of [16, 32, 48, 256, 1024]) {
      const iv = randomBytes(16);
      const data = randomBytes(dataSize);
      const encrypted = await encryptNoPad(key, iv, data);
      assertEquals(encrypted.length, data.length);
      const decrypted = await decryptNoPad(key, iv, encrypted);
      assertEquals(toHex(decrypted), toHex(data), `key=${keySize} data=${dataSize}`);
    }
  }
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
