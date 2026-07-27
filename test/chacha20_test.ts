/**
 * Tests for the ChaCha20 and Poly1305 primitives in src/crypto/
 *
 * ChaCha20 known-answer vectors were generated with Node.js v24 (OpenSSL) for
 * the DJB 8-byte-nonce variant via the counter(4 LE) || 0x00000000 || nonce(8)
 * IV mapping, and cross-checked against @noble/ciphers chacha20orig before
 * that dependency was removed. Poly1305 vectors are from RFC 8439.
 */

import { assertEquals } from '@std/assert';
import { chacha20 } from '../src/crypto/chacha20.ts';
import { poly1305 } from '../src/crypto/poly1305.ts';
import { fromHex, toHex } from '../src/utils/binary.ts';

Deno.test('chacha20 DJB variant known-answer vectors', () => {
  const key = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const nonce = fromHex('0000000000000001');
  const data = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223');

  assertEquals(
    toHex(chacha20(key, nonce, data, 0)),
    '0122bbe21eff8fa1a1402169fd5cf4e42ab2fe48fde9a867a841a54886ea65f368661c5a',
  );
  assertEquals(
    toHex(chacha20(key, nonce, data, 1)),
    '695d7eda350fbe7d25787424bf19191d00e02d53daa4ea625d23af3335f38115f30cce29',
  );
});

Deno.test('chacha20 zero key/nonce keystream', () => {
  // Counter 0: first ChaCha20 block, matches RFC 8439 A.1 test vector #1
  assertEquals(
    toHex(chacha20(new Uint8Array(32), new Uint8Array(8), new Uint8Array(16))),
    '76b8e0ada0f13d90405d6ae55386bd28',
  );
  // Counter 1: second block
  assertEquals(
    toHex(chacha20(new Uint8Array(32), new Uint8Array(8), new Uint8Array(16), 1)),
    '9f07e7be5551387a98ba977c732d080d',
  );
});

Deno.test('chacha20 encrypt/decrypt round-trip', () => {
  const key = fromHex('ff'.repeat(32));
  const nonce = fromHex('0102030405060708');
  const data = new TextEncoder().encode('SSH packet payload data for round-trip');
  const encrypted = chacha20(key, nonce, data, 1);
  const decrypted = chacha20(key, nonce, encrypted, 1);
  assertEquals(toHex(decrypted), toHex(data));
});

Deno.test('poly1305 RFC 8439 §2.5.2 test vector', () => {
  const key = fromHex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
  const msg = new TextEncoder().encode('Cryptographic Forum Research Group');
  assertEquals(toHex(poly1305(msg, key)), 'a8061dc1305136c6c22b8baf0c0127a9');
});

Deno.test('poly1305 RFC 8439 §A.3 test vectors', () => {
  // Vector #1: zero key, zero message
  assertEquals(
    toHex(poly1305(new Uint8Array(64), new Uint8Array(32))),
    '00000000000000000000000000000000',
  );

  // Vector #2: r = 0, s = key of the IETF submission text
  const text = new TextEncoder().encode(
    'Any submission to the IETF intended by the Contributor for publication as all or part of an ' +
      'IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is ' +
      'considered an "IETF Contribution". Such statements include oral statements in IETF sessions, ' +
      'as well as written and electronic communications made at any time or place, which are addressed to',
  );
  const key2 = fromHex('0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e');
  assertEquals(toHex(poly1305(text, key2)), '36e5f6b5c5e06070f0efca96227a863e');

  // Vector #3: s = 0
  const key3 = fromHex('36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000');
  assertEquals(toHex(poly1305(text, key3)), 'f3477e7cd95417af89a6b8794c310cf0');
});

Deno.test('poly1305 handles non-block-aligned messages', () => {
  // 4 + 36 bytes like an SSH MAC input (encrypted length + payload), plus odd sizes
  const key = fromHex('1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0');
  for (const len of [1, 4, 15, 16, 17, 40, 100]) {
    const msg = new Uint8Array(len).fill(0xab);
    const mac = poly1305(msg, key);
    assertEquals(mac.length, 16);
  }
});
