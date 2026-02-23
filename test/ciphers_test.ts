/**
 * Tests for SSH Cipher implementations
 *
 * Tests cipher/decipher functionality using Web Crypto API.
 */

import { assertEquals, assertExists, assertRejects } from '@std/assert';
import { createCipher, createDecipher, NullCipher, NullDecipher } from '../src/crypto/ciphers.ts';
import { CIPHER_INFO, MAC_INFO } from '../src/protocol/constants.ts';
import { randomBytes } from '../src/crypto/random.ts';
import { concatBytes } from '../src/utils/binary.ts';

// Test NullCipher (no encryption, used during handshake)
Deno.test('NullCipher encrypts packet without encryption', async () => {
  let output: Uint8Array | undefined;
  const cipher = new NullCipher(0, (data) => {
    output = data;
  });

  const packet = cipher.allocPacket(5);
  // Set payload
  packet[5] = 0x01;
  packet[6] = 0x02;
  packet[7] = 0x03;
  packet[8] = 0x04;
  packet[9] = 0x05;

  await cipher.encrypt(packet);

  assertExists(output);
  assertEquals(output.length, packet.length);
  cipher.free();
});

Deno.test('NullCipher and NullDecipher round-trip', async () => {
  const payloads: Uint8Array[] = [];
  let ciphered: Uint8Array = new Uint8Array(0);

  const cipher = new NullCipher(0, (data) => {
    ciphered = concatBytes([ciphered, data]);
  });

  const decipher = new NullDecipher(0, (payload) => {
    payloads.push(new Uint8Array(payload));
  });

  // Use NullCipher to create a properly formatted packet
  const payloadData = new Uint8Array([0x01, 0x02, 0x03]);
  const packet = cipher.allocPacket(payloadData.length);
  packet.set(payloadData, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(payloads.length, 1);
  assertEquals(payloads[0].length, payloadData.length);
  for (let i = 0; i < payloadData.length; i++) {
    assertEquals(payloads[0][i], payloadData[i]);
  }

  cipher.free();
  decipher.free();
});

// Test AES-GCM cipher
Deno.test('AES-128-GCM cipher encrypts and decrypts correctly', async () => {
  const cipherInfo = CIPHER_INFO['aes128-gcm@openssh.com'];
  const key = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  // Create separate IV copies - cipher and decipher each track their own
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey: key,
      cipherIV: ivEnc,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: key,
      decipherIV: ivDec,
    },
  });

  // Test with a simple payload
  const payload = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);

  // Decrypt
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0].length, payload.length);
  for (let i = 0; i < payload.length; i++) {
    assertEquals(deciphered[0][i], payload[i]);
  }

  cipher.free();
  decipher.free();
});

// Test AES-256-GCM cipher
Deno.test('AES-256-GCM cipher encrypts and decrypts correctly', async () => {
  const cipherInfo = CIPHER_INFO['aes256-gcm@openssh.com'];
  const key = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey: key,
      cipherIV: ivEnc,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: key,
      decipherIV: ivDec,
    },
  });

  // Test with larger payload
  const payload = randomBytes(1024);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0].length, payload.length);
  for (let i = 0; i < payload.length; i++) {
    assertEquals(deciphered[0][i], payload[i]);
  }

  cipher.free();
  decipher.free();
});

// Test AES-CTR cipher with HMAC
Deno.test('AES-128-CTR with HMAC-SHA1 encrypts and decrypts correctly', async () => {
  const cipherInfo = CIPHER_INFO['aes128-ctr'];
  const macInfo = MAC_INFO['hmac-sha1'];
  const cipherKey = randomBytes(cipherInfo.keyLen);
  const cipherIVOrig = randomBytes(cipherInfo.ivLen!);
  const cipherIVEnc = new Uint8Array(cipherIVOrig);
  const cipherIVDec = new Uint8Array(cipherIVOrig);
  const macKey = randomBytes(macInfo.len);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey,
      cipherIV: cipherIVEnc,
      macInfo,
      macKey,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: cipherKey,
      decipherIV: cipherIVDec,
      macInfo,
      macKey,
    },
  });

  const payload = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0].length, payload.length);
  for (let i = 0; i < payload.length; i++) {
    assertEquals(deciphered[0][i], payload[i]);
  }

  cipher.free();
  decipher.free();
});

// Test empty payload
Deno.test('Cipher handles empty payload', async () => {
  const cipherInfo = CIPHER_INFO['aes128-gcm@openssh.com'];
  const key = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey: key,
      cipherIV: ivEnc,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: key,
      decipherIV: ivDec,
    },
  });

  // Empty payload
  const packet = cipher.allocPacket(0);
  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0].length, 0);

  cipher.free();
  decipher.free();
});

// Test sequence number tracking
Deno.test('Cipher tracks sequence numbers correctly', async () => {
  const cipherInfo = CIPHER_INFO['aes128-gcm@openssh.com'];
  const key = randomBytes(cipherInfo.keyLen);
  const iv = randomBytes(cipherInfo.ivLen!);

  const cipher = createCipher({
    outbound: {
      seqno: 10,
      onWrite: () => {},
      cipherInfo,
      cipherKey: key,
      cipherIV: iv,
    },
  });

  assertEquals(cipher.outSeqno, 10);

  const packet = cipher.allocPacket(5);
  await cipher.encrypt(packet);

  assertEquals(cipher.outSeqno, 11);

  cipher.free();
});

// Test multiple packets
Deno.test('Cipher handles multiple packets', async () => {
  const cipherInfo = CIPHER_INFO['aes128-gcm@openssh.com'];
  const key = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey: key,
      cipherIV: ivEnc,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: key,
      decipherIV: ivDec,
    },
  });

  // Send multiple packets
  for (let i = 0; i < 5; i++) {
    const payload = new Uint8Array([i]);
    const packet = cipher.allocPacket(payload.length);
    packet.set(payload, 5);
    await cipher.encrypt(packet);
  }

  // Decrypt all
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 5);
  for (let i = 0; i < 5; i++) {
    assertEquals(deciphered[i][0], i);
  }

  cipher.free();
  decipher.free();
});

// Test large payload
Deno.test('Cipher handles large payload (32KB)', async () => {
  const cipherInfo = CIPHER_INFO['aes256-gcm@openssh.com'];
  const key = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey: key,
      cipherIV: ivEnc,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: key,
      decipherIV: ivDec,
    },
  });

  const payload = randomBytes(32 * 1024);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0].length, payload.length);

  // Verify first and last bytes
  for (let i = 0; i < 100; i++) {
    assertEquals(deciphered[0][i], payload[i]);
  }
  for (let i = payload.length - 100; i < payload.length; i++) {
    assertEquals(deciphered[0][i], payload[i]);
  }

  cipher.free();
  decipher.free();
});

// Test sequence number rollover (wrap at 2^32)
Deno.test('Sequence number rolls over at 2^32', async () => {
  const cipherInfo = CIPHER_INFO['aes128-gcm@openssh.com'];
  const key = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: (2 ** 32) - 1, // Start at max value
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey: key,
      cipherIV: ivEnc,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: (2 ** 32) - 1, // Start at max value
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: key,
      decipherIV: ivDec,
    },
  });

  assertEquals(cipher.outSeqno, (2 ** 32) - 1);
  assertEquals(decipher.inSeqno, (2 ** 32) - 1);

  const payload = randomBytes(4);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  // Sequence numbers should have rolled over to 0
  assertEquals(cipher.outSeqno, 0);
  assertEquals(decipher.inSeqno, 0);
  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0], payload);

  cipher.free();
  decipher.free();
});

// Test chunked input - split length bytes
Deno.test('Decipher handles chunked input (split length bytes)', async () => {
  const cipherInfo = CIPHER_INFO['aes128-gcm@openssh.com'];
  const key = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey: key,
      cipherIV: ivEnc,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: key,
      decipherIV: ivDec,
    },
  });

  const payload = randomBytes(100);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);

  // Decrypt in chunks - first 2 bytes (partial length), then the rest
  await decipher.decrypt(ciphered, 0, 2);
  await decipher.decrypt(ciphered, 2, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0], payload);

  cipher.free();
  decipher.free();
});

// Test chunked input - split length from payload
Deno.test('Decipher handles chunked input (split length from payload)', async () => {
  const cipherInfo = CIPHER_INFO['aes128-gcm@openssh.com'];
  const key = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey: key,
      cipherIV: ivEnc,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: key,
      decipherIV: ivDec,
    },
  });

  const payload = randomBytes(100);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);

  // Decrypt in chunks - first 4 bytes (full length), then the rest
  await decipher.decrypt(ciphered, 0, 4);
  await decipher.decrypt(ciphered, 4, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0], payload);

  cipher.free();
  decipher.free();
});

// Test chunked input - split before MAC
Deno.test('Decipher handles chunked input (split before MAC)', async () => {
  const cipherInfo = CIPHER_INFO['aes128-gcm@openssh.com'];
  const macSize = cipherInfo.authLen!;
  const key = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey: key,
      cipherIV: ivEnc,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: key,
      decipherIV: ivDec,
    },
  });

  const payload = randomBytes(100);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);

  // Decrypt in chunks - everything except MAC, then the MAC
  await decipher.decrypt(ciphered, 0, ciphered.length - macSize);
  await decipher.decrypt(ciphered, ciphered.length - macSize, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0], payload);

  cipher.free();
  decipher.free();
});

// Test NullDecipher packet length validation
Deno.test('NullDecipher rejects bad packet length', async () => {
  const decipher = new NullDecipher(0, () => {});

  // Create a packet with invalid length (0 is not valid for SSH packets)
  const badPacket = new Uint8Array([0, 0, 0, 0, 4, 0, 0, 0, 0]);

  await assertRejects(
    async () => {
      await decipher.decrypt(badPacket, 0, badPacket.length);
    },
    Error,
    'packet length',
  );

  decipher.free();
});

// Test NullDecipher rejects oversized packet
Deno.test('NullDecipher rejects oversized packet', async () => {
  const decipher = new NullDecipher(0, () => {});

  // Create a packet with very large length (0xFFFFFFFF)
  const badPacket = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 4, 0, 0, 0, 0]);

  await assertRejects(
    async () => {
      await decipher.decrypt(badPacket, 0, badPacket.length);
    },
    Error,
    'packet length',
  );

  decipher.free();
});

// Test single byte payload
Deno.test('Cipher handles single byte payload', async () => {
  const cipherInfo = CIPHER_INFO['aes128-gcm@openssh.com'];
  const key = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => {
        ciphered = concatBytes([ciphered, data]);
      },
      cipherInfo,
      cipherKey: key,
      cipherIV: ivEnc,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => {
        deciphered.push(new Uint8Array(payload));
      },
      decipherInfo: cipherInfo,
      decipherKey: key,
      decipherIV: ivDec,
    },
  });

  // Single byte payload
  const payload = new Uint8Array([0xEF]);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0].length, 1);
  assertEquals(deciphered[0][0], 0xEF);

  cipher.free();
  decipher.free();
});

// =============================================================================
// AES-128-CBC with HMAC-SHA2-256 (MAC-then-Encrypt)
// =============================================================================

Deno.test('AES-128-CBC with HMAC-SHA2-256 round-trip', async () => {
  const cipherInfo = CIPHER_INFO['aes128-cbc'];
  const macInfo = MAC_INFO['hmac-sha2-256'];
  const cipherKey = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);
  const macKey = randomBytes(macInfo.len);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => { ciphered = concatBytes([ciphered, data]); },
      cipherInfo,
      cipherKey,
      cipherIV: ivEnc,
      macInfo,
      macKey,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => { deciphered.push(new Uint8Array(payload)); },
      decipherInfo: cipherInfo,
      decipherKey: cipherKey,
      decipherIV: ivDec,
      macInfo,
      macKey,
    },
  });

  const payload = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0], payload);

  cipher.free();
  decipher.free();
});

Deno.test('AES-256-CBC with HMAC-SHA2-256 round-trip', async () => {
  const cipherInfo = CIPHER_INFO['aes256-cbc'];
  const macInfo = MAC_INFO['hmac-sha2-256'];
  const cipherKey = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);
  const macKey = randomBytes(macInfo.len);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => { ciphered = concatBytes([ciphered, data]); },
      cipherInfo,
      cipherKey,
      cipherIV: ivEnc,
      macInfo,
      macKey,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => { deciphered.push(new Uint8Array(payload)); },
      decipherInfo: cipherInfo,
      decipherKey: cipherKey,
      decipherIV: ivDec,
      macInfo,
      macKey,
    },
  });

  const payload = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55]);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0], payload);

  cipher.free();
  decipher.free();
});

Deno.test('AES-128-CBC multi-packet round-trip (IV chaining)', async () => {
  const cipherInfo = CIPHER_INFO['aes128-cbc'];
  const macInfo = MAC_INFO['hmac-sha2-256'];
  const cipherKey = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);
  const macKey = randomBytes(macInfo.len);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => { ciphered = concatBytes([ciphered, data]); },
      cipherInfo,
      cipherKey,
      cipherIV: ivEnc,
      macInfo,
      macKey,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => { deciphered.push(new Uint8Array(payload)); },
      decipherInfo: cipherInfo,
      decipherKey: cipherKey,
      decipherIV: ivDec,
      macInfo,
      macKey,
    },
  });

  // Encrypt three packets to verify IV chaining across packets
  const p1 = cipher.allocPacket(4);
  p1.set([0xAA, 0xBB, 0xCC, 0xDD], 5);
  await cipher.encrypt(p1);

  const p2 = cipher.allocPacket(3);
  p2.set([0x11, 0x22, 0x33], 5);
  await cipher.encrypt(p2);

  const p3 = cipher.allocPacket(2);
  p3.set([0xFE, 0xED], 5);
  await cipher.encrypt(p3);

  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 3);
  assertEquals(deciphered[0], new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]));
  assertEquals(deciphered[1], new Uint8Array([0x11, 0x22, 0x33]));
  assertEquals(deciphered[2], new Uint8Array([0xFE, 0xED]));

  cipher.free();
  decipher.free();
});

Deno.test('AES-128-CBC with HMAC-SHA2-256-ETM round-trip', async () => {
  const cipherInfo = CIPHER_INFO['aes128-cbc'];
  const macInfo = MAC_INFO['hmac-sha2-256-etm@openssh.com'];
  const cipherKey = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);
  const macKey = randomBytes(macInfo.len);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => { ciphered = concatBytes([ciphered, data]); },
      cipherInfo,
      cipherKey,
      cipherIV: ivEnc,
      macInfo,
      macKey,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => { deciphered.push(new Uint8Array(payload)); },
      decipherInfo: cipherInfo,
      decipherKey: cipherKey,
      decipherIV: ivDec,
      macInfo,
      macKey,
    },
  });

  const payload = new Uint8Array([0xCA, 0xFE, 0xBA, 0xBE]);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0], payload);

  cipher.free();
  decipher.free();
});

// =============================================================================
// AES-128-CTR with ETM (Encrypt-Then-MAC) - covers the _macETM code path
// =============================================================================

Deno.test('AES-128-CTR with HMAC-SHA2-256-ETM round-trip', async () => {
  const cipherInfo = CIPHER_INFO['aes128-ctr'];
  const macInfo = MAC_INFO['hmac-sha2-256-etm@openssh.com'];
  const cipherKey = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);
  const macKey = randomBytes(macInfo.len);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => { ciphered = concatBytes([ciphered, data]); },
      cipherInfo,
      cipherKey,
      cipherIV: ivEnc,
      macInfo,
      macKey,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => { deciphered.push(new Uint8Array(payload)); },
      decipherInfo: cipherInfo,
      decipherKey: cipherKey,
      decipherIV: ivDec,
      macInfo,
      macKey,
    },
  });

  const payload = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0], payload);

  cipher.free();
  decipher.free();
});

// =============================================================================
// NullCipher: dead check after free()
// =============================================================================

Deno.test('NullCipher: encrypt after free() is a no-op (dead check)', async () => {
  let written = 0;
  const cipher = new NullCipher(0, (_data) => { written++; });
  const packet = cipher.allocPacket(4);
  cipher.free(); // sets _dead = true
  await cipher.encrypt(packet); // should return immediately without writing
  assertEquals(written, 0);
});

// =============================================================================
// NullDecipher: partial packet receive (feed data in small chunks)
// =============================================================================

Deno.test('NullDecipher: packet split across multiple decrypt() calls', async () => {
  const payloads: Uint8Array[] = [];
  let ciphered: Uint8Array = new Uint8Array(0);

  const cipher = new NullCipher(0, (data) => { ciphered = concatBytes([ciphered, data]); });
  const decipher = new NullDecipher(0, (p) => { payloads.push(new Uint8Array(p)); });

  const payload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);
  await cipher.encrypt(packet);

  // Feed 1 byte at a time to exercise the incremental read path
  for (let i = 0; i < ciphered.length; i++) {
    await decipher.decrypt(ciphered, i, i + 1);
  }

  assertEquals(payloads.length, 1);
  assertEquals(payloads[0], payload);

  cipher.free();
  decipher.free();
});

Deno.test('NullDecipher: two packets fed incrementally', async () => {
  const payloads: Uint8Array[] = [];
  let ciphered: Uint8Array = new Uint8Array(0);

  const cipher = new NullCipher(0, (data) => { ciphered = concatBytes([ciphered, data]); });
  const decipher = new NullDecipher(0, (p) => { payloads.push(new Uint8Array(p)); });

  // Encrypt two separate packets
  const p1 = cipher.allocPacket(4);
  p1.set([0xAA, 0xBB, 0xCC, 0xDD], 5);
  await cipher.encrypt(p1);
  const p2 = cipher.allocPacket(2);
  p2.set([0x11, 0x22], 5);
  await cipher.encrypt(p2);

  // Feed combined data in small chunks
  const chunkSize = 3;
  for (let i = 0; i < ciphered.length; i += chunkSize) {
    await decipher.decrypt(ciphered, i, Math.min(i + chunkSize, ciphered.length));
  }

  assertEquals(payloads.length, 2);
  assertEquals(payloads[0], new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]));
  assertEquals(payloads[1], new Uint8Array([0x11, 0x22]));
  cipher.free();
  decipher.free();
});

// =============================================================================
// AES-192-CTR with HMAC-SHA2-256
// =============================================================================

Deno.test('AES-192-CTR with HMAC-SHA2-256 round-trip', async () => {
  const cipherInfo = CIPHER_INFO['aes192-ctr'];
  const macInfo = MAC_INFO['hmac-sha2-256'];
  const cipherKey = randomBytes(cipherInfo.keyLen);
  const ivOrig = randomBytes(cipherInfo.ivLen!);
  const ivEnc = new Uint8Array(ivOrig);
  const ivDec = new Uint8Array(ivOrig);
  const macKey = randomBytes(macInfo.len);

  let ciphered: Uint8Array = new Uint8Array(0);
  const deciphered: Uint8Array[] = [];

  const cipher = createCipher({
    outbound: {
      seqno: 0,
      onWrite: (data) => { ciphered = concatBytes([ciphered, data]); },
      cipherInfo,
      cipherKey,
      cipherIV: ivEnc,
      macInfo,
      macKey,
    },
  });

  const decipher = createDecipher({
    inbound: {
      seqno: 0,
      onPayload: (payload) => { deciphered.push(new Uint8Array(payload)); },
      decipherInfo: cipherInfo,
      decipherKey: cipherKey,
      decipherIV: ivDec,
      macInfo,
      macKey,
    },
  });

  const payload = new Uint8Array([0x01, 0x02, 0x03]);
  const packet = cipher.allocPacket(payload.length);
  packet.set(payload, 5);

  await cipher.encrypt(packet);
  await decipher.decrypt(ciphered, 0, ciphered.length);

  assertEquals(deciphered.length, 1);
  assertEquals(deciphered[0], payload);

  cipher.free();
  decipher.free();
});
