/**
 * Unpadded AES-CBC on top of Web Crypto.
 *
 * SSH transport ciphers and OpenSSH key blobs use AES-CBC on block-aligned
 * data without PKCS#7 padding, but crypto.subtle always applies PKCS#7.
 * Both directions can still be expressed with subtle alone:
 *
 * - Encrypt: PKCS#7 on block-aligned input appends exactly one full padding
 *   block, and CBC encryption of a prefix is unaffected by what follows, so
 *   encrypting normally and dropping the final block yields the raw ciphertext.
 * - Decrypt: CBC-encrypting an empty message with IV set to the last
 *   ciphertext block produces the one block T = E_k(padBlock XOR lastCtBlock).
 *   Appending T makes the padding validate as a full block, which subtle
 *   strips, returning exactly the original plaintext.
 */

const BLOCK_LEN = 16;

/**
 * Import a raw AES key (16/24/32 bytes) for use with encryptNoPad/decryptNoPad.
 */
export function importCbcKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as Uint8Array<ArrayBuffer>, 'AES-CBC', false, [
    'encrypt',
    'decrypt',
  ]);
}

/**
 * AES-CBC encrypt block-aligned data without PKCS#7 padding.
 */
export async function encryptNoPad(
  key: CryptoKey,
  iv: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  if (data.length % BLOCK_LEN !== 0) {
    throw new Error(`AES-CBC data length ${data.length} is not a multiple of ${BLOCK_LEN}`);
  }
  const padded = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: iv as Uint8Array<ArrayBuffer> },
    key,
    data as Uint8Array<ArrayBuffer>,
  );
  // Drop the final padding block
  return new Uint8Array(padded, 0, data.length);
}

/**
 * AES-CBC decrypt block-aligned data without PKCS#7 padding.
 */
export async function decryptNoPad(
  key: CryptoKey,
  iv: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  if (data.length === 0) return new Uint8Array(0);
  if (data.length % BLOCK_LEN !== 0) {
    throw new Error(`AES-CBC data length ${data.length} is not a multiple of ${BLOCK_LEN}`);
  }
  const lastBlock = data.subarray(data.length - BLOCK_LEN) as Uint8Array<ArrayBuffer>;
  const trailer = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: lastBlock },
    key,
    new Uint8Array(0),
  );
  const extended = new Uint8Array(data.length + BLOCK_LEN);
  extended.set(data, 0);
  extended.set(new Uint8Array(trailer), data.length);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: iv as Uint8Array<ArrayBuffer> },
    key,
    extended,
  );
  return new Uint8Array(plaintext);
}
