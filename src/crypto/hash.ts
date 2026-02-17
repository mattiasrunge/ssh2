/**
 * Hash and HMAC utilities using Web Crypto API
 * Replaces Node.js crypto.createHash and crypto.createHmac
 */

export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

// Map common names to Web Crypto algorithm names
const HASH_ALGORITHM_MAP: Record<string, HashAlgorithm> = {
  'sha1': 'SHA-1',
  'sha-1': 'SHA-1',
  'SHA-1': 'SHA-1',
  'sha256': 'SHA-256',
  'sha-256': 'SHA-256',
  'SHA-256': 'SHA-256',
  'sha384': 'SHA-384',
  'sha-384': 'SHA-384',
  'SHA-384': 'SHA-384',
  'sha512': 'SHA-512',
  'sha-512': 'SHA-512',
  'SHA-512': 'SHA-512',
};

/**
 * Normalize hash algorithm name to Web Crypto format.
 */
export function normalizeHashAlgorithm(algorithm: string): HashAlgorithm {
  const normalized = HASH_ALGORITHM_MAP[algorithm];
  if (!normalized) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
  return normalized;
}

/**
 * Compute a hash of the given data.
 * Replacement for crypto.createHash().update().digest().
 */
export async function hash(algorithm: string, data: Uint8Array): Promise<Uint8Array> {
  const normalizedAlg = normalizeHashAlgorithm(algorithm);
  const hashBuffer = await crypto.subtle.digest(normalizedAlg, data as BufferSource);
  return new Uint8Array(hashBuffer);
}

/**
 * Compute an HMAC of the given data.
 * Replacement for crypto.createHmac().update().digest().
 */
export async function hmac(
  algorithm: string,
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const normalizedAlg = normalizeHashAlgorithm(algorithm);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'HMAC', hash: normalizedAlg },
    false,
    ['sign'],
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data as BufferSource);
  return new Uint8Array(signature);
}

/**
 * Verify an HMAC.
 */
export async function hmacVerify(
  algorithm: string,
  key: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const normalizedAlg = normalizeHashAlgorithm(algorithm);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'HMAC', hash: normalizedAlg },
    false,
    ['verify'],
  );

  return await crypto.subtle.verify(
    'HMAC',
    cryptoKey,
    signature as BufferSource,
    data as BufferSource,
  );
}

/**
 * Get the output length in bytes for a hash algorithm.
 */
export function hashLength(algorithm: string): number {
  const normalizedAlg = normalizeHashAlgorithm(algorithm);
  switch (normalizedAlg) {
    case 'SHA-1':
      return 20;
    case 'SHA-256':
      return 32;
    case 'SHA-384':
      return 48;
    case 'SHA-512':
      return 64;
  }
}

/**
 * Incremental hash builder for streaming data.
 * Note: Web Crypto doesn't support streaming, so we buffer all data.
 */
export class HashBuilder {
  private chunks: Uint8Array[] = [];
  private algorithm: HashAlgorithm;

  constructor(algorithm: string) {
    this.algorithm = normalizeHashAlgorithm(algorithm);
  }

  update(data: Uint8Array): this {
    this.chunks.push(data);
    return this;
  }

  async digest(): Promise<Uint8Array> {
    // Concatenate all chunks
    const totalLength = this.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of this.chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }

    const hashBuffer = await crypto.subtle.digest(this.algorithm, combined as BufferSource);
    return new Uint8Array(hashBuffer);
  }
}

/**
 * Incremental HMAC builder for streaming data.
 */
export class HmacBuilder {
  private chunks: Uint8Array[] = [];
  private algorithm: HashAlgorithm;
  private key: Uint8Array;

  constructor(algorithm: string, key: Uint8Array) {
    this.algorithm = normalizeHashAlgorithm(algorithm);
    this.key = key;
  }

  update(data: Uint8Array): this {
    this.chunks.push(data);
    return this;
  }

  async digest(): Promise<Uint8Array> {
    // Concatenate all chunks
    const totalLength = this.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of this.chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }

    return await hmac(this.algorithm, this.key, combined);
  }
}
