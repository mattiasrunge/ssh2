/**
 * Cryptographically secure random number generation
 * Replaces Node.js crypto.randomBytes and crypto.randomFillSync
 */

/**
 * Generate cryptographically secure random bytes.
 * Replacement for crypto.randomBytes().
 */
export function randomBytes(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Fill a Uint8Array with cryptographically secure random bytes.
 * Replacement for crypto.randomFillSync().
 */
export function randomFill(buffer: Uint8Array, offset: number = 0, size?: number): Uint8Array {
  const end = size !== undefined ? offset + size : buffer.length;
  const view = buffer.subarray(offset, end);
  crypto.getRandomValues(view);
  return buffer;
}

/**
 * Generate a random unsigned 32-bit integer.
 */
export function randomUInt32(): number {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}
