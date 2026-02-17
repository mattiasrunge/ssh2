/**
 * Crypto utility functions
 */

/**
 * Constant-time comparison of two Uint8Arrays.
 * Replacement for crypto.timingSafeEqual().
 *
 * This function always takes the same amount of time regardless of
 * where the first difference occurs, preventing timing attacks.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    // Still do a comparison to maintain constant time relative to the shorter input
    // This leaks length information but that's usually acceptable
    const dummy = new Uint8Array(a.length);
    timingSafeEqual(a, dummy);
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * XOR two Uint8Arrays of the same length.
 */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new Error('Uint8Arrays must have the same length for XOR');
  }
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/**
 * XOR bytes in place (modifies first array).
 */
export function xorBytesInPlace(target: Uint8Array, source: Uint8Array): void {
  const len = Math.min(target.length, source.length);
  for (let i = 0; i < len; i++) {
    target[i] ^= source[i];
  }
}

/**
 * Increment a counter stored as big-endian bytes.
 * Note: We must check the stored value after increment, not the return value
 * of ++, because Uint8Array wraps 255→0 but ++ returns the pre-clamped 256.
 */
export function incrementCounter(counter: Uint8Array): void {
  for (let i = counter.length - 1; i >= 0; i--) {
    counter[i] = (counter[i] + 1) & 0xff;
    if (counter[i] !== 0) {
      break;
    }
  }
}

/**
 * Zero out a Uint8Array (for secure cleanup).
 */
export function zeroBytes(bytes: Uint8Array): void {
  bytes.fill(0);
}
