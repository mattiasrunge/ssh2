/**
 * Binary utilities for working with Uint8Array
 * Replaces Node.js Buffer API with Web-standard equivalents
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Allocate a zero-filled Uint8Array of the given size */
export function allocBytes(size: number): Uint8Array {
  return new Uint8Array(size);
}

/** Allocate a Uint8Array (not guaranteed to be zeroed, same as allocBytes in practice) */
export const allocBytesUnsafe = allocBytes;

/** Create Uint8Array from a UTF-8 string */
export function fromString(str: string): Uint8Array {
  return encoder.encode(str);
}

/** Create Uint8Array from a hex string */
export function fromHex(hex: string): Uint8Array {
  const len = hex.length / 2;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Create Uint8Array from a base64 string */
export function fromBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Create Uint8Array from an array of numbers */
export function fromArray(arr: number[] | ArrayLike<number>): Uint8Array {
  return new Uint8Array(arr);
}

/** Concatenate multiple Uint8Arrays into one */
export function concatBytes(arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/** Check if a value is a Uint8Array */
export function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

/** Convert Uint8Array to UTF-8 string */
export function toUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Convert Uint8Array to hex string */
export function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/** Convert Uint8Array to base64 string */
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Read unsigned 32-bit big-endian integer */
export function readUInt32BE(buf: Uint8Array, offset: number): number {
  return (
    ((buf[offset] << 24) >>> 0) +
    (buf[offset + 1] << 16) +
    (buf[offset + 2] << 8) +
    buf[offset + 3]
  );
}

/** Write unsigned 32-bit big-endian integer, returns new offset */
export function writeUInt32BE(buf: Uint8Array, value: number, offset: number): number {
  buf[offset] = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
  return offset + 4;
}

/** Read unsigned 64-bit big-endian integer (as bigint) */
export function readUInt64BE(buf: Uint8Array, offset: number): bigint {
  const high = BigInt(readUInt32BE(buf, offset));
  const low = BigInt(readUInt32BE(buf, offset + 4));
  return (high << 32n) | low;
}

/** Write unsigned 64-bit big-endian integer (from bigint), returns new offset */
export function writeUInt64BE(buf: Uint8Array, value: bigint, offset: number): number {
  const high = Number((value >> 32n) & 0xffffffffn);
  const low = Number(value & 0xffffffffn);
  writeUInt32BE(buf, high, offset);
  writeUInt32BE(buf, low, offset + 4);
  return offset + 8;
}

/** Read signed 32-bit big-endian integer */
export function readInt32BE(buf: Uint8Array, offset: number): number {
  const val = readUInt32BE(buf, offset);
  return val > 0x7fffffff ? val - 0x100000000 : val;
}

/** Write signed 32-bit big-endian integer, returns new offset */
export function writeInt32BE(buf: Uint8Array, value: number, offset: number): number {
  return writeUInt32BE(buf, value < 0 ? value + 0x100000000 : value, offset);
}

/** Read unsigned 16-bit big-endian integer */
export function readUInt16BE(buf: Uint8Array, offset: number): number {
  return (buf[offset] << 8) + buf[offset + 1];
}

/** Write unsigned 16-bit big-endian integer, returns new offset */
export function writeUInt16BE(buf: Uint8Array, value: number, offset: number): number {
  buf[offset] = (value >>> 8) & 0xff;
  buf[offset + 1] = value & 0xff;
  return offset + 2;
}

/** Read unsigned 8-bit integer */
export function readUInt8(buf: Uint8Array, offset: number): number {
  return buf[offset];
}

/** Write unsigned 8-bit integer, returns new offset */
export function writeUInt8(buf: Uint8Array, value: number, offset: number): number {
  buf[offset] = value & 0xff;
  return offset + 1;
}

/** Create a slice of the buffer (shares underlying ArrayBuffer) */
export function sliceBytes(buf: Uint8Array, start: number, end?: number): Uint8Array {
  return buf.subarray(start, end);
}

/** Copy bytes from source to target at offset */
export function copyBytes(
  source: Uint8Array,
  target: Uint8Array,
  targetOffset: number = 0,
  sourceStart: number = 0,
  sourceEnd?: number,
): number {
  const src = sourceEnd !== undefined
    ? source.subarray(sourceStart, sourceEnd)
    : source.subarray(sourceStart);
  target.set(src, targetOffset);
  return src.length;
}

/** Compare two Uint8Arrays for equality */
export function equalsBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Compare two Uint8Arrays lexicographically (-1, 0, 1) */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  if (a.length < b.length) return -1;
  if (a.length > b.length) return 1;
  return 0;
}

/** Fill a Uint8Array with a value */
export function fillBytes(
  buf: Uint8Array,
  value: number,
  start: number = 0,
  end?: number,
): Uint8Array {
  buf.fill(value, start, end);
  return buf;
}

/** Create a Uint8Array view over an existing ArrayBuffer */
export function viewBytes(
  buffer: ArrayBuffer,
  byteOffset?: number,
  byteLength?: number,
): Uint8Array {
  return new Uint8Array(buffer, byteOffset, byteLength);
}

/** Empty Uint8Array constant */
export const EMPTY_BYTES: Uint8Array = new Uint8Array(0);
