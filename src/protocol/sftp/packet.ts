/**
 * SFTP Packet Serialization and Parsing
 *
 * Handles binary encoding/decoding of SFTP protocol packets.
 */

import { fromString, readUInt32BE, toUtf8, writeUInt32BE } from '../../utils/binary.ts';
import { ATTR, REQUEST, RESPONSE } from './constants.ts';
import type { ExtendedAttribute, FileAttributes, InputAttributes } from './types.ts';

/**
 * Reusable buffer for attribute serialization (28 bytes max)
 */
const ATTRS_BUF = new Uint8Array(28);

/**
 * Convert attributes to bytes for protocol transmission
 * Returns the flags and number of bytes written
 */
export function attrsToBytes(attrs: InputAttributes | undefined): { flags: number; nb: number } {
  let flags = 0;
  let nb = 0;

  if (typeof attrs === 'object' && attrs !== null) {
    // Size (8 bytes, 64-bit)
    if (typeof attrs.size === 'number' || typeof attrs.size === 'bigint') {
      flags |= ATTR.SIZE;
      const val = typeof attrs.size === 'bigint' ? attrs.size : BigInt(attrs.size);
      // Write as big-endian 64-bit
      ATTRS_BUF[nb++] = Number((val >> 56n) & 0xFFn);
      ATTRS_BUF[nb++] = Number((val >> 48n) & 0xFFn);
      ATTRS_BUF[nb++] = Number((val >> 40n) & 0xFFn);
      ATTRS_BUF[nb++] = Number((val >> 32n) & 0xFFn);
      ATTRS_BUF[nb++] = Number((val >> 24n) & 0xFFn);
      ATTRS_BUF[nb++] = Number((val >> 16n) & 0xFFn);
      ATTRS_BUF[nb++] = Number((val >> 8n) & 0xFFn);
      ATTRS_BUF[nb++] = Number(val & 0xFFn);
    }

    // UID/GID (4 bytes each)
    if (typeof attrs.uid === 'number' && typeof attrs.gid === 'number') {
      flags |= ATTR.UIDGID;
      const uid = attrs.uid;
      const gid = attrs.gid;
      ATTRS_BUF[nb++] = (uid >>> 24) & 0xFF;
      ATTRS_BUF[nb++] = (uid >>> 16) & 0xFF;
      ATTRS_BUF[nb++] = (uid >>> 8) & 0xFF;
      ATTRS_BUF[nb++] = uid & 0xFF;
      ATTRS_BUF[nb++] = (gid >>> 24) & 0xFF;
      ATTRS_BUF[nb++] = (gid >>> 16) & 0xFF;
      ATTRS_BUF[nb++] = (gid >>> 8) & 0xFF;
      ATTRS_BUF[nb++] = gid & 0xFF;
    }

    // Mode/permissions (4 bytes)
    if (typeof attrs.mode === 'number' || typeof attrs.mode === 'string') {
      const mode = modeNum(attrs.mode);
      flags |= ATTR.PERMISSIONS;
      ATTRS_BUF[nb++] = (mode >>> 24) & 0xFF;
      ATTRS_BUF[nb++] = (mode >>> 16) & 0xFF;
      ATTRS_BUF[nb++] = (mode >>> 8) & 0xFF;
      ATTRS_BUF[nb++] = mode & 0xFF;
    }

    // Access/modification time (4 bytes each)
    if (attrs.atime !== undefined && attrs.mtime !== undefined) {
      const atime = toUnixTimestamp(attrs.atime);
      const mtime = toUnixTimestamp(attrs.mtime);
      flags |= ATTR.ACMODTIME;
      ATTRS_BUF[nb++] = (atime >>> 24) & 0xFF;
      ATTRS_BUF[nb++] = (atime >>> 16) & 0xFF;
      ATTRS_BUF[nb++] = (atime >>> 8) & 0xFF;
      ATTRS_BUF[nb++] = atime & 0xFF;
      ATTRS_BUF[nb++] = (mtime >>> 24) & 0xFF;
      ATTRS_BUF[nb++] = (mtime >>> 16) & 0xFF;
      ATTRS_BUF[nb++] = (mtime >>> 8) & 0xFF;
      ATTRS_BUF[nb++] = mtime & 0xFF;
    }
  }

  return { flags, nb };
}

/**
 * Get the serialized attribute bytes
 */
export function getAttrBytes(nb: number): Uint8Array {
  return ATTRS_BUF.subarray(0, nb);
}

/**
 * Convert time value to Unix timestamp
 */
export function toUnixTimestamp(time: number | Date): number {
  if (typeof time === 'number' && !Number.isNaN(time)) {
    return Math.floor(time);
  }
  if (time instanceof Date) {
    return Math.floor(time.getTime() / 1000);
  }
  throw new Error(`Cannot parse time: ${time}`);
}

/**
 * Convert mode to number
 */
export function modeNum(mode: number | string): number {
  if (typeof mode === 'number' && !Number.isNaN(mode)) {
    return mode;
  }
  if (typeof mode === 'string') {
    return parseInt(mode, 8);
  }
  throw new Error(`Cannot parse mode: ${mode}`);
}

/**
 * Buffer parser for reading SFTP packets
 */
export class PacketParser {
  private _buffer: Uint8Array = new Uint8Array(0);
  private _pos = 0;

  init(buffer: Uint8Array, pos = 0): void {
    this._buffer = buffer;
    this._pos = pos;
  }

  clear(): void {
    this._buffer = new Uint8Array(0);
    this._pos = 0;
  }

  get pos(): number {
    return this._pos;
  }

  get remaining(): number {
    return this._buffer.length - this._pos;
  }

  skip(n: number): boolean {
    if (this._pos + n > this._buffer.length) return false;
    this._pos += n;
    return true;
  }

  readByte(): number | undefined {
    if (this._pos >= this._buffer.length) return undefined;
    return this._buffer[this._pos++];
  }

  readUInt32BE(): number | undefined {
    if (this._pos + 4 > this._buffer.length) return undefined;
    const val = readUInt32BE(this._buffer, this._pos);
    this._pos += 4;
    return val;
  }

  readUInt64BE(asBigInt = false): number | bigint | undefined {
    if (this._pos + 8 > this._buffer.length) return undefined;
    const buf = this._buffer;
    const pos = this._pos;
    this._pos += 8;

    if (asBigInt) {
      return (
        (BigInt(buf[pos]) << 56n) |
        (BigInt(buf[pos + 1]) << 48n) |
        (BigInt(buf[pos + 2]) << 40n) |
        (BigInt(buf[pos + 3]) << 32n) |
        (BigInt(buf[pos + 4]) << 24n) |
        (BigInt(buf[pos + 5]) << 16n) |
        (BigInt(buf[pos + 6]) << 8n) |
        BigInt(buf[pos + 7])
      );
    }

    // Return as number (may lose precision for very large values)
    const hi =
      (buf[pos] * 0x1000000 + buf[pos + 1] * 0x10000 + buf[pos + 2] * 0x100 + buf[pos + 3]) >>> 0;
    const lo =
      (buf[pos + 4] * 0x1000000 + buf[pos + 5] * 0x10000 + buf[pos + 6] * 0x100 + buf[pos + 7]) >>>
      0;
    return hi * 0x100000000 + lo;
  }

  readString(asString = false): Uint8Array | string | undefined {
    const len = this.readUInt32BE();
    if (len === undefined) return undefined;
    if (this._pos + len > this._buffer.length) return undefined;

    const data = this._buffer.subarray(this._pos, this._pos + len);
    this._pos += len;

    if (asString) {
      return toUtf8(data);
    }
    return data;
  }

  /**
   * Read file attributes from current position
   */
  readAttrs(useBigInt = false): FileAttributes | undefined {
    const flags = this.readUInt32BE();
    if (flags === undefined) return undefined;

    const attrs: FileAttributes = {};

    if (flags & ATTR.SIZE) {
      const size = this.readUInt64BE(useBigInt);
      if (size === undefined) return undefined;
      attrs.size = size;
    }

    if (flags & ATTR.UIDGID) {
      const uid = this.readUInt32BE();
      const gid = this.readUInt32BE();
      if (gid === undefined) return undefined;
      attrs.uid = uid;
      attrs.gid = gid;
    }

    if (flags & ATTR.PERMISSIONS) {
      const mode = this.readUInt32BE();
      if (mode === undefined) return undefined;
      attrs.mode = mode;
    }

    if (flags & ATTR.ACMODTIME) {
      const atime = this.readUInt32BE();
      const mtime = this.readUInt32BE();
      if (mtime === undefined) return undefined;
      attrs.atime = atime;
      attrs.mtime = mtime;
    }

    if (flags & ATTR.EXTENDED) {
      const count = this.readUInt32BE();
      if (count === undefined) return undefined;

      const extended: ExtendedAttribute[] = [];
      for (let i = 0; i < count; i++) {
        const type = this.readString(true) as string | undefined;
        const data = this.readString(false) as Uint8Array | undefined;
        if (data === undefined) return undefined;
        extended.push({ type: type!, data });
      }
      attrs.extended = extended;
    }

    return attrs;
  }
}

/**
 * Create a new packet parser instance
 */
export function makePacketParser(): PacketParser {
  return new PacketParser();
}

/**
 * Write a string to a buffer at the specified offset
 * Returns the new offset after writing
 */
export function writeString(buf: Uint8Array, str: string | Uint8Array, offset: number): number {
  const bytes = typeof str === 'string' ? fromString(str) : str;
  writeUInt32BE(buf, bytes.length, offset);
  buf.set(bytes, offset + 4);
  return offset + 4 + bytes.length;
}

/**
 * Write a 64-bit value to a buffer
 */
export function writeUInt64BE(buf: Uint8Array, val: number | bigint, offset: number): void {
  const v = typeof val === 'bigint' ? val : BigInt(val);
  buf[offset] = Number((v >> 56n) & 0xFFn);
  buf[offset + 1] = Number((v >> 48n) & 0xFFn);
  buf[offset + 2] = Number((v >> 40n) & 0xFFn);
  buf[offset + 3] = Number((v >> 32n) & 0xFFn);
  buf[offset + 4] = Number((v >> 24n) & 0xFFn);
  buf[offset + 5] = Number((v >> 16n) & 0xFFn);
  buf[offset + 6] = Number((v >> 8n) & 0xFFn);
  buf[offset + 7] = Number(v & 0xFFn);
}

/**
 * Calculate the byte length needed for a string in protocol format
 */
export function stringByteLength(str: string | Uint8Array): number {
  if (typeof str === 'string') {
    return 4 + new TextEncoder().encode(str).length;
  }
  return 4 + str.length;
}

/**
 * Client version packet (SFTP version 3)
 */
export const CLIENT_VERSION_BUFFER = new Uint8Array([
  0,
  0,
  0,
  5, // length
  REQUEST.INIT,
  0,
  0,
  0,
  3, // version 3
]);

/**
 * Server version packet (SFTP version 3)
 */
export const SERVER_VERSION_BUFFER = new Uint8Array([
  0,
  0,
  0,
  5, // length
  RESPONSE.VERSION,
  0,
  0,
  0,
  3, // version 3
]);
