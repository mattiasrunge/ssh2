/**
 * SSH Protocol Utilities
 *
 * Buffer parsing, error handling, and signature conversion utilities
 * for SSH protocol implementation.
 */

import { Ber, BerReader, BerWriter } from '../utils/ber.ts';
import { allocBytes, readUInt32BE, toUtf8, writeUInt32BE } from '../utils/binary.ts';
import { DISCONNECT_REASON } from './constants.ts';

/**
 * SSH Protocol Error with level and fatal flag
 */
export interface SSHError extends Error {
  level: string;
  fatal: boolean;
}

/**
 * Create an SSH protocol error
 */
export function makeError(msg: string, level?: string | boolean, fatal?: boolean): SSHError {
  const err = new Error(msg) as SSHError;
  if (typeof level === 'boolean') {
    fatal = level;
    err.level = 'protocol';
  } else {
    err.level = level || 'protocol';
  }
  err.fatal = !!fatal;
  return err;
}

/**
 * Protocol interface for doFatalError (methods optional for flexibility)
 */
export interface FatalErrorProtocol {
  disconnect?(reason: number): void;
  _destruct?(): void;
  _onError?(err: Error): void;
}

/**
 * Handle a fatal protocol error
 */
export function doFatalError(
  protocol: FatalErrorProtocol,
  msg: string | Error,
  level?: string | number,
  reason?: number,
): number {
  let err: SSHError;
  if (msg instanceof Error) {
    // doFatalError(protocol, err[, reason])
    err = msg as SSHError;
    if (!err.level) err.level = 'protocol';
    if (typeof level !== 'number') {
      reason = DISCONNECT_REASON.PROTOCOL_ERROR;
    } else {
      reason = level;
    }
  } else {
    // doFatalError(protocol, msg[, level[, reason]])
    err = makeError(msg, level as string, true);
  }
  if (typeof reason !== 'number') {
    reason = DISCONNECT_REASON.PROTOCOL_ERROR;
  }
  protocol.disconnect?.(reason);
  protocol._destruct?.();
  protocol._onError?.(err);
  return Infinity;
}

/**
 * Slice a Uint8Array (creates a view, not a copy)
 */
export function sliceBytes(buf: Uint8Array, start: number, end?: number): Uint8Array {
  if (end === undefined) {
    end = buf.length;
  }
  return new Uint8Array(buf.buffer, buf.byteOffset + start, end - start);
}

/**
 * Copy bytes from source to destination
 */
export function copyBytes(
  src: Uint8Array,
  dest: Uint8Array,
  srcStart: number,
  srcEnd: number,
  destStart = 0,
): number {
  if (srcEnd > src.length) {
    srcEnd = src.length;
  }
  let nb = srcEnd - srcStart;
  const destLeft = dest.length - destStart;
  if (nb > destLeft) {
    nb = destLeft;
  }
  dest.set(new Uint8Array(src.buffer, src.byteOffset + srcStart, nb), destStart);
  return nb;
}

/**
 * Buffer parser for reading SSH protocol data
 */
export interface BufferParser {
  init(buf: Uint8Array, start?: number): void;
  pos(): number;
  length(): number;
  avail(): number;
  clear(): void;
  readUInt32BE(): number | undefined;
  readUInt64BE(behavior?: 'always' | 'maybe'): number | bigint | undefined;
  skip(n: number): void;
  skipString(): number | undefined;
  readByte(): number | undefined;
  readBool(): boolean | undefined;
  readList(): string[] | undefined;
  readString(
    dest?: boolean | Uint8Array | number,
    maxLen?: number,
  ): Uint8Array | string | number | undefined;
  readRaw(len?: number): Uint8Array | undefined;
}

/**
 * Create a buffer parser instance
 */
export function makeBufferParser(): BufferParser {
  let pos = 0;
  let buffer: Uint8Array | undefined;

  const self: BufferParser = {
    init: (buf: Uint8Array, start?: number) => {
      buffer = buf;
      pos = typeof start === 'number' ? start : 0;
    },
    pos: () => pos,
    length: () => (buffer ? buffer.length : 0),
    avail: () => (buffer && pos < buffer.length ? buffer.length - pos : 0),
    clear: () => {
      buffer = undefined;
    },
    readUInt32BE: () => {
      if (!buffer || pos + 3 >= buffer.length) {
        return undefined;
      }
      return (
        buffer[pos++] * 16777216 +
        buffer[pos++] * 65536 +
        buffer[pos++] * 256 +
        buffer[pos++]
      );
    },
    readUInt64BE: (behavior?: 'always' | 'maybe') => {
      if (!buffer || pos + 7 >= buffer.length) {
        return undefined;
      }
      switch (behavior) {
        case 'always': {
          // Always return BigInt
          const slice = buffer.subarray(pos, pos + 8);
          pos += 8;
          let hex = '0x';
          for (let i = 0; i < 8; i++) {
            hex += slice[i].toString(16).padStart(2, '0');
          }
          return BigInt(hex);
        }
        case 'maybe': {
          // Return BigInt if value is large
          if (buffer[pos] > 0x1f) {
            const slice = buffer.subarray(pos, pos + 8);
            pos += 8;
            let hex = '0x';
            for (let i = 0; i < 8; i++) {
              hex += slice[i].toString(16).padStart(2, '0');
            }
            return BigInt(hex);
          }
        }
          // FALLTHROUGH - default to number
      }
      // Return as number (may lose precision for very large values)
      return (
        buffer[pos++] * 72057594037927940 +
        buffer[pos++] * 281474976710656 +
        buffer[pos++] * 1099511627776 +
        buffer[pos++] * 4294967296 +
        buffer[pos++] * 16777216 +
        buffer[pos++] * 65536 +
        buffer[pos++] * 256 +
        buffer[pos++]
      );
    },
    skip: (n: number) => {
      if (buffer && n > 0) {
        pos += n;
      }
    },
    skipString: () => {
      const len = self.readUInt32BE();
      if (len === undefined) {
        return undefined;
      }
      pos += len;
      return pos <= buffer!.length ? len : undefined;
    },
    readByte: () => {
      if (buffer && pos < buffer.length) {
        return buffer[pos++];
      }
      return undefined;
    },
    readBool: () => {
      if (buffer && pos < buffer.length) {
        return !!buffer[pos++];
      }
      return undefined;
    },
    readList: () => {
      const list = self.readString(true);
      if (list === undefined) {
        return undefined;
      }
      return list ? (list as string).split(',') : [];
    },
    readString: (dest?: boolean | Uint8Array | number, maxLen?: number) => {
      if (typeof dest === 'number') {
        maxLen = dest;
        dest = undefined;
      }

      const len = self.readUInt32BE();
      if (len === undefined) {
        return undefined;
      }

      if (
        buffer!.length - pos < len ||
        (typeof maxLen === 'number' && len > maxLen)
      ) {
        return undefined;
      }

      if (dest) {
        if (dest instanceof Uint8Array) {
          return copyBytes(buffer!, dest, pos, pos += len);
        }
        // Return as UTF-8 string
        return toUtf8(buffer!.subarray(pos, pos += len));
      }
      return sliceBytes(buffer!, pos, pos += len);
    },
    readRaw: (len?: number) => {
      if (!buffer) {
        return undefined;
      }
      if (typeof len !== 'number') {
        return sliceBytes(buffer, pos, pos += buffer.length - pos);
      }
      if (buffer.length - pos >= len) {
        return sliceBytes(buffer, pos, pos += len);
      }
      return undefined;
    },
  };

  return self;
}

/** Shared buffer parser instance */
export const bufferParser: BufferParser = makeBufferParser();

/**
 * Read a string from a buffer at given offset
 */
export function readString(
  buffer: Uint8Array,
  start?: number,
  dest?: boolean | Uint8Array | number,
  maxLen?: number,
): Uint8Array | string | number | undefined {
  if (typeof dest === 'number') {
    maxLen = dest;
    dest = undefined;
  }

  if (start === undefined) {
    start = 0;
  }

  const left = buffer.length - start;
  if (start < 0 || start >= buffer.length || left < 4) {
    return undefined;
  }

  const len = readUInt32BE(buffer, start);
  if (left < 4 + len || (typeof maxLen === 'number' && len > maxLen)) {
    return undefined;
  }

  start += 4;
  const end = start + len;

  if (dest) {
    if (dest instanceof Uint8Array) {
      return copyBytes(buffer, dest, start, end);
    }
    return toUtf8(buffer.subarray(start, end));
  }
  return sliceBytes(buffer, start, end);
}

/**
 * Convert SSH signature format to ASN.1 format for verification
 */
export function sigSSHToASN1(sig: Uint8Array, type: string): Uint8Array | undefined {
  switch (type) {
    case 'ecdsa-sha2-nistp256':
    case 'ecdsa-sha2-nistp384':
    case 'ecdsa-sha2-nistp521': {
      bufferParser.init(sig, 0);
      const r = bufferParser.readString() as Uint8Array | undefined;
      const s = bufferParser.readString() as Uint8Array | undefined;
      bufferParser.clear();
      if (r === undefined || s === undefined) {
        return undefined;
      }

      const asnWriter = new BerWriter();
      asnWriter.startSequence();
      asnWriter.writeBuffer(r, Ber.Integer);
      asnWriter.writeBuffer(s, Ber.Integer);
      asnWriter.endSequence();
      return new Uint8Array(asnWriter.buffer);
    }
    default:
      return sig;
  }
}

/**
 * Convert ASN.1 signature format to SSH format for signing
 */
export function convertSignature(signature: Uint8Array, keyType: string): Uint8Array | false {
  switch (keyType) {
    case 'ecdsa-sha2-nistp256':
    case 'ecdsa-sha2-nistp384':
    case 'ecdsa-sha2-nistp521': {
      if (signature[0] === 0) {
        return signature;
      }
      // Convert ASN.1 BER to SSH signature format
      const asnReader = new BerReader(signature);
      asnReader.readSequence();
      const r = asnReader.readString(Ber.Integer, true);
      const s = asnReader.readString(Ber.Integer, true);
      if (r === null || s === null) {
        return false;
      }
      const newSig = allocBytes(4 + r.length + 4 + s.length);
      writeUInt32BE(newSig, r.length, 0);
      newSig.set(r, 4);
      writeUInt32BE(newSig, s.length, 4 + r.length);
      newSig.set(s, 4 + 4 + r.length);
      return newSig;
    }
  }

  return signature;
}

/**
 * Write UInt32 in little-endian format
 */
export function writeUInt32LE(buf: Uint8Array, value: number, offset: number): number {
  buf[offset++] = value;
  buf[offset++] = value >>> 8;
  buf[offset++] = value >>> 16;
  buf[offset++] = value >>> 24;
  return offset;
}
