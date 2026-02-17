/**
 * Minimal BER (Basic Encoding Rules) for ASN.1
 *
 * Provides DER/BER encoding and decoding for SSH key parsing.
 * This is a pure TypeScript implementation covering the subset
 * of ASN.1 used by SSH keys (SEQUENCE, INTEGER, OID, OCTET STRING, BIT STRING).
 */

import { allocBytes } from './binary.ts';

// ASN.1 Universal Tags
export const Ber = {
  EOC: 0x00,
  Boolean: 0x01,
  Integer: 0x02,
  BitString: 0x03,
  OctetString: 0x04,
  Null: 0x05,
  OID: 0x06,
  Enumeration: 0x0a,
  UTF8String: 0x0c,
  Sequence: 0x30,
  Set: 0x31,
  PrintableString: 0x13,
  IA5String: 0x16,
  UTCTime: 0x17,
  GeneralizedTime: 0x18,
  Context: 0xa0,
} as const;

/**
 * BER Reader for parsing DER-encoded data
 */
export class BerReader {
  private _buf: Uint8Array;
  private _offset = 0;
  private _len = 0;
  private _size = 0;

  constructor(data: Uint8Array) {
    this._buf = data;
    this._size = data.length;
  }

  get buffer(): Uint8Array {
    return this._buf;
  }

  get offset(): number {
    return this._offset;
  }

  get length(): number {
    return this._len;
  }

  get remain(): number {
    return this._size - this._offset;
  }

  /**
   * Read a byte from the buffer
   */
  readByte(peek = false): number {
    if (this._offset >= this._size) {
      throw new Error('BER read past end of buffer');
    }
    const byte = this._buf[this._offset];
    if (!peek) this._offset++;
    return byte;
  }

  /**
   * Read tag and length, return the tag
   */
  private _readTagLen(): { tag: number; len: number } {
    const tag = this.readByte();
    let len = this.readByte();

    if (len & 0x80) {
      const numBytes = len & 0x7f;
      if (numBytes > 4) {
        throw new Error('BER length too long');
      }
      len = 0;
      for (let i = 0; i < numBytes; i++) {
        len = (len << 8) | this.readByte();
      }
    }

    return { tag, len };
  }

  /**
   * Read a SEQUENCE tag and return its length
   */
  readSequence(tag: number = Ber.Sequence): number | null {
    const { tag: readTag, len } = this._readTagLen();
    if (readTag !== tag) {
      this._offset -= 2; // Rewind
      return null;
    }
    this._len = len;
    return len;
  }

  /**
   * Read an INTEGER value as a number
   */
  readInt(tag: number = Ber.Integer): number {
    const { tag: readTag, len } = this._readTagLen();
    if (readTag !== tag) {
      throw new Error(`Expected INTEGER tag ${tag}, got ${readTag}`);
    }

    if (len > 4) {
      // For large integers, just skip and return 0
      // (caller should use readString for large values)
      this._offset += len;
      return 0;
    }

    let value = 0;
    for (let i = 0; i < len; i++) {
      value = (value << 8) | this.readByte();
    }

    // Handle sign extension for negative numbers
    if (len > 0 && this._buf[this._offset - len] & 0x80) {
      // Negative number
      const mask = (1 << (len * 8)) - 1;
      value = value - mask - 1;
    }

    return value;
  }

  /**
   * Read an OBJECT IDENTIFIER as a string
   */
  readOID(tag: number = Ber.OID): string {
    const { tag: readTag, len } = this._readTagLen();
    if (readTag !== tag) {
      throw new Error(`Expected OID tag ${tag}, got ${readTag}`);
    }

    const end = this._offset + len;
    const values: number[] = [];

    // First byte encodes first two components
    const first = this.readByte();
    values.push(Math.floor(first / 40));
    values.push(first % 40);

    // Remaining bytes
    while (this._offset < end) {
      let value = 0;
      let byte: number;
      do {
        byte = this.readByte();
        value = (value << 7) | (byte & 0x7f);
      } while (byte & 0x80);
      values.push(value);
    }

    return values.join('.');
  }

  /**
   * Read a string value (OCTET STRING, BIT STRING, INTEGER as bytes, etc.)
   */
  readString(tag?: number, returnBuffer?: boolean): Uint8Array | string | null;
  readString(tag: number, returnBuffer: true): Uint8Array | null;
  readString(tag?: number, returnBuffer?: boolean): Uint8Array | string | null {
    if (tag === undefined) tag = Ber.OctetString;

    const savedOffset = this._offset;
    const { tag: readTag, len } = this._readTagLen();

    if (readTag !== tag) {
      this._offset = savedOffset;
      return null;
    }

    const data = this._buf.subarray(this._offset, this._offset + len);
    this._offset += len;

    if (returnBuffer) {
      return data;
    }

    return new TextDecoder().decode(data);
  }
}

/**
 * BER Writer for creating DER-encoded data
 */
export class BerWriter {
  _buf: Uint8Array;
  _offset = 0;
  private _seq: number[] = [];

  constructor(options?: { size?: number }) {
    this._buf = allocBytes(options?.size || 1024);
  }

  get buffer(): Uint8Array {
    return this._buf.subarray(0, this._offset);
  }

  /**
   * Ensure buffer has enough space
   */
  _ensure(len: number): void {
    if (this._offset + len > this._buf.length) {
      const newBuf = allocBytes(this._buf.length * 2 + len);
      newBuf.set(this._buf);
      this._buf = newBuf;
    }
  }

  /**
   * Write a single byte
   */
  writeByte(byte: number): void {
    this._ensure(1);
    this._buf[this._offset++] = byte & 0xff;
  }

  /**
   * Write length in DER format
   */
  private _writeLength(len: number): void {
    if (len < 0x80) {
      this.writeByte(len);
    } else if (len < 0x100) {
      this.writeByte(0x81);
      this.writeByte(len);
    } else if (len < 0x10000) {
      this.writeByte(0x82);
      this.writeByte(len >> 8);
      this.writeByte(len & 0xff);
    } else if (len < 0x1000000) {
      this.writeByte(0x83);
      this.writeByte(len >> 16);
      this.writeByte((len >> 8) & 0xff);
      this.writeByte(len & 0xff);
    } else {
      this.writeByte(0x84);
      this.writeByte(len >> 24);
      this.writeByte((len >> 16) & 0xff);
      this.writeByte((len >> 8) & 0xff);
      this.writeByte(len & 0xff);
    }
  }

  /**
   * Start a SEQUENCE (or other constructed type)
   */
  startSequence(tag: number = Ber.Sequence): void {
    this.writeByte(tag);
    this._seq.push(this._offset);
    // Reserve space for length (will be filled in endSequence)
    this._offset += 3; // Reserve space for up to 2-byte length
  }

  /**
   * End a SEQUENCE and fill in the length
   */
  endSequence(): void {
    const start = this._seq.pop();
    if (start === undefined) {
      throw new Error('No sequence to end');
    }

    const len = this._offset - start - 3;

    // Calculate actual length encoding size
    let lenSize: number;
    if (len < 0x80) {
      lenSize = 1;
    } else if (len < 0x100) {
      lenSize = 2;
    } else {
      lenSize = 3;
    }

    // Shift content if length encoding is different size
    if (lenSize !== 3) {
      const shift = 3 - lenSize;
      this._buf.copyWithin(start + lenSize, start + 3, this._offset);
      this._offset -= shift;
    }

    // Write length at correct position
    const lenOffset = start;
    if (len < 0x80) {
      this._buf[lenOffset] = len;
    } else if (len < 0x100) {
      this._buf[lenOffset] = 0x81;
      this._buf[lenOffset + 1] = len;
    } else {
      this._buf[lenOffset] = 0x82;
      this._buf[lenOffset + 1] = len >> 8;
      this._buf[lenOffset + 2] = len & 0xff;
    }
  }

  /**
   * Write a NULL value
   */
  writeNull(): void {
    this.writeByte(Ber.Null);
    this.writeByte(0x00);
  }

  /**
   * Write an INTEGER value
   */
  writeInt(value: number, tag: number = Ber.Integer): void {
    this.writeByte(tag);

    // Handle negative numbers
    const isNeg = value < 0;
    if (isNeg) value = ~value;

    // Calculate bytes needed
    let bytes: number[] = [];
    do {
      bytes.unshift(value & 0xff);
      value = Math.floor(value / 256);
    } while (value > 0);

    // Add sign byte if needed
    if (isNeg) {
      bytes = bytes.map((b) => ~b & 0xff);
      if (!(bytes[0] & 0x80)) {
        bytes.unshift(0xff);
      }
    } else if (bytes[0] & 0x80) {
      bytes.unshift(0x00);
    }

    this._writeLength(bytes.length);
    for (const b of bytes) {
      this.writeByte(b);
    }
  }

  /**
   * Write a buffer with a tag (INTEGER, OCTET STRING, BIT STRING, etc.)
   */
  writeBuffer(data: Uint8Array, tag: number = Ber.OctetString): void {
    this.writeByte(tag);
    this._writeLength(data.length);
    this._ensure(data.length);
    this._buf.set(data, this._offset);
    this._offset += data.length;
  }

  /**
   * Write an OBJECT IDENTIFIER
   */
  writeOID(oid: string, tag: number = Ber.OID): void {
    const components = oid.split('.').map((s) => parseInt(s, 10));
    if (components.length < 2) {
      throw new Error('OID must have at least 2 components');
    }

    const bytes: number[] = [];

    // First two components encoded in first byte
    bytes.push(components[0] * 40 + components[1]);

    // Remaining components use base-128 encoding
    for (let i = 2; i < components.length; i++) {
      let value = components[i];
      const encoded: number[] = [];
      do {
        encoded.unshift((value & 0x7f) | (encoded.length ? 0x80 : 0));
        value = Math.floor(value / 128);
      } while (value > 0);
      bytes.push(...encoded);
    }

    this.writeByte(tag);
    this._writeLength(bytes.length);
    for (const b of bytes) {
      this.writeByte(b);
    }
  }
}

// Export Reader and Writer classes with legacy names
export const Reader = BerReader;
export const Writer = BerWriter;

// Also export Ber namespace-style for compatibility
export default {
  Reader: BerReader,
  Writer: BerWriter,
  Integer: Ber.Integer,
  BitString: Ber.BitString,
  OctetString: Ber.OctetString,
  Null: Ber.Null,
  OID: Ber.OID,
  Sequence: Ber.Sequence,
};
