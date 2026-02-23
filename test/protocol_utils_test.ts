/**
 * Protocol Utils Tests
 *
 * Tests for makeError, doFatalError, makeBufferParser, readString,
 * sigSSHToASN1, convertSignature, writeUInt32LE, sliceBytes, copyBytes.
 */

import { assertEquals, assertNotEquals } from '@std/assert';
import { DISCONNECT_REASON } from '../src/protocol/constants.ts';
import {
  bufferParser,
  convertSignature,
  copyBytes,
  doFatalError,
  makeBufferParser,
  makeError,
  readString,
  sigSSHToASN1,
  sliceBytes,
  writeUInt32LE,
} from '../src/protocol/utils.ts';

// =============================================================================
// makeError tests
// =============================================================================

Deno.test('makeError: no args gives protocol level and fatal=false', () => {
  const err = makeError('test message');
  assertEquals(err.message, 'test message');
  assertEquals(err.level, 'protocol');
  assertEquals(err.fatal, false);
});

Deno.test('makeError: string level arg is used', () => {
  const err = makeError('test', 'handshake');
  assertEquals(err.level, 'handshake');
  assertEquals(err.fatal, false);
});

Deno.test('makeError: boolean true as level sets fatal=true, level=protocol', () => {
  const err = makeError('fatal msg', true);
  assertEquals(err.level, 'protocol');
  assertEquals(err.fatal, true);
});

Deno.test('makeError: string level + explicit fatal=true', () => {
  const err = makeError('oops', 'crypto', true);
  assertEquals(err.level, 'crypto');
  assertEquals(err.fatal, true);
});

// =============================================================================
// doFatalError tests
// =============================================================================

function makeMockProtocol() {
  const calls: string[] = [];
  return {
    disconnect(r: number) {
      calls.push(`disconnect:${r}`);
    },
    _destruct() {
      calls.push('destruct');
    },
    _onError(e: Error) {
      calls.push(`error:${e.message}`);
    },
    calls,
  };
}

Deno.test('doFatalError: with Error instance calls all methods and returns Infinity', () => {
  const proto = makeMockProtocol();
  const err = new Error('bad thing');
  const result = doFatalError(proto, err);
  assertEquals(result, Infinity);
  assertEquals(proto.calls[0], `disconnect:${DISCONNECT_REASON.PROTOCOL_ERROR}`);
  assertEquals(proto.calls[1], 'destruct');
  assertEquals(proto.calls[2], 'error:bad thing');
});

Deno.test('doFatalError: Error instance without level gets level=protocol', () => {
  const proto = makeMockProtocol();
  const err = new Error('no level');
  doFatalError(proto, err);
  assertEquals((err as any).level, 'protocol');
});

Deno.test('doFatalError: Error instance with numeric second arg uses that as disconnect reason', () => {
  const proto = makeMockProtocol();
  const err = new Error('bye');
  doFatalError(proto, err, DISCONNECT_REASON.AUTH_CANCELED_BY_USER);
  assertEquals(proto.calls[0], `disconnect:${DISCONNECT_REASON.AUTH_CANCELED_BY_USER}`);
});

Deno.test('doFatalError: string message with level and reason', () => {
  const proto = makeMockProtocol();
  doFatalError(proto, 'connection reset', 'network', DISCONNECT_REASON.CONNECTION_LOST);
  assertEquals(proto.calls[0], `disconnect:${DISCONNECT_REASON.CONNECTION_LOST}`);
  assertEquals(proto.calls[2], 'error:connection reset');
});

Deno.test('doFatalError: empty protocol (no methods) does not throw', () => {
  const result = doFatalError({}, 'silent error');
  assertEquals(result, Infinity);
});

Deno.test('doFatalError: always returns Infinity', () => {
  assertEquals(doFatalError({}, 'msg1'), Infinity);
  assertEquals(doFatalError({}, new Error('msg2')), Infinity);
});

// =============================================================================
// makeBufferParser / bufferParser tests
// =============================================================================

Deno.test('makeBufferParser: init/pos/length/avail/clear', () => {
  const bp = makeBufferParser();
  const buf = new Uint8Array([10, 20, 30, 40, 50]);
  bp.init(buf, 2);
  assertEquals(bp.pos(), 2);
  assertEquals(bp.length(), 5);
  assertEquals(bp.avail(), 3);
  bp.clear();
  assertEquals(bp.length(), 0);
  assertEquals(bp.avail(), 0);
});

Deno.test('makeBufferParser: readUInt32BE success and boundary', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([0x01, 0x02, 0x03, 0x04]), 0);
  assertEquals(bp.readUInt32BE(), 0x01020304);
  // Already consumed all bytes
  bp.init(new Uint8Array([0x00, 0x00, 0x00]), 0);
  assertEquals(bp.readUInt32BE(), undefined); // < 4 bytes
});

Deno.test('makeBufferParser: readUInt32BE returns undefined past end', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([1, 2, 3, 4, 5]), 0);
  bp.readUInt32BE(); // consume 4 bytes, pos=4
  assertEquals(bp.readUInt32BE(), undefined); // only 1 byte left
});

Deno.test('makeBufferParser: readUInt64BE always returns BigInt', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 42]), 0);
  const result = bp.readUInt64BE('always');
  assertEquals(typeof result, 'bigint');
  assertEquals(result, 42n);
});

Deno.test('makeBufferParser: readUInt64BE maybe returns number for small value', () => {
  const bp = makeBufferParser();
  // First byte 0x00 (≤ 0x1f) → return number
  bp.init(new Uint8Array([0x00, 0, 0, 0, 0, 0, 0, 99]), 0);
  const result = bp.readUInt64BE('maybe');
  assertEquals(typeof result, 'number');
});

Deno.test('makeBufferParser: readUInt64BE maybe returns BigInt for large value', () => {
  const bp = makeBufferParser();
  // First byte 0x20 (> 0x1f) → return BigInt
  bp.init(new Uint8Array([0x20, 0, 0, 0, 0, 0, 0, 0]), 0);
  const result = bp.readUInt64BE('maybe');
  assertEquals(typeof result, 'bigint');
});

Deno.test('makeBufferParser: readUInt64BE default returns number', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 5]), 0);
  const result = bp.readUInt64BE();
  assertEquals(typeof result, 'number');
  assertEquals(result, 5);
});

Deno.test('makeBufferParser: readUInt64BE returns undefined when too short', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([0, 0, 0, 0, 0, 0, 0]), 0); // 7 bytes only
  assertEquals(bp.readUInt64BE('always'), undefined);
});

Deno.test('makeBufferParser: skip advances pos', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([1, 2, 3, 4, 5]), 0);
  bp.skip(3);
  assertEquals(bp.pos(), 3);
  assertEquals(bp.avail(), 2);
});

Deno.test('makeBufferParser: skipString reads length then skips content', () => {
  const bp = makeBufferParser();
  // Build: uint32(3) + "abc"
  const buf = new Uint8Array([0, 0, 0, 3, 97, 98, 99]);
  bp.init(buf, 0);
  const len = bp.skipString();
  assertEquals(len, 3);
  assertEquals(bp.pos(), 7);
});

Deno.test('makeBufferParser: skipString returns undefined when buffer too short', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([0, 0, 0, 10, 1, 2]), 0); // says length=10 but only 2 bytes follow
  assertEquals(bp.skipString(), undefined);
});

Deno.test('makeBufferParser: readByte returns byte and undefined at end', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([42, 7]), 0);
  assertEquals(bp.readByte(), 42);
  assertEquals(bp.readByte(), 7);
  assertEquals(bp.readByte(), undefined);
});

Deno.test('makeBufferParser: readBool false/true', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([0, 1, 255]), 0);
  assertEquals(bp.readBool(), false);
  assertEquals(bp.readBool(), true);
  assertEquals(bp.readBool(), true); // any nonzero is true
});

Deno.test('makeBufferParser: readBool returns undefined past end', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([1]), 0);
  bp.readBool();
  assertEquals(bp.readBool(), undefined);
});

Deno.test('makeBufferParser: readList parses comma-separated string', () => {
  const bp = makeBufferParser();
  // Encode "a,b,c" as SSH string (uint32 length + bytes)
  const str = new TextEncoder().encode('a,b,c');
  const buf = new Uint8Array(4 + str.length);
  buf[3] = str.length;
  buf.set(str, 4);
  bp.init(buf, 0);
  assertEquals(bp.readList(), ['a', 'b', 'c']);
});

Deno.test('makeBufferParser: readList returns undefined when buffer too short', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([0, 0]), 0); // too short for uint32
  assertEquals(bp.readList(), undefined);
});

Deno.test('makeBufferParser: readString returns Uint8Array view', () => {
  const bp = makeBufferParser();
  const data = new Uint8Array([0, 0, 0, 3, 10, 20, 30]);
  bp.init(data, 0);
  const result = bp.readString();
  assertEquals(result instanceof Uint8Array, true);
  assertEquals((result as Uint8Array).length, 3);
  assertEquals((result as Uint8Array)[0], 10);
});

Deno.test('makeBufferParser: readString(true) returns UTF-8 string', () => {
  const bp = makeBufferParser();
  const text = new TextEncoder().encode('hello');
  const buf = new Uint8Array(4 + text.length);
  buf[3] = text.length;
  buf.set(text, 4);
  bp.init(buf, 0);
  const result = bp.readString(true);
  assertEquals(result, 'hello');
});

Deno.test('makeBufferParser: readString(destBuf) copies into dest and returns count', () => {
  const bp = makeBufferParser();
  const payload = new Uint8Array([1, 2, 3, 4]);
  const buf = new Uint8Array([0, 0, 0, 4, ...payload]);
  bp.init(buf, 0);
  const dest = new Uint8Array(4);
  const n = bp.readString(dest);
  assertEquals(typeof n, 'number');
  assertEquals(dest, payload);
});

Deno.test('makeBufferParser: readString with maxLen returns undefined when len > maxLen', () => {
  const bp = makeBufferParser();
  // String of length 10, maxLen=5
  const buf = new Uint8Array([0, 0, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  bp.init(buf, 0);
  assertEquals(bp.readString(5), undefined);
});

Deno.test('makeBufferParser: readRaw no arg reads all remaining', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([1, 2, 3, 4, 5]), 2);
  const raw = bp.readRaw();
  assertEquals(raw instanceof Uint8Array, true);
  assertEquals((raw as Uint8Array).length, 3);
  assertEquals((raw as Uint8Array)[0], 3);
});

Deno.test('makeBufferParser: readRaw(n) reads n bytes', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([10, 20, 30, 40]), 0);
  const raw = bp.readRaw(2);
  assertEquals((raw as Uint8Array).length, 2);
  assertEquals((raw as Uint8Array)[0], 10);
});

Deno.test('makeBufferParser: readRaw(n) returns undefined if n > remaining', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([1, 2]), 0);
  assertEquals(bp.readRaw(5), undefined);
});

Deno.test('makeBufferParser: after clear(), readByte returns undefined', () => {
  const bp = makeBufferParser();
  bp.init(new Uint8Array([1, 2, 3]), 0);
  bp.clear();
  assertEquals(bp.readByte(), undefined);
  assertEquals(bp.length(), 0);
  assertEquals(bp.avail(), 0);
});

Deno.test('shared bufferParser singleton works independently', () => {
  // Verify bufferParser is a separate instance from any makeBufferParser() call
  const buf = new Uint8Array([0x00, 0x00, 0x00, 0x07]);
  bufferParser.init(buf, 0);
  assertEquals(bufferParser.readUInt32BE(), 7);
  bufferParser.clear();
});

// =============================================================================
// readString standalone function tests
// =============================================================================

Deno.test('readString: reads from offset 0', () => {
  const payload = new Uint8Array([5, 6, 7]);
  const buf = new Uint8Array([0, 0, 0, 3, ...payload]);
  const result = readString(buf);
  assertEquals(result instanceof Uint8Array, true);
  assertEquals((result as Uint8Array).length, 3);
  assertEquals((result as Uint8Array)[0], 5);
});

Deno.test('readString: reads from a start offset', () => {
  const buf = new Uint8Array([0xff, 0xff, 0, 0, 0, 2, 11, 22]);
  const result = readString(buf, 2);
  assertEquals((result as Uint8Array).length, 2);
  assertEquals((result as Uint8Array)[0], 11);
});

Deno.test('readString: returns undefined when start is negative', () => {
  assertEquals(readString(new Uint8Array([0, 0, 0, 1, 5]), -1), undefined);
});

Deno.test('readString: returns undefined when buffer too short for length field', () => {
  assertEquals(readString(new Uint8Array([0, 0]), 0), undefined);
});

Deno.test('readString: with dest=true returns UTF-8 string', () => {
  const text = new TextEncoder().encode('world');
  const buf = new Uint8Array(4 + text.length);
  buf[3] = text.length;
  buf.set(text, 4);
  assertEquals(readString(buf, 0, true), 'world');
});

Deno.test('readString: with dest=Uint8Array copies into buffer', () => {
  const buf = new Uint8Array([0, 0, 0, 3, 1, 2, 3]);
  const dest = new Uint8Array(3);
  readString(buf, 0, dest);
  assertEquals(dest[0], 1);
  assertEquals(dest[1], 2);
  assertEquals(dest[2], 3);
});

// =============================================================================
// sigSSHToASN1 tests
// =============================================================================

/** Build a SSH-format 4-byte-length-prefixed string */
function sshStr(data: Uint8Array): Uint8Array {
  const buf = new Uint8Array(4 + data.length);
  buf[0] = (data.length >>> 24) & 0xff;
  buf[1] = (data.length >>> 16) & 0xff;
  buf[2] = (data.length >>> 8) & 0xff;
  buf[3] = data.length & 0xff;
  buf.set(data, 4);
  return buf;
}

Deno.test('sigSSHToASN1: ECDSA type converts to ASN.1 SEQUENCE', () => {
  const r = new Uint8Array([0x01, 0x02, 0x03]);
  const s = new Uint8Array([0x04, 0x05, 0x06]);
  const sig = new Uint8Array([...sshStr(r), ...sshStr(s)]);
  const result = sigSSHToASN1(sig, 'ecdsa-sha2-nistp256');
  assertEquals(result instanceof Uint8Array, true);
  // ASN.1 SEQUENCE starts with 0x30
  assertEquals((result as Uint8Array)[0], 0x30);
});

Deno.test('sigSSHToASN1: non-ECDSA type returns signature unchanged', () => {
  const sig = new Uint8Array([1, 2, 3, 4]);
  const result = sigSSHToASN1(sig, 'ssh-rsa');
  assertEquals(result, sig); // same reference
});

Deno.test('sigSSHToASN1: malformed ECDSA sig returns undefined', () => {
  const badSig = new Uint8Array([0x00, 0x00]); // too short
  const result = sigSSHToASN1(badSig, 'ecdsa-sha2-nistp384');
  assertEquals(result, undefined);
});

// =============================================================================
// convertSignature tests
// =============================================================================

Deno.test('convertSignature: non-ECDSA returns signature unchanged', () => {
  const sig = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const result = convertSignature(sig, 'ssh-rsa');
  assertEquals(result, sig);
});

Deno.test('convertSignature: ECDSA where sig[0]===0 returns as-is', () => {
  const sig = new Uint8Array([0x00, 1, 2, 3]);
  const result = convertSignature(sig, 'ecdsa-sha2-nistp256');
  assertEquals(result, sig);
});

Deno.test('convertSignature: ECDSA with valid ASN.1 input converts to SSH format', () => {
  // Build a valid ASN.1 DER SEQUENCE with two INTEGER values
  // ASN.1: SEQUENCE { INTEGER 0x0102, INTEGER 0x0304 }
  // Manually: 30 0C  02 02 01 02  02 02 03 04
  // (0x30=SEQUENCE, 0x0C=12 bytes length, 0x02=INTEGER, 0x02=2 bytes, etc.)
  const asn1Sig = new Uint8Array([
    0x30,
    0x0C,
    0x02,
    0x02,
    0x01,
    0x02, // r = [0x01, 0x02]
    0x02,
    0x02,
    0x03,
    0x04, // s = [0x03, 0x04]
  ]);
  const result = convertSignature(asn1Sig, 'ecdsa-sha2-nistp256');
  // result should be false on parse failure or Uint8Array on success
  // The result should be a Uint8Array (SSH format: len+r+len+s)
  assertNotEquals(result, false);
  if (result !== false) {
    // Should start with length of r (2 bytes)
    const dv = new DataView(result.buffer, result.byteOffset);
    const rLen = dv.getUint32(0);
    assertEquals(rLen, 2);
  }
});

// =============================================================================
// writeUInt32LE tests
// =============================================================================

Deno.test('writeUInt32LE: writes in little-endian order', () => {
  const buf = new Uint8Array(4);
  const end = writeUInt32LE(buf, 0x01020304, 0);
  assertEquals(end, 4);
  assertEquals(buf[0], 0x04); // LSB first
  assertEquals(buf[1], 0x03);
  assertEquals(buf[2], 0x02);
  assertEquals(buf[3], 0x01); // MSB last
});

Deno.test('writeUInt32LE: writes at non-zero offset and returns correct end', () => {
  const buf = new Uint8Array(8);
  const end = writeUInt32LE(buf, 0xdeadbeef, 2);
  assertEquals(end, 6);
  assertEquals(buf[2], 0xef);
  assertEquals(buf[3], 0xbe);
  assertEquals(buf[4], 0xad);
  assertEquals(buf[5], 0xde);
});

// =============================================================================
// sliceBytes / copyBytes tests
// =============================================================================

Deno.test('sliceBytes: returns a view with correct range', () => {
  const buf = new Uint8Array([10, 20, 30, 40, 50]);
  const slice = sliceBytes(buf, 1, 4);
  assertEquals(slice.length, 3);
  assertEquals(slice[0], 20);
  assertEquals(slice[2], 40);
  // It's a view, not a copy — same underlying buffer
  assertEquals(slice.buffer, buf.buffer);
});

Deno.test('sliceBytes: no end arg slices to end of buffer', () => {
  const buf = new Uint8Array([1, 2, 3, 4]);
  const slice = sliceBytes(buf, 2);
  assertEquals(slice.length, 2);
  assertEquals(slice[0], 3);
  assertEquals(slice[1], 4);
});

Deno.test('copyBytes: copies srcEnd clamped to src.length', () => {
  const src = new Uint8Array([1, 2, 3]);
  const dest = new Uint8Array(5);
  // srcEnd=10 > src.length=3 → clamped to 3
  const n = copyBytes(src, dest, 0, 10, 0);
  assertEquals(n, 3);
  assertEquals(dest[0], 1);
  assertEquals(dest[1], 2);
  assertEquals(dest[2], 3);
});

Deno.test('copyBytes: clamped when dest space is smaller than nb', () => {
  const src = new Uint8Array([10, 20, 30, 40, 50]);
  const dest = new Uint8Array(2); // only 2 bytes available from offset 0
  const n = copyBytes(src, dest, 0, 5, 0); // try to copy 5 bytes into 2-byte dest
  assertEquals(n, 2);
  assertEquals(dest[0], 10);
  assertEquals(dest[1], 20);
});
