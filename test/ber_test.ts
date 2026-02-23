/**
 * Tests for BER (Basic Encoding Rules) module
 */

import { assertEquals, assertThrows } from '@std/assert';
import { Ber, BerReader, BerWriter } from '../src/utils/ber.ts';
import { fromHex, toHex } from '../src/utils/binary.ts';

// Writer tests
Deno.test('BerWriter writes NULL', () => {
  const writer = new BerWriter();
  writer.writeNull();
  assertEquals(toHex(writer.buffer), '0500');
});

Deno.test('BerWriter writes small integer', () => {
  const writer = new BerWriter();
  writer.writeInt(5);
  // INTEGER tag (02), length 1, value 5
  assertEquals(toHex(writer.buffer), '020105');
});

Deno.test('BerWriter writes negative integer', () => {
  const writer = new BerWriter();
  writer.writeInt(-1);
  // INTEGER tag (02), length 1, value -1 (0xff)
  assertEquals(toHex(writer.buffer), '0201ff');
});

Deno.test('BerWriter writes large integer', () => {
  const writer = new BerWriter();
  writer.writeInt(256);
  // INTEGER tag (02), length 2, value 256 (0x0100)
  assertEquals(toHex(writer.buffer), '02020100');
});

Deno.test('BerWriter writes integer with leading zero for positive', () => {
  const writer = new BerWriter();
  writer.writeInt(128); // 0x80 needs leading zero to stay positive
  assertEquals(toHex(writer.buffer), '02020080');
});

Deno.test('BerWriter writes OID', () => {
  const writer = new BerWriter();
  writer.writeOID('1.2.840.113549.1.1.1'); // rsaEncryption
  const hex = toHex(writer.buffer);
  // OID tag (06), then encoded OID
  assertEquals(hex.startsWith('06'), true);
});

Deno.test('BerWriter writes buffer as OCTET STRING', () => {
  const writer = new BerWriter();
  const data = new Uint8Array([0x01, 0x02, 0x03]);
  writer.writeBuffer(data);
  // OCTET STRING tag (04), length 3, data
  assertEquals(toHex(writer.buffer), '0403010203');
});

Deno.test('BerWriter writes buffer as INTEGER', () => {
  const writer = new BerWriter();
  const data = new Uint8Array([0x01, 0x02, 0x03]);
  writer.writeBuffer(data, Ber.Integer);
  // INTEGER tag (02), length 3, data
  assertEquals(toHex(writer.buffer), '0203010203');
});

Deno.test('BerWriter writes SEQUENCE', () => {
  const writer = new BerWriter();
  writer.startSequence();
  writer.writeInt(42);
  writer.endSequence();
  // SEQUENCE tag (30), length, then INTEGER
  const hex = toHex(writer.buffer);
  assertEquals(hex.startsWith('30'), true);
  assertEquals(hex.includes('02012a'), true); // INTEGER 42
});

Deno.test('BerWriter writes nested SEQUENCE', () => {
  const writer = new BerWriter();
  writer.startSequence();
  writer.startSequence();
  writer.writeInt(1);
  writer.endSequence();
  writer.writeInt(2);
  writer.endSequence();
  const hex = toHex(writer.buffer);
  assertEquals(hex.startsWith('30'), true);
});

Deno.test('BerWriter writes BIT STRING sequence', () => {
  const writer = new BerWriter();
  writer.startSequence(Ber.BitString);
  writer.writeByte(0x00); // Unused bits
  writer.writeByte(0xff);
  writer.endSequence();
  const hex = toHex(writer.buffer);
  assertEquals(hex.startsWith('03'), true); // BIT STRING tag
});

// Reader tests
Deno.test('BerReader reads SEQUENCE', () => {
  // SEQUENCE containing INTEGER 5
  const data = fromHex('3003020105');
  const reader = new BerReader(data);
  const len = reader.readSequence();
  assertEquals(len, 3);
});

Deno.test('BerReader reads INTEGER', () => {
  // INTEGER 42
  const data = fromHex('02012a');
  const reader = new BerReader(data);
  const value = reader.readInt();
  assertEquals(value, 42);
});

Deno.test('BerReader reads multi-byte INTEGER', () => {
  // INTEGER 256 (0x0100)
  const data = fromHex('02020100');
  const reader = new BerReader(data);
  const value = reader.readInt();
  assertEquals(value, 256);
});

Deno.test('BerReader reads OID', () => {
  // rsaEncryption OID: 1.2.840.113549.1.1.1
  const data = fromHex('06092a864886f70d010101');
  const reader = new BerReader(data);
  const oid = reader.readOID();
  assertEquals(oid, '1.2.840.113549.1.1.1');
});

Deno.test('BerReader reads OCTET STRING', () => {
  // OCTET STRING with data [1, 2, 3]
  const data = fromHex('0403010203');
  const reader = new BerReader(data);
  const value = reader.readString(Ber.OctetString, true);
  assertEquals(value instanceof Uint8Array, true);
  assertEquals(toHex(value as Uint8Array), '010203');
});

Deno.test('BerReader reads string as buffer', () => {
  // OCTET STRING with data [1, 2, 3]
  const data = fromHex('0403010203');
  const reader = new BerReader(data);
  const value = reader.readString(Ber.OctetString, true);
  assertEquals(value instanceof Uint8Array, true);
});

Deno.test('BerReader returns null for wrong tag', () => {
  // INTEGER instead of OCTET STRING
  const data = fromHex('020105');
  const reader = new BerReader(data);
  const value = reader.readString(Ber.OctetString, true);
  assertEquals(value, null);
});

Deno.test('BerReader readSequence returns null for wrong tag', () => {
  // INTEGER instead of SEQUENCE
  const data = fromHex('020105');
  const reader = new BerReader(data);
  const len = reader.readSequence();
  assertEquals(len, null);
});

// Round-trip tests
Deno.test('BerWriter and BerReader round-trip SEQUENCE with INTEGER', () => {
  const writer = new BerWriter();
  writer.startSequence();
  writer.writeInt(12345);
  writer.endSequence();

  const reader = new BerReader(writer.buffer);
  reader.readSequence();
  const value = reader.readInt();
  assertEquals(value, 12345);
});

Deno.test('BerWriter and BerReader round-trip OID', () => {
  const oid = '1.2.840.10045.2.1'; // id-ecPublicKey
  const writer = new BerWriter();
  writer.writeOID(oid);

  const reader = new BerReader(writer.buffer);
  const readOid = reader.readOID();
  assertEquals(readOid, oid);
});

Deno.test('BerWriter and BerReader round-trip complex structure', () => {
  // Simulate a simple X.509 SubjectPublicKeyInfo structure
  const writer = new BerWriter();
  writer.startSequence();

  // Algorithm identifier
  writer.startSequence();
  writer.writeOID('1.2.840.113549.1.1.1'); // rsaEncryption
  writer.writeNull();
  writer.endSequence();

  // Public key (bit string with some data)
  writer.startSequence(Ber.BitString);
  writer.writeByte(0x00); // unused bits
  writer.writeByte(0xaa);
  writer.writeByte(0xbb);
  writer.endSequence();

  writer.endSequence();

  // Read it back
  const reader = new BerReader(writer.buffer);
  const outerLen = reader.readSequence();
  assertEquals(outerLen !== null, true);

  // Algorithm
  const algoLen = reader.readSequence();
  assertEquals(algoLen !== null, true);

  const oid = reader.readOID();
  assertEquals(oid, '1.2.840.113549.1.1.1');
});

// Error handling tests
Deno.test('BerWriter throws on endSequence without startSequence', () => {
  const writer = new BerWriter();
  assertThrows(
    () => {
      writer.endSequence();
    },
    Error,
    'No sequence to end',
  );
});

Deno.test('BerWriter throws on OID with less than 2 components', () => {
  const writer = new BerWriter();
  assertThrows(
    () => {
      writer.writeOID('1');
    },
    Error,
    'OID must have at least 2 components',
  );
});

Deno.test('BerReader throws on read past end', () => {
  const data = new Uint8Array(0);
  const reader = new BerReader(data);
  assertThrows(
    () => {
      reader.readByte();
    },
    Error,
    'read past end',
  );
});

// Tag constants tests
Deno.test('Ber constants have correct values', () => {
  assertEquals(Ber.Integer, 0x02);
  assertEquals(Ber.BitString, 0x03);
  assertEquals(Ber.OctetString, 0x04);
  assertEquals(Ber.Null, 0x05);
  assertEquals(Ber.OID, 0x06);
  assertEquals(Ber.Sequence, 0x30);
});

// =============================================================================
// Additional BerReader tests for uncovered paths
// =============================================================================

Deno.test('BerReader: buffer/offset/length/remain getters', () => {
  const data = fromHex('3003020105'); // SEQUENCE { INTEGER 5 }
  const reader = new BerReader(data);
  assertEquals(reader.buffer, data);
  assertEquals(reader.offset, 0);
  // length and remain before reading sequence
  assertEquals(reader.remain, 5);
  reader.readSequence();
  assertEquals(reader.offset, 2);
  assertEquals(reader.remain, 3);
  // length is set by readSequence
  assertEquals(reader.length, 3);
});

Deno.test('BerReader: readInt throws for wrong tag', () => {
  // OCTET STRING instead of INTEGER
  const data = fromHex('0401ff');
  const reader = new BerReader(data);
  assertThrows(() => reader.readInt(), Error, 'Expected INTEGER tag');
});

Deno.test('BerReader: readInt with len > 4 returns 0 and skips', () => {
  // INTEGER with 5-byte value (len=5 → should skip and return 0)
  const data = new Uint8Array([0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
  const reader = new BerReader(data);
  const val = reader.readInt();
  assertEquals(val, 0);
  // Should have advanced past the 5 bytes
  assertEquals(reader.offset, 7);
});

Deno.test('BerReader: readInt handles negative number (sign bit set)', () => {
  // INTEGER: tag=0x02, len=1, value=0xff (= -1 in signed)
  const data = fromHex('0201ff');
  const reader = new BerReader(data);
  const val = reader.readInt();
  assertEquals(val, -1);
});

Deno.test('BerReader: readOID throws for wrong tag', () => {
  // INTEGER instead of OID
  const data = fromHex('020105');
  const reader = new BerReader(data);
  assertThrows(() => reader.readOID(), Error, 'Expected OID tag');
});

Deno.test('BerReader: readString without returnBuffer returns UTF-8 string', () => {
  // OCTET STRING containing "hi"
  const hiBytes = new TextEncoder().encode('hi');
  const data = new Uint8Array([0x04, 2, ...hiBytes]);
  const reader = new BerReader(data);
  const str = reader.readString(Ber.OctetString);
  assertEquals(typeof str, 'string');
  assertEquals(str, 'hi');
});

Deno.test('BerWriter: constructor with size option', () => {
  const writer = new BerWriter({ size: 64 });
  writer.writeNull();
  assertEquals(toHex(writer.buffer), '0500');
});

Deno.test('BerWriter: _writeLength for len >= 0x10000 (3-byte length)', () => {
  const writer = new BerWriter();
  // Write a large buffer (65536 bytes) to trigger 3-byte length encoding
  const largeData = new Uint8Array(0x10000); // 65536 bytes
  writer.writeBuffer(largeData, Ber.OctetString);
  const buf = writer.buffer;
  // Tag (0x04), then 0x83 (3-byte len indicator), then 3 bytes of length
  assertEquals(buf[0], 0x04); // OCTET STRING tag
  assertEquals(buf[1], 0x83); // 3-byte length indicator
  assertEquals(buf[2], 0x01); // 0x010000 >> 16
  assertEquals(buf[3], 0x00); // (0x010000 >> 8) & 0xff
  assertEquals(buf[4], 0x00); // 0x010000 & 0xff
});

Deno.test('BerWriter: writeInt with negative number needing leading 0xff', () => {
  // -256: after inversion, bytes=[0x00]; 0x00 & 0x80 === 0, so prepend 0xff
  const writer = new BerWriter();
  writer.writeInt(-256);
  // Expected: tag(02) + len(02) + ff + 00
  assertEquals(toHex(writer.buffer), '0202ff00');
});
