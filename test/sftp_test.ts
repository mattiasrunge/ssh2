/**
 * SFTP Module Tests
 */

import { assertEquals, assertExists } from '@std/assert';

import {
  ATTR,
  attrsToBytes,
  flagsToString,
  getAttrBytes,
  makePacketParser,
  modeNum,
  OPEN_MODE,
  REQUEST,
  RESPONSE,
  SFTPError,
  Stats,
  STATUS_CODE,
  STATUS_CODE_STR,
  stringByteLength,
  stringToFlags,
  toUnixTimestamp,
  writeUInt64BE,
} from '../src/protocol/sftp/mod.ts';

// =============================================================================
// Constants Tests
// =============================================================================

Deno.test('STATUS_CODE constants are defined', () => {
  assertEquals(STATUS_CODE.OK, 0);
  assertEquals(STATUS_CODE.EOF, 1);
  assertEquals(STATUS_CODE.NO_SUCH_FILE, 2);
  assertEquals(STATUS_CODE.PERMISSION_DENIED, 3);
  assertEquals(STATUS_CODE.FAILURE, 4);
});

Deno.test('STATUS_CODE_STR maps codes to strings', () => {
  assertEquals(STATUS_CODE_STR[0], 'No error');
  assertEquals(STATUS_CODE_STR[1], 'End of file');
  assertEquals(STATUS_CODE_STR[2], 'No such file or directory');
});

Deno.test('REQUEST constants are defined', () => {
  assertEquals(REQUEST.INIT, 1);
  assertEquals(REQUEST.OPEN, 3);
  assertEquals(REQUEST.CLOSE, 4);
  assertEquals(REQUEST.READ, 5);
  assertEquals(REQUEST.WRITE, 6);
});

Deno.test('RESPONSE constants are defined', () => {
  assertEquals(RESPONSE.VERSION, 2);
  assertEquals(RESPONSE.STATUS, 101);
  assertEquals(RESPONSE.HANDLE, 102);
  assertEquals(RESPONSE.DATA, 103);
});

Deno.test('ATTR flags are defined', () => {
  assertEquals(ATTR.SIZE, 0x00000001);
  assertEquals(ATTR.UIDGID, 0x00000002);
  assertEquals(ATTR.PERMISSIONS, 0x00000004);
  assertEquals(ATTR.ACMODTIME, 0x00000008);
});

Deno.test('OPEN_MODE flags are defined', () => {
  assertEquals(OPEN_MODE.READ, 0x00000001);
  assertEquals(OPEN_MODE.WRITE, 0x00000002);
  assertEquals(OPEN_MODE.APPEND, 0x00000004);
  assertEquals(OPEN_MODE.CREAT, 0x00000008);
});

// =============================================================================
// Stats Tests
// =============================================================================

Deno.test('Stats isDirectory', () => {
  const stats = new Stats({ mode: 0o40755 }); // S_IFDIR
  assertEquals(stats.isDirectory(), true);
  assertEquals(stats.isFile(), false);
  assertEquals(stats.isSymbolicLink(), false);
});

Deno.test('Stats isFile', () => {
  const stats = new Stats({ mode: 0o100644 }); // S_IFREG
  assertEquals(stats.isDirectory(), false);
  assertEquals(stats.isFile(), true);
  assertEquals(stats.isSymbolicLink(), false);
});

Deno.test('Stats isSymbolicLink', () => {
  const stats = new Stats({ mode: 0o120777 }); // S_IFLNK
  assertEquals(stats.isDirectory(), false);
  assertEquals(stats.isFile(), false);
  assertEquals(stats.isSymbolicLink(), true);
});

Deno.test('Stats isBlockDevice', () => {
  const stats = new Stats({ mode: 0o60600 }); // S_IFBLK
  assertEquals(stats.isBlockDevice(), true);
});

Deno.test('Stats isCharacterDevice', () => {
  const stats = new Stats({ mode: 0o20666 }); // S_IFCHR
  assertEquals(stats.isCharacterDevice(), true);
});

Deno.test('Stats isFIFO', () => {
  const stats = new Stats({ mode: 0o10600 }); // S_IFIFO
  assertEquals(stats.isFIFO(), true);
});

Deno.test('Stats isSocket', () => {
  const stats = new Stats({ mode: 0o140755 }); // S_IFSOCK
  assertEquals(stats.isSocket(), true);
});

Deno.test('Stats copies attributes', () => {
  const attrs = {
    mode: 0o100644,
    uid: 1000,
    gid: 1000,
    size: 12345,
    atime: 1609459200,
    mtime: 1609459200,
  };
  const stats = new Stats(attrs);

  assertEquals(stats.mode, 0o100644);
  assertEquals(stats.uid, 1000);
  assertEquals(stats.gid, 1000);
  assertEquals(stats.size, 12345);
  assertEquals(stats.atime, 1609459200);
  assertEquals(stats.mtime, 1609459200);
});

Deno.test('Stats atimeDate and mtimeDate getters', () => {
  const stats = new Stats({ atime: 1609459200, mtime: 1609459200 });
  const atimeDate = stats.atimeDate;
  const mtimeDate = stats.mtimeDate;
  assertExists(atimeDate);
  assertExists(mtimeDate);
  assertEquals(atimeDate!.getTime(), 1609459200 * 1000);
  assertEquals(mtimeDate!.getTime(), 1609459200 * 1000);
});

Deno.test('Stats atimeDate and mtimeDate undefined when not set', () => {
  const stats = new Stats({});
  assertEquals(stats.atimeDate, undefined);
  assertEquals(stats.mtimeDate, undefined);
});

Deno.test('Stats constructor handles Date objects for atime/mtime', () => {
  const date = new Date('2021-01-01T00:00:00Z');
  // deno-lint-ignore no-explicit-any
  const stats = new Stats({ atime: date as any, mtime: date as any });
  assertEquals(stats.atime, 1609459200);
  assertEquals(stats.mtime, 1609459200);
});

Deno.test('Stats empty constructor', () => {
  const stats = new Stats();
  assertEquals(stats.mode, undefined);
  assertEquals(stats.uid, undefined);
  assertEquals(stats.isFile(), false);
  assertEquals(stats.isDirectory(), false);
});

// =============================================================================
// Packet Parsing Tests
// =============================================================================

Deno.test('attrsToBytes encodes size', () => {
  const result = attrsToBytes({ size: 1234567890 });
  assertEquals(result.flags & ATTR.SIZE, ATTR.SIZE);
  assertEquals(result.nb, 8); // 64-bit size
});

Deno.test('attrsToBytes encodes uid/gid', () => {
  const result = attrsToBytes({ uid: 1000, gid: 1000 });
  assertEquals(result.flags & ATTR.UIDGID, ATTR.UIDGID);
  assertEquals(result.nb, 8); // 2 x 32-bit
});

Deno.test('attrsToBytes encodes mode', () => {
  const result = attrsToBytes({ mode: 0o755 });
  assertEquals(result.flags & ATTR.PERMISSIONS, ATTR.PERMISSIONS);
  assertEquals(result.nb, 4); // 32-bit mode
});

Deno.test('attrsToBytes encodes times', () => {
  const result = attrsToBytes({ atime: 1609459200, mtime: 1609459200 });
  assertEquals(result.flags & ATTR.ACMODTIME, ATTR.ACMODTIME);
  assertEquals(result.nb, 8); // 2 x 32-bit
});

Deno.test('attrsToBytes encodes all attributes', () => {
  const result = attrsToBytes({
    size: 1234,
    uid: 1000,
    gid: 1000,
    mode: 0o644,
    atime: 1609459200,
    mtime: 1609459200,
  });

  const expectedFlags = ATTR.SIZE | ATTR.UIDGID | ATTR.PERMISSIONS | ATTR.ACMODTIME;
  assertEquals(result.flags, expectedFlags);
  assertEquals(result.nb, 8 + 8 + 4 + 8); // size + uid/gid + mode + times
});

Deno.test('attrsToBytes returns empty for undefined', () => {
  const result = attrsToBytes(undefined);
  assertEquals(result.flags, 0);
  assertEquals(result.nb, 0);
});

Deno.test('getAttrBytes returns correct subarray', () => {
  const result = attrsToBytes({ mode: 0o755 });
  const bytes = getAttrBytes(result.nb);
  assertEquals(bytes.length, 4);
});

Deno.test('toUnixTimestamp handles number', () => {
  assertEquals(toUnixTimestamp(1609459200), 1609459200);
  assertEquals(toUnixTimestamp(1609459200.5), 1609459200);
});

Deno.test('toUnixTimestamp handles Date', () => {
  const date = new Date('2021-01-01T00:00:00Z');
  assertEquals(toUnixTimestamp(date), 1609459200);
});

Deno.test('modeNum handles number', () => {
  assertEquals(modeNum(0o755), 0o755);
});

Deno.test('modeNum handles octal string', () => {
  assertEquals(modeNum('755'), 0o755);
  assertEquals(modeNum('644'), 0o644);
});

Deno.test('PacketParser reads basic types', () => {
  const parser = makePacketParser();

  // Create test buffer: byte, uint32, uint32
  const buf = new Uint8Array(9);
  buf[0] = 0x42;
  buf[1] = 0x00;
  buf[2] = 0x00;
  buf[3] = 0x01;
  buf[4] = 0x00;
  buf[5] = 0xDE;
  buf[6] = 0xAD;
  buf[7] = 0xBE;
  buf[8] = 0xEF;

  parser.init(buf, 0);

  assertEquals(parser.readByte(), 0x42);
  assertEquals(parser.readUInt32BE(), 256);
  assertEquals(parser.readUInt32BE(), 0xDEADBEEF);

  parser.clear();
});

Deno.test('PacketParser reads 64-bit as number', () => {
  const parser = makePacketParser();

  const buf = new Uint8Array(8);
  buf[0] = 0x00;
  buf[1] = 0x00;
  buf[2] = 0x00;
  buf[3] = 0x00;
  buf[4] = 0x00;
  buf[5] = 0x01;
  buf[6] = 0x00;
  buf[7] = 0x00;

  parser.init(buf, 0);

  assertEquals(parser.readUInt64BE(false), 65536);

  parser.clear();
});

Deno.test('PacketParser reads 64-bit as bigint', () => {
  const parser = makePacketParser();

  const buf = new Uint8Array(8);
  buf[0] = 0x00;
  buf[1] = 0x00;
  buf[2] = 0x00;
  buf[3] = 0x01;
  buf[4] = 0x00;
  buf[5] = 0x00;
  buf[6] = 0x00;
  buf[7] = 0x00;

  parser.init(buf, 0);

  assertEquals(parser.readUInt64BE(true), 0x100000000n);

  parser.clear();
});

Deno.test('PacketParser reads string', () => {
  const parser = makePacketParser();

  const text = 'hello';
  const buf = new Uint8Array(4 + text.length);
  buf[0] = 0;
  buf[1] = 0;
  buf[2] = 0;
  buf[3] = 5;
  for (let i = 0; i < text.length; i++) {
    buf[4 + i] = text.charCodeAt(i);
  }

  parser.init(buf, 0);

  assertEquals(parser.readString(true), 'hello');

  parser.clear();
});

Deno.test('writeUInt64BE writes correctly', () => {
  const buf = new Uint8Array(8);
  writeUInt64BE(buf, 0x123456789ABCDEFn, 0);

  assertEquals(buf[0], 0x01);
  assertEquals(buf[1], 0x23);
  assertEquals(buf[2], 0x45);
  assertEquals(buf[3], 0x67);
  assertEquals(buf[4], 0x89);
  assertEquals(buf[5], 0xAB);
  assertEquals(buf[6], 0xCD);
  assertEquals(buf[7], 0xEF);
});

Deno.test('stringByteLength calculates correctly', () => {
  assertEquals(stringByteLength('hello'), 4 + 5);
  assertEquals(stringByteLength(''), 4);
  assertEquals(stringByteLength(new Uint8Array(10)), 4 + 10);
});

// =============================================================================
// Types Tests
// =============================================================================

Deno.test('stringToFlags converts read flags', () => {
  assertEquals(stringToFlags('r'), OPEN_MODE.READ);
});

Deno.test('stringToFlags converts write flags', () => {
  const flags = stringToFlags('w');
  assertExists(flags);
  assertEquals((flags & OPEN_MODE.WRITE) !== 0, true);
  assertEquals((flags & OPEN_MODE.CREAT) !== 0, true);
  assertEquals((flags & OPEN_MODE.TRUNC) !== 0, true);
});

Deno.test('stringToFlags converts read-write flags', () => {
  const flags = stringToFlags('r+');
  assertExists(flags);
  assertEquals((flags & OPEN_MODE.READ) !== 0, true);
  assertEquals((flags & OPEN_MODE.WRITE) !== 0, true);
});

Deno.test('stringToFlags converts append flags', () => {
  const flags = stringToFlags('a');
  assertExists(flags);
  assertEquals((flags & OPEN_MODE.APPEND) !== 0, true);
  assertEquals((flags & OPEN_MODE.CREAT) !== 0, true);
});

Deno.test('stringToFlags returns null for unknown flags', () => {
  assertEquals(stringToFlags('xyz'), null);
});

Deno.test('flagsToString converts flags back to string', () => {
  assertEquals(flagsToString(OPEN_MODE.READ), 'r');
});

Deno.test('SFTPError has correct properties', () => {
  const err = new SFTPError('Test error', STATUS_CODE.NO_SUCH_FILE, 'en');
  assertEquals(err.message, 'Test error');
  assertEquals(err.code, STATUS_CODE.NO_SUCH_FILE);
  assertEquals(err.lang, 'en');
  assertEquals(err.name, 'SFTPError');
});
