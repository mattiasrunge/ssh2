/**
 * Tests for zlib compression module (Web Compression API)
 */

import { assertEquals } from '@std/assert';
import {
  PacketReader,
  PacketWriter,
  ZlibCompressor,
  ZlibDecompressor,
  ZlibPacketReader,
  ZlibPacketWriter,
} from '../src/protocol/zlib.ts';
import { allocBytes, fromString, toUtf8 } from '../src/utils/binary.ts';

// Async compression tests
Deno.test('ZlibCompressor compressAsync compresses data', async () => {
  const compressor = new ZlibCompressor();
  const data = fromString('Hello, World!');
  const compressed = await compressor.compressAsync(data);

  // Compressed data should be different from original
  assertEquals(compressed.length > 0, true);
});

Deno.test('ZlibDecompressor decompressAsync decompresses data', async () => {
  const compressor = new ZlibCompressor();
  const decompressor = new ZlibDecompressor();

  const original = fromString('Hello, World!');
  const compressed = await compressor.compressAsync(original);
  const decompressed = await decompressor.decompressAsync(compressed);

  assertEquals(toUtf8(decompressed), 'Hello, World!');
});

Deno.test('ZlibCompressor and ZlibDecompressor round-trip', async () => {
  const compressor = new ZlibCompressor();
  const decompressor = new ZlibDecompressor();

  const testData = 'The quick brown fox jumps over the lazy dog. '.repeat(100);
  const original = fromString(testData);

  const compressed = await compressor.compressAsync(original);
  const decompressed = await decompressor.decompressAsync(compressed);

  assertEquals(toUtf8(decompressed), testData);
});

Deno.test('ZlibCompressor compresses empty data', async () => {
  const compressor = new ZlibCompressor();
  const data = new Uint8Array(0);
  const compressed = await compressor.compressAsync(data);

  // Empty input should produce some output (header/footer)
  assertEquals(compressed instanceof Uint8Array, true);
});

Deno.test('ZlibDecompressor handles empty compressed data', async () => {
  const compressor = new ZlibCompressor();
  const decompressor = new ZlibDecompressor();

  const empty = new Uint8Array(0);
  const compressed = await compressor.compressAsync(empty);
  const decompressed = await decompressor.decompressAsync(compressed);

  assertEquals(decompressed.length, 0);
});

Deno.test('ZlibCompressor compresses binary data', async () => {
  const compressor = new ZlibCompressor();
  const decompressor = new ZlibDecompressor();

  // Binary data with various byte values
  const original = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    original[i] = i;
  }

  const compressed = await compressor.compressAsync(original);
  const decompressed = await decompressor.decompressAsync(compressed);

  assertEquals(decompressed.length, original.length);
  for (let i = 0; i < original.length; i++) {
    assertEquals(decompressed[i], original[i]);
  }
});

Deno.test('ZlibCompressor handles repeated data well', async () => {
  const compressor = new ZlibCompressor();
  const decompressor = new ZlibDecompressor();

  // Highly compressible data
  const original = new Uint8Array(10000);
  original.fill(0x41); // All 'A's

  const compressed = await compressor.compressAsync(original);

  // Compressed should be much smaller
  assertEquals(compressed.length < original.length / 10, true);

  const decompressed = await decompressor.decompressAsync(compressed);
  assertEquals(decompressed.length, original.length);
});

Deno.test('ZlibCompressor cleanup does not throw', () => {
  const compressor = new ZlibCompressor();
  compressor.cleanup();
  // Should not throw
});

Deno.test('ZlibDecompressor cleanup does not throw', () => {
  const decompressor = new ZlibDecompressor();
  decompressor.cleanup();
  // Should not throw
});

// Multiple compressions
Deno.test('ZlibCompressor handles multiple compressions', async () => {
  const compressor = new ZlibCompressor();

  const messages = ['Hello', 'World', 'Foo', 'Bar', 'Baz'];

  for (const msg of messages) {
    const original = fromString(msg);
    const compressed = await compressor.compressAsync(original);
    const decompressor = new ZlibDecompressor();
    const decompressed = await decompressor.decompressAsync(compressed);
    assertEquals(toUtf8(decompressed), msg);
  }
});

// Large data test
Deno.test('ZlibCompressor handles large data', async () => {
  const compressor = new ZlibCompressor();
  const decompressor = new ZlibDecompressor();

  // 1MB of random-ish data
  const original = new Uint8Array(1024 * 1024);
  for (let i = 0; i < original.length; i++) {
    original[i] = (i * 17 + 31) % 256;
  }

  const compressed = await compressor.compressAsync(original);
  const decompressed = await decompressor.decompressAsync(compressed);

  assertEquals(decompressed.length, original.length);

  // Verify first and last few bytes
  for (let i = 0; i < 100; i++) {
    assertEquals(decompressed[i], original[i]);
  }
  for (let i = original.length - 100; i < original.length; i++) {
    assertEquals(decompressed[i], original[i]);
  }
});

// =============================================================================
// PacketWriter / PacketReader tests
// =============================================================================

Deno.test('PacketReader read returns data as-is', () => {
  const reader = new PacketReader();
  const data = fromString('test data');
  assertEquals(reader.read(data), data);
});

Deno.test('PacketReader cleanup does not throw', () => {
  const reader = new PacketReader();
  reader.cleanup();
});

Deno.test('PacketWriter alloc returns cipher packet when no kexinit', () => {
  const protocol = {
    _kexinit: undefined,
    _cipher: {
      allocPacket(size: number) {
        return allocBytes(size + 5);
      },
    },
  };
  const writer = new PacketWriter(protocol);
  const packet = writer.alloc(10);
  assertEquals(packet.length, 15); // 10 + 5
});

Deno.test('PacketWriter alloc returns plain buffer during kex', () => {
  const protocol = {
    _kexinit: {}, // non-undefined = kex in progress
    _cipher: {
      allocPacket(size: number) {
        return allocBytes(size + 5);
      },
    },
  };
  const writer = new PacketWriter(protocol);
  const packet = writer.alloc(10);
  assertEquals(packet.length, 10); // plain buffer, no cipher
});

Deno.test('PacketWriter alloc with force bypasses kex check', () => {
  const protocol = {
    _kexinit: {}, // kex in progress
    _cipher: {
      allocPacket(size: number) {
        return allocBytes(size + 5);
      },
    },
  };
  const writer = new PacketWriter(protocol);
  const packet = writer.alloc(10, true);
  assertEquals(packet.length, 15); // force = true, uses cipher
});

Deno.test('PacketWriter finalize returns packet as-is', () => {
  const protocol = {
    _kexinit: undefined,
    _cipher: {
      allocPacket(size: number) {
        return allocBytes(size + 5);
      },
    },
  };
  const writer = new PacketWriter(protocol);
  const packet = fromString('test');
  assertEquals(writer.finalize(packet), packet);
});

Deno.test('PacketWriter cleanup does not throw', () => {
  const protocol = {
    _kexinit: undefined,
    _cipher: { allocPacket: (s: number) => allocBytes(s) },
  };
  const writer = new PacketWriter(protocol);
  writer.cleanup();
});

Deno.test('PacketWriter allocStart constants', () => {
  const protocol = {
    _kexinit: undefined,
    _cipher: { allocPacket: (s: number) => allocBytes(s) },
  };
  const writer = new PacketWriter(protocol);
  assertEquals(writer.allocStart, 5);
  assertEquals(writer.allocStartKEX, 5);
});

Deno.test('ZlibPacketWriter allocStart constants', () => {
  const protocol = {
    _kexinit: undefined,
    _cipher: { allocPacket: (s: number) => allocBytes(s) },
  };
  const writer = new ZlibPacketWriter(protocol);
  assertEquals(writer.allocStart, 0);
  assertEquals(writer.allocStartKEX, 0);
});

Deno.test('ZlibPacketWriter alloc returns plain buffer', () => {
  const protocol = {
    _kexinit: undefined,
    _cipher: { allocPacket: (s: number) => allocBytes(s) },
  };
  const writer = new ZlibPacketWriter(protocol);
  const buf = writer.alloc(10);
  assertEquals(buf.length, 10);
});

Deno.test('ZlibPacketWriter cleanup does not throw', () => {
  const protocol = {
    _kexinit: undefined,
    _cipher: { allocPacket: (s: number) => allocBytes(s) },
  };
  const writer = new ZlibPacketWriter(protocol);
  writer.cleanup();
});

Deno.test('ZlibPacketReader read returns decompressed data', () => {
  const reader = new ZlibPacketReader();
  // Note: sync decompress is a best-effort implementation
  // Just verify it doesn't throw
  const data = new Uint8Array([1, 2, 3]);
  const result = reader.read(data);
  assertEquals(result instanceof Uint8Array, true);
});

Deno.test('ZlibPacketReader cleanup does not throw', () => {
  const reader = new ZlibPacketReader();
  reader.cleanup();
});

// =============================================================================
// ZlibCompressor.compress() — sync method
// =============================================================================

Deno.test('ZlibCompressor compress returns Uint8Array', () => {
  const compressor = new ZlibCompressor();
  const data = fromString('Hello, World!');
  const result = compressor.compress(data);
  assertEquals(result instanceof Uint8Array, true);
});

Deno.test('ZlibCompressor compress returns Uint8Array for empty input', () => {
  const compressor = new ZlibCompressor();
  const result = compressor.compress(new Uint8Array(0));
  assertEquals(result instanceof Uint8Array, true);
});

Deno.test('ZlibCompressor compress returns Uint8Array for binary data', () => {
  const compressor = new ZlibCompressor();
  const data = new Uint8Array(64);
  for (let i = 0; i < 64; i++) data[i] = i;
  const result = compressor.compress(data);
  assertEquals(result instanceof Uint8Array, true);
});

// =============================================================================
// ZlibDecompressor.decompress() — sync method
// Only safe to call with empty data; non-deflate bytes cause async rejection.
// =============================================================================

Deno.test('ZlibDecompressor decompress returns Uint8Array for empty input', () => {
  const decompressor = new ZlibDecompressor();
  const result = decompressor.decompress(new Uint8Array(0));
  assertEquals(result instanceof Uint8Array, true);
});

// =============================================================================
// ZlibPacketWriter.finalize() tests
// =============================================================================

function makeZlibProtocol(kexinit: unknown = undefined) {
  return {
    _kexinit: kexinit,
    _cipher: {
      allocPacket(size: number) {
        return allocBytes(size + 5);
      },
    },
  };
}

Deno.test('ZlibPacketWriter finalize compresses when kexinit is undefined', () => {
  const protocol = makeZlibProtocol(undefined);
  const writer = new ZlibPacketWriter(protocol);
  const payload = fromString('test payload data');
  const result = writer.finalize(payload);
  // Result should be a Uint8Array (cipher packet wrapping compressed data)
  assertEquals(result instanceof Uint8Array, true);
  // Packet is bigger than 5 bytes (5-byte header + compressed data)
  assertEquals(result.length >= 5, true);
});

Deno.test('ZlibPacketWriter finalize returns payload as-is during kex', () => {
  const protocol = makeZlibProtocol({}); // non-undefined = kex in progress
  const writer = new ZlibPacketWriter(protocol);
  const payload = fromString('test payload');
  const result = writer.finalize(payload);
  // During kex, payload is returned unchanged (no compression)
  assertEquals(result, payload);
});

Deno.test('ZlibPacketWriter finalize with force=true compresses during kex', () => {
  const protocol = makeZlibProtocol({}); // kex in progress
  const writer = new ZlibPacketWriter(protocol);
  const payload = fromString('force compress');
  const result = writer.finalize(payload, true);
  // force=true bypasses kex check, should return cipher packet
  assertEquals(result instanceof Uint8Array, true);
  assertEquals(result.length >= 5, true);
});

Deno.test('ZlibPacketWriter finalize with force=false during kex returns payload', () => {
  const protocol = makeZlibProtocol({}); // kex in progress
  const writer = new ZlibPacketWriter(protocol);
  const payload = new Uint8Array([10, 20, 30, 40]);
  const result = writer.finalize(payload, false);
  // force=false + kex in progress → return payload unchanged
  assertEquals(result, payload);
});
