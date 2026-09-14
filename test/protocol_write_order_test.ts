import { assertEquals } from '@std/assert';
import { Protocol } from '../src/protocol/Protocol.ts';

// deno-lint-ignore no-explicit-any
type Internal = any;

Deno.test('Protocol serializes asynchronous outbound packet encryption', async () => {
  const writes: number[] = [];
  let activeEncryptions = 0;
  let maxActiveEncryptions = 0;

  const protocol = new Protocol({
    server: false,
    onWrite: () => {},
    onError: (err) => {
      throw err;
    },
  });

  (protocol as Internal)._cipher = {
    outSeqno: 0,
    free: () => {},
    allocPacket: (payloadLength: number) => new Uint8Array(5 + payloadLength),
    encrypt: async (packet: Uint8Array) => {
      activeEncryptions++;
      maxActiveEncryptions = Math.max(maxActiveEncryptions, activeEncryptions);

      const marker = packet[14];
      if (marker === 1) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      writes.push(marker);
      activeEncryptions--;
    },
  };

  protocol.channelData(7, new Uint8Array([1]));
  protocol.channelData(7, new Uint8Array([2]));

  await new Promise((resolve) => setTimeout(resolve, 40));
  assertEquals(maxActiveEncryptions, 1);
  assertEquals(writes, [1, 2]);
});

Deno.test('Protocol assembles segmented channel data in the cipher packet', () => {
  let encrypted: Uint8Array | undefined;
  const protocol = new Protocol({
    server: false,
    onWrite: () => {},
    onError: (err) => {
      throw err;
    },
  });

  (protocol as Internal)._cipher = {
    outSeqno: 0,
    free: () => {},
    allocPacket: (payloadLength: number) => new Uint8Array(5 + payloadLength),
    encrypt: (packet: Uint8Array) => {
      encrypted = packet;
    },
  };

  protocol.channelDataParts(7, [new Uint8Array([1, 2]), new Uint8Array([3, 4])]);

  assertEquals(
    encrypted?.subarray(5),
    new Uint8Array([94, 0, 0, 0, 7, 0, 0, 0, 4, 1, 2, 3, 4]),
  );
});
