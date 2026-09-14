import { assertEquals, assertStrictEquals, assertThrows } from '@std/assert';
import { coalesceTransportWrite } from '../src/utils/transport-write.ts';

Deno.test('coalesceTransportWrite returns a lone record without copying', () => {
  const record = new Uint8Array([1, 2, 3]);
  const result = coalesceTransportWrite([record], 0, 8);

  assertStrictEquals(result.data, record);
  assertEquals(result.nextIndex, 1);
});

Deno.test('coalesceTransportWrite combines ordered records up to the bound', () => {
  const queue = [
    new Uint8Array([1, 2]),
    new Uint8Array([3, 4, 5]),
    new Uint8Array([6, 7]),
  ];

  const first = coalesceTransportWrite(queue, 0, 5);
  assertEquals(first.data, new Uint8Array([1, 2, 3, 4, 5]));
  assertEquals(first.nextIndex, 2);

  const second = coalesceTransportWrite(queue, first.nextIndex, 5);
  assertStrictEquals(second.data, queue[2]);
  assertEquals(second.nextIndex, 3);
});

Deno.test('coalesceTransportWrite permits one record larger than the bound', () => {
  const record = new Uint8Array(9);
  const result = coalesceTransportWrite([record, new Uint8Array([1])], 0, 8);

  assertStrictEquals(result.data, record);
  assertEquals(result.nextIndex, 1);
  assertThrows(() => coalesceTransportWrite([record], 1, 8), RangeError);
});
