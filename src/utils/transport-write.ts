/** Keep transport syscalls large enough to avoid one async write per SSH record. */
export const MAX_TRANSPORT_WRITE = 256 * 1024;

export type CoalescedWrite = {
  data: Uint8Array;
  nextIndex: number;
};

/**
 * Return the next bounded transport write while preserving SSH record order.
 * A single queued record is returned as-is; only a run of smaller records is
 * copied into a larger buffer.
 */
export function coalesceTransportWrite(
  queue: readonly Uint8Array[],
  start: number,
  maxLength = MAX_TRANSPORT_WRITE,
): CoalescedWrite {
  const first = queue[start];
  if (!first) throw new RangeError('transport write queue index is out of bounds');

  let nextIndex = start + 1;
  let length = first.length;
  while (nextIndex < queue.length && length + queue[nextIndex].length <= maxLength) {
    length += queue[nextIndex].length;
    ++nextIndex;
  }

  if (nextIndex === start + 1) return { data: first, nextIndex };

  const data = new Uint8Array(length);
  let offset = 0;
  for (let i = start; i < nextIndex; ++i) {
    data.set(queue[i], offset);
    offset += queue[i].length;
  }
  return { data, nextIndex };
}
