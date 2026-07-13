/**
 * Strict KEX (RFC 9700 / Terrapin, CVE-2023-48795) message-filtering tests.
 *
 * During the initial key exchange (before the first NEWKEYS), a peer that
 * negotiated strict KEX must not accept any non-KEX transport message. These
 * tests drive Protocol._onPayload (the inbound dispatch) directly, which is
 * exactly what the decipher calls per decrypted packet.
 */

import { assertEquals, assertExists, assertStringIncludes } from '@std/assert';
import { Protocol } from '../src/protocol/Protocol.ts';
import { MESSAGE } from '../src/protocol/constants.ts';

// deno-lint-ignore no-explicit-any
type Internal = any;

function makeClient() {
  let error: Error | undefined;
  const writes: Uint8Array[] = [];
  const protocol = new Protocol({
    server: false,
    onWrite: (d) => writes.push(d),
    onError: (e) => {
      error = e;
    },
  });
  return { protocol, writes, getError: () => error };
}

// A bare SSH_MSG_IGNORE / SSH_MSG_DEBUG payload (message byte + minimal body).
function ignorePayload() {
  return new Uint8Array([MESSAGE.IGNORE, 0, 0, 0, 0]);
}

Deno.test('strict KEX: IGNORE before first NEWKEYS aborts the connection', async () => {
  const { protocol, writes, getError } = makeClient();
  (protocol as Internal)._strictKex = true; // negotiated
  // _firstKexComplete defaults to false (initial handshake in progress)

  await (protocol as Internal)._onPayload(ignorePayload());

  const error = getError();
  assertExists(error);
  assertStringIncludes(error!.message, 'Strict KEX');
  // A DISCONNECT packet should have been written to the peer.
  assertEquals(writes.length > 0, true);
});

Deno.test('strict KEX: DEBUG before first NEWKEYS aborts the connection', async () => {
  const { protocol, getError } = makeClient();
  (protocol as Internal)._strictKex = true;

  await (protocol as Internal)._onPayload(new Uint8Array([MESSAGE.DEBUG, 0, 0, 0, 0, 0]));

  assertExists(getError());
});

Deno.test('strict KEX: non-KEX message is allowed after the first NEWKEYS', async () => {
  const { protocol, getError } = makeClient();
  (protocol as Internal)._strictKex = true;
  (protocol as Internal)._firstKexComplete = true; // initial KEX done

  await (protocol as Internal)._onPayload(ignorePayload());

  // The guard must not fire once the initial key exchange has completed.
  assertEquals(getError(), undefined);
});

Deno.test('strict KEX disabled: non-KEX message during handshake is allowed', async () => {
  const { protocol, getError } = makeClient();
  // _strictKex defaults to false (peer did not negotiate strict KEX)

  await (protocol as Internal)._onPayload(ignorePayload());

  assertEquals(getError(), undefined);
});
