/**
 * Protocol Message Handlers Tests
 *
 * Direct unit tests for all handlers in createMessageHandlers().
 * Each test constructs a raw binary payload and verifies the handler
 * calls the correct callback with correct arguments.
 */

import { assertEquals } from '@std/assert';
import {
  createMessageHandlers,
  type HandlerProtocol,
  type ProtocolHandlers,
} from '../src/protocol/handlers.ts';
import { CHANNEL_OPEN_FAILURE, COMPAT, MESSAGE, TERMINAL_MODE } from '../src/protocol/constants.ts';

const enc = new TextEncoder();
const handlers = createMessageHandlers();

// =============================================================================
// Test helpers
// =============================================================================

/** Build a 4-byte big-endian uint32. */
function uint32BE(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

/** Build an SSH length-prefixed string from text. */
function sshString(text: string): Uint8Array {
  const data = enc.encode(text);
  return concat(uint32BE(data.length), data);
}

/** Build an SSH length-prefixed string from raw bytes. */
function sshBytes(data: Uint8Array): Uint8Array {
  return concat(uint32BE(data.length), data);
}

/** Concatenate Uint8Arrays. */
function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Build a payload with leading message type byte. */
function payload(type: number, ...parts: Uint8Array[]): Uint8Array {
  return concat(new Uint8Array([type]), ...parts);
}

/** A single bool byte. */
function bool(v: boolean): Uint8Array {
  return new Uint8Array([v ? 1 : 0]);
}

// deno-lint-ignore no-explicit-any
type Call = { name: string; args: any[] };

/**
 * Create a mock HandlerProtocol. Captures all handler callbacks and
 * protocol method calls. Errors from doFatalError are captured in `errors`.
 */
function mockProtocol(
  overrides?: Partial<ProtocolHandlers>,
  opts?: { authsQueue?: string[]; compatFlags?: number },
) {
  const calls: Call[] = [];
  const errors: string[] = [];

  const handlerCallbacks: ProtocolHandlers = {};
  // Build proxy handlers that record calls
  const handlerNames: (keyof ProtocolHandlers)[] = [
    'DISCONNECT', 'DEBUG', 'SERVICE_REQUEST', 'SERVICE_ACCEPT', 'EXT_INFO',
    'USERAUTH_REQUEST', 'USERAUTH_FAILURE', 'USERAUTH_SUCCESS', 'USERAUTH_BANNER',
    'USERAUTH_PASSWD_CHANGEREQ', 'USERAUTH_PK_OK', 'USERAUTH_INFO_REQUEST',
    'USERAUTH_INFO_RESPONSE',
    'GLOBAL_REQUEST', 'REQUEST_SUCCESS', 'REQUEST_FAILURE',
    'CHANNEL_OPEN', 'CHANNEL_OPEN_CONFIRMATION', 'CHANNEL_OPEN_FAILURE',
    'CHANNEL_WINDOW_ADJUST', 'CHANNEL_DATA', 'CHANNEL_EXTENDED_DATA',
    'CHANNEL_EOF', 'CHANNEL_CLOSE', 'CHANNEL_REQUEST',
    'CHANNEL_SUCCESS', 'CHANNEL_FAILURE',
  ];
  for (const name of handlerNames) {
    // deno-lint-ignore no-explicit-any
    (handlerCallbacks as any)[name] = (...args: any[]) => {
      // Strip the first arg (protocol self) from recorded args
      calls.push({ name, args: args.slice(1) });
    };
  }
  // Apply overrides (e.g. to remove a handler for "no handler" tests)
  if (overrides) {
    for (const [k, v] of Object.entries(overrides)) {
      // deno-lint-ignore no-explicit-any
      (handlerCallbacks as any)[k] = v;
    }
  }

  const proto: HandlerProtocol = {
    _handlers: handlerCallbacks,
    _authsQueue: opts?.authsQueue ?? [],
    _compatFlags: opts?.compatFlags ?? 0,
    _kex: { sessionID: new Uint8Array([0x01, 0x02, 0x03, 0x04]) },
    _debug: undefined,
    // doFatalError calls these:
    disconnect(_reason: number) {},
    _destruct() {},
    _onError(err: Error) { errors.push(err.message); },
    requestFailure() { calls.push({ name: 'requestFailure', args: [] }); },
    channelOpenFail(recipient: number, reason: number, desc: string, lang: string) {
      calls.push({ name: 'channelOpenFail', args: [recipient, reason, desc, lang] });
    },
  };

  return { proto, calls, errors };
}

// =============================================================================
// Transport layer protocol
// =============================================================================

Deno.test('DISCONNECT: valid packet calls handler', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.DISCONNECT,
    uint32BE(11), // reason: CONNECTION_LOST
    sshString('connection lost'),
    sshString('en'),
  );
  handlers[MESSAGE.DISCONNECT](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'DISCONNECT');
  assertEquals(calls[0].args[0], 11);
  assertEquals(calls[0].args[1], 'connection lost');
});

Deno.test('DISCONNECT: truncated packet triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.DISCONNECT, uint32BE(11));
  handlers[MESSAGE.DISCONNECT](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed DISCONNECT packet');
});

Deno.test('IGNORE: valid packet does not crash', () => {
  const { proto, calls, errors } = mockProtocol();
  const p = payload(MESSAGE.IGNORE, sshString('ignored data'));
  handlers[MESSAGE.IGNORE](proto, p);
  assertEquals(calls.length, 0);
  assertEquals(errors.length, 0);
});

Deno.test('UNIMPLEMENTED: valid packet with seqno', () => {
  const debugMsgs: string[] = [];
  const { proto, errors } = mockProtocol();
  proto._debug = (msg) => debugMsgs.push(msg);
  const p = payload(MESSAGE.UNIMPLEMENTED, uint32BE(42));
  handlers[MESSAGE.UNIMPLEMENTED](proto, p);
  assertEquals(errors.length, 0);
  assertEquals(debugMsgs.length, 1);
  assertEquals(debugMsgs[0].includes('42'), true);
});

Deno.test('UNIMPLEMENTED: truncated packet triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.UNIMPLEMENTED); // no seqno
  handlers[MESSAGE.UNIMPLEMENTED](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed UNIMPLEMENTED packet');
});

Deno.test('DEBUG: valid packet calls handler', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.DEBUG,
    bool(true),
    sshString('debug message'),
    sshString('en'),
  );
  handlers[MESSAGE.DEBUG](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'DEBUG');
  assertEquals(calls[0].args[0], true);
  assertEquals(calls[0].args[1], 'debug message');
});

Deno.test('DEBUG: truncated packet triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.DEBUG, bool(true));
  handlers[MESSAGE.DEBUG](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed DEBUG packet');
});

Deno.test('SERVICE_REQUEST: valid packet calls handler', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.SERVICE_REQUEST, sshString('ssh-userauth'));
  handlers[MESSAGE.SERVICE_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'SERVICE_REQUEST');
  assertEquals(calls[0].args[0], 'ssh-userauth');
});

Deno.test('SERVICE_REQUEST: truncated packet triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.SERVICE_REQUEST); // no name
  handlers[MESSAGE.SERVICE_REQUEST](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed SERVICE_REQUEST packet');
});

Deno.test('SERVICE_ACCEPT: valid packet calls handler', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.SERVICE_ACCEPT, sshString('ssh-userauth'));
  handlers[MESSAGE.SERVICE_ACCEPT](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'SERVICE_ACCEPT');
  assertEquals(calls[0].args[0], 'ssh-userauth');
});

Deno.test('SERVICE_ACCEPT: truncated packet triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.SERVICE_ACCEPT);
  handlers[MESSAGE.SERVICE_ACCEPT](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed SERVICE_ACCEPT packet');
});

Deno.test('EXT_INFO: server-sig-algs extension parsed', () => {
  const { proto, calls } = mockProtocol();
  const algsData = enc.encode('rsa-sha2-256,rsa-sha2-512');
  const p = payload(MESSAGE.EXT_INFO,
    uint32BE(1), // 1 extension
    sshString('server-sig-algs'),
    sshBytes(algsData),
  );
  handlers[MESSAGE.EXT_INFO](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'EXT_INFO');
  assertEquals(calls[0].args[0], [
    { name: 'server-sig-algs', algs: ['rsa-sha2-256', 'rsa-sha2-512'] },
  ]);
});

Deno.test('EXT_INFO: unknown extension is skipped but still parsed', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.EXT_INFO,
    uint32BE(1),
    sshString('some-unknown-ext'),
    sshBytes(new Uint8Array([1, 2, 3])),
  );
  handlers[MESSAGE.EXT_INFO](proto, p);
  assertEquals(calls.length, 1);
  // Unknown extensions get continue'd, so the array has no entries
  assertEquals(calls[0].args[0], []);
});

Deno.test('EXT_INFO: truncated packet triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.EXT_INFO, uint32BE(1)); // missing extension data
  handlers[MESSAGE.EXT_INFO](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed EXT_INFO packet');
});

// =============================================================================
// User auth protocol -- generic
// =============================================================================

Deno.test('USERAUTH_REQUEST: none method', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.USERAUTH_REQUEST,
    sshString('alice'),
    sshString('ssh-connection'),
    sshString('none'),
  );
  handlers[MESSAGE.USERAUTH_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'USERAUTH_REQUEST');
  assertEquals(calls[0].args[0], 'alice');
  assertEquals(calls[0].args[1], 'ssh-connection');
  assertEquals(calls[0].args[2], 'none');
  assertEquals(calls[0].args[3], null);
  assertEquals(proto._authsQueue, ['none']);
});

Deno.test('USERAUTH_REQUEST: password method', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.USERAUTH_REQUEST,
    sshString('bob'),
    sshString('ssh-connection'),
    sshString('password'),
    bool(false), // not a change
    sshString('secret123'),
  );
  handlers[MESSAGE.USERAUTH_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[2], 'password');
  assertEquals(calls[0].args[3], 'secret123');
});

Deno.test('USERAUTH_REQUEST: password change', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.USERAUTH_REQUEST,
    sshString('bob'),
    sshString('ssh-connection'),
    sshString('password'),
    bool(true), // change
    sshString('oldpass'),
    sshString('newpass'),
  );
  handlers[MESSAGE.USERAUTH_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[3], { oldPassword: 'oldpass', newPassword: 'newpass' });
});

Deno.test('USERAUTH_REQUEST: keyboard-interactive method', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.USERAUTH_REQUEST,
    sshString('alice'),
    sshString('ssh-connection'),
    sshString('keyboard-interactive'),
    sshString(''), // language (skipped)
    sshString(''), // submethods (readList returns [])
  );
  handlers[MESSAGE.USERAUTH_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[2], 'keyboard-interactive');
});

Deno.test('USERAUTH_REQUEST: unknown method with raw data', () => {
  const { proto, calls } = mockProtocol();
  const rawData = new Uint8Array([0xaa, 0xbb, 0xcc]);
  const p = payload(MESSAGE.USERAUTH_REQUEST,
    sshString('alice'),
    sshString('ssh-connection'),
    sshString('custom-method'),
    rawData,
  );
  handlers[MESSAGE.USERAUTH_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[2], 'custom-method');
});

Deno.test('USERAUTH_REQUEST: truncated packet triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.USERAUTH_REQUEST, sshString('alice'));
  handlers[MESSAGE.USERAUTH_REQUEST](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed USERAUTH_REQUEST packet');
});

Deno.test('USERAUTH_FAILURE: valid packet', () => {
  const { proto, calls } = mockProtocol(undefined, { authsQueue: ['password'] });
  const p = payload(MESSAGE.USERAUTH_FAILURE,
    sshString('publickey,password'),
    bool(false),
  );
  handlers[MESSAGE.USERAUTH_FAILURE](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'USERAUTH_FAILURE');
  assertEquals(calls[0].args[0], ['publickey', 'password']);
  assertEquals(calls[0].args[1], false);
  assertEquals(proto._authsQueue.length, 0); // shifted
});

Deno.test('USERAUTH_FAILURE: truncated packet triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.USERAUTH_FAILURE); // no data
  handlers[MESSAGE.USERAUTH_FAILURE](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed USERAUTH_FAILURE packet');
});

Deno.test('USERAUTH_SUCCESS: calls handler and shifts authsQueue', () => {
  const { proto, calls } = mockProtocol(undefined, { authsQueue: ['password'] });
  const p = payload(MESSAGE.USERAUTH_SUCCESS);
  handlers[MESSAGE.USERAUTH_SUCCESS](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'USERAUTH_SUCCESS');
  assertEquals(proto._authsQueue.length, 0);
});

Deno.test('USERAUTH_BANNER: valid packet', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.USERAUTH_BANNER,
    sshString('Welcome!'),
    sshString('en'),
  );
  handlers[MESSAGE.USERAUTH_BANNER](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'USERAUTH_BANNER');
  assertEquals(calls[0].args[0], 'Welcome!');
});

Deno.test('USERAUTH_BANNER: truncated packet triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.USERAUTH_BANNER, sshString('Welcome!'));
  handlers[MESSAGE.USERAUTH_BANNER](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed USERAUTH_BANNER packet');
});

// =============================================================================
// User auth protocol -- method-specific (type 60 / 61)
// =============================================================================

Deno.test('type 60: empty authsQueue is silently ignored', () => {
  const { proto, calls, errors } = mockProtocol(undefined, { authsQueue: [] });
  const p = payload(60, sshString('data'));
  handlers[60](proto, p);
  assertEquals(calls.length, 0);
  assertEquals(errors.length, 0);
});

Deno.test('type 60 password: USERAUTH_PASSWD_CHANGEREQ', () => {
  const { proto, calls } = mockProtocol(undefined, { authsQueue: ['password'] });
  const p = payload(60,
    sshString('Please change your password'),
    sshString('en'),
  );
  handlers[60](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'USERAUTH_PASSWD_CHANGEREQ');
  assertEquals(calls[0].args[0], 'Please change your password');
});

Deno.test('type 60 password: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol(undefined, { authsQueue: ['password'] });
  const p = payload(60, sshString('prompt')); // missing lang
  handlers[60](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed USERAUTH_PASSWD_CHANGEREQ packet');
});

Deno.test('type 60 publickey: USERAUTH_PK_OK', () => {
  const { proto, calls } = mockProtocol(undefined, { authsQueue: ['publickey'] });
  const keyData = new Uint8Array([0x00, 0x00, 0x00, 0x07, ...enc.encode('ssh-rsa'), 0x01]);
  const p = payload(60,
    sshString('ssh-rsa'),
    sshBytes(keyData),
  );
  handlers[60](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'USERAUTH_PK_OK');
  assertEquals(calls[0].args[0], 'ssh-rsa');
  // authsQueue should be shifted
  assertEquals(proto._authsQueue.length, 0);
});

Deno.test('type 60 publickey: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol(undefined, { authsQueue: ['publickey'] });
  const p = payload(60, sshString('ssh-rsa')); // missing key
  handlers[60](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed USERAUTH_PK_OK packet');
});

Deno.test('type 60 keyboard-interactive: USERAUTH_INFO_REQUEST', () => {
  const { proto, calls } = mockProtocol(undefined, { authsQueue: ['keyboard-interactive'] });
  const p = payload(60,
    sshString('Auth Name'),
    sshString('Please enter code'),
    sshString('en'), // lang
    uint32BE(1), // 1 prompt
    sshString('Code: '),
    bool(true), // echo
  );
  handlers[60](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'USERAUTH_INFO_REQUEST');
  assertEquals(calls[0].args[0], 'Auth Name');
  assertEquals(calls[0].args[1], 'Please enter code');
  assertEquals(calls[0].args[2], [{ prompt: 'Code: ', echo: true }]);
});

Deno.test('type 60 keyboard-interactive: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol(undefined, { authsQueue: ['keyboard-interactive'] });
  const p = payload(60,
    sshString('Auth Name'),
    sshString('instr'),
    sshString('en'),
    uint32BE(2), // 2 prompts but only 1 provided
    sshString('Code: '),
    bool(true),
  );
  handlers[60](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed USERAUTH_INFO_REQUEST packet');
});

Deno.test('type 60 unknown method: silently ignored', () => {
  const debugMsgs: string[] = [];
  const { proto, calls, errors } = mockProtocol(undefined, { authsQueue: ['custom'] });
  proto._debug = (msg) => debugMsgs.push(msg);
  const p = payload(60, sshString('data'));
  handlers[60](proto, p);
  assertEquals(calls.length, 0);
  assertEquals(errors.length, 0);
  assertEquals(debugMsgs[0].includes('unexpected'), true);
});

Deno.test('type 61: empty authsQueue is silently ignored', () => {
  const { proto, calls, errors } = mockProtocol(undefined, { authsQueue: [] });
  const p = payload(61, uint32BE(1), sshString('response'));
  handlers[61](proto, p);
  assertEquals(calls.length, 0);
  assertEquals(errors.length, 0);
});

Deno.test('type 61: wrong auth method triggers fatal error', () => {
  const { proto, errors } = mockProtocol(undefined, { authsQueue: ['password'] });
  const p = payload(61, uint32BE(1), sshString('response'));
  handlers[61](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Received unexpected payload type 61');
});

Deno.test('type 61 keyboard-interactive: USERAUTH_INFO_RESPONSE', () => {
  const { proto, calls } = mockProtocol(undefined, { authsQueue: ['keyboard-interactive'] });
  const p = payload(61,
    uint32BE(2), // 2 responses
    sshString('answer1'),
    sshString('answer2'),
  );
  handlers[61](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'USERAUTH_INFO_RESPONSE');
  assertEquals(calls[0].args[0], ['answer1', 'answer2']);
});

Deno.test('type 61 keyboard-interactive: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol(undefined, { authsQueue: ['keyboard-interactive'] });
  const p = payload(61,
    uint32BE(2), // claims 2 responses
    sshString('only-one'),
  );
  handlers[61](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed USERAUTH_INFO_RESPONSE packet');
});

// =============================================================================
// Connection protocol -- generic
// =============================================================================

Deno.test('GLOBAL_REQUEST: tcpip-forward', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.GLOBAL_REQUEST,
    sshString('tcpip-forward'),
    bool(true),
    sshString('0.0.0.0'),
    uint32BE(8080),
  );
  handlers[MESSAGE.GLOBAL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'GLOBAL_REQUEST');
  assertEquals(calls[0].args[0], 'tcpip-forward');
  assertEquals(calls[0].args[1], true);
  assertEquals(calls[0].args[2], { bindAddr: '0.0.0.0', bindPort: 8080 });
});

Deno.test('GLOBAL_REQUEST: cancel-tcpip-forward', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.GLOBAL_REQUEST,
    sshString('cancel-tcpip-forward'),
    bool(false),
    sshString('127.0.0.1'),
    uint32BE(9090),
  );
  handlers[MESSAGE.GLOBAL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[0], 'cancel-tcpip-forward');
  assertEquals(calls[0].args[2], { bindAddr: '127.0.0.1', bindPort: 9090 });
});

Deno.test('GLOBAL_REQUEST: streamlocal-forward@openssh.com', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.GLOBAL_REQUEST,
    sshString('streamlocal-forward@openssh.com'),
    bool(true),
    sshString('/tmp/test.sock'),
  );
  handlers[MESSAGE.GLOBAL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[2], { socketPath: '/tmp/test.sock' });
});

Deno.test('GLOBAL_REQUEST: no-more-sessions@openssh.com', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.GLOBAL_REQUEST,
    sshString('no-more-sessions@openssh.com'),
    bool(false),
  );
  handlers[MESSAGE.GLOBAL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[2], null);
});

Deno.test('GLOBAL_REQUEST: unknown type passes raw data', () => {
  const { proto, calls } = mockProtocol();
  const rawData = new Uint8Array([0xde, 0xad]);
  const p = payload(MESSAGE.GLOBAL_REQUEST,
    sshString('custom-request'),
    bool(true),
    rawData,
  );
  handlers[MESSAGE.GLOBAL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[0], 'custom-request');
});

Deno.test('GLOBAL_REQUEST: no handler calls requestFailure', () => {
  const { proto, calls } = mockProtocol({ GLOBAL_REQUEST: undefined });
  const p = payload(MESSAGE.GLOBAL_REQUEST,
    sshString('tcpip-forward'),
    bool(true),
    sshString('0.0.0.0'),
    uint32BE(8080),
  );
  handlers[MESSAGE.GLOBAL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'requestFailure');
});

Deno.test('GLOBAL_REQUEST: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.GLOBAL_REQUEST,
    sshString('tcpip-forward'),
    bool(true),
    sshString('0.0.0.0'),
    // missing port
  );
  handlers[MESSAGE.GLOBAL_REQUEST](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed GLOBAL_REQUEST packet');
});

Deno.test('REQUEST_SUCCESS: with data', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.REQUEST_SUCCESS, new Uint8Array([0x01, 0x02]));
  handlers[MESSAGE.REQUEST_SUCCESS](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'REQUEST_SUCCESS');
  assertEquals(calls[0].args[0], new Uint8Array([0x01, 0x02]));
});

Deno.test('REQUEST_SUCCESS: empty payload passes null', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.REQUEST_SUCCESS);
  handlers[MESSAGE.REQUEST_SUCCESS](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[0], null);
});

Deno.test('REQUEST_FAILURE: calls handler', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.REQUEST_FAILURE);
  handlers[MESSAGE.REQUEST_FAILURE](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'REQUEST_FAILURE');
});

// =============================================================================
// Connection protocol -- channel-related
// =============================================================================

Deno.test('CHANNEL_OPEN: session (default type)', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_OPEN,
    sshString('session'),
    uint32BE(0), // sender
    uint32BE(2097152), // window
    uint32BE(32768), // packetSize
  );
  handlers[MESSAGE.CHANNEL_OPEN](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_OPEN');
  assertEquals(calls[0].args[0].type, 'session');
  assertEquals(calls[0].args[0].sender, 0);
  assertEquals(calls[0].args[0].window, 2097152);
  assertEquals(calls[0].args[0].packetSize, 32768);
  assertEquals(calls[0].args[0].data, {});
});

Deno.test('CHANNEL_OPEN: direct-tcpip', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_OPEN,
    sshString('direct-tcpip'),
    uint32BE(1),
    uint32BE(65536),
    uint32BE(16384),
    sshString('192.168.1.1'), // destIP
    uint32BE(80), // destPort
    sshString('10.0.0.1'), // srcIP
    uint32BE(12345), // srcPort
  );
  handlers[MESSAGE.CHANNEL_OPEN](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[0].type, 'direct-tcpip');
  assertEquals(calls[0].args[0].data, {
    destIP: '192.168.1.1', destPort: 80,
    srcIP: '10.0.0.1', srcPort: 12345,
  });
});

Deno.test('CHANNEL_OPEN: forwarded-streamlocal@openssh.com', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_OPEN,
    sshString('forwarded-streamlocal@openssh.com'),
    uint32BE(2),
    uint32BE(65536),
    uint32BE(16384),
    sshString('/tmp/agent.sock'),
  );
  handlers[MESSAGE.CHANNEL_OPEN](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[0].type, 'forwarded-streamlocal@openssh.com');
  assertEquals(calls[0].args[0].data, { socketPath: '/tmp/agent.sock' });
});

Deno.test('CHANNEL_OPEN: x11', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_OPEN,
    sshString('x11'),
    uint32BE(3),
    uint32BE(65536),
    uint32BE(16384),
    sshString('127.0.0.1'),
    uint32BE(6010),
  );
  handlers[MESSAGE.CHANNEL_OPEN](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[0].type, 'x11');
  assertEquals(calls[0].args[0].data, { srcIP: '127.0.0.1', srcPort: 6010 });
});

Deno.test('CHANNEL_OPEN: no handler calls channelOpenFail', () => {
  const { proto, calls } = mockProtocol({ CHANNEL_OPEN: undefined });
  const p = payload(MESSAGE.CHANNEL_OPEN,
    sshString('session'),
    uint32BE(5),
    uint32BE(65536),
    uint32BE(16384),
  );
  handlers[MESSAGE.CHANNEL_OPEN](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'channelOpenFail');
  assertEquals(calls[0].args[0], 5); // sender/recipient
  assertEquals(calls[0].args[1], CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED);
});

Deno.test('CHANNEL_OPEN: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_OPEN); // empty
  handlers[MESSAGE.CHANNEL_OPEN](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_OPEN packet');
});

Deno.test('CHANNEL_OPEN_CONFIRMATION: valid', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_OPEN_CONFIRMATION,
    uint32BE(0), // recipient
    uint32BE(1), // sender
    uint32BE(2097152), // window
    uint32BE(32768), // packetSize
  );
  handlers[MESSAGE.CHANNEL_OPEN_CONFIRMATION](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_OPEN_CONFIRMATION');
  assertEquals(calls[0].args[0].recipient, 0);
  assertEquals(calls[0].args[0].sender, 1);
  assertEquals(calls[0].args[0].window, 2097152);
  assertEquals(calls[0].args[0].packetSize, 32768);
});

Deno.test('CHANNEL_OPEN_CONFIRMATION: with extra data', () => {
  const { proto, calls } = mockProtocol();
  const extraData = new Uint8Array([0xaa, 0xbb]);
  const p = payload(MESSAGE.CHANNEL_OPEN_CONFIRMATION,
    uint32BE(0),
    uint32BE(1),
    uint32BE(65536),
    uint32BE(16384),
    extraData,
  );
  handlers[MESSAGE.CHANNEL_OPEN_CONFIRMATION](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[0].data, extraData);
});

Deno.test('CHANNEL_OPEN_CONFIRMATION: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_OPEN_CONFIRMATION, uint32BE(0), uint32BE(1));
  handlers[MESSAGE.CHANNEL_OPEN_CONFIRMATION](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_OPEN_CONFIRMATION packet');
});

Deno.test('CHANNEL_OPEN_FAILURE: valid', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_OPEN_FAILURE,
    uint32BE(0), // recipient
    uint32BE(2), // reason: CONNECT_FAILED
    sshString('Connection refused'),
    sshString('en'),
  );
  handlers[MESSAGE.CHANNEL_OPEN_FAILURE](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_OPEN_FAILURE');
  assertEquals(calls[0].args[0], 0);
  assertEquals(calls[0].args[1], 2);
  assertEquals(calls[0].args[2], 'Connection refused');
});

Deno.test('CHANNEL_OPEN_FAILURE: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_OPEN_FAILURE, uint32BE(0), uint32BE(2));
  handlers[MESSAGE.CHANNEL_OPEN_FAILURE](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_OPEN_FAILURE packet');
});

Deno.test('CHANNEL_WINDOW_ADJUST: valid', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_WINDOW_ADJUST,
    uint32BE(3),
    uint32BE(131072),
  );
  handlers[MESSAGE.CHANNEL_WINDOW_ADJUST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_WINDOW_ADJUST');
  assertEquals(calls[0].args[0], 3);
  assertEquals(calls[0].args[1], 131072);
});

Deno.test('CHANNEL_WINDOW_ADJUST: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_WINDOW_ADJUST, uint32BE(3));
  handlers[MESSAGE.CHANNEL_WINDOW_ADJUST](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_WINDOW_ADJUST packet');
});

Deno.test('CHANNEL_DATA: valid', () => {
  const { proto, calls } = mockProtocol();
  const data = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
  const p = payload(MESSAGE.CHANNEL_DATA, uint32BE(0), sshBytes(data));
  handlers[MESSAGE.CHANNEL_DATA](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_DATA');
  assertEquals(calls[0].args[0], 0);
  assertEquals(calls[0].args[1], data);
});

Deno.test('CHANNEL_DATA: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_DATA, uint32BE(0));
  handlers[MESSAGE.CHANNEL_DATA](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_DATA packet');
});

Deno.test('CHANNEL_EXTENDED_DATA: valid', () => {
  const { proto, calls } = mockProtocol();
  const data = new Uint8Array([0x45, 0x72, 0x72]); // "Err"
  const p = payload(MESSAGE.CHANNEL_EXTENDED_DATA,
    uint32BE(1), // recipient
    uint32BE(1), // type: SSH_EXTENDED_DATA_STDERR
    sshBytes(data),
  );
  handlers[MESSAGE.CHANNEL_EXTENDED_DATA](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_EXTENDED_DATA');
  assertEquals(calls[0].args[0], 1);
  assertEquals(calls[0].args[1], data);
  assertEquals(calls[0].args[2], 1);
});

Deno.test('CHANNEL_EXTENDED_DATA: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_EXTENDED_DATA, uint32BE(1), uint32BE(1));
  handlers[MESSAGE.CHANNEL_EXTENDED_DATA](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_EXTENDED_DATA packet');
});

Deno.test('CHANNEL_EOF: valid', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_EOF, uint32BE(7));
  handlers[MESSAGE.CHANNEL_EOF](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_EOF');
  assertEquals(calls[0].args[0], 7);
});

Deno.test('CHANNEL_EOF: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_EOF);
  handlers[MESSAGE.CHANNEL_EOF](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_EOF packet');
});

Deno.test('CHANNEL_CLOSE: valid', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_CLOSE, uint32BE(7));
  handlers[MESSAGE.CHANNEL_CLOSE](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_CLOSE');
  assertEquals(calls[0].args[0], 7);
});

Deno.test('CHANNEL_CLOSE: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_CLOSE);
  handlers[MESSAGE.CHANNEL_CLOSE](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_CLOSE packet');
});

Deno.test('CHANNEL_SUCCESS: valid', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_SUCCESS, uint32BE(4));
  handlers[MESSAGE.CHANNEL_SUCCESS](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_SUCCESS');
  assertEquals(calls[0].args[0], 4);
});

Deno.test('CHANNEL_SUCCESS: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_SUCCESS);
  handlers[MESSAGE.CHANNEL_SUCCESS](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_SUCCESS packet');
});

Deno.test('CHANNEL_FAILURE: valid', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_FAILURE, uint32BE(4));
  handlers[MESSAGE.CHANNEL_FAILURE](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_FAILURE');
  assertEquals(calls[0].args[0], 4);
});

Deno.test('CHANNEL_FAILURE: malformed triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_FAILURE);
  handlers[MESSAGE.CHANNEL_FAILURE](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_FAILURE packet');
});

// =============================================================================
// CHANNEL_REQUEST subtypes
// =============================================================================

Deno.test('CHANNEL_REQUEST: exit-status', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('exit-status'),
    bool(false),
    uint32BE(127),
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].name, 'CHANNEL_REQUEST');
  assertEquals(calls[0].args[0], 0);
  assertEquals(calls[0].args[1], 'exit-status');
  assertEquals(calls[0].args[2], false);
  assertEquals(calls[0].args[3], 127);
});

Deno.test('CHANNEL_REQUEST: exit-signal (normal)', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('exit-signal'),
    bool(false),
    sshString('TERM'),
    bool(false), // coreDumped
    sshString('Terminated'), // errorMessage
    sshString('en'), // lang
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[1], 'exit-signal');
  assertEquals(calls[0].args[3], {
    signal: 'TERM',
    coreDumped: false,
    errorMessage: 'Terminated',
  });
});

Deno.test('CHANNEL_REQUEST: exit-signal with OLD_EXIT compat', () => {
  const { proto, calls } = mockProtocol(undefined, { compatFlags: COMPAT.OLD_EXIT });
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('exit-signal'),
    bool(false),
    uint32BE(9), // KILL signal number
    sshString('Killed'), // errorMessage
    sshString('en'), // lang
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[3], {
    signal: 'KILL',
    coreDumped: false,
    errorMessage: 'Killed',
  });
});

Deno.test('CHANNEL_REQUEST: exit-signal OLD_EXIT unknown signal number', () => {
  const { proto, calls } = mockProtocol(undefined, { compatFlags: COMPAT.OLD_EXIT });
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('exit-signal'),
    bool(false),
    uint32BE(99), // unknown signal
    sshString('Unknown signal'), // errorMessage
    sshString('en'), // lang
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[3].signal, 'UNKNOWN (99)');
});

Deno.test('CHANNEL_REQUEST: pty-req with terminal modes', () => {
  const { proto, calls } = mockProtocol();
  // Build terminal modes: VINTR=3, TTY_OP_END
  const modes = new Uint8Array([
    TERMINAL_MODE.VINTR, 0, 0, 0, 3, // VINTR = 3
    TERMINAL_MODE.TTY_OP_END,
  ]);
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('pty-req'),
    bool(true),
    sshString('xterm-256color'),
    uint32BE(80), // cols
    uint32BE(24), // rows
    uint32BE(640), // width
    uint32BE(480), // height
    sshBytes(modes),
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[1], 'pty-req');
  assertEquals(calls[0].args[3], {
    term: 'xterm-256color',
    cols: 80,
    rows: 24,
    width: 640,
    height: 480,
    modes: { VINTR: 3 },
  });
});

Deno.test('CHANNEL_REQUEST: window-change', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('window-change'),
    bool(false),
    uint32BE(120), // cols
    uint32BE(40), // rows
    uint32BE(960), // width
    uint32BE(800), // height
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[3], { cols: 120, rows: 40, width: 960, height: 800 });
});

Deno.test('CHANNEL_REQUEST: x11-req', () => {
  const { proto, calls } = mockProtocol();
  const cookie = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('x11-req'),
    bool(true),
    bool(true), // single connection
    sshString('MIT-MAGIC-COOKIE-1'),
    sshBytes(cookie),
    uint32BE(0), // screen
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[3].single, true);
  assertEquals(calls[0].args[3].protocol, 'MIT-MAGIC-COOKIE-1');
  assertEquals(calls[0].args[3].cookie, cookie);
  assertEquals(calls[0].args[3].screen, 0);
});

Deno.test('CHANNEL_REQUEST: env', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('env'),
    bool(true),
    sshString('LANG'),
    sshString('en_US.UTF-8'),
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[3], { name: 'LANG', value: 'en_US.UTF-8' });
});

Deno.test('CHANNEL_REQUEST: shell', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('shell'),
    bool(true),
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[1], 'shell');
  assertEquals(calls[0].args[3], null);
});

Deno.test('CHANNEL_REQUEST: exec', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('exec'),
    bool(true),
    sshString('ls -la'),
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[1], 'exec');
  assertEquals(calls[0].args[3], 'ls -la');
});

Deno.test('CHANNEL_REQUEST: subsystem', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('subsystem'),
    bool(true),
    sshString('sftp'),
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[1], 'subsystem');
  assertEquals(calls[0].args[3], 'sftp');
});

Deno.test('CHANNEL_REQUEST: signal', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('signal'),
    bool(false),
    sshString('TERM'),
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[1], 'signal');
  assertEquals(calls[0].args[3], 'TERM');
});

Deno.test('CHANNEL_REQUEST: xon-xoff', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('xon-xoff'),
    bool(false),
    bool(true), // client can do
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[1], 'xon-xoff');
  assertEquals(calls[0].args[3], true);
});

Deno.test('CHANNEL_REQUEST: auth-agent-req@openssh.com', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('auth-agent-req@openssh.com'),
    bool(true),
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[1], 'auth-agent-req@openssh.com');
  assertEquals(calls[0].args[3], null);
});

Deno.test('CHANNEL_REQUEST: unknown type with remaining data', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('custom-type'),
    bool(false),
    new Uint8Array([0x01, 0x02, 0x03]),
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[1], 'custom-type');
});

Deno.test('CHANNEL_REQUEST: unknown type without remaining data', () => {
  const { proto, calls } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST,
    uint32BE(0),
    sshString('empty-type'),
    bool(false),
  );
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].args[3], null);
});

Deno.test('CHANNEL_REQUEST: malformed (missing wantReply) triggers fatal error', () => {
  const { proto, errors } = mockProtocol();
  const p = payload(MESSAGE.CHANNEL_REQUEST, uint32BE(0));
  handlers[MESSAGE.CHANNEL_REQUEST](proto, p);
  assertEquals(errors.length, 1);
  assertEquals(errors[0], 'Inbound: Malformed CHANNEL_REQUEST packet');
});
