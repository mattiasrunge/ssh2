/**
 * SSH Protocol Message Handlers
 *
 * Handles incoming SSH protocol messages for:
 * - Transport layer (DISCONNECT, IGNORE, DEBUG, etc.)
 * - User authentication (USERAUTH_*)
 * - Connection protocol (GLOBAL_REQUEST, CHANNEL_*, etc.)
 */

import { allocBytes, toUtf8, writeUInt32BE } from '../utils/binary.ts';
import { CHANNEL_OPEN_FAILURE, COMPAT, MESSAGE, TERMINAL_MODE } from './constants.ts';
import { parseKey } from './keyParser.ts';
import { doFatalError, type FatalErrorProtocol, makeBufferParser, sigSSHToASN1 } from './utils.ts';

// Create reverse mapping for terminal modes
const TERMINAL_MODE_BY_VALUE: Record<number, string> = {};
for (const [key, value] of Object.entries(TERMINAL_MODE)) {
  TERMINAL_MODE_BY_VALUE[value as number] = key;
}

/**
 * Protocol interface for message handlers
 */
export interface HandlerProtocol extends FatalErrorProtocol {
  _debug?: (msg: string) => void;
  _handlers: ProtocolHandlers;
  _authsQueue: string[];
  _kex: {
    sessionID: Uint8Array;
  };
  _compatFlags: number;
  requestFailure(): void;
  channelOpenFail(
    recipient: number,
    reason: number,
    description: string,
    lang: string,
  ): void;
}

/**
 * Handler callbacks interface
 */
export interface ProtocolHandlers {
  DISCONNECT?: (
    protocol: HandlerProtocol,
    reason: number,
    description: string,
  ) => void;
  DEBUG?: (protocol: HandlerProtocol, display: boolean, message: string) => void;
  SERVICE_REQUEST?: (protocol: HandlerProtocol, name: string) => void;
  SERVICE_ACCEPT?: (protocol: HandlerProtocol, name: string) => void;
  EXT_INFO?: (
    protocol: HandlerProtocol,
    extensions: Array<{ name: string; algs?: string[] }>,
  ) => void;
  USERAUTH_REQUEST?: (
    protocol: HandlerProtocol,
    user: string,
    service: string,
    method: string,
    methodData: unknown,
  ) => void;
  USERAUTH_FAILURE?: (
    protocol: HandlerProtocol,
    authMethods: string[],
    partialSuccess: boolean,
  ) => void;
  USERAUTH_SUCCESS?: (protocol: HandlerProtocol) => void;
  USERAUTH_BANNER?: (protocol: HandlerProtocol, message: string) => void;
  USERAUTH_PASSWD_CHANGEREQ?: (protocol: HandlerProtocol, prompt: string) => void;
  USERAUTH_PK_OK?: (
    protocol: HandlerProtocol,
    keyAlgo: string,
    key: Uint8Array,
  ) => void;
  USERAUTH_INFO_REQUEST?: (
    protocol: HandlerProtocol,
    name: string,
    instructions: string,
    prompts: Array<{ prompt: string; echo: boolean }>,
  ) => void;
  USERAUTH_INFO_RESPONSE?: (protocol: HandlerProtocol, responses: string[]) => void;
  GLOBAL_REQUEST?: (
    protocol: HandlerProtocol,
    name: string,
    wantReply: boolean,
    data: unknown,
  ) => void;
  REQUEST_SUCCESS?: (protocol: HandlerProtocol, data: Uint8Array | null) => void;
  REQUEST_FAILURE?: (protocol: HandlerProtocol) => void;
  CHANNEL_OPEN?: (protocol: HandlerProtocol, channelInfo: ChannelOpenInfo) => void;
  CHANNEL_OPEN_CONFIRMATION?: (
    protocol: HandlerProtocol,
    info: ChannelConfirmationInfo,
  ) => void;
  CHANNEL_OPEN_FAILURE?: (
    protocol: HandlerProtocol,
    recipient: number,
    reason: number,
    description: string,
  ) => void;
  CHANNEL_WINDOW_ADJUST?: (
    protocol: HandlerProtocol,
    recipient: number,
    bytesToAdd: number,
  ) => void;
  CHANNEL_DATA?: (
    protocol: HandlerProtocol,
    recipient: number,
    data: Uint8Array,
  ) => void;
  CHANNEL_EXTENDED_DATA?: (
    protocol: HandlerProtocol,
    recipient: number,
    data: Uint8Array,
    type: number,
  ) => void;
  CHANNEL_EOF?: (protocol: HandlerProtocol, recipient: number) => void;
  CHANNEL_CLOSE?: (protocol: HandlerProtocol, recipient: number) => void;
  CHANNEL_REQUEST?: (
    protocol: HandlerProtocol,
    recipient: number,
    type: string,
    wantReply: boolean,
    data: unknown,
  ) => void;
  CHANNEL_SUCCESS?: (protocol: HandlerProtocol, recipient: number) => void;
  CHANNEL_FAILURE?: (protocol: HandlerProtocol, recipient: number) => void;
}

/**
 * Channel open information
 */
export interface ChannelOpenInfo {
  type: string;
  sender: number;
  window: number;
  packetSize: number;
  data: Record<string, unknown>;
}

/**
 * Channel confirmation information
 */
export interface ChannelConfirmationInfo {
  recipient: number;
  sender: number;
  window: number;
  packetSize: number;
  data?: Uint8Array;
}

/**
 * Message handler function type
 */
export type MessageHandler = (protocol: HandlerProtocol, payload: Uint8Array) => void;

// Helper to safely get string from parser result
function asString(
  val: string | number | Uint8Array | undefined,
): string | undefined {
  if (typeof val === 'string') return val;
  if (val instanceof Uint8Array) return toUtf8(val);
  return undefined;
}

// Helper to safely get Uint8Array from parser result
function asBytes(
  val: string | number | Uint8Array | undefined,
): Uint8Array | undefined {
  if (val instanceof Uint8Array) return val;
  return undefined;
}

/**
 * Create message handlers array
 */
export function createMessageHandlers(): MessageHandler[] {
  const handlers: MessageHandler[] = new Array(256);

  // Transport layer protocol ==================================================

  // DISCONNECT
  handlers[MESSAGE.DISCONNECT] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const reason = parser.readUInt32BE();
    const desc = asString(parser.readString(true));
    const lang = parser.readString();
    parser.clear();

    if (lang === undefined) {
      return doFatalError(self, 'Inbound: Malformed DISCONNECT packet');
    }

    self._debug?.(`Inbound: Received DISCONNECT (${reason}, "${desc}")`);

    const handler = self._handlers.DISCONNECT;
    handler?.(self, reason!, desc!);
  };

  // IGNORE
  handlers[MESSAGE.IGNORE] = (self: HandlerProtocol, _payload: Uint8Array) => {
    self._debug?.('Inbound: Received IGNORE');
  };

  // UNIMPLEMENTED
  handlers[MESSAGE.UNIMPLEMENTED] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const seqno = parser.readUInt32BE();
    parser.clear();

    if (seqno === undefined) {
      return doFatalError(self, 'Inbound: Malformed UNIMPLEMENTED packet');
    }

    self._debug?.(`Inbound: Received UNIMPLEMENTED (seqno ${seqno})`);
  };

  // DEBUG
  handlers[MESSAGE.DEBUG] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const display = parser.readBool();
    const msg = asString(parser.readString(true));
    const lang = parser.readString();
    parser.clear();

    if (lang === undefined) {
      return doFatalError(self, 'Inbound: Malformed DEBUG packet');
    }

    self._debug?.('Inbound: Received DEBUG');

    const handler = self._handlers.DEBUG;
    handler?.(self, display!, msg!);
  };

  // SERVICE_REQUEST
  handlers[MESSAGE.SERVICE_REQUEST] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const name = asString(parser.readString(true));
    parser.clear();

    if (name === undefined) {
      return doFatalError(self, 'Inbound: Malformed SERVICE_REQUEST packet');
    }

    self._debug?.(`Inbound: Received SERVICE_REQUEST (${name})`);

    const handler = self._handlers.SERVICE_REQUEST;
    handler?.(self, name);
  };

  // SERVICE_ACCEPT
  handlers[MESSAGE.SERVICE_ACCEPT] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const name = asString(parser.readString(true));
    parser.clear();

    if (name === undefined) {
      return doFatalError(self, 'Inbound: Malformed SERVICE_ACCEPT packet');
    }

    self._debug?.(`Inbound: Received SERVICE_ACCEPT (${name})`);

    const handler = self._handlers.SERVICE_ACCEPT;
    handler?.(self, name);
  };

  // EXT_INFO
  handlers[MESSAGE.EXT_INFO] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const numExts = parser.readUInt32BE();
    let exts: Array<{ name: string; algs?: string[] }> | undefined;

    if (numExts !== undefined) {
      exts = [];
      for (let i = 0; i < numExts; ++i) {
        const name = asString(parser.readString(true));
        const data = asBytes(parser.readString());
        if (data !== undefined && name !== undefined) {
          switch (name) {
            case 'server-sig-algs': {
              const algs = toUtf8(data).split(',');
              exts.push({ name, algs });
              continue;
            }
            default:
              continue;
          }
        }
        exts = undefined;
        break;
      }
    }
    parser.clear();

    if (exts === undefined) {
      return doFatalError(self, 'Inbound: Malformed EXT_INFO packet');
    }

    self._debug?.('Inbound: Received EXT_INFO');

    const handler = self._handlers.EXT_INFO;
    handler?.(self, exts);
  };

  // User auth protocol -- generic =============================================

  // USERAUTH_REQUEST
  handlers[MESSAGE.USERAUTH_REQUEST] = (
    self: HandlerProtocol,
    payload: Uint8Array,
  ) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const user = asString(parser.readString(true));
    const service = asString(parser.readString(true));
    const method = asString(parser.readString(true));
    let methodData: unknown;
    let methodDesc: string | undefined;

    switch (method) {
      case 'none':
        methodData = null;
        break;
      case 'password': {
        const isChange = parser.readBool();
        if (isChange !== undefined) {
          methodData = asString(parser.readString(true));
          if (methodData !== undefined && isChange) {
            const newPassword = asString(parser.readString(true));
            if (newPassword !== undefined) {
              methodData = { oldPassword: methodData, newPassword };
            } else {
              methodData = undefined;
            }
          }
        }
        break;
      }
      case 'publickey': {
        const hasSig = parser.readBool();
        if (hasSig !== undefined) {
          const keyAlgo = asString(parser.readString(true));
          let realKeyAlgo = keyAlgo;
          const key = asBytes(parser.readString());

          let hashAlgo: string | undefined;
          switch (keyAlgo) {
            case 'rsa-sha2-256':
              realKeyAlgo = 'ssh-rsa';
              hashAlgo = 'sha256';
              break;
            case 'rsa-sha2-512':
              realKeyAlgo = 'ssh-rsa';
              hashAlgo = 'sha512';
              break;
          }

          if (hasSig) {
            const blobEnd = parser.pos();
            let signature = asBytes(parser.readString());
            if (signature !== undefined && keyAlgo !== undefined) {
              if (
                signature.length > 4 + keyAlgo.length + 4 &&
                toUtf8(signature.subarray(4, 4 + keyAlgo.length)) === keyAlgo
              ) {
                signature = signature.subarray(4 + keyAlgo.length + 4);
              }

              const convertedSig = sigSSHToASN1(signature, realKeyAlgo!);
              if (convertedSig) {
                const sessionID = self._kex.sessionID;
                const blob = allocBytes(4 + sessionID.length + blobEnd);
                writeUInt32BE(blob, sessionID.length, 0);
                blob.set(sessionID, 4);
                blob.set(payload.subarray(0, blobEnd), 4 + sessionID.length);
                methodData = {
                  keyAlgo: realKeyAlgo,
                  key,
                  signature: convertedSig,
                  blob,
                  hashAlgo,
                };
              }
            }
          } else {
            methodData = { keyAlgo: realKeyAlgo, key, hashAlgo };
            methodDesc = 'publickey -- check';
          }
        }
        break;
      }
      case 'hostbased': {
        const keyAlgo = asString(parser.readString(true));
        let realKeyAlgo = keyAlgo;
        const key = asBytes(parser.readString());
        const localHostname = asString(parser.readString(true));
        const localUsername = asString(parser.readString(true));

        let hashAlgo: string | undefined;
        switch (keyAlgo) {
          case 'rsa-sha2-256':
            realKeyAlgo = 'ssh-rsa';
            hashAlgo = 'sha256';
            break;
          case 'rsa-sha2-512':
            realKeyAlgo = 'ssh-rsa';
            hashAlgo = 'sha512';
            break;
        }

        const blobEnd = parser.pos();
        let signature = asBytes(parser.readString());
        if (signature !== undefined && keyAlgo !== undefined) {
          if (
            signature.length > 4 + keyAlgo.length + 4 &&
            toUtf8(signature.subarray(4, 4 + keyAlgo.length)) === keyAlgo
          ) {
            signature = signature.subarray(4 + keyAlgo.length + 4);
          }

          const convertedSig = sigSSHToASN1(signature, realKeyAlgo!);
          if (convertedSig !== undefined) {
            const sessionID = self._kex.sessionID;
            const blob = allocBytes(4 + sessionID.length + blobEnd);
            writeUInt32BE(blob, sessionID.length, 0);
            blob.set(sessionID, 4);
            blob.set(payload.subarray(0, blobEnd), 4 + sessionID.length);
            methodData = {
              keyAlgo: realKeyAlgo,
              key,
              signature: convertedSig,
              blob,
              localHostname,
              localUsername,
              hashAlgo,
            };
          }
        }
        break;
      }
      case 'keyboard-interactive':
        parser.skipString();
        methodData = parser.readList();
        break;
      default:
        if (method !== undefined) {
          methodData = parser.readRaw();
        }
    }
    parser.clear();

    if (methodData === undefined) {
      return doFatalError(self, 'Inbound: Malformed USERAUTH_REQUEST packet');
    }

    if (methodDesc === undefined) {
      methodDesc = method;
    }

    self._authsQueue.push(method!);

    self._debug?.(`Inbound: Received USERAUTH_REQUEST (${methodDesc})`);

    const handler = self._handlers.USERAUTH_REQUEST;
    handler?.(self, user!, service!, method!, methodData);
  };

  // USERAUTH_FAILURE
  handlers[MESSAGE.USERAUTH_FAILURE] = (
    self: HandlerProtocol,
    payload: Uint8Array,
  ) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const authMethods = parser.readList();
    const partialSuccess = parser.readBool();
    parser.clear();

    if (partialSuccess === undefined) {
      return doFatalError(self, 'Inbound: Malformed USERAUTH_FAILURE packet');
    }

    self._debug?.(`Inbound: Received USERAUTH_FAILURE (${authMethods})`);

    self._authsQueue.shift();
    const handler = self._handlers.USERAUTH_FAILURE;
    handler?.(self, authMethods!, partialSuccess);
  };

  // USERAUTH_SUCCESS
  handlers[MESSAGE.USERAUTH_SUCCESS] = (
    self: HandlerProtocol,
    _payload: Uint8Array,
  ) => {
    self._debug?.('Inbound: Received USERAUTH_SUCCESS');

    self._authsQueue.shift();

    // Enable compression after auth success (for 'zlib@openssh.com')
    // deno-lint-ignore no-explicit-any
    (self as any).enableCompression?.();

    const handler = self._handlers.USERAUTH_SUCCESS;
    handler?.(self);
  };

  // USERAUTH_BANNER
  handlers[MESSAGE.USERAUTH_BANNER] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const msg = asString(parser.readString(true));
    const lang = parser.readString();
    parser.clear();

    if (lang === undefined) {
      return doFatalError(self, 'Inbound: Malformed USERAUTH_BANNER packet');
    }

    self._debug?.('Inbound: Received USERAUTH_BANNER');

    const handler = self._handlers.USERAUTH_BANNER;
    handler?.(self, msg!);
  };

  // User auth protocol -- method-specific =====================================

  // Type 60 - context-dependent based on auth method
  handlers[60] = (self: HandlerProtocol, payload: Uint8Array) => {
    if (!self._authsQueue.length) {
      self._debug?.('Inbound: Received payload type 60 without auth');
      return;
    }

    const parser = makeBufferParser();

    switch (self._authsQueue[0]) {
      case 'password': {
        parser.init(payload, 1);
        const prompt = asString(parser.readString(true));
        const lang = parser.readString();
        parser.clear();

        if (lang === undefined) {
          return doFatalError(
            self,
            'Inbound: Malformed USERAUTH_PASSWD_CHANGEREQ packet',
          );
        }

        self._debug?.('Inbound: Received USERAUTH_PASSWD_CHANGEREQ');

        const handler = self._handlers.USERAUTH_PASSWD_CHANGEREQ;
        handler?.(self, prompt!);
        break;
      }
      case 'publickey': {
        parser.init(payload, 1);
        const keyAlgo = asString(parser.readString(true));
        const key = asBytes(parser.readString());
        parser.clear();

        if (key === undefined) {
          return doFatalError(self, 'Inbound: Malformed USERAUTH_PK_OK packet');
        }

        self._debug?.('Inbound: Received USERAUTH_PK_OK');

        self._authsQueue.shift();
        const handler = self._handlers.USERAUTH_PK_OK;
        handler?.(self, keyAlgo!, key);
        break;
      }
      case 'keyboard-interactive': {
        parser.init(payload, 1);
        const name = asString(parser.readString(true));
        const instructions = asString(parser.readString(true));
        parser.readString(); // skip lang
        const numPrompts = parser.readUInt32BE();
        let prompts: Array<{ prompt: string; echo: boolean }> | undefined;

        if (numPrompts !== undefined) {
          prompts = new Array(numPrompts);
          let i;
          for (i = 0; i < numPrompts; ++i) {
            const prompt = asString(parser.readString(true));
            const echo = parser.readBool();
            if (echo === undefined || prompt === undefined) break;
            prompts[i] = { prompt, echo };
          }
          if (i !== numPrompts) prompts = undefined;
        }
        parser.clear();

        if (prompts === undefined) {
          return doFatalError(
            self,
            'Inbound: Malformed USERAUTH_INFO_REQUEST packet',
          );
        }

        self._debug?.('Inbound: Received USERAUTH_INFO_REQUEST');

        const handler = self._handlers.USERAUTH_INFO_REQUEST;
        handler?.(self, name!, instructions!, prompts);
        break;
      }
      default:
        self._debug?.('Inbound: Received unexpected payload type 60');
    }
  };

  // Type 61 - USERAUTH_INFO_RESPONSE (keyboard-interactive)
  handlers[61] = (self: HandlerProtocol, payload: Uint8Array) => {
    if (!self._authsQueue.length) {
      self._debug?.('Inbound: Received payload type 61 without auth');
      return;
    }

    if (self._authsQueue[0] !== 'keyboard-interactive') {
      return doFatalError(
        self,
        'Inbound: Received unexpected payload type 61',
      );
    }

    const parser = makeBufferParser();
    parser.init(payload, 1);
    const numResponses = parser.readUInt32BE();
    let responses: string[] | undefined;

    if (numResponses !== undefined) {
      responses = new Array(numResponses);
      let i;
      for (i = 0; i < numResponses; ++i) {
        const response = asString(parser.readString(true));
        if (response === undefined) break;
        responses[i] = response;
      }
      if (i !== numResponses) responses = undefined;
    }
    parser.clear();

    if (responses === undefined) {
      return doFatalError(
        self,
        'Inbound: Malformed USERAUTH_INFO_RESPONSE packet',
      );
    }

    self._debug?.('Inbound: Received USERAUTH_INFO_RESPONSE');

    const handler = self._handlers.USERAUTH_INFO_RESPONSE;
    handler?.(self, responses);
  };

  // Connection protocol -- generic ============================================

  // GLOBAL_REQUEST
  handlers[MESSAGE.GLOBAL_REQUEST] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const name = asString(parser.readString(true));
    const wantReply = parser.readBool();
    let data: unknown;

    if (wantReply !== undefined) {
      switch (name) {
        case 'tcpip-forward':
        case 'cancel-tcpip-forward': {
          const bindAddr = asString(parser.readString(true));
          const bindPort = parser.readUInt32BE();
          if (bindPort !== undefined) {
            data = { bindAddr, bindPort };
          }
          break;
        }
        case 'streamlocal-forward@openssh.com':
        case 'cancel-streamlocal-forward@openssh.com': {
          const socketPath = asString(parser.readString(true));
          if (socketPath !== undefined) {
            data = { socketPath };
          }
          break;
        }
        case 'no-more-sessions@openssh.com':
          data = null;
          break;
        case 'hostkeys-00@openssh.com': {
          data = [];
          while (parser.avail() > 0) {
            const keyRaw = asBytes(parser.readString());
            if (keyRaw === undefined) {
              data = undefined;
              break;
            }
            const key = parseKey(keyRaw);
            if (!(key instanceof Error)) {
              (data as unknown[]).push(key);
            }
          }
          break;
        }
        default:
          data = parser.readRaw();
      }
    }
    parser.clear();

    if (data === undefined) {
      return doFatalError(self, 'Inbound: Malformed GLOBAL_REQUEST packet');
    }

    self._debug?.(`Inbound: GLOBAL_REQUEST (${name})`);

    const handler = self._handlers.GLOBAL_REQUEST;
    if (handler) {
      handler(self, name!, wantReply!, data);
    } else {
      self.requestFailure();
    }
  };

  // REQUEST_SUCCESS
  handlers[MESSAGE.REQUEST_SUCCESS] = (self: HandlerProtocol, payload: Uint8Array) => {
    const data = payload.length > 1 ? payload.subarray(1) : null;

    self._debug?.('Inbound: REQUEST_SUCCESS');

    const handler = self._handlers.REQUEST_SUCCESS;
    handler?.(self, data);
  };

  // REQUEST_FAILURE
  handlers[MESSAGE.REQUEST_FAILURE] = (
    self: HandlerProtocol,
    _payload: Uint8Array,
  ) => {
    self._debug?.('Inbound: Received REQUEST_FAILURE');

    const handler = self._handlers.REQUEST_FAILURE;
    handler?.(self);
  };

  // Connection protocol -- channel-related ====================================

  // CHANNEL_OPEN
  handlers[MESSAGE.CHANNEL_OPEN] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const type = asString(parser.readString(true));
    const sender = parser.readUInt32BE();
    const window = parser.readUInt32BE();
    const packetSize = parser.readUInt32BE();
    let channelInfo: ChannelOpenInfo | undefined;

    switch (type) {
      case 'forwarded-tcpip':
      case 'direct-tcpip': {
        const destIP = asString(parser.readString(true));
        const destPort = parser.readUInt32BE();
        const srcIP = asString(parser.readString(true));
        const srcPort = parser.readUInt32BE();
        if (srcPort !== undefined) {
          channelInfo = {
            type: type!,
            sender: sender!,
            window: window!,
            packetSize: packetSize!,
            data: { destIP, destPort, srcIP, srcPort },
          };
        }
        break;
      }
      case 'forwarded-streamlocal@openssh.com':
      case 'direct-streamlocal@openssh.com': {
        const socketPath = asString(parser.readString(true));
        if (socketPath !== undefined) {
          channelInfo = {
            type: type!,
            sender: sender!,
            window: window!,
            packetSize: packetSize!,
            data: { socketPath },
          };
        }
        break;
      }
      case 'x11': {
        const srcIP = asString(parser.readString(true));
        const srcPort = parser.readUInt32BE();
        if (srcPort !== undefined) {
          channelInfo = {
            type: type!,
            sender: sender!,
            window: window!,
            packetSize: packetSize!,
            data: { srcIP, srcPort },
          };
        }
        break;
      }
      default:
        if (type !== undefined) {
          channelInfo = {
            type,
            sender: sender!,
            window: window!,
            packetSize: packetSize!,
            data: {},
          };
        }
    }
    parser.clear();

    if (channelInfo === undefined) {
      return doFatalError(self, 'Inbound: Malformed CHANNEL_OPEN packet');
    }

    self._debug?.(`Inbound: CHANNEL_OPEN (s:${sender}, ${type})`);

    const handler = self._handlers.CHANNEL_OPEN;
    if (handler) {
      handler(self, channelInfo);
    } else {
      self.channelOpenFail(
        channelInfo.sender,
        CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED,
        '',
        '',
      );
    }
  };

  // CHANNEL_OPEN_CONFIRMATION
  handlers[MESSAGE.CHANNEL_OPEN_CONFIRMATION] = (
    self: HandlerProtocol,
    payload: Uint8Array,
  ) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const recipient = parser.readUInt32BE();
    const sender = parser.readUInt32BE();
    const window = parser.readUInt32BE();
    const packetSize = parser.readUInt32BE();
    const data = parser.avail() ? parser.readRaw() : undefined;
    parser.clear();

    if (packetSize === undefined) {
      return doFatalError(
        self,
        'Inbound: Malformed CHANNEL_OPEN_CONFIRMATION packet',
      );
    }

    self._debug?.(
      `Inbound: CHANNEL_OPEN_CONFIRMATION (r:${recipient}, s:${sender})`,
    );

    const handler = self._handlers.CHANNEL_OPEN_CONFIRMATION;
    handler?.(self, {
      recipient: recipient!,
      sender: sender!,
      window: window!,
      packetSize,
      data,
    });
  };

  // CHANNEL_OPEN_FAILURE
  handlers[MESSAGE.CHANNEL_OPEN_FAILURE] = (
    self: HandlerProtocol,
    payload: Uint8Array,
  ) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const recipient = parser.readUInt32BE();
    const reason = parser.readUInt32BE();
    const description = asString(parser.readString(true));
    const lang = parser.readString();
    parser.clear();

    if (lang === undefined) {
      return doFatalError(
        self,
        'Inbound: Malformed CHANNEL_OPEN_FAILURE packet',
      );
    }

    self._debug?.(`Inbound: CHANNEL_OPEN_FAILURE (r:${recipient})`);

    const handler = self._handlers.CHANNEL_OPEN_FAILURE;
    handler?.(self, recipient!, reason!, description!);
  };

  // CHANNEL_WINDOW_ADJUST
  handlers[MESSAGE.CHANNEL_WINDOW_ADJUST] = (
    self: HandlerProtocol,
    payload: Uint8Array,
  ) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const recipient = parser.readUInt32BE();
    const bytesToAdd = parser.readUInt32BE();
    parser.clear();

    if (bytesToAdd === undefined) {
      return doFatalError(
        self,
        'Inbound: Malformed CHANNEL_WINDOW_ADJUST packet',
      );
    }

    self._debug?.(
      `Inbound: CHANNEL_WINDOW_ADJUST (r:${recipient}, ${bytesToAdd})`,
    );

    const handler = self._handlers.CHANNEL_WINDOW_ADJUST;
    handler?.(self, recipient!, bytesToAdd);
  };

  // CHANNEL_DATA
  handlers[MESSAGE.CHANNEL_DATA] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const recipient = parser.readUInt32BE();
    const data = asBytes(parser.readString());
    parser.clear();

    if (data === undefined) {
      return doFatalError(self, 'Inbound: Malformed CHANNEL_DATA packet');
    }

    self._debug?.(`Inbound: CHANNEL_DATA (r:${recipient}, ${data.length})`);

    const handler = self._handlers.CHANNEL_DATA;
    handler?.(self, recipient!, data);
  };

  // CHANNEL_EXTENDED_DATA
  handlers[MESSAGE.CHANNEL_EXTENDED_DATA] = (
    self: HandlerProtocol,
    payload: Uint8Array,
  ) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const recipient = parser.readUInt32BE();
    const type = parser.readUInt32BE();
    const data = asBytes(parser.readString());
    parser.clear();

    if (data === undefined) {
      return doFatalError(
        self,
        'Inbound: Malformed CHANNEL_EXTENDED_DATA packet',
      );
    }

    self._debug?.(
      `Inbound: CHANNEL_EXTENDED_DATA (r:${recipient}, ${data.length})`,
    );

    const handler = self._handlers.CHANNEL_EXTENDED_DATA;
    handler?.(self, recipient!, data, type!);
  };

  // CHANNEL_EOF
  handlers[MESSAGE.CHANNEL_EOF] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const recipient = parser.readUInt32BE();
    parser.clear();

    if (recipient === undefined) {
      return doFatalError(self, 'Inbound: Malformed CHANNEL_EOF packet');
    }

    self._debug?.(`Inbound: CHANNEL_EOF (r:${recipient})`);

    const handler = self._handlers.CHANNEL_EOF;
    handler?.(self, recipient);
  };

  // CHANNEL_CLOSE
  handlers[MESSAGE.CHANNEL_CLOSE] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const recipient = parser.readUInt32BE();
    parser.clear();

    if (recipient === undefined) {
      return doFatalError(self, 'Inbound: Malformed CHANNEL_CLOSE packet');
    }

    self._debug?.(`Inbound: CHANNEL_CLOSE (r:${recipient})`);

    const handler = self._handlers.CHANNEL_CLOSE;
    handler?.(self, recipient);
  };

  // CHANNEL_REQUEST
  handlers[MESSAGE.CHANNEL_REQUEST] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const recipient = parser.readUInt32BE();
    const type = asString(parser.readString(true));
    const wantReply = parser.readBool();
    let data: unknown;

    if (wantReply !== undefined) {
      switch (type) {
        case 'exit-status':
          data = parser.readUInt32BE();
          self._debug?.(
            `Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${data})`,
          );
          break;
        case 'exit-signal': {
          let signal: string | undefined;
          let coreDumped: boolean | undefined;
          if (self._compatFlags & COMPAT.OLD_EXIT) {
            const num = parser.readUInt32BE();
            switch (num) {
              case 1:
                signal = 'HUP';
                break;
              case 2:
                signal = 'INT';
                break;
              case 3:
                signal = 'QUIT';
                break;
              case 6:
                signal = 'ABRT';
                break;
              case 9:
                signal = 'KILL';
                break;
              case 14:
                signal = 'ALRM';
                break;
              case 15:
                signal = 'TERM';
                break;
              default:
                if (num !== undefined) {
                  signal = `UNKNOWN (${num})`;
                }
            }
            coreDumped = false;
          } else {
            signal = asString(parser.readString(true));
            coreDumped = parser.readBool();
            if (coreDumped === undefined) signal = undefined;
          }
          const errorMessage = asString(parser.readString(true));
          if (parser.skipString() !== undefined) {
            data = { signal, coreDumped, errorMessage };
          }
          self._debug?.(
            `Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${signal})`,
          );
          break;
        }
        case 'pty-req': {
          const term = asString(parser.readString(true));
          const cols = parser.readUInt32BE();
          const rows = parser.readUInt32BE();
          const width = parser.readUInt32BE();
          const height = parser.readUInt32BE();
          const modesBinary = asBytes(parser.readString());
          if (modesBinary !== undefined) {
            parser.init(modesBinary, 0);
            let modes: Record<string, number> | undefined = {};
            while (parser.avail()) {
              const opcode = parser.readByte();
              if (opcode === TERMINAL_MODE.TTY_OP_END) break;
              const modeName = TERMINAL_MODE_BY_VALUE[opcode!];
              const value = parser.readUInt32BE();
              if (
                opcode === undefined ||
                modeName === undefined ||
                value === undefined
              ) {
                modes = undefined;
                break;
              }
              modes[modeName] = value;
            }
            if (modes !== undefined) {
              data = { term, cols, rows, width, height, modes };
            }
          }
          self._debug?.(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
          break;
        }
        case 'window-change': {
          const cols = parser.readUInt32BE();
          const rows = parser.readUInt32BE();
          const width = parser.readUInt32BE();
          const height = parser.readUInt32BE();
          if (height !== undefined) {
            data = { cols, rows, width, height };
          }
          self._debug?.(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
          break;
        }
        case 'x11-req': {
          const single = parser.readBool();
          const protocol = asString(parser.readString(true));
          const cookie = asBytes(parser.readString());
          const screen = parser.readUInt32BE();
          if (screen !== undefined) {
            data = { single, protocol, cookie, screen };
          }
          self._debug?.(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
          break;
        }
        case 'env': {
          const envName = asString(parser.readString(true));
          const value = asString(parser.readString(true));
          if (value !== undefined) {
            data = { name: envName, value };
          }
          self._debug?.(
            `Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${envName}=${value})`,
          );
          break;
        }
        case 'shell':
          data = null;
          self._debug?.(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
          break;
        case 'exec':
          data = asString(parser.readString(true));
          self._debug?.(
            `Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${data})`,
          );
          break;
        case 'subsystem':
          data = asString(parser.readString(true));
          self._debug?.(
            `Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${data})`,
          );
          break;
        case 'signal':
          data = asString(parser.readString(true));
          self._debug?.(
            `Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${data})`,
          );
          break;
        case 'xon-xoff':
          data = parser.readBool();
          self._debug?.(
            `Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${data})`,
          );
          break;
        case 'auth-agent-req@openssh.com':
          data = null;
          self._debug?.(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
          break;
        default:
          data = parser.avail() ? parser.readRaw() : null;
          self._debug?.(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
      }
    }
    parser.clear();

    if (data === undefined) {
      return doFatalError(self, 'Inbound: Malformed CHANNEL_REQUEST packet');
    }

    const handler = self._handlers.CHANNEL_REQUEST;
    handler?.(self, recipient!, type!, wantReply!, data);
  };

  // CHANNEL_SUCCESS
  handlers[MESSAGE.CHANNEL_SUCCESS] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const recipient = parser.readUInt32BE();
    parser.clear();

    if (recipient === undefined) {
      return doFatalError(self, 'Inbound: Malformed CHANNEL_SUCCESS packet');
    }

    self._debug?.(`Inbound: CHANNEL_SUCCESS (r:${recipient})`);

    const handler = self._handlers.CHANNEL_SUCCESS;
    handler?.(self, recipient);
  };

  // CHANNEL_FAILURE
  handlers[MESSAGE.CHANNEL_FAILURE] = (self: HandlerProtocol, payload: Uint8Array) => {
    const parser = makeBufferParser();
    parser.init(payload, 1);
    const recipient = parser.readUInt32BE();
    parser.clear();

    if (recipient === undefined) {
      return doFatalError(self, 'Inbound: Malformed CHANNEL_FAILURE packet');
    }

    self._debug?.(`Inbound: CHANNEL_FAILURE (r:${recipient})`);

    const handler = self._handlers.CHANNEL_FAILURE;
    handler?.(self, recipient);
  };

  return handlers;
}

/** Indexed array of handler functions for each SSH message type. */
export const MESSAGE_HANDLERS: MessageHandler[] = createMessageHandlers();
