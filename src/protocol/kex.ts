/**
 * SSH Key Exchange Protocol Handler
 *
 * Handles the SSH key exchange process including:
 * - KEXINIT message generation and parsing
 * - Algorithm negotiation
 * - Key exchange execution
 * - Session key derivation
 */

import { hash } from '../crypto/hash.ts';
import { createKeyExchange, type KeyExchange, type KeyExchangeResult } from '../crypto/kex.ts';
import { randomBytes } from '../crypto/random.ts';
import { allocBytes, concatBytes, fromString, writeUInt32BE } from '../utils/binary.ts';
import {
  CIPHER_INFO,
  DEFAULT_CIPHER,
  DEFAULT_COMPRESSION,
  DEFAULT_KEX,
  DEFAULT_MAC,
  DEFAULT_SERVER_HOST_KEY,
  MAC_INFO,
  MESSAGE,
} from './constants.ts';
import { makeBufferParser } from './utils.ts';

// Constants
const GEX_MIN_BITS = 2048; // RFC 8270
const GEX_MAX_BITS = 8192; // RFC 8270

/**
 * Encode a byte array as an SSH mpint (used for shared secret in key derivation)
 * Per RFC 4253, the shared secret K must be encoded as mpint for key derivation
 */
function writeMpint(data: Uint8Array): Uint8Array {
  // Strip leading zeros
  let start = 0;
  while (start < data.length && data[start] === 0) {
    start++;
  }

  // Add leading zero if MSB is set (to indicate positive number)
  const needsZero = start < data.length && (data[start] & 0x80) !== 0;
  const len = data.length - start + (needsZero ? 1 : 0);

  const buf = allocBytes(4 + len);
  writeUInt32BE(buf, len, 0);

  if (needsZero) {
    buf[4] = 0;
    buf.set(data.subarray(start), 5);
  } else {
    buf.set(data.subarray(start), 4);
  }

  return buf;
}

/**
 * Algorithm lists for key exchange
 */
export interface KexAlgorithms {
  kex: string[];
  serverHostKey: string[];
  cs: {
    cipher: string[];
    mac: string[];
    compress: string[];
    lang: string[];
  };
  sc: {
    cipher: string[];
    mac: string[];
    compress: string[];
    lang: string[];
  };
}

/**
 * Negotiated algorithms after KEXINIT exchange
 */
export interface NegotiatedAlgorithms {
  kex: string;
  serverHostKey: string;
  cs: {
    cipher: string;
    mac: string;
    compress: string;
  };
  sc: {
    cipher: string;
    mac: string;
    compress: string;
  };
}

/**
 * Session keys derived from key exchange
 */
export interface SessionKeys {
  ivC2S: Uint8Array; // Client to server IV
  ivS2C: Uint8Array; // Server to client IV
  keyC2S: Uint8Array; // Client to server encryption key
  keyS2C: Uint8Array; // Server to client encryption key
  macKeyC2S: Uint8Array; // Client to server MAC key
  macKeyS2C: Uint8Array; // Server to client MAC key
}

/**
 * Key exchange state
 */
export interface KexState {
  kexinit?: Uint8Array;
  remoteKexinit?: Uint8Array;
  algorithms?: NegotiatedAlgorithms;
  exchange?: KeyExchange;
  exchangeResult?: KeyExchangeResult;
  sharedSecret?: Uint8Array;
  exchangeHash?: Uint8Array;
  sessionId?: Uint8Array;
}

/**
 * Create default algorithm offer
 */
export function createDefaultOffer(): KexAlgorithms {
  return {
    kex: [...DEFAULT_KEX],
    serverHostKey: [...DEFAULT_SERVER_HOST_KEY],
    cs: {
      cipher: [...DEFAULT_CIPHER],
      mac: [...DEFAULT_MAC],
      compress: [...DEFAULT_COMPRESSION],
      lang: [],
    },
    sc: {
      cipher: [...DEFAULT_CIPHER],
      mac: [...DEFAULT_MAC],
      compress: [...DEFAULT_COMPRESSION],
      lang: [],
    },
  };
}

/**
 * Build a KEXINIT message
 */
export function buildKexInit(offer: KexAlgorithms): Uint8Array {
  const encoder = new TextEncoder();

  // Calculate total size
  const lists = [
    offer.kex.join(','),
    offer.serverHostKey.join(','),
    offer.cs.cipher.join(','),
    offer.sc.cipher.join(','),
    offer.cs.mac.join(','),
    offer.sc.mac.join(','),
    offer.cs.compress.join(','),
    offer.sc.compress.join(','),
    offer.cs.lang.join(','),
    offer.sc.lang.join(','),
  ];

  let totalSize = 1 + 16; // message type + cookie
  for (const list of lists) {
    totalSize += 4 + encoder.encode(list).length;
  }
  totalSize += 1 + 4; // first_kex_packet_follows + reserved

  const payload = allocBytes(totalSize);
  let offset = 0;

  // Message type
  payload[offset++] = MESSAGE.KEXINIT;

  // Random cookie
  const cookie = randomBytes(16);
  payload.set(cookie, offset);
  offset += 16;

  // Write each name-list
  for (const list of lists) {
    const encoded = encoder.encode(list);
    writeUInt32BE(payload, encoded.length, offset);
    offset += 4;
    payload.set(encoded, offset);
    offset += encoded.length;
  }

  // first_kex_packet_follows = false
  payload[offset++] = 0;

  // reserved (uint32 = 0)
  writeUInt32BE(payload, 0, offset);

  return payload;
}

/**
 * Parse a KEXINIT message
 */
export function parseKexInit(payload: Uint8Array): KexAlgorithms | Error {
  const parser = makeBufferParser();
  parser.init(payload, 17); // Skip message type and cookie

  const kex = parser.readList();
  const serverHostKey = parser.readList();
  const csCipher = parser.readList();
  const scCipher = parser.readList();
  const csMac = parser.readList();
  const scMac = parser.readList();
  const csCompress = parser.readList();
  const scCompress = parser.readList();
  const csLang = parser.readList();
  const scLang = parser.readList();

  parser.clear();

  if (
    !kex ||
    !serverHostKey ||
    !csCipher ||
    !scCipher ||
    !csMac ||
    !scMac ||
    !csCompress ||
    !scCompress ||
    !csLang ||
    !scLang
  ) {
    return new Error('Malformed KEXINIT message');
  }

  return {
    kex,
    serverHostKey,
    cs: {
      cipher: csCipher,
      mac: csMac,
      compress: csCompress,
      lang: csLang,
    },
    sc: {
      cipher: scCipher,
      mac: scMac,
      compress: scCompress,
      lang: scLang,
    },
  };
}

/**
 * Negotiate algorithms between local and remote offers
 */
export function negotiateAlgorithms(
  local: KexAlgorithms,
  remote: KexAlgorithms,
  isServer: boolean,
): NegotiatedAlgorithms | Error {
  // Helper to find first matching algorithm
  function negotiate(localList: string[], remoteList: string[]): string | null {
    // Client's list has preference
    const preferred = isServer ? remoteList : localList;
    const other = isServer ? localList : remoteList;

    for (const algo of preferred) {
      if (other.includes(algo)) {
        return algo;
      }
    }
    return null;
  }

  const kex = negotiate(local.kex, remote.kex);
  if (!kex) {
    return new Error('No matching key exchange algorithm');
  }

  const serverHostKey = negotiate(local.serverHostKey, remote.serverHostKey);
  if (!serverHostKey) {
    return new Error('No matching server host key algorithm');
  }

  const csCipher = negotiate(local.cs.cipher, remote.cs.cipher);
  if (!csCipher) {
    return new Error('No matching client-to-server cipher');
  }

  const scCipher = negotiate(local.sc.cipher, remote.sc.cipher);
  if (!scCipher) {
    return new Error('No matching server-to-client cipher');
  }

  const csMac = negotiate(local.cs.mac, remote.cs.mac);
  if (!csMac) {
    return new Error('No matching client-to-server MAC');
  }

  const scMac = negotiate(local.sc.mac, remote.sc.mac);
  if (!scMac) {
    return new Error('No matching server-to-client MAC');
  }

  const csCompress = negotiate(local.cs.compress, remote.cs.compress);
  if (!csCompress) {
    return new Error('No matching client-to-server compression');
  }

  const scCompress = negotiate(local.sc.compress, remote.sc.compress);
  if (!scCompress) {
    return new Error('No matching server-to-client compression');
  }

  return {
    kex,
    serverHostKey,
    cs: {
      cipher: csCipher,
      mac: csMac,
      compress: csCompress,
    },
    sc: {
      cipher: scCipher,
      mac: scMac,
      compress: scCompress,
    },
  };
}

/**
 * Get the hash algorithm for a key exchange method
 */
export function getKexHashAlgorithm(kexAlgo: string): string {
  if (kexAlgo.includes('sha512')) return 'sha512';
  if (kexAlgo.includes('sha384')) return 'sha384';
  if (kexAlgo.includes('sha256')) return 'sha256';
  if (kexAlgo.includes('sha1')) return 'sha1';
  // Default based on algorithm
  if (kexAlgo.includes('curve25519')) return 'sha256';
  if (kexAlgo.includes('nistp256')) return 'sha256';
  if (kexAlgo.includes('nistp384')) return 'sha384';
  if (kexAlgo.includes('nistp521')) return 'sha512';
  return 'sha256';
}

/**
 * Derive session keys from shared secret and exchange hash
 *
 * Key derivation follows RFC 4253 Section 7.2
 */
export async function deriveSessionKeys(
  sharedSecret: Uint8Array,
  exchangeHash: Uint8Array,
  sessionId: Uint8Array,
  algorithms: NegotiatedAlgorithms,
): Promise<SessionKeys> {
  const hashAlgo = getKexHashAlgorithm(algorithms.kex);

  // Per RFC 4253 Section 7.2, K (shared secret) must be encoded as mpint for key derivation
  const K = writeMpint(sharedSecret);

  // Get required key/IV sizes from cipher info
  const csCipherInfo = CIPHER_INFO[algorithms.cs.cipher as keyof typeof CIPHER_INFO];
  const scCipherInfo = CIPHER_INFO[algorithms.sc.cipher as keyof typeof CIPHER_INFO];
  const csMacInfo = MAC_INFO[algorithms.cs.mac as keyof typeof MAC_INFO];
  const scMacInfo = MAC_INFO[algorithms.sc.mac as keyof typeof MAC_INFO];

  // Default sizes if not found
  const csIvLen = csCipherInfo?.ivLen ?? 16;
  const scIvLen = scCipherInfo?.ivLen ?? 16;
  const csKeyLen = csCipherInfo?.keyLen ?? 32;
  const scKeyLen = scCipherInfo?.keyLen ?? 32;
  const csMacKeyLen = csMacInfo?.len ?? 32;
  const scMacKeyLen = scMacInfo?.len ?? 32;

  // Derive each key using HASH(K || H || X || session_id)
  // where X is a single character 'A', 'B', 'C', 'D', 'E', or 'F'
  async function deriveKey(char: string, length: number): Promise<Uint8Array> {
    const charByte = fromString(char);

    // Initial derivation: HASH(K || H || X || session_id)
    const input1 = concatBytes([K, exchangeHash, charByte, sessionId]);
    let key = await hash(hashAlgo, input1);

    // Extend key if necessary: HASH(K || H || K1)
    // Per RFC 4253: K2 = HASH(K || H || K1), K3 = HASH(K || H || K1 || K2), etc.
    while (key.length < length) {
      const inputN = concatBytes([K, exchangeHash, key]);
      const extension = await hash(hashAlgo, inputN);
      key = concatBytes([key, extension]);
    }

    // Return a copy, not a view, to avoid shared underlying buffers
    return new Uint8Array(key.subarray(0, length));
  }

  const result = {
    ivC2S: await deriveKey('A', csIvLen),
    ivS2C: await deriveKey('B', scIvLen),
    keyC2S: await deriveKey('C', csKeyLen),
    keyS2C: await deriveKey('D', scKeyLen),
    macKeyC2S: await deriveKey('E', csMacKeyLen),
    macKeyS2C: await deriveKey('F', scMacKeyLen),
  };

  return result;
}

/**
 * Build exchange hash input for DH/ECDH key exchange
 *
 * The exchange hash H is computed as:
 * H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
 *
 * Where:
 * - V_C, V_S are client/server version strings
 * - I_C, I_S are client/server KEXINIT payloads
 * - K_S is the server's host key
 * - e, f are the client/server DH public values
 * - K is the shared secret
 */
export function buildExchangeHashInput(
  clientVersion: string,
  serverVersion: string,
  clientKexinit: Uint8Array,
  serverKexinit: Uint8Array,
  serverHostKey: Uint8Array,
  clientPublic: Uint8Array,
  serverPublic: Uint8Array,
  sharedSecret: Uint8Array,
): Uint8Array {
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];

  // Helper to write string with length prefix
  function writeString(str: string): Uint8Array {
    const encoded = encoder.encode(str);
    const buf = allocBytes(4 + encoded.length);
    writeUInt32BE(buf, encoded.length, 0);
    buf.set(encoded, 4);
    return buf;
  }

  // Helper to write binary data with length prefix
  function writeBinary(data: Uint8Array): Uint8Array {
    const buf = allocBytes(4 + data.length);
    writeUInt32BE(buf, data.length, 0);
    buf.set(data, 4);
    return buf;
  }

  // Note: writeMpint is defined at module level

  const vcBin = writeString(clientVersion);
  const vsBin = writeString(serverVersion);
  const icBin = writeBinary(clientKexinit);
  const isBin = writeBinary(serverKexinit);
  const ksBin = writeBinary(serverHostKey);
  const qcBin = writeBinary(clientPublic);
  const qsBin = writeBinary(serverPublic);
  const kBin = writeMpint(sharedSecret);

  parts.push(vcBin);
  parts.push(vsBin);
  parts.push(icBin);
  parts.push(isBin);
  parts.push(ksBin);
  parts.push(qcBin);
  parts.push(qsBin);
  parts.push(kBin);

  return concatBytes(parts);
}

/**
 * Compute the exchange hash
 */
export async function computeExchangeHash(
  hashAlgo: string,
  clientVersion: string,
  serverVersion: string,
  clientKexinit: Uint8Array,
  serverKexinit: Uint8Array,
  serverHostKey: Uint8Array,
  clientPublic: Uint8Array,
  serverPublic: Uint8Array,
  sharedSecret: Uint8Array,
): Promise<Uint8Array> {
  const input = buildExchangeHashInput(
    clientVersion,
    serverVersion,
    clientKexinit,
    serverKexinit,
    serverHostKey,
    clientPublic,
    serverPublic,
    sharedSecret,
  );

  return await hash(hashAlgo, input);
}

/**
 * Key exchange handler class
 */
export class KexHandler {
  private _state: KexState = {};
  private _isServer: boolean;
  private _offer: KexAlgorithms;
  private _clientVersion: string;
  private _serverVersion: string;

  constructor(isServer: boolean, offer?: KexAlgorithms) {
    this._isServer = isServer;
    this._offer = offer || createDefaultOffer();
    this._clientVersion = '';
    this._serverVersion = '';
  }

  /**
   * Set version strings
   */
  setVersions(clientVersion: string, serverVersion: string): void {
    this._clientVersion = clientVersion;
    this._serverVersion = serverVersion;
  }

  /**
   * Get current state
   */
  get state(): KexState {
    return this._state;
  }

  /**
   * Get algorithm offer
   */
  get offer(): KexAlgorithms {
    return this._offer;
  }

  /**
   * Generate KEXINIT message
   */
  generateKexInit(): Uint8Array {
    this._state.kexinit = buildKexInit(this._offer);
    return this._state.kexinit;
  }

  /**
   * Handle received KEXINIT message
   * Returns { algorithms, strictKex } or Error
   */
  handleKexInit(
    payload: Uint8Array,
  ): { algorithms: NegotiatedAlgorithms; strictKex: boolean } | Error {
    this._state.remoteKexinit = payload;

    const remoteOffer = parseKexInit(payload);
    if (remoteOffer instanceof Error) {
      return remoteOffer;
    }

    const algorithms = negotiateAlgorithms(this._offer, remoteOffer, this._isServer);
    if (algorithms instanceof Error) {
      return algorithms;
    }

    // Check for strict KEX extension (RFC 9700)
    // Server looks for kex-strict-c-v00@openssh.com in client's list
    // Client looks for kex-strict-s-v00@openssh.com in server's list
    const strictExtension = this._isServer
      ? 'kex-strict-c-v00@openssh.com'
      : 'kex-strict-s-v00@openssh.com';
    const strictKex = remoteOffer.kex.includes(strictExtension);

    this._state.algorithms = algorithms;
    return { algorithms, strictKex };
  }

  /**
   * Initialize key exchange
   */
  async initKeyExchange(): Promise<KeyExchangeResult | Error> {
    if (!this._state.algorithms) {
      return new Error('Algorithms not negotiated');
    }

    try {
      this._state.exchange = createKeyExchange(this._state.algorithms.kex);
      this._state.exchangeResult = await this._state.exchange.generateKeyPair();
      return this._state.exchangeResult;
    } catch (e) {
      return e as Error;
    }
  }

  /**
   * Complete key exchange with peer's public key
   */
  async completeKeyExchange(
    peerPublicKey: Uint8Array,
    serverHostKey: Uint8Array,
  ): Promise<SessionKeys | Error> {
    if (!this._state.exchangeResult || !this._state.algorithms) {
      return new Error('Key exchange not initialized');
    }

    try {
      // Compute shared secret
      this._state.sharedSecret = await this._state.exchangeResult.computeSecret(peerPublicKey);

      // Determine client/server public keys based on role
      const clientPublic = this._isServer ? peerPublicKey : this._state.exchangeResult.publicKey;
      const serverPublic = this._isServer ? this._state.exchangeResult.publicKey : peerPublicKey;

      // Determine client/server KEXINIT based on role
      const clientKexinit = this._isServer ? this._state.remoteKexinit! : this._state.kexinit!;
      const serverKexinit = this._isServer ? this._state.kexinit! : this._state.remoteKexinit!;

      // Compute exchange hash
      const hashAlgo = getKexHashAlgorithm(this._state.algorithms.kex);

      this._state.exchangeHash = await computeExchangeHash(
        hashAlgo,
        this._clientVersion,
        this._serverVersion,
        clientKexinit,
        serverKexinit,
        serverHostKey,
        clientPublic,
        serverPublic,
        this._state.sharedSecret,
      );

      // First exchange hash becomes the session ID
      if (!this._state.sessionId) {
        this._state.sessionId = this._state.exchangeHash;
      }

      // Derive session keys
      return deriveSessionKeys(
        this._state.sharedSecret,
        this._state.exchangeHash,
        this._state.sessionId,
        this._state.algorithms,
      );
    } catch (e) {
      return e as Error;
    }
  }

  /**
   * Reset state for re-keying
   */
  reset(): void {
    const sessionId = this._state.sessionId;
    this._state = { sessionId };
  }
}

export { GEX_MAX_BITS, GEX_MIN_BITS };
