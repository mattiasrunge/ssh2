/**
 * SSH Key Parser
 *
 * Parses various SSH key formats:
 * - OpenSSH private keys (new format)
 * - OpenSSH old-style private keys (PEM)
 * - PuTTY PPK private keys
 * - OpenSSH public keys
 * - RFC4716 public keys
 */

import { Ber, BerReader, BerWriter } from '../utils/ber.ts';
import { pbkdf as bcrypt_pbkdf } from 'bcrypt-pbkdf';
import {
  allocBytes,
  fromBase64,
  readUInt32BE,
  toBase64,
  toUtf8,
  writeUInt32BE,
} from '../utils/binary.ts';
import { CIPHER_INFO } from './constants.ts';
import { makeBufferParser, readString } from './utils.ts';

// Symbols for private key properties (exported for testing)
export const SYM_HASH_ALGO = Symbol('Hash Algorithm');
export const SYM_PRIV_PEM = Symbol('Private key PEM');
export const SYM_PUB_PEM = Symbol('Public key PEM');
export const SYM_PUB_SSH = Symbol('Public key SSH');
export const SYM_DECRYPTED = Symbol('Decrypted Key');

/**
 * Parsed SSH Key interface
 */
export interface ParsedKey {
  type: string;
  comment: string;
  sign(data: Uint8Array, algo?: string): Promise<Uint8Array | Error>;
  verify(data: Uint8Array, signature: Uint8Array, algo?: string): Promise<boolean | Error>;
  isPrivateKey(): boolean;
  getPrivatePEM(): string | null;
  getPublicPEM(): string | null;
  getPublicSSH(): Uint8Array | null;
  equals(key: ParsedKey | string | Uint8Array): boolean;
  [SYM_HASH_ALGO]: string | null;
  [SYM_PRIV_PEM]: string | null;
  [SYM_PUB_PEM]: string | null;
  [SYM_PUB_SSH]: Uint8Array | null;
  [SYM_DECRYPTED]: boolean;
}

// Create OpenSSL cipher name -> SSH cipher name conversion table
const CIPHER_INFO_OPENSSL: Record<string, (typeof CIPHER_INFO)[keyof typeof CIPHER_INFO]> = Object
  .create(null);
{
  const keys = Object.keys(CIPHER_INFO) as (keyof typeof CIPHER_INFO)[];
  for (const key of keys) {
    const cipherName = CIPHER_INFO[key].sslName;
    if (!cipherName || CIPHER_INFO_OPENSSL[cipherName]) continue;
    CIPHER_INFO_OPENSSL[cipherName] = CIPHER_INFO[key];
  }
}

const binaryKeyParser = makeBufferParser();

/**
 * Create a PEM-formatted string from binary data
 */
function makePEM(type: string, data: Uint8Array): string {
  const b64 = toBase64(data);
  let formatted = b64.replace(/.{64}/g, '$&\n');
  if (b64.length % 64 !== 0) {
    formatted += '\n';
  }
  return `-----BEGIN ${type} KEY-----\n${formatted}-----END ${type} KEY-----`;
}

/**
 * Skip fields in SSH format buffer
 */
function skipFields(buf: Uint8Array & { _pos?: number }, nfields: number): boolean {
  const bufLen = buf.length;
  let pos = buf._pos || 0;
  for (let i = 0; i < nfields; ++i) {
    const left = bufLen - pos;
    if (pos >= bufLen || left < 4) return false;
    const len = readUInt32BE(buf, pos);
    if (left < 4 + len) return false;
    pos += 4 + len;
  }
  buf._pos = pos;
  return true;
}

/**
 * Read a string/buffer from buffer and update _pos
 * @param asString - if true, returns string; if false/undefined, returns Uint8Array
 */
function readStringAndUpdatePos(
  buf: Uint8Array & { _pos?: number },
  asString: boolean = false,
): Uint8Array | string | undefined {
  const start = buf._pos || 0;
  // readString: dest=true returns string, dest=false/undefined returns Uint8Array
  const result = readString(buf, start, asString);
  if (result !== undefined && typeof result !== 'number') {
    // Calculate new position: start + 4 (length) + data length
    const len = readUInt32BE(buf, start);
    buf._pos = start + 4 + len;
    return result;
  }
  return undefined;
}

// ============================================================================
// Key Generation Utilities (OpenSSL PEM format)
// ============================================================================

function genOpenSSLRSAPub(n: Uint8Array, e: Uint8Array): string {
  const asnWriter = new BerWriter();
  asnWriter.startSequence();
  // algorithm
  asnWriter.startSequence();
  asnWriter.writeOID('1.2.840.113549.1.1.1'); // rsaEncryption
  asnWriter.writeNull();
  asnWriter.endSequence();
  // subjectPublicKey
  asnWriter.startSequence(Ber.BitString);
  asnWriter.writeByte(0x00);
  asnWriter.startSequence();
  asnWriter.writeBuffer(n, Ber.Integer);
  asnWriter.writeBuffer(e, Ber.Integer);
  asnWriter.endSequence();
  asnWriter.endSequence();
  asnWriter.endSequence();
  return makePEM('PUBLIC', new Uint8Array(asnWriter.buffer));
}

function genOpenSSHRSAPub(n: Uint8Array, e: Uint8Array): Uint8Array {
  const publicKey = allocBytes(4 + 7 + 4 + e.length + 4 + n.length);
  const encoder = new TextEncoder();

  writeUInt32BE(publicKey, 7, 0);
  publicKey.set(encoder.encode('ssh-rsa'), 4);

  let i = 4 + 7;
  writeUInt32BE(publicKey, e.length, i);
  publicKey.set(e, i += 4);

  writeUInt32BE(publicKey, n.length, i += e.length);
  publicKey.set(n, i + 4);

  return publicKey;
}

/**
 * Convert ECDSA signature from P1363 format (r||s) to SSH format (two mpints)
 * P1363: r and s are fixed-size big-endian integers
 * SSH: r and s are mpint (length-prefixed, with leading zero for positive values)
 */
function convertECDSAToSSH(signature: Uint8Array): Uint8Array {
  const halfLen = signature.length / 2;
  let r = signature.subarray(0, halfLen);
  let s = signature.subarray(halfLen);

  // Remove leading zeros but keep at least one byte
  while (r.length > 1 && r[0] === 0 && (r[1] & 0x80) === 0) {
    r = r.subarray(1);
  }
  while (s.length > 1 && s[0] === 0 && (s[1] & 0x80) === 0) {
    s = s.subarray(1);
  }

  // Add leading zero if high bit is set (to ensure positive number)
  const rPad = r[0] & 0x80 ? 1 : 0;
  const sPad = s[0] & 0x80 ? 1 : 0;

  // Build SSH format: length(4) + r + length(4) + s
  const result = allocBytes(4 + rPad + r.length + 4 + sPad + s.length);
  let offset = 0;

  // Write r
  writeUInt32BE(result, rPad + r.length, offset);
  offset += 4;
  if (rPad) {
    result[offset++] = 0;
  }
  result.set(r, offset);
  offset += r.length;

  // Write s
  writeUInt32BE(result, sPad + s.length, offset);
  offset += 4;
  if (sPad) {
    result[offset++] = 0;
  }
  result.set(s, offset);

  return result;
}

// Exported for private key generation
function bigIntFromBuffer(buf: Uint8Array): bigint {
  let hex = '0x';
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i].toString(16).padStart(2, '0');
  }
  return BigInt(hex);
}

function bigIntToBuffer(bn: bigint): Uint8Array {
  let hex = bn.toString(16);
  if ((hex.length & 1) !== 0) {
    hex = `0${hex}`;
  } else {
    const sigbit = hex.charCodeAt(0);
    // BER/DER integers require leading zero byte for positive value when first byte >= 0x80
    if (
      sigbit === 56 /* '8' */ ||
      sigbit === 57 /* '9' */ ||
      (sigbit >= 97 /* 'a' */ && sigbit <= 102) /* 'f' */
    ) {
      hex = `00${hex}`;
    }
  }
  const bytes = allocBytes(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function genOpenSSLRSAPriv(
  n: Uint8Array,
  e: Uint8Array,
  d: Uint8Array,
  iqmp: Uint8Array,
  p: Uint8Array,
  q: Uint8Array,
): string {
  const bn_d = bigIntFromBuffer(d);
  const dmp1 = bigIntToBuffer(bn_d % (bigIntFromBuffer(p) - 1n));
  const dmq1 = bigIntToBuffer(bn_d % (bigIntFromBuffer(q) - 1n));

  // Generate PKCS#1 RSA private key structure
  const pkcs1Writer = new BerWriter();
  pkcs1Writer.startSequence();
  pkcs1Writer.writeInt(0x00, Ber.Integer);
  pkcs1Writer.writeBuffer(n, Ber.Integer);
  pkcs1Writer.writeBuffer(e, Ber.Integer);
  pkcs1Writer.writeBuffer(d, Ber.Integer);
  pkcs1Writer.writeBuffer(p, Ber.Integer);
  pkcs1Writer.writeBuffer(q, Ber.Integer);
  pkcs1Writer.writeBuffer(dmp1, Ber.Integer);
  pkcs1Writer.writeBuffer(dmq1, Ber.Integer);
  pkcs1Writer.writeBuffer(iqmp, Ber.Integer);
  pkcs1Writer.endSequence();
  const pkcs1Key = new Uint8Array(pkcs1Writer.buffer);

  // Wrap in PKCS#8 format for Web Crypto API compatibility
  const pkcs8Writer = new BerWriter();
  pkcs8Writer.startSequence();
  // Version
  pkcs8Writer.writeInt(0x00, Ber.Integer);
  // Algorithm identifier
  pkcs8Writer.startSequence();
  pkcs8Writer.writeOID('1.2.840.113549.1.1.1'); // rsaEncryption
  pkcs8Writer.writeNull();
  pkcs8Writer.endSequence();
  // Private key as OCTET STRING
  pkcs8Writer.writeBuffer(pkcs1Key, Ber.OctetString);
  pkcs8Writer.endSequence();

  return makePEM('PRIVATE', new Uint8Array(pkcs8Writer.buffer));
}

function genOpenSSLEdPub(pub: Uint8Array): string {
  const asnWriter = new BerWriter();
  asnWriter.startSequence();
  // algorithm
  asnWriter.startSequence();
  asnWriter.writeOID('1.3.101.112'); // id-Ed25519
  asnWriter.endSequence();
  // PublicKey
  asnWriter.startSequence(Ber.BitString);
  asnWriter.writeByte(0x00);
  // Write raw buffer
  asnWriter._ensure(pub.length);
  asnWriter._buf.set(pub, asnWriter._offset);
  asnWriter._offset += pub.length;
  asnWriter.endSequence();
  asnWriter.endSequence();
  return makePEM('PUBLIC', new Uint8Array(asnWriter.buffer));
}

function genOpenSSHEdPub(pub: Uint8Array): Uint8Array {
  const publicKey = allocBytes(4 + 11 + 4 + pub.length);
  const encoder = new TextEncoder();

  writeUInt32BE(publicKey, 11, 0);
  publicKey.set(encoder.encode('ssh-ed25519'), 4);

  writeUInt32BE(publicKey, pub.length, 15);
  publicKey.set(pub, 19);

  return publicKey;
}

// Exported for Ed25519 private key generation
export function genOpenSSLEdPriv(priv: Uint8Array): string {
  const asnWriter = new BerWriter();
  asnWriter.startSequence();
  // version
  asnWriter.writeInt(0x00, Ber.Integer);
  // algorithm
  asnWriter.startSequence();
  asnWriter.writeOID('1.3.101.112'); // id-Ed25519
  asnWriter.endSequence();
  // PrivateKey
  asnWriter.startSequence(Ber.OctetString);
  asnWriter.writeBuffer(priv, Ber.OctetString);
  asnWriter.endSequence();
  asnWriter.endSequence();
  return makePEM('PRIVATE', new Uint8Array(asnWriter.buffer));
}

function genOpenSSLECDSAPub(oid: string, Q: Uint8Array): string {
  const asnWriter = new BerWriter();
  asnWriter.startSequence();
  // algorithm
  asnWriter.startSequence();
  asnWriter.writeOID('1.2.840.10045.2.1'); // id-ecPublicKey
  asnWriter.writeOID(oid);
  asnWriter.endSequence();
  // subjectPublicKey
  asnWriter.startSequence(Ber.BitString);
  asnWriter.writeByte(0x00);
  // Write raw buffer
  asnWriter._ensure(Q.length);
  asnWriter._buf.set(Q, asnWriter._offset);
  asnWriter._offset += Q.length;
  asnWriter.endSequence();
  asnWriter.endSequence();
  return makePEM('PUBLIC', new Uint8Array(asnWriter.buffer));
}

function genOpenSSHECDSAPub(oid: string, Q: Uint8Array): Uint8Array | undefined {
  let curveName: string;
  switch (oid) {
    case '1.2.840.10045.3.1.7':
      curveName = 'nistp256';
      break;
    case '1.3.132.0.34':
      curveName = 'nistp384';
      break;
    case '1.3.132.0.35':
      curveName = 'nistp521';
      break;
    default:
      return undefined;
  }

  const publicKey = allocBytes(4 + 19 + 4 + 8 + 4 + Q.length);
  const encoder = new TextEncoder();

  writeUInt32BE(publicKey, 19, 0);
  publicKey.set(encoder.encode(`ecdsa-sha2-${curveName}`), 4);

  writeUInt32BE(publicKey, 8, 23);
  publicKey.set(encoder.encode(curveName), 27);

  writeUInt32BE(publicKey, Q.length, 35);
  publicKey.set(Q, 39);

  return publicKey;
}

// Exported for ECDSA private key generation
export function genOpenSSLECDSAPriv(
  oid: string,
  pub: Uint8Array,
  priv: Uint8Array,
): string {
  // Generate SEC1 EC private key structure first
  const sec1Writer = new BerWriter();
  sec1Writer.startSequence();
  // version
  sec1Writer.writeInt(0x01, Ber.Integer);
  // privateKey
  sec1Writer.writeBuffer(priv, Ber.OctetString);
  // publicKey (optional) - [1] BIT STRING
  sec1Writer.startSequence(0xa1);
  sec1Writer.startSequence(Ber.BitString);
  sec1Writer.writeByte(0x00); // padding bits
  sec1Writer._ensure(pub.length);
  sec1Writer._buf.set(pub, sec1Writer._offset);
  sec1Writer._offset += pub.length;
  sec1Writer.endSequence();
  sec1Writer.endSequence();
  sec1Writer.endSequence();
  const sec1Key = new Uint8Array(sec1Writer.buffer);

  // Wrap in PKCS#8 format for Web Crypto API compatibility
  const pkcs8Writer = new BerWriter();
  pkcs8Writer.startSequence();
  // Version
  pkcs8Writer.writeInt(0x00, Ber.Integer);
  // Algorithm identifier
  pkcs8Writer.startSequence();
  pkcs8Writer.writeOID('1.2.840.10045.2.1'); // ecPublicKey
  pkcs8Writer.writeOID(oid); // curve OID
  pkcs8Writer.endSequence();
  // Private key as OCTET STRING
  pkcs8Writer.writeBuffer(sec1Key, Ber.OctetString);
  pkcs8Writer.endSequence();

  return makePEM('PRIVATE', new Uint8Array(pkcs8Writer.buffer));
}

// ============================================================================
// Base Key Implementation
// ============================================================================

/**
 * Create base key methods
 */
function createBaseKey(
  type: string,
  comment: string,
  privPEM: string | null,
  pubPEM: string | null,
  pubSSH: Uint8Array | null,
  algo: string | null,
  decrypted: boolean,
): ParsedKey {
  const key: ParsedKey = {
    type,
    comment,
    [SYM_PRIV_PEM]: privPEM,
    [SYM_PUB_PEM]: pubPEM,
    [SYM_PUB_SSH]: pubSSH,
    [SYM_HASH_ALGO]: algo,
    [SYM_DECRYPTED]: decrypted,

    async sign(data: Uint8Array, hashAlgo?: string): Promise<Uint8Array | Error> {
      const pem = this[SYM_PRIV_PEM];
      if (pem === null) {
        return new Error('No private key available');
      }
      // Map SSH algorithm names to hash algorithms
      if (hashAlgo) {
        switch (hashAlgo) {
          case 'ssh-rsa':
            hashAlgo = 'sha1';
            break;
          case 'rsa-sha2-256':
          case 'ecdsa-sha2-nistp256':
            hashAlgo = 'sha256';
            break;
          case 'rsa-sha2-384':
          case 'ecdsa-sha2-nistp384':
            hashAlgo = 'sha384';
            break;
          case 'rsa-sha2-512':
          case 'ecdsa-sha2-nistp521': // P-521 uses SHA-512
            hashAlgo = 'sha512';
            break;
        }
      }
      if (!hashAlgo) {
        hashAlgo = this[SYM_HASH_ALGO] || 'sha256';
      }
      try {
        // Import the key and sign
        const keyData = await importPrivateKey(pem, this.type, hashAlgo);
        if (keyData instanceof Error) return keyData;
        const rawSignature = await crypto.subtle.sign(
          keyData.algorithm,
          keyData.key,
          data as BufferSource,
        );
        const signature = new Uint8Array(rawSignature);

        // For ECDSA, convert from P1363 format (r||s) to SSH format (two mpints)
        if (this.type.startsWith('ecdsa-sha2-')) {
          return convertECDSAToSSH(signature);
        }

        return signature;
      } catch (ex) {
        return ex as Error;
      }
    },

    async verify(
      data: Uint8Array,
      signature: Uint8Array,
      hashAlgo?: string,
    ): Promise<boolean | Error> {
      const pem = this[SYM_PUB_PEM];
      if (pem === null) {
        return new Error('No public key available');
      }
      if (!hashAlgo) {
        hashAlgo = this[SYM_HASH_ALGO] || 'sha256';
      }
      try {
        const keyData = await importPublicKey(pem, this.type, hashAlgo);
        if (keyData instanceof Error) return keyData;
        return await crypto.subtle.verify(
          keyData.algorithm,
          keyData.key,
          signature as BufferSource,
          data as BufferSource,
        );
      } catch (ex) {
        return ex as Error;
      }
    },

    isPrivateKey(): boolean {
      return this[SYM_PRIV_PEM] !== null;
    },

    getPrivatePEM(): string | null {
      return this[SYM_PRIV_PEM];
    },

    getPublicPEM(): string | null {
      return this[SYM_PUB_PEM];
    },

    getPublicSSH(): Uint8Array | null {
      return this[SYM_PUB_SSH];
    },

    equals(other: ParsedKey | string | Uint8Array): boolean {
      const parsed = parseKey(other);
      if (parsed instanceof Error) return false;
      const thisPubSSH = this[SYM_PUB_SSH];
      const otherPubSSH = parsed[SYM_PUB_SSH];
      if (!thisPubSSH || !otherPubSSH) return false;
      if (thisPubSSH.length !== otherPubSSH.length) return false;
      for (let i = 0; i < thisPubSSH.length; i++) {
        if (thisPubSSH[i] !== otherPubSSH[i]) return false;
      }
      return (
        this.type === parsed.type &&
        this[SYM_PRIV_PEM] === parsed[SYM_PRIV_PEM] &&
        this[SYM_PUB_PEM] === parsed[SYM_PUB_PEM]
      );
    },
  };

  return key;
}

// ============================================================================
// Web Crypto Key Import Helpers
// ============================================================================

interface ImportedKeyData {
  key: CryptoKey;
  algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
}

// Map hash algorithm names to Web Crypto API format
function normalizeHashAlgo(algo: string): string {
  switch (algo.toLowerCase()) {
    case 'sha1':
    case 'sha-1':
      return 'SHA-1';
    case 'sha256':
    case 'sha-256':
      return 'SHA-256';
    case 'sha384':
    case 'sha-384':
      return 'SHA-384';
    case 'sha512':
    case 'sha-512':
      return 'SHA-512';
    default:
      return algo.toUpperCase();
  }
}

async function importPrivateKey(
  pem: string,
  keyType: string,
  hashAlgo: string,
): Promise<ImportedKeyData | Error> {
  // Parse PEM to get raw key data
  const pemMatch = pem.match(
    /-----BEGIN ([A-Z ]+) KEY-----\n?([\s\S]+?)\n?-----END ([A-Z ]+) KEY-----/,
  );
  if (!pemMatch) {
    return new Error('Invalid PEM format');
  }
  const keyData = fromBase64(pemMatch[2].replace(/\s/g, ''));
  const normalizedHash = normalizeHashAlgo(hashAlgo);

  try {
    switch (keyType) {
      case 'ssh-rsa': {
        const key = await crypto.subtle.importKey(
          'pkcs8',
          keyData as BufferSource,
          { name: 'RSASSA-PKCS1-v1_5', hash: normalizedHash },
          false,
          ['sign'],
        );
        return {
          key,
          algorithm: { name: 'RSASSA-PKCS1-v1_5' },
        };
      }
      case 'ssh-ed25519': {
        const key = await crypto.subtle.importKey(
          'pkcs8',
          keyData as BufferSource,
          { name: 'Ed25519' },
          false,
          ['sign'],
        );
        return {
          key,
          algorithm: { name: 'Ed25519' },
        };
      }
      case 'ecdsa-sha2-nistp256':
      case 'ecdsa-sha2-nistp384':
      case 'ecdsa-sha2-nistp521': {
        const curve = keyType.includes('256')
          ? 'P-256'
          : keyType.includes('384')
          ? 'P-384'
          : 'P-521';
        const key = await crypto.subtle.importKey(
          'pkcs8',
          keyData as BufferSource,
          { name: 'ECDSA', namedCurve: curve },
          false,
          ['sign'],
        );
        return {
          key,
          algorithm: { name: 'ECDSA', hash: normalizedHash },
        };
      }
      default:
        return new Error(`Unsupported key type for signing: ${keyType}`);
    }
  } catch (ex) {
    return ex as Error;
  }
}

async function importPublicKey(
  pem: string,
  keyType: string,
  hashAlgo: string,
): Promise<ImportedKeyData | Error> {
  const pemMatch = pem.match(
    /-----BEGIN ([A-Z ]+) KEY-----\n?([\s\S]+?)\n?-----END ([A-Z ]+) KEY-----/,
  );
  if (!pemMatch) {
    return new Error('Invalid PEM format');
  }
  const keyData = fromBase64(pemMatch[2].replace(/\s/g, ''));

  try {
    switch (keyType) {
      case 'ssh-rsa': {
        const key = await crypto.subtle.importKey(
          'spki',
          keyData as BufferSource,
          { name: 'RSASSA-PKCS1-v1_5', hash: normalizeHashAlgo(hashAlgo) },
          false,
          ['verify'],
        );
        return {
          key,
          algorithm: { name: 'RSASSA-PKCS1-v1_5' },
        };
      }
      case 'ssh-ed25519': {
        const key = await crypto.subtle.importKey(
          'spki',
          keyData as BufferSource,
          { name: 'Ed25519' },
          false,
          ['verify'],
        );
        return {
          key,
          algorithm: { name: 'Ed25519' },
        };
      }
      case 'ecdsa-sha2-nistp256':
      case 'ecdsa-sha2-nistp384':
      case 'ecdsa-sha2-nistp521': {
        const curve = keyType.includes('256')
          ? 'P-256'
          : keyType.includes('384')
          ? 'P-384'
          : 'P-521';
        const key = await crypto.subtle.importKey(
          'spki',
          keyData as BufferSource,
          { name: 'ECDSA', namedCurve: curve },
          false,
          ['verify'],
        );
        return {
          key,
          algorithm: { name: 'ECDSA', hash: hashAlgo.toUpperCase() },
        };
      }
      default:
        return new Error(`Unsupported key type for verification: ${keyType}`);
    }
  } catch (ex) {
    return ex as Error;
  }
}

// ============================================================================
// Key Format Parsers
// ============================================================================

/**
 * Parse OpenSSH public key format
 */
function parseOpenSSHPublic(str: string): ParsedKey | Error | null {
  // Match supported key types: RSA, Ed25519, and ECDSA
  const regexp =
    /^(((?:ssh-(?:rsa|ed25519))|ecdsa-sha2-nistp(?:256|384|521))(?:-cert-v0[01]@openssh.com)?) ([A-Z0-9a-z/+=]+)(?:$|\s+([\S].*)?)$/;

  const m = regexp.exec(str);
  if (m === null) return null;

  const fullType = m[1];
  const baseType = m[2];
  const data = fromBase64(m[3]) as Uint8Array & { _pos?: number };
  const comment = m[4] || '';

  const type = readStringAndUpdatePos(data, true) as string | undefined;
  if (type === undefined || !type.startsWith(baseType)) {
    return new Error('Malformed OpenSSH public key');
  }

  return parseDER(data, baseType, comment, fullType);
}

/**
 * Parse DER-encoded key data
 */
function parseDER(
  data: Uint8Array & { _pos?: number },
  baseType: string,
  comment: string,
  fullType: string,
): ParsedKey | Error {
  if (!isSupportedKeyType(baseType)) {
    return new Error(`Unsupported OpenSSH public key type: ${baseType}`);
  }

  let algo: string | null = null;
  let oid: string | undefined;
  let pubPEM: string | null = null;
  let pubSSH: Uint8Array | null = null;

  switch (baseType) {
    case 'ssh-rsa': {
      const e = readStringAndUpdatePos(data) as Uint8Array | undefined;
      if (e === undefined) return new Error('Malformed OpenSSH public key');
      const n = readStringAndUpdatePos(data) as Uint8Array | undefined;
      if (n === undefined) return new Error('Malformed OpenSSH public key');
      pubPEM = genOpenSSLRSAPub(n, e);
      pubSSH = genOpenSSHRSAPub(n, e);
      algo = 'sha1';
      break;
    }
    case 'ssh-ed25519': {
      const edpub = readStringAndUpdatePos(data) as Uint8Array | undefined;
      if (edpub === undefined || edpub.length !== 32) {
        return new Error('Malformed OpenSSH public key');
      }
      pubPEM = genOpenSSLEdPub(edpub);
      pubSSH = genOpenSSHEdPub(edpub);
      algo = null;
      break;
    }
    case 'ecdsa-sha2-nistp256':
      algo = 'sha256';
      oid = '1.2.840.10045.3.1.7';
    // FALLTHROUGH
    case 'ecdsa-sha2-nistp384':
      if (algo === undefined) {
        algo = 'sha384';
        oid = '1.3.132.0.34';
      }
    // FALLTHROUGH
    case 'ecdsa-sha2-nistp521': {
      if (algo === undefined) {
        algo = 'sha512';
        oid = '1.3.132.0.35';
      }
      if (!skipFields(data, 1)) {
        return new Error('Malformed OpenSSH public key');
      }
      const ecpub = readStringAndUpdatePos(data) as Uint8Array | undefined;
      if (ecpub === undefined) {
        return new Error('Malformed OpenSSH public key');
      }
      pubPEM = genOpenSSLECDSAPub(oid!, ecpub);
      pubSSH = genOpenSSHECDSAPub(oid!, ecpub) || null;
      break;
    }
    default:
      return new Error(`Unsupported OpenSSH public key type: ${baseType}`);
  }

  return createBaseKey(fullType, comment, null, pubPEM, pubSSH, algo, false);
}

/**
 * Check if key type is supported
 */
function isSupportedKeyType(type: string): boolean {
  switch (type) {
    case 'ssh-rsa':
    case 'ssh-ed25519':
    case 'ecdsa-sha2-nistp256':
    case 'ecdsa-sha2-nistp384':
    case 'ecdsa-sha2-nistp521':
      return true;
    default:
      return false;
  }
}

/**
 * Check if a value is a parsed key
 */
export function isParsedKey(val: unknown): val is ParsedKey {
  if (!val || typeof val !== 'object') return false;
  return typeof (val as ParsedKey)[SYM_DECRYPTED] === 'boolean';
}

// Supported ciphers for OpenSSH private keys
const SUPPORTED_CIPHER = [
  'aes256-ctr',
  'aes192-ctr',
  'aes128-ctr',
  'aes256-cbc',
  'aes192-cbc',
  'aes128-cbc',
  'aes128-gcm@openssh.com',
  'aes256-gcm@openssh.com',
];

/**
 * Parse OpenSSH private key format (new format: BEGIN OPENSSH PRIVATE KEY)
 */
function parseOpenSSHPrivate(
  str: string,
  passphrase?: Uint8Array,
): ParsedKey | Error | null {
  const regexp =
    /^-----BEGIN OPENSSH PRIVATE KEY-----(?:\r\n|\n)([\s\S]+)(?:\r\n|\n)-----END OPENSSH PRIVATE KEY-----$/;
  const m = regexp.exec(str);
  if (m === null) return null;

  const data = fromBase64(m[1].replace(/\s/g, '')) as Uint8Array & { _pos?: number };
  if (data.length < 31) {
    return new Error('Malformed OpenSSH private key');
  }

  // Check magic
  const magic = toUtf8(data.subarray(0, 15));
  if (magic !== 'openssh-key-v1\0') {
    return new Error(`Unsupported OpenSSH key magic: ${magic}`);
  }
  data._pos = 15;

  const cipherName = readStringAndUpdatePos(data, true) as string | undefined;
  if (cipherName === undefined) {
    return new Error('Malformed OpenSSH private key');
  }
  if (cipherName !== 'none' && !SUPPORTED_CIPHER.includes(cipherName)) {
    return new Error(`Unsupported cipher for OpenSSH key: ${cipherName}`);
  }

  const kdfName = readStringAndUpdatePos(data, true) as string | undefined;
  if (kdfName === undefined) {
    return new Error('Malformed OpenSSH private key');
  }
  if (kdfName !== 'none') {
    if (cipherName === 'none') {
      return new Error('Malformed OpenSSH private key');
    }
    if (kdfName !== 'bcrypt') {
      return new Error(`Unsupported kdf name for OpenSSH key: ${kdfName}`);
    }
    if (!passphrase) {
      return new Error('Encrypted private OpenSSH key detected, but no passphrase given');
    }
  } else if (cipherName !== 'none') {
    return new Error('Malformed OpenSSH private key');
  }

  let encInfo: typeof CIPHER_INFO[keyof typeof CIPHER_INFO] | undefined;
  let cipherKey: Uint8Array | undefined;
  let cipherIV: Uint8Array | undefined;

  if (cipherName !== 'none') {
    encInfo = CIPHER_INFO[cipherName as keyof typeof CIPHER_INFO];
    if (!encInfo) {
      return new Error(`Unsupported cipher for OpenSSH key: ${cipherName}`);
    }
  }

  const kdfOptions = readStringAndUpdatePos(data) as Uint8Array | undefined;
  if (kdfOptions === undefined) {
    return new Error('Malformed OpenSSH private key');
  }

  if (kdfOptions.length > 0) {
    if (kdfName === 'none') {
      return new Error('Malformed OpenSSH private key');
    }
    if (kdfName === 'bcrypt' && encInfo && passphrase) {
      // Parse kdfOptions: string salt, uint32 rounds
      const kdfData = kdfOptions as Uint8Array & { _pos?: number };
      kdfData._pos = 0;
      const salt = readStringAndUpdatePos(kdfData) as Uint8Array | undefined;
      if (salt === undefined || (kdfData._pos || 0) + 4 > kdfOptions.length) {
        return new Error('Malformed OpenSSH private key');
      }
      const rounds = readUInt32BE(kdfOptions, kdfData._pos || 0);

      const gen = allocBytes(encInfo.keyLen + (encInfo.ivLen || 0));
      const r = bcrypt_pbkdf(
        passphrase,
        passphrase.length,
        salt,
        salt.length,
        gen,
        gen.length,
        rounds,
      );
      if (r !== 0) {
        return new Error('Failed to generate information to decrypt key');
      }
      cipherKey = gen.subarray(0, encInfo.keyLen);
      cipherIV = gen.subarray(encInfo.keyLen);
    }
  } else if (kdfName !== 'none') {
    return new Error('Malformed OpenSSH private key');
  }

  if ((data._pos || 0) + 3 >= data.length) {
    return new Error('Malformed OpenSSH private key');
  }
  const keyCount = readUInt32BE(data, data._pos || 0);
  data._pos = (data._pos || 0) + 4;

  if (keyCount === 0) {
    return new Error('No keys in OpenSSH private key file');
  }

  // Read public keys first (skip them)
  for (let i = 0; i < keyCount; ++i) {
    const pubData = readStringAndUpdatePos(data) as Uint8Array | undefined;
    if (pubData === undefined) {
      return new Error('Malformed OpenSSH private key');
    }
  }

  let privBlob = readStringAndUpdatePos(data) as Uint8Array | undefined;
  if (privBlob === undefined) {
    return new Error('Malformed OpenSSH private key');
  }

  // Decrypt if encrypted
  if (cipherKey !== undefined && cipherIV !== undefined && encInfo) {
    if (privBlob.length < encInfo.blockLen || (privBlob.length % encInfo.blockLen) !== 0) {
      return new Error('Malformed OpenSSH private key');
    }

    try {
      privBlob = decryptPrivateKey(privBlob, cipherKey, cipherIV, encInfo, data, data._pos || 0);
    } catch (ex) {
      return ex as Error;
    }
  }

  // Check for extra data
  if (encInfo?.authLen === undefined || encInfo.authLen === 0) {
    if ((data._pos || 0) !== data.length) {
      return new Error('Malformed OpenSSH private key');
    }
  }

  // Parse private keys
  const result = parseOpenSSHPrivKeys(
    privBlob as Uint8Array & { _pos?: number },
    keyCount,
    cipherKey !== undefined,
  );
  if (result instanceof Error) return result;
  return result[0];
}

/**
 * Decrypt private key blob (placeholder - encrypted keys not yet supported)
 */
function decryptPrivateKey(
  _privBlob: Uint8Array,
  _cipherKey: Uint8Array,
  _cipherIV: Uint8Array,
  _encInfo: typeof CIPHER_INFO[keyof typeof CIPHER_INFO],
  _data: Uint8Array,
  _pos: number,
): Uint8Array {
  // TODO: Implement encrypted key decryption using @noble/ciphers
  throw new Error('Encrypted OpenSSH private keys not yet supported');
}

/**
 * Parse OpenSSH private key blob
 */
function parseOpenSSHPrivKeys(
  data: Uint8Array & { _pos?: number },
  nkeys: number,
  decrypted: boolean,
): ParsedKey[] | Error {
  const keys: ParsedKey[] = [];

  if (data.length < 8) {
    return new Error('Malformed OpenSSH private key');
  }

  const check1 = readUInt32BE(data, 0);
  const check2 = readUInt32BE(data, 4);
  if (check1 !== check2) {
    if (decrypted) {
      return new Error('OpenSSH key integrity check failed -- bad passphrase?');
    }
    return new Error('OpenSSH key integrity check failed');
  }
  data._pos = 8;

  for (let i = 0; i < nkeys; ++i) {
    let algo: string | null = null;
    let oid: string | undefined;
    let privPEM: string | null = null;
    let pubPEM: string | null = null;
    let pubSSH: Uint8Array | null = null;

    const type = readStringAndUpdatePos(data, true) as string | undefined;
    if (type === undefined) {
      return new Error('Malformed OpenSSH private key');
    }

    switch (type) {
      case 'ssh-rsa': {
        const n = readStringAndUpdatePos(data) as Uint8Array | undefined;
        if (n === undefined) return new Error('Malformed OpenSSH private key');
        const e = readStringAndUpdatePos(data) as Uint8Array | undefined;
        if (e === undefined) return new Error('Malformed OpenSSH private key');
        const d = readStringAndUpdatePos(data) as Uint8Array | undefined;
        if (d === undefined) return new Error('Malformed OpenSSH private key');
        const iqmp = readStringAndUpdatePos(data) as Uint8Array | undefined;
        if (iqmp === undefined) return new Error('Malformed OpenSSH private key');
        const p = readStringAndUpdatePos(data) as Uint8Array | undefined;
        if (p === undefined) return new Error('Malformed OpenSSH private key');
        const q = readStringAndUpdatePos(data) as Uint8Array | undefined;
        if (q === undefined) return new Error('Malformed OpenSSH private key');

        pubPEM = genOpenSSLRSAPub(n, e);
        pubSSH = genOpenSSHRSAPub(n, e);
        privPEM = genOpenSSLRSAPriv(n, e, d, iqmp, p, q);
        algo = 'sha1';
        break;
      }
      case 'ssh-ed25519': {
        const edpub = readStringAndUpdatePos(data) as Uint8Array | undefined;
        if (edpub === undefined || edpub.length !== 32) {
          return new Error('Malformed OpenSSH private key');
        }
        const edpriv = readStringAndUpdatePos(data) as Uint8Array | undefined;
        if (edpriv === undefined || edpriv.length !== 64) {
          return new Error('Malformed OpenSSH private key');
        }

        pubPEM = genOpenSSLEdPub(edpub);
        pubSSH = genOpenSSHEdPub(edpub);
        privPEM = genOpenSSLEdPriv(edpriv.subarray(0, 32));
        algo = null;
        break;
      }
      case 'ecdsa-sha2-nistp256':
        algo = 'sha256';
        oid = '1.2.840.10045.3.1.7';
        // FALLTHROUGH
      case 'ecdsa-sha2-nistp384':
        if (algo === undefined) {
          algo = 'sha384';
          oid = '1.3.132.0.34';
        }
        // FALLTHROUGH
      case 'ecdsa-sha2-nistp521': {
        if (algo === undefined) {
          algo = 'sha512';
          oid = '1.3.132.0.35';
        }
        // Skip curve name
        if (!skipFields(data, 1)) {
          return new Error('Malformed OpenSSH private key');
        }
        const ecpub = readStringAndUpdatePos(data) as Uint8Array | undefined;
        if (ecpub === undefined) return new Error('Malformed OpenSSH private key');
        const ecpriv = readStringAndUpdatePos(data) as Uint8Array | undefined;
        if (ecpriv === undefined) return new Error('Malformed OpenSSH private key');

        pubPEM = genOpenSSLECDSAPub(oid!, ecpub);
        pubSSH = genOpenSSHECDSAPub(oid!, ecpub) || null;
        privPEM = genOpenSSLECDSAPriv(oid!, ecpub, ecpriv);
        break;
      }
      default:
        return new Error(`Unsupported OpenSSH private key type: ${type}`);
    }

    const privComment = readStringAndUpdatePos(data, true) as string | undefined;
    if (privComment === undefined) {
      return new Error('Malformed OpenSSH private key');
    }

    keys.push(createBaseKey(type, privComment, privPEM, pubPEM, pubSSH, algo, decrypted));
  }

  return keys;
}

/**
 * Parse old-style PEM format private keys
 * Supports:
 * - BEGIN RSA PRIVATE KEY (PKCS#1)
 * - BEGIN EC PRIVATE KEY (SEC1)
 */
function parseOldPEMPrivate(
  str: string,
  _passphrase?: Uint8Array,
): ParsedKey | Error | null {
  // Check for various PEM private key formats
  const rsaMatch = str.match(
    /-----BEGIN RSA PRIVATE KEY-----([\s\S]+?)-----END RSA PRIVATE KEY-----/,
  );
  const ecMatch = str.match(
    /-----BEGIN EC PRIVATE KEY-----([\s\S]+?)-----END EC PRIVATE KEY-----/,
  );

  if (!rsaMatch && !ecMatch) {
    return null;
  }

  try {
    if (rsaMatch) {
      // PKCS#1 RSA Private Key
      const derData = fromBase64(rsaMatch[1].replace(/\s/g, ''));
      const reader = new BerReader(derData);
      reader.readSequence();

      // Version
      const version = reader.readInt();
      if (version !== 0) {
        return new Error('Unsupported RSA private key version');
      }

      // Read RSA parameters
      const n = reader.readString(Ber.Integer, true) as Uint8Array;
      const e = reader.readString(Ber.Integer, true) as Uint8Array;
      const d = reader.readString(Ber.Integer, true) as Uint8Array;
      const p = reader.readString(Ber.Integer, true) as Uint8Array;
      const q = reader.readString(Ber.Integer, true) as Uint8Array;
      const dmp1 = reader.readString(Ber.Integer, true) as Uint8Array; // d mod (p-1)
      const dmq1 = reader.readString(Ber.Integer, true) as Uint8Array; // d mod (q-1)
      const iqmp = reader.readString(Ber.Integer, true) as Uint8Array;

      if (!n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp) {
        return new Error('Malformed PKCS#1 RSA private key');
      }

      const privPEM = genOpenSSLRSAPriv(n, e, d, iqmp, p, q);
      const pubPEM = genOpenSSLRSAPub(n, e);
      const pubSSH = genOpenSSHRSAPub(n, e);

      return createBaseKey('ssh-rsa', '', privPEM, pubPEM, pubSSH, 'sha1', true);
    }

    if (ecMatch) {
      // SEC1 EC Private Key
      const derData = fromBase64(ecMatch[1].replace(/\s/g, ''));
      const reader = new BerReader(derData);
      reader.readSequence();

      // Version (1 for SEC1)
      const version = reader.readInt();
      if (version !== 1) {
        return new Error('Unsupported EC private key version');
      }

      // Private key value (OCTET STRING)
      const ecpriv = reader.readString(Ber.OctetString, true) as Uint8Array;

      // Parameters - context-specific [0] containing OID
      reader.readSequence(0xa0);
      const curveOID = reader.readOID();

      // Public key - context-specific [1] containing BIT STRING
      reader.readSequence(0xa1);
      // Read BIT STRING (tag 0x03)
      const bitString = reader.readString(Ber.BitString, true) as Uint8Array;
      // Skip the first byte (padding bits, should be 0)
      const ecpub = bitString ? bitString.subarray(1) : undefined;

      if (!ecpriv || !curveOID || !ecpub) {
        return new Error('Malformed EC private key');
      }

      // Determine curve type from OID
      let curveType: string;
      let hashAlgo: string;
      switch (curveOID) {
        case '1.2.840.10045.3.1.7': // P-256
          curveType = 'ecdsa-sha2-nistp256';
          hashAlgo = 'sha256';
          break;
        case '1.3.132.0.34': // P-384
          curveType = 'ecdsa-sha2-nistp384';
          hashAlgo = 'sha384';
          break;
        case '1.3.132.0.35': // P-521
          curveType = 'ecdsa-sha2-nistp521';
          hashAlgo = 'sha512';
          break;
        default:
          return new Error(`Unsupported EC curve OID: ${curveOID}`);
      }

      const privPEM = genOpenSSLECDSAPriv(curveOID, ecpub, ecpriv);
      const pubPEM = genOpenSSLECDSAPub(curveOID, ecpub);
      const pubSSH = genOpenSSHECDSAPub(curveOID, ecpub);

      if (!pubSSH) {
        return new Error('Failed to generate SSH public key for EC key');
      }

      return createBaseKey(curveType, '', privPEM, pubPEM, pubSSH, hashAlgo, true);
    }
  } catch (ex) {
    return new Error(`Failed to parse PEM private key: ${(ex as Error).message}`);
  }

  return null;
}

/**
 * Main key parsing function
 */
export function parseKey(
  data: string | Uint8Array | ParsedKey,
  passphrase?: string | Uint8Array,
): ParsedKey | Error {
  if (isParsedKey(data)) {
    return data;
  }

  let strData: string;
  let origBuffer: Uint8Array | undefined;

  if (data instanceof Uint8Array) {
    origBuffer = data;
    strData = toUtf8(data).trim();
  } else if (typeof data === 'string') {
    strData = data.trim();
  } else {
    return new Error('Key data must be a Buffer or string');
  }

  // Validate passphrase if provided (will be used for encrypted private keys)
  if (passphrase !== undefined) {
    if (typeof passphrase !== 'string' && !(passphrase instanceof Uint8Array)) {
      return new Error('Passphrase must be a string or Uint8Array when supplied');
    }
  }

  let ret: ParsedKey | Error | null;

  // Convert passphrase to Uint8Array if string
  let passphraseBytes: Uint8Array | undefined;
  if (passphrase !== undefined) {
    if (typeof passphrase === 'string') {
      passphraseBytes = new TextEncoder().encode(passphrase);
    } else {
      passphraseBytes = passphrase;
    }
  }

  // Try public key formats first (simpler, no passphrase needed)
  ret = parseOpenSSHPublic(strData);
  if (ret !== null) return ret;

  // Try OpenSSH new format private key
  ret = parseOpenSSHPrivate(strData, passphraseBytes);
  if (ret !== null) return ret;

  // Try old PEM format private keys (PKCS#1, SEC1 EC)
  ret = parseOldPEMPrivate(strData, passphraseBytes);
  if (ret !== null) return ret;

  // TODO: Add more private key parsers:
  // - OpenSSH_Old_Private.parse(strData, passphraseBytes) - old PEM format
  // - PPK_Private.parse(strData, passphraseBytes) - PuTTY format
  // - RFC4716_Public.parse(strData) - RFC4716 public key

  // Try binary format if we have original buffer
  if (origBuffer) {
    binaryKeyParser.init(origBuffer, 0);
    const type = binaryKeyParser.readString(true) as string | undefined;
    if (type !== undefined) {
      const keyData = binaryKeyParser.readRaw();
      if (keyData !== undefined) {
        ret = parseDER(keyData as Uint8Array & { _pos?: number }, type, '', type);
        if (!(ret instanceof Error)) {
          binaryKeyParser.clear();
          return ret;
        }
      }
    }
    binaryKeyParser.clear();
  }

  return new Error('Unsupported key format');
}

/**
 * Parse DER key (for internal use)
 */
export function parseDERKey(
  data: Uint8Array,
  type: string,
): ParsedKey | Error {
  return parseDER(data as Uint8Array & { _pos?: number }, type, '', type);
}

export { isSupportedKeyType };
