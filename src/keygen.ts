/**
 * SSH Key Generation
 *
 * Generate SSH key pairs in OpenSSH format using Web Crypto API.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { pbkdf as bcryptPbkdf } from 'bcrypt-pbkdf';
import { randomBytes } from './crypto/mod.ts';
import { CIPHER_INFO } from './protocol/constants.ts';
import { Ber, BerReader } from './utils/ber.ts';
import { allocBytes, concatBytes, fromString, toBase64, writeUInt32BE } from './utils/binary.ts';

const SALT_LEN = 16;
const DEFAULT_ROUNDS = 16;

/**
 * Key generation options
 */
export interface KeyGenOptions {
  /** Number of bits (required for RSA and ECDSA) */
  bits?: number;
  /** Comment to include in the key */
  comment?: string;
  /** Output format ('new' for OpenSSH format) */
  format?: 'new';
  /** Passphrase to encrypt private key */
  passphrase?: string | Uint8Array;
  /** Cipher to use for encryption */
  cipher?: string;
  /** Number of bcrypt rounds for key derivation */
  rounds?: number;
}

/**
 * Generated key pair
 */
export interface KeyPair {
  /** Private key in PEM format */
  private: string;
  /** Public key in OpenSSH format */
  public: string;
}

/**
 * Parsed key components
 */
interface ParsedKeys {
  sshName: string;
  priv: Uint8Array;
  pub: Uint8Array;
}

/**
 * Encryption info for private key
 */
interface EncryptionInfo {
  cipher: (typeof CIPHER_INFO)[keyof typeof CIPHER_INFO];
  cipherName: string;
  kdfName: string;
  kdfOptions: Uint8Array;
  key: Uint8Array;
  iv: Uint8Array;
}

/**
 * Generate RSA key pair using Web Crypto
 */
async function generateRSAKeys(bits: number): Promise<{ pub: Uint8Array; priv: Uint8Array }> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  const pub = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  return { pub, priv };
}

/**
 * Generate ECDSA key pair using Web Crypto
 */
async function generateECDSAKeys(
  bits: number,
): Promise<{ pub: Uint8Array; priv: Uint8Array }> {
  let namedCurve: string;
  switch (bits) {
    case 256:
      namedCurve = 'P-256';
      break;
    case 384:
      namedCurve = 'P-384';
      break;
    case 521:
      namedCurve = 'P-521';
      break;
    default:
      throw new Error('ECDSA bits must be 256, 384, or 521');
  }

  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve,
    },
    true,
    ['sign', 'verify'],
  );

  const pub = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  return { pub, priv };
}

/**
 * Generate Ed25519 key pair using @noble/curves
 */
function generateEd25519Keys(): { pub: Uint8Array; priv: Uint8Array } {
  const privKey = ed25519.utils.randomPrivateKey();
  const pubKey = ed25519.getPublicKey(privKey);

  return { pub: pubKey, priv: privKey };
}

/**
 * Parse DER-encoded keys to OpenSSH format
 */
function parseDERs(keyType: string, pub: Uint8Array, priv: Uint8Array): ParsedKeys {
  switch (keyType) {
    case 'rsa': {
      // Parse PKCS8 private key
      let reader = new BerReader(priv);
      reader.readSequence();

      // Version
      if (reader.readInt() !== 0) {
        throw new Error('Unsupported version in RSA private key');
      }

      // Algorithm
      reader.readSequence();
      if (reader.readOID() !== '1.2.840.113549.1.1.1') {
        throw new Error('Bad RSA private OID');
      }
      // Algorithm parameters (RSA has none)
      if (reader.readByte() !== Ber.Null) {
        throw new Error('Malformed RSA private key (expected null)');
      }
      if (reader.readByte() !== 0x00) {
        throw new Error('Malformed RSA private key (expected zero-length null)');
      }

      reader = new BerReader(reader.readString(Ber.OctetString, true)!);
      reader.readSequence();
      if (reader.readInt() !== 0) {
        throw new Error('Unsupported version in RSA private key');
      }

      const n = new Uint8Array(reader.readString(Ber.Integer, true)!);
      const e = new Uint8Array(reader.readString(Ber.Integer, true)!);
      const d = new Uint8Array(reader.readString(Ber.Integer, true)!);
      const p = new Uint8Array(reader.readString(Ber.Integer, true)!);
      const q = new Uint8Array(reader.readString(Ber.Integer, true)!);
      reader.readString(Ber.Integer, true); // dmp1
      reader.readString(Ber.Integer, true); // dmq1
      const iqmp = new Uint8Array(reader.readString(Ber.Integer, true)!);

      // OpenSSH RSA private key format
      const keyName = fromString('ssh-rsa');
      const privBuf = allocBytes(
        4 + keyName.length + 4 + n.length + 4 + e.length + 4 + d.length + 4 + iqmp.length + 4 +
          p.length + 4 + q.length,
      );
      let pos = 0;

      writeUInt32BE(privBuf, keyName.length, pos);
      pos += 4;
      privBuf.set(keyName, pos);
      pos += keyName.length;
      writeUInt32BE(privBuf, n.length, pos);
      pos += 4;
      privBuf.set(n, pos);
      pos += n.length;
      writeUInt32BE(privBuf, e.length, pos);
      pos += 4;
      privBuf.set(e, pos);
      pos += e.length;
      writeUInt32BE(privBuf, d.length, pos);
      pos += 4;
      privBuf.set(d, pos);
      pos += d.length;
      writeUInt32BE(privBuf, iqmp.length, pos);
      pos += 4;
      privBuf.set(iqmp, pos);
      pos += iqmp.length;
      writeUInt32BE(privBuf, p.length, pos);
      pos += 4;
      privBuf.set(p, pos);
      pos += p.length;
      writeUInt32BE(privBuf, q.length, pos);
      pos += 4;
      privBuf.set(q, pos);

      // OpenSSH RSA public key format
      const pubBuf = allocBytes(4 + keyName.length + 4 + e.length + 4 + n.length);
      pos = 0;

      writeUInt32BE(pubBuf, keyName.length, pos);
      pos += 4;
      pubBuf.set(keyName, pos);
      pos += keyName.length;
      writeUInt32BE(pubBuf, e.length, pos);
      pos += 4;
      pubBuf.set(e, pos);
      pos += e.length;
      writeUInt32BE(pubBuf, n.length, pos);
      pos += 4;
      pubBuf.set(n, pos);

      return { sshName: 'ssh-rsa', priv: privBuf, pub: pubBuf };
    }

    case 'ec': {
      // Parse SPKI public key
      let reader = new BerReader(pub);
      reader.readSequence();

      reader.readSequence();
      if (reader.readOID() !== '1.2.840.10045.2.1') {
        throw new Error('Bad ECDSA public OID');
      }
      reader.readOID(); // Skip curve OID
      let pubBin = new Uint8Array(reader.readString(Ber.BitString, true)!);
      {
        let i = 0;
        for (; i < pubBin.length && pubBin[i] === 0x00; ++i);
        if (i > 0) pubBin = pubBin.subarray(i);
      }

      // Parse PKCS8 private key
      reader = new BerReader(priv);
      reader.readSequence();

      if (reader.readInt() !== 0) {
        throw new Error('Unsupported version in ECDSA private key');
      }

      reader.readSequence();
      if (reader.readOID() !== '1.2.840.10045.2.1') {
        throw new Error('Bad ECDSA private OID');
      }

      const curveOID = reader.readOID();
      let sshCurveName: string;
      switch (curveOID) {
        case '1.2.840.10045.3.1.7':
          sshCurveName = 'nistp256';
          break;
        case '1.3.132.0.34':
          sshCurveName = 'nistp384';
          break;
        case '1.3.132.0.35':
          sshCurveName = 'nistp521';
          break;
        default:
          throw new Error('Unsupported curve in ECDSA private key');
      }

      reader = new BerReader(reader.readString(Ber.OctetString, true)!);
      reader.readSequence();

      if (reader.readInt() !== 1) {
        throw new Error('Unsupported version in ECDSA private key');
      }

      // Add leading zero byte to prevent negative bignum
      const privBinRaw = new Uint8Array(reader.readString(Ber.OctetString, true)!);
      const privBin = concatBytes([new Uint8Array([0x00]), privBinRaw]);

      // OpenSSH ECDSA private key format
      const keyName = fromString(`ecdsa-sha2-${sshCurveName}`);
      const curveNameBin = fromString(sshCurveName);
      const privBuf = allocBytes(
        4 + keyName.length + 4 + curveNameBin.length + 4 + pubBin.length + 4 + privBin.length,
      );
      let pos = 0;

      writeUInt32BE(privBuf, keyName.length, pos);
      pos += 4;
      privBuf.set(keyName, pos);
      pos += keyName.length;
      writeUInt32BE(privBuf, curveNameBin.length, pos);
      pos += 4;
      privBuf.set(curveNameBin, pos);
      pos += curveNameBin.length;
      writeUInt32BE(privBuf, pubBin.length, pos);
      pos += 4;
      privBuf.set(pubBin, pos);
      pos += pubBin.length;
      writeUInt32BE(privBuf, privBin.length, pos);
      pos += 4;
      privBuf.set(privBin, pos);

      // OpenSSH ECDSA public key format
      const pubBuf = allocBytes(4 + keyName.length + 4 + curveNameBin.length + 4 + pubBin.length);
      pos = 0;

      writeUInt32BE(pubBuf, keyName.length, pos);
      pos += 4;
      pubBuf.set(keyName, pos);
      pos += keyName.length;
      writeUInt32BE(pubBuf, curveNameBin.length, pos);
      pos += 4;
      pubBuf.set(curveNameBin, pos);
      pos += curveNameBin.length;
      writeUInt32BE(pubBuf, pubBin.length, pos);
      pos += 4;
      pubBuf.set(pubBin, pos);

      return { sshName: `ecdsa-sha2-${sshCurveName}`, priv: privBuf, pub: pubBuf };
    }

    case 'ed25519': {
      // For ed25519, pub and priv are raw bytes from @noble/curves
      const pubBin = pub;
      const privBin = priv;

      // OpenSSH ed25519 private key format
      const keyName = fromString('ssh-ed25519');
      const privBuf = allocBytes(
        4 + keyName.length + 4 + pubBin.length + 4 + (privBin.length + pubBin.length),
      );
      let pos = 0;

      writeUInt32BE(privBuf, keyName.length, pos);
      pos += 4;
      privBuf.set(keyName, pos);
      pos += keyName.length;
      writeUInt32BE(privBuf, pubBin.length, pos);
      pos += 4;
      privBuf.set(pubBin, pos);
      pos += pubBin.length;
      writeUInt32BE(privBuf, privBin.length + pubBin.length, pos);
      pos += 4;
      privBuf.set(privBin, pos);
      pos += privBin.length;
      privBuf.set(pubBin, pos);

      // OpenSSH ed25519 public key format
      const pubBuf = allocBytes(4 + keyName.length + 4 + pubBin.length);
      pos = 0;

      writeUInt32BE(pubBuf, keyName.length, pos);
      pos += 4;
      pubBuf.set(keyName, pos);
      pos += keyName.length;
      writeUInt32BE(pubBuf, pubBin.length, pos);
      pos += 4;
      pubBuf.set(pubBin, pos);

      return { sshName: 'ssh-ed25519', priv: privBuf, pub: pubBuf };
    }

    default:
      throw new Error(`Unsupported key type: ${keyType}`);
  }
}

/**
 * Encrypt data using AES cipher
 */
async function encryptPrivateKey(
  data: Uint8Array,
  cipherInfo: (typeof CIPHER_INFO)[keyof typeof CIPHER_INFO],
  key: Uint8Array,
  iv: Uint8Array,
): Promise<{ encrypted: Uint8Array; authTag: Uint8Array }> {
  // Map cipher names to Web Crypto algorithm names
  let algorithm: string;
  if (cipherInfo.sslName.includes('gcm')) {
    algorithm = 'AES-GCM';
  } else if (cipherInfo.sslName.includes('ctr')) {
    algorithm = 'AES-CTR';
  } else if (cipherInfo.sslName.includes('cbc')) {
    algorithm = 'AES-CBC';
  } else {
    throw new Error(`Unsupported cipher: ${cipherInfo.sslName}`);
  }

  // Convert to standard ArrayBuffer for Web Crypto compatibility
  const keyBuffer = new Uint8Array(key).buffer;
  const ivBuffer = new Uint8Array(iv);
  const dataBuffer = new Uint8Array(data);

  const cryptoKey = await crypto.subtle.importKey('raw', keyBuffer, { name: algorithm }, false, [
    'encrypt',
  ]);

  let encrypted: ArrayBuffer;
  let authTag = new Uint8Array(0);

  if (algorithm === 'AES-GCM') {
    encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: ivBuffer.buffer, tagLength: 128 },
      cryptoKey,
      dataBuffer,
    );
    // For GCM, the auth tag is appended to the ciphertext
    const fullOutput = new Uint8Array(encrypted);
    const tagLen = cipherInfo.authLen || 16;
    authTag = new Uint8Array(fullOutput.subarray(fullOutput.length - tagLen));
    encrypted = fullOutput.subarray(0, fullOutput.length - tagLen).buffer;
  } else if (algorithm === 'AES-CTR') {
    encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter: ivBuffer.buffer, length: 64 },
      cryptoKey,
      dataBuffer,
    );
  } else {
    encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: ivBuffer.buffer },
      cryptoKey,
      dataBuffer,
    );
  }

  return { encrypted: new Uint8Array(encrypted), authTag };
}

/**
 * Convert keys to OpenSSH format
 */
async function convertKeys(
  keyType: string,
  pub: Uint8Array,
  priv: Uint8Array,
  opts?: KeyGenOptions,
): Promise<KeyPair> {
  const format = opts?.format || 'new';
  let encrypted: EncryptionInfo | undefined;
  const comment = opts?.comment || '';

  if (opts?.passphrase) {
    let passphrase: Uint8Array;
    if (typeof opts.passphrase === 'string') {
      passphrase = fromString(opts.passphrase);
    } else {
      passphrase = opts.passphrase;
    }

    if (!opts.cipher) {
      throw new Error('Missing cipher name');
    }

    const cipher = CIPHER_INFO[opts.cipher as keyof typeof CIPHER_INFO];
    if (!cipher) {
      throw new Error('Invalid cipher name');
    }

    if (format === 'new') {
      const rounds = opts.rounds && opts.rounds > 0 ? opts.rounds : DEFAULT_ROUNDS;
      const gen = allocBytes(cipher.keyLen + cipher.ivLen);
      const salt = randomBytes(SALT_LEN);

      const r = bcryptPbkdf(
        passphrase,
        passphrase.length,
        salt,
        salt.length,
        gen,
        gen.length,
        rounds,
      );
      if (r !== 0) {
        throw new Error('Failed to generate information to encrypt key');
      }

      // KDF options: string salt, uint32 rounds
      const kdfOptions = allocBytes(4 + salt.length + 4);
      writeUInt32BE(kdfOptions, salt.length, 0);
      kdfOptions.set(salt, 4);
      writeUInt32BE(kdfOptions, rounds, 4 + salt.length);

      encrypted = {
        cipher,
        cipherName: opts.cipher,
        kdfName: 'bcrypt',
        kdfOptions,
        key: gen.subarray(0, cipher.keyLen),
        iv: gen.subarray(cipher.keyLen),
      };
    }
  }

  if (format !== 'new') {
    throw new Error('Invalid output key format');
  }

  // Build OpenSSH private key format
  let privateB64 = '-----BEGIN OPENSSH PRIVATE KEY-----\n';

  const cipherName = fromString(encrypted ? encrypted.cipherName : 'none');
  const kdfName = fromString(encrypted ? encrypted.kdfName : 'none');
  const kdfOptions = encrypted ? encrypted.kdfOptions : new Uint8Array(0);
  const blockLen = encrypted ? encrypted.cipher.blockLen : 8;

  const parsed = parseDERs(keyType, pub, priv);

  const checkInt = randomBytes(4);
  const commentBin = fromString(comment);
  const privBlobLen = 4 + 4 + parsed.priv.length + 4 + commentBin.length;

  // Calculate padding
  const paddingNeeded = blockLen - (privBlobLen % blockLen);
  const padding = allocBytes(paddingNeeded === blockLen ? 0 : paddingNeeded);
  for (let i = 0; i < padding.length; ++i) {
    padding[i] = (i + 1) & 0xff;
  }

  // Build private blob
  let privBlob = allocBytes(privBlobLen + padding.length);
  let pos = 0;
  privBlob.set(checkInt, pos);
  pos += 4;
  privBlob.set(checkInt, pos);
  pos += 4;
  privBlob.set(parsed.priv, pos);
  pos += parsed.priv.length;
  writeUInt32BE(privBlob, commentBin.length, pos);
  pos += 4;
  privBlob.set(commentBin, pos);
  pos += commentBin.length;
  privBlob.set(padding, pos);

  let extra: Uint8Array = new Uint8Array(0);
  if (encrypted) {
    const result = await encryptPrivateKey(privBlob, encrypted.cipher, encrypted.key, encrypted.iv);
    privBlob = result.encrypted;
    extra = new Uint8Array(result.authTag);
    // Clear sensitive data
    encrypted.key.fill(0);
    encrypted.iv.fill(0);
  }

  // Build final private key binary
  const magicBytes = fromString('openssh-key-v1\0');
  const privBin = allocBytes(
    magicBytes.length +
      4 +
      cipherName.length +
      4 +
      kdfName.length +
      4 +
      kdfOptions.length +
      4 +
      4 +
      parsed.pub.length +
      4 +
      privBlob.length +
      extra.length,
  );

  pos = 0;
  privBin.set(magicBytes, pos);
  pos += magicBytes.length;
  writeUInt32BE(privBin, cipherName.length, pos);
  pos += 4;
  privBin.set(cipherName, pos);
  pos += cipherName.length;
  writeUInt32BE(privBin, kdfName.length, pos);
  pos += 4;
  privBin.set(kdfName, pos);
  pos += kdfName.length;
  writeUInt32BE(privBin, kdfOptions.length, pos);
  pos += 4;
  privBin.set(kdfOptions, pos);
  pos += kdfOptions.length;
  writeUInt32BE(privBin, 1, pos); // Number of keys
  pos += 4;
  writeUInt32BE(privBin, parsed.pub.length, pos);
  pos += 4;
  privBin.set(parsed.pub, pos);
  pos += parsed.pub.length;
  writeUInt32BE(privBin, privBlob.length, pos);
  pos += 4;
  privBin.set(privBlob, pos);
  pos += privBlob.length;
  privBin.set(extra, pos);

  // Format as PEM
  const b64 = toBase64(privBin);
  let formatted = b64.replace(/.{64}/g, '$&\n');
  if (b64.length % 64) {
    formatted += '\n';
  }
  privateB64 += formatted;
  privateB64 += '-----END OPENSSH PRIVATE KEY-----\n';

  // Build public key
  const publicB64 = `${parsed.sshName} ${toBase64(parsed.pub)}${comment ? ` ${comment}` : ''}`;

  return {
    private: privateB64,
    public: publicB64,
  };
}

/**
 * Generate an SSH key pair
 *
 * @param keyType - Type of key to generate: 'rsa', 'ecdsa', or 'ed25519'
 * @param opts - Key generation options
 * @returns The generated key pair
 */
export async function generateKeyPair(keyType: string, opts?: KeyGenOptions): Promise<KeyPair> {
  if (typeof keyType !== 'string') {
    throw new TypeError('Key type must be a string');
  }

  const type = keyType.toLowerCase();

  switch (type) {
    case 'rsa': {
      if (!opts?.bits) {
        throw new TypeError('Missing bits option for RSA key');
      }
      if (!Number.isInteger(opts.bits)) {
        throw new TypeError('RSA bits must be an integer');
      }
      if (opts.bits <= 0 || opts.bits > 16384) {
        throw new RangeError('RSA bits must be non-zero and <= 16384');
      }
      const { pub, priv } = await generateRSAKeys(opts.bits);
      return convertKeys('rsa', pub, priv, opts);
    }

    case 'ecdsa': {
      if (!opts?.bits) {
        throw new TypeError('Missing bits option for ECDSA key');
      }
      if (!Number.isInteger(opts.bits)) {
        throw new TypeError('ECDSA bits must be an integer');
      }
      const { pub, priv } = await generateECDSAKeys(opts.bits);
      return convertKeys('ec', pub, priv, opts);
    }

    case 'ed25519': {
      const { pub, priv } = generateEd25519Keys();
      return convertKeys('ed25519', pub, priv, opts);
    }

    default:
      throw new Error(`Unsupported key type: ${keyType}`);
  }
}
