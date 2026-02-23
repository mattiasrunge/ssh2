/**
 * ChaCha20-Poly1305 Cipher implementation for SSH
 *
 * Uses @noble/ciphers for the underlying ChaCha20 and Poly1305 implementations.
 * SSH's chacha20-poly1305@openssh.com uses a custom construction different from
 * standard AEAD ChaCha20-Poly1305 (RFC 8439).
 */

// Use chacha20orig (DJB format with 8-byte nonce) not chacha20 (IETF format with 12-byte nonce)
// OpenSSH uses DJB ChaCha20 format
import { poly1305 } from '@noble/ciphers/_poly1305';
import { chacha20orig as chacha20 } from '@noble/ciphers/chacha';
import { allocBytes, readUInt32BE, writeUInt32BE } from '../utils/binary.ts';
import type { Cipher, CipherConfig, Decipher, DecipherConfig } from './ciphers.ts';
import { randomFill } from './random.ts';
import { timingSafeEqual } from './utils.ts';

const MAX_PACKET_SIZE = 35000;

/**
 * ChaCha20-Poly1305 Cipher for SSH
 *
 * SSH's chacha20-poly1305@openssh.com uses:
 * - Two 256-bit keys: one for packet length encryption, one for payload
 * - Custom nonce construction using sequence number
 * - Poly1305 MAC over encrypted length + encrypted payload
 */
export class ChaChaPolyCipher implements Cipher {
  outSeqno: number;
  private _onWrite: (data: Uint8Array) => void;
  private _encKeyMain: Uint8Array;
  private _encKeyPktLen: Uint8Array;
  private _dead = false;

  constructor(config: CipherConfig) {
    const enc = config.outbound;
    this.outSeqno = enc.seqno;
    this._onWrite = enc.onWrite;
    // SSH chacha20-poly1305 uses 64 bytes key per OpenSSH cipher-chachapoly.c:
    // main_ctx = key[0:32] - for payload encryption
    // header_ctx = key[32:64] - for length encryption
    this._encKeyMain = enc.cipherKey.subarray(0, 32);
    this._encKeyPktLen = enc.cipherKey.subarray(32, 64);
  }

  free(): void {
    this._dead = true;
  }

  allocPacket(payloadLen: number): Uint8Array {
    let pktLen = 4 + 1 + payloadLen;
    let padLen = 8 - ((pktLen - 4) & (8 - 1));
    if (padLen < 4) padLen += 8;
    pktLen += padLen;

    const packet = allocBytes(pktLen);
    writeUInt32BE(packet, pktLen - 4, 0);
    packet[4] = padLen;
    randomFill(packet, 5 + payloadLen, padLen);

    return packet;
  }

  async encrypt(packet: Uint8Array): Promise<void> {
    if (this._dead) return;

    // Build 8-byte nonce: 64-bit sequence number in big-endian (DJB format)
    const nonce = allocBytes(8);
    // seqno is 32-bit, so upper 4 bytes are 0
    writeUInt32BE(nonce, this.outSeqno, 4);

    // Generate Poly1305 key using ChaCha20 with counter=0
    const polyKeyNonce = new Uint8Array(nonce);
    const zeros32 = allocBytes(32);
    const polyKey = chacha20(this._encKeyMain, polyKeyNonce, zeros32);

    // Encrypt packet length (4 bytes) with length key
    const lenBytes = packet.subarray(0, 4);
    const encryptedLen = chacha20(this._encKeyPktLen, nonce, lenBytes);
    this._onWrite(encryptedLen);

    // Encrypt payload with main key, counter=1
    // ChaCha20 counter starts at 1 for payload encryption
    const payload = packet.subarray(4);
    const encryptedPayload = chacha20(this._encKeyMain, nonce, payload, undefined, 1);
    this._onWrite(encryptedPayload);

    // Calculate Poly1305 MAC over encrypted length + encrypted payload
    // Note: poly1305 from @noble/ciphers takes (message, key) not (key, message)
    const macData = allocBytes(encryptedLen.length + encryptedPayload.length);
    macData.set(encryptedLen, 0);
    macData.set(encryptedPayload, encryptedLen.length);
    const mac = poly1305(macData, polyKey);
    this._onWrite(mac);

    this.outSeqno = (this.outSeqno + 1) >>> 0;
  }
}

/** Payload callback type that supports both sync and async returns */
type PayloadCallback = (
  payload: Uint8Array,
) => void | boolean | number | Promise<void | boolean | number>;

/**
 * ChaCha20-Poly1305 Decipher for SSH
 */
export class ChaChaPolyDecipher implements Decipher {
  inSeqno: number;
  private _onPayload: PayloadCallback;
  private _decKeyMain: Uint8Array;
  private _decKeyPktLen: Uint8Array;

  // State for incremental decryption
  private _len = 0;
  private _lenBuf = allocBytes(4);
  private _lenPos = 0;
  private _packet: Uint8Array | null = null;
  private _pktLen = 0;
  private _mac = allocBytes(16);
  private _macPos = 0;

  constructor(config: DecipherConfig) {
    const dec = config.inbound;
    this.inSeqno = dec.seqno;
    this._onPayload = dec.onPayload;
    // SSH chacha20-poly1305 uses 64 bytes key per OpenSSH cipher-chachapoly.c:
    // main_ctx = key[0:32] - for payload encryption
    // header_ctx = key[32:64] - for length encryption
    this._decKeyMain = dec.decipherKey.subarray(0, 32);
    this._decKeyPktLen = dec.decipherKey.subarray(32, 64);
  }

  free(): void {}

  async decrypt(
    data: Uint8Array,
    p: number,
    dataLen: number,
  ): Promise<void | boolean | number> {
    while (p < dataLen) {
      // Read encrypted packet length (4 bytes)
      if (this._lenPos < 4) {
        const nb = Math.min(4 - this._lenPos, dataLen - p);
        for (let i = 0; i < nb; i++) {
          this._lenBuf[this._lenPos++] = data[p++];
        }
        if (this._lenPos < 4) return;

        // Build 8-byte nonce: 64-bit sequence number in big-endian (DJB format)
        const nonce = allocBytes(8);
        // seqno is 32-bit, so upper 4 bytes are 0
        writeUInt32BE(nonce, this.inSeqno, 4);

        // Decrypt length
        const decryptedLen = chacha20(this._decKeyPktLen, nonce, this._lenBuf);
        this._len = readUInt32BE(decryptedLen, 0);

        if (this._len > MAX_PACKET_SIZE || this._len < 8 || (this._len & 7) !== 0) {
          throw new Error('Bad packet length');
        }
      }

      // Read encrypted payload
      if (this._pktLen < this._len) {
        if (p >= dataLen) return;
        const nb = Math.min(this._len - this._pktLen, dataLen - p);
        const chunk = data.subarray(p, p + nb);
        if (nb === this._len) {
          this._packet = new Uint8Array(chunk);
        } else {
          if (!this._packet) {
            this._packet = allocBytes(this._len);
          }
          this._packet.set(chunk, this._pktLen);
        }
        p += nb;
        this._pktLen += nb;
        if (this._pktLen < this._len || p >= dataLen) return;
      }

      // Read Poly1305 MAC (16 bytes)
      {
        const nb = Math.min(16 - this._macPos, dataLen - p);
        for (let i = 0; i < nb; i++) {
          this._mac[this._macPos++] = data[p++];
        }
        if (this._macPos < 16) return;
      }

      // Build 8-byte nonce: 64-bit sequence number in big-endian (DJB format)
      const nonce = allocBytes(8);
      // seqno is 32-bit, so upper 4 bytes are 0
      writeUInt32BE(nonce, this.inSeqno, 4);

      // Generate Poly1305 key
      const zeros32 = allocBytes(32);
      const polyKey = chacha20(this._decKeyMain, nonce, zeros32);

      // Verify MAC
      // Note: poly1305 from @noble/ciphers takes (message, key) not (key, message)
      const macData = allocBytes(4 + this._packet!.length);
      macData.set(this._lenBuf, 0);
      macData.set(this._packet!, 4);
      const expectedMac = poly1305(macData, polyKey);

      if (!timingSafeEqual(expectedMac, this._mac)) {
        throw new Error('Invalid MAC');
      }

      // Decrypt payload with counter=1
      const decryptedPayload = chacha20(this._decKeyMain, nonce, this._packet!, undefined, 1);

      const padLen = decryptedPayload[0];
      const payload = decryptedPayload.subarray(1, decryptedPayload.length - padLen);

      // Prepare for next packet
      this.inSeqno = (this.inSeqno + 1) >>> 0;
      this._len = 0;
      this._lenPos = 0;
      this._packet = null;
      this._pktLen = 0;
      this._macPos = 0;

      const ret = await this._onPayload(payload);
      if (ret !== undefined) {
        return ret === false ? p : ret;
      }
    }
  }
}
