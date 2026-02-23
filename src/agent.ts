/**
 * SSH Agent Protocol
 *
 * Implements the SSH agent protocol for key management and signing operations.
 * Supports OpenSSH agent communication over Unix sockets.
 */

import { isParsedKey, type ParsedKey, parseKey } from './protocol/keyParser.ts';
import { makeBufferParser } from './protocol/utils.ts';
import {
  allocBytes,
  concatBytes,
  fromString,
  readUInt32BE,
  writeUInt32BE,
} from './utils/binary.ts';
import { EventEmitter } from './utils/events.ts';

// Agent protocol message types
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_FAILURE = 5;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENT_SIGN_RESPONSE = 14;

// Signature flags
const SSH_AGENT_RSA_SHA2_256 = 1 << 1;
const SSH_AGENT_RSA_SHA2_512 = 1 << 2;

const binaryParser = makeBufferParser();

/**
 * Sign options
 */
export interface SignOptions {
  hash?: 'sha256' | 'sha512';
}

/**
 * Base agent interface
 */
export interface Agent {
  /** Get available identities (public keys) */
  getIdentities(): Promise<ParsedKey[]>;

  /** Sign data with a key */
  sign(
    pubKey: ParsedKey | Uint8Array,
    data: Uint8Array,
    options?: SignOptions,
  ): Promise<Uint8Array>;
}

/**
 * Base agent class with default implementations
 */
export class BaseAgent implements Agent {
  async getIdentities(): Promise<ParsedKey[]> {
    throw new Error('Missing getIdentities() implementation');
  }

  async sign(
    _pubKey: ParsedKey | Uint8Array,
    _data: Uint8Array,
    _options?: SignOptions,
  ): Promise<Uint8Array> {
    throw new Error('Missing sign() implementation');
  }
}

/**
 * OpenSSH agent that connects via Unix socket
 */
export class OpenSSHAgent extends BaseAgent {
  private socketPath: string;

  constructor(socketPath: string) {
    super();
    this.socketPath = socketPath;
  }

  /**
   * Get a connection to the agent
   */
  private async getConnection(): Promise<Deno.Conn> {
    try {
      return await Deno.connect({
        path: this.socketPath,
        transport: 'unix',
      });
    } catch {
      throw new Error('Failed to connect to agent');
    }
  }

  /**
   * Send a message to the agent and get response
   */
  private async sendMessage(conn: Deno.Conn, message: Uint8Array): Promise<Uint8Array> {
    // Write message with length prefix
    const lenBuf = allocBytes(4);
    writeUInt32BE(lenBuf, message.length, 0);
    await conn.write(concatBytes([lenBuf, message]));

    // Read response length
    const respLenBuf = new Uint8Array(4);
    let n = await conn.read(respLenBuf);
    if (n === null || n < 4) {
      throw new Error('Failed to read response length');
    }

    const respLen = readUInt32BE(respLenBuf, 0);
    if (respLen > 256 * 1024) {
      throw new Error('Response too large');
    }

    // Read response
    const response = new Uint8Array(respLen);
    let offset = 0;
    while (offset < respLen) {
      n = await conn.read(response.subarray(offset));
      if (n === null) {
        throw new Error('Connection closed while reading response');
      }
      offset += n;
    }

    return response;
  }

  override async getIdentities(): Promise<ParsedKey[]> {
    const conn = await this.getConnection();
    try {
      // Send SSH_AGENTC_REQUEST_IDENTITIES
      const request = new Uint8Array([SSH_AGENTC_REQUEST_IDENTITIES]);
      const response = await this.sendMessage(conn, request);

      if (response.length === 0 || response[0] === SSH_AGENT_FAILURE) {
        throw new Error('Agent responded with failure');
      }

      if (response[0] !== SSH_AGENT_IDENTITIES_ANSWER) {
        throw new Error('Agent responded with unexpected message type');
      }

      // Parse response
      binaryParser.init(response, 1);

      const numKeys = binaryParser.readUInt32BE();
      if (numKeys === undefined) {
        binaryParser.clear();
        throw new Error('Malformed agent response');
      }

      const keys: ParsedKey[] = [];
      for (let i = 0; i < numKeys; ++i) {
        const keyBlob = binaryParser.readString();
        if (keyBlob === undefined) {
          binaryParser.clear();
          throw new Error('Malformed agent response');
        }

        const comment = binaryParser.readString(true) as string | undefined;
        if (comment === undefined) {
          binaryParser.clear();
          throw new Error('Malformed agent response');
        }

        const pubKey = parseKey(keyBlob as Uint8Array);
        if (pubKey instanceof Error) {
          // Skip unsupported key types
          continue;
        }

        pubKey.comment = pubKey.comment || comment;
        keys.push(pubKey);
      }

      binaryParser.clear();
      return keys;
    } finally {
      try {
        conn.close();
      } catch {
        // Ignore close errors
      }
    }
  }

  override async sign(
    pubKey: ParsedKey | Uint8Array,
    data: Uint8Array,
    options?: SignOptions,
  ): Promise<Uint8Array> {
    const conn = await this.getConnection();
    try {
      // Parse key if needed
      let key: ParsedKey;
      if (pubKey instanceof Uint8Array) {
        const parsed = parseKey(pubKey);
        if (parsed instanceof Error) {
          throw new Error('Invalid public key');
        }
        key = parsed;
      } else {
        key = pubKey;
      }

      // Determine flags
      let flags = 0;
      if (key.type === 'ssh-rsa' && options?.hash) {
        if (options.hash === 'sha256') {
          flags = SSH_AGENT_RSA_SHA2_256;
        } else if (options.hash === 'sha512') {
          flags = SSH_AGENT_RSA_SHA2_512;
        }
      }

      // Get public key blob
      const keyBlob = key.getPublicSSH();
      if (keyBlob === null) {
        throw new Error('Failed to get public key blob');
      }

      // Build request
      const requestLen = 1 + 4 + keyBlob.length + 4 + data.length + 4;
      const request = allocBytes(requestLen);
      let pos = 0;

      request[pos++] = SSH_AGENTC_SIGN_REQUEST;

      writeUInt32BE(request, keyBlob.length, pos);
      pos += 4;
      request.set(keyBlob, pos);
      pos += keyBlob.length;

      writeUInt32BE(request, data.length, pos);
      pos += 4;
      request.set(data, pos);
      pos += data.length;

      writeUInt32BE(request, flags, pos);

      const response = await this.sendMessage(conn, request);

      if (response.length === 0 || response[0] === SSH_AGENT_FAILURE) {
        throw new Error('Agent responded with failure');
      }

      if (response[0] !== SSH_AGENT_SIGN_RESPONSE) {
        throw new Error('Agent responded with unexpected message type');
      }

      // Parse signature response
      binaryParser.init(response, 1);
      let signature = binaryParser.readString() as Uint8Array | undefined;
      binaryParser.clear();

      if (signature === undefined) {
        throw new Error('Malformed agent response');
      }

      // Strip the algorithm prefix from OpenSSH signature format
      binaryParser.init(signature, 0);
      binaryParser.readString(true); // Skip algorithm
      signature = binaryParser.readString() as Uint8Array | undefined;
      binaryParser.clear();

      if (signature === undefined) {
        throw new Error('Malformed OpenSSH signature format');
      }

      return signature;
    } finally {
      try {
        conn.close();
      } catch {
        // Ignore close errors
      }
    }
  }
}

/**
 * Agent context for iterating through agent keys
 */
export class AgentContext {
  private agent: Agent;
  private keys: ParsedKey[] | null = null;
  private keyIndex = -1;
  private initPromise: Promise<void> | null = null;

  constructor(agent: Agent | string) {
    if (typeof agent === 'string') {
      this.agent = createAgent(agent);
    } else if (isAgent(agent)) {
      this.agent = agent;
    } else {
      throw new Error('Invalid agent argument');
    }
  }

  /**
   * Initialize the agent context by fetching keys
   */
  async init(): Promise<void> {
    if (this.keys !== null) {
      return;
    }

    if (this.initPromise !== null) {
      return this.initPromise;
    }

    this.initPromise = (async () => {
      const keys = await this.agent.getIdentities();

      if (!Array.isArray(keys)) {
        throw new Error('Agent implementation failed to provide keys');
      }

      const validKeys: ParsedKey[] = [];
      for (const key of keys) {
        if (isParsedKey(key)) {
          validKeys.push(key);
        } else {
          const parsed = parseKey(key as unknown as Uint8Array);
          if (!(parsed instanceof Error)) {
            validKeys.push(parsed);
          }
        }
      }

      this.keys = validKeys;
      this.keyIndex = -1;
    })();

    try {
      await this.initPromise;
    } finally {
      this.initPromise = null;
    }
  }

  /**
   * Get the next key in the list
   */
  nextKey(): ParsedKey | false {
    if (this.keys === null || ++this.keyIndex >= this.keys.length) {
      return false;
    }
    return this.keys[this.keyIndex];
  }

  /**
   * Get the current key
   */
  currentKey(): ParsedKey | null {
    if (this.keys === null || this.keyIndex >= this.keys.length) {
      return null;
    }
    return this.keys[this.keyIndex];
  }

  /**
   * Get current position in key list
   */
  pos(): number {
    if (this.keys === null || this.keyIndex >= this.keys.length) {
      return -1;
    }
    return this.keyIndex;
  }

  /**
   * Reset key iteration
   */
  reset(): void {
    this.keyIndex = -1;
  }

  /**
   * Sign data with the agent
   */
  async sign(
    pubKey: ParsedKey | Uint8Array,
    data: Uint8Array,
    options?: SignOptions,
  ): Promise<Uint8Array> {
    return this.agent.sign(pubKey, data, options);
  }
}

/**
 * Agent protocol events
 */
export interface AgentProtocolEvents {
  error: [Error];
  identities: [AgentInboundRequest];
  sign: [AgentInboundRequest, ParsedKey, Uint8Array, { hash?: string }];
}

/**
 * Inbound request from client
 */
export class AgentInboundRequest {
  private type: number;
  private response: Uint8Array | undefined;
  private context: string | undefined;

  constructor(type: number, context?: string) {
    this.type = type;
    this.context = context;
  }

  hasResponded(): boolean {
    return this.response !== undefined;
  }

  getType(): number {
    return this.type;
  }

  getContext(): string | undefined {
    return this.context;
  }

  setResponse(data: Uint8Array): void {
    this.response = data;
  }

  getResponse(): Uint8Array | undefined {
    return this.response;
  }
}

/**
 * Agent protocol handler for server-side agent forwarding
 */
export class AgentProtocol extends EventEmitter<AgentProtocolEvents> {
  private isClient: boolean;
  private buffer: Uint8Array | null = null;
  private messageLen = -1;
  private requests: AgentInboundRequest[] = [];
  private pendingCallbacks: Map<
    number,
    { type: number; resolve: (value: unknown) => void; reject: (err: Error) => void }
  > = new Map();
  private requestId = 0;

  constructor(isClient: boolean) {
    super();
    this.isClient = isClient;
  }

  /**
   * Process incoming data
   */
  processData(data: Uint8Array): Uint8Array[] {
    if (this.buffer === null) {
      this.buffer = data;
    } else {
      this.buffer = concatBytes([this.buffer, data]);
    }

    const responses: Uint8Array[] = [];
    const buffer = this.buffer;
    const bufferLen = buffer.length;
    let p = 0;

    while (p < bufferLen) {
      // Wait for length + type
      if (bufferLen - p < 5) {
        break;
      }

      if (this.messageLen === -1) {
        this.messageLen = readUInt32BE(buffer, p);
      }

      // Check if we have the entire message
      if (bufferLen - p < 4 + this.messageLen) {
        break;
      }

      const msgType = buffer[p + 4];
      const msgStart = p + 5;
      const msgEnd = p + 4 + this.messageLen;

      if (this.isClient) {
        // Handle server responses
        const pending = this.pendingCallbacks.get(this.requestId - 1);
        if (pending) {
          this.pendingCallbacks.delete(this.requestId - 1);

          if (msgType === SSH_AGENT_FAILURE) {
            pending.reject(new Error('Agent responded with failure'));
          } else if (
            msgType === SSH_AGENT_IDENTITIES_ANSWER &&
            pending.type === SSH_AGENTC_REQUEST_IDENTITIES
          ) {
            pending.resolve(buffer.subarray(msgStart - 1, msgEnd));
          } else if (
            msgType === SSH_AGENT_SIGN_RESPONSE && pending.type === SSH_AGENTC_SIGN_REQUEST
          ) {
            pending.resolve(buffer.subarray(msgStart - 1, msgEnd));
          } else {
            pending.reject(new Error('Unexpected response type'));
          }
        }
      } else {
        // Handle client requests
        if (msgType === SSH_AGENTC_REQUEST_IDENTITIES) {
          const req = new AgentInboundRequest(msgType);
          this.requests.push(req);
          this.emit('identities', req);
        } else if (msgType === SSH_AGENTC_SIGN_REQUEST) {
          binaryParser.init(buffer, msgStart);
          const keyBlob = binaryParser.readString() as Uint8Array | undefined;
          const signData = binaryParser.readString() as Uint8Array | undefined;
          const flagsVal = binaryParser.readUInt32BE();
          binaryParser.clear();

          if (keyBlob === undefined || signData === undefined || flagsVal === undefined) {
            const req = new AgentInboundRequest(msgType);
            this.requests.push(req);
            responses.push(this.createFailureResponse(req));
          } else {
            const pubKey = parseKey(keyBlob);
            if (pubKey instanceof Error) {
              const req = new AgentInboundRequest(msgType);
              this.requests.push(req);
              responses.push(this.createFailureResponse(req));
            } else {
              const flags: { hash?: string } = {};
              let ctx: string | undefined;

              if (pubKey.type === 'ssh-rsa') {
                if (flagsVal & SSH_AGENT_RSA_SHA2_256) {
                  ctx = 'rsa-sha2-256';
                  flags.hash = 'sha256';
                } else if (flagsVal & SSH_AGENT_RSA_SHA2_512) {
                  ctx = 'rsa-sha2-512';
                  flags.hash = 'sha512';
                }
              }
              if (ctx === undefined) {
                ctx = pubKey.type;
              }

              const req = new AgentInboundRequest(msgType, ctx);
              this.requests.push(req);
              this.emit('sign', req, pubKey, signData, flags);
            }
          }
        } else {
          const req = new AgentInboundRequest(msgType);
          this.requests.push(req);
          responses.push(this.createFailureResponse(req));
        }
      }

      // Move to next message
      p = msgEnd;
      this.messageLen = -1;
    }

    // Update buffer
    if (p === bufferLen) {
      this.buffer = null;
    } else if (p > 0) {
      this.buffer = buffer.subarray(p);
    }

    return responses;
  }

  /**
   * Create a failure response
   */
  createFailureResponse(req: AgentInboundRequest): Uint8Array {
    if (req.hasResponded()) {
      return new Uint8Array(0);
    }

    const buf = allocBytes(5);
    writeUInt32BE(buf, 1, 0);
    buf[4] = SSH_AGENT_FAILURE;
    req.setResponse(buf);
    return buf;
  }

  /**
   * Create an identities response
   */
  createIdentitiesResponse(req: AgentInboundRequest, keys: ParsedKey[]): Uint8Array {
    if (req.hasResponded()) {
      return new Uint8Array(0);
    }

    if (req.getType() !== SSH_AGENTC_REQUEST_IDENTITIES) {
      throw new Error('Invalid response to request');
    }

    // Calculate total size
    let totalSize = 1 + 4; // type + nkeys
    const keyData: { pub: Uint8Array; comment: Uint8Array }[] = [];

    for (const key of keys) {
      if (!isParsedKey(key)) continue;

      const pub = key.getPublicSSH();
      if (pub === null) continue;

      const comment = fromString(key.comment || '');

      totalSize += 4 + pub.length + 4 + comment.length;
      keyData.push({ pub, comment });
    }

    const buf = allocBytes(4 + totalSize);
    let pos = 0;

    writeUInt32BE(buf, totalSize, pos);
    pos += 4;

    buf[pos++] = SSH_AGENT_IDENTITIES_ANSWER;

    writeUInt32BE(buf, keyData.length, pos);
    pos += 4;

    for (const { pub, comment } of keyData) {
      writeUInt32BE(buf, pub.length, pos);
      pos += 4;
      buf.set(pub, pos);
      pos += pub.length;

      writeUInt32BE(buf, comment.length, pos);
      pos += 4;
      buf.set(comment, pos);
      pos += comment.length;
    }

    req.setResponse(buf);
    return buf;
  }

  /**
   * Create a sign response
   */
  createSignResponse(req: AgentInboundRequest, signature: Uint8Array): Uint8Array {
    if (req.hasResponded()) {
      return new Uint8Array(0);
    }

    if (req.getType() !== SSH_AGENTC_SIGN_REQUEST) {
      throw new Error('Invalid response to request');
    }

    const sigFormat = fromString(req.getContext() || 'ssh-rsa');
    const totalSigLen = 4 + sigFormat.length + 4 + signature.length;
    const totalLen = 1 + 4 + totalSigLen;

    const buf = allocBytes(4 + totalLen);
    let pos = 0;

    writeUInt32BE(buf, totalLen, pos);
    pos += 4;

    buf[pos++] = SSH_AGENT_SIGN_RESPONSE;

    writeUInt32BE(buf, totalSigLen, pos);
    pos += 4;

    writeUInt32BE(buf, sigFormat.length, pos);
    pos += 4;
    buf.set(sigFormat, pos);
    pos += sigFormat.length;

    writeUInt32BE(buf, signature.length, pos);
    pos += 4;
    buf.set(signature, pos);

    req.setResponse(buf);
    return buf;
  }
}

/**
 * Check if value is an Agent instance
 */
export function isAgent(val: unknown): val is Agent {
  return val instanceof BaseAgent || (
    typeof val === 'object' &&
    val !== null &&
    typeof (val as Agent).getIdentities === 'function' &&
    typeof (val as Agent).sign === 'function'
  );
}

/**
 * Create an agent based on the socket path
 */
export function createAgent(path: string): Agent {
  // For now, only support OpenSSH agent
  // Windows-specific agents (Pageant, Cygwin) would need platform-specific handling
  return new OpenSSHAgent(path);
}
