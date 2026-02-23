/**
 * SSH2 Client
 *
 * High-level SSH client for connecting to SSH servers.
 * Supports password, public key, agent, and keyboard-interactive authentication.
 */

import type { Transport } from './adapters/types.ts';
import { type Agent, AgentContext, createAgent, isAgent } from './agent.ts';
import { Channel, type ChannelInfo, MAX_WINDOW, PACKET_SIZE } from './Channel.ts';
import { hash } from './crypto/mod.ts';
import {
  CHANNEL_EXTENDED_DATATYPE,
  CHANNEL_OPEN_FAILURE,
  DEFAULT_CIPHER,
  DEFAULT_COMPRESSION,
  DEFAULT_KEX,
  DEFAULT_MAC,
  DEFAULT_SERVER_HOST_KEY,
  DISCONNECT_REASON,
  DISCONNECT_REASON_BY_VALUE,
  SUPPORTED_CIPHER,
  SUPPORTED_COMPRESSION,
  SUPPORTED_KEX,
  SUPPORTED_MAC,
  SUPPORTED_SERVER_HOST_KEY,
} from './protocol/constants.ts';
import { type ParsedKey, parseKey } from './protocol/keyParser.ts';
import { Protocol, type ProtocolConfig } from './protocol/Protocol.ts';
import { SFTP } from './protocol/sftp/mod.ts';
import { makeBufferParser } from './protocol/utils.ts';
import {
  ChannelManager,
  type ChannelOrCallback,
  generateAlgorithmList,
  onChannelClose,
  onChannelOpenFailure,
} from './utils.ts';
import { EventEmitter } from './utils/events.ts';

const STDERR = CHANNEL_EXTENDED_DATATYPE.STDERR;
const bufferParser = makeBufferParser();

/**
 * Algorithm configuration
 */
export interface AlgorithmConfig {
  kex?: string[];
  serverHostKey?: string[];
  cipher?: string[];
  hmac?: string[];
  compress?: string[];
}

/**
 * Authentication method types
 */
export type AuthMethod =
  | 'none'
  | 'password'
  | 'publickey'
  | 'agent'
  | 'keyboard-interactive'
  | 'hostbased';

/**
 * Authentication request for password
 */
export interface PasswordAuth {
  type: 'password';
  username: string;
  password: string;
}

/**
 * Authentication request for public key
 */
export interface PublicKeyAuth {
  type: 'publickey';
  username: string;
  key: ParsedKey;
}

/**
 * Authentication request for agent
 */
export interface AgentAuth {
  type: 'agent';
  username: string;
  agent: Agent | string;
}

/**
 * Authentication request for keyboard-interactive
 */
export interface KeyboardInteractiveAuth {
  type: 'keyboard-interactive';
  username: string;
  prompt: (
    name: string,
    instructions: string,
    lang: string,
    prompts: Array<{ prompt: string; echo: boolean }>,
    finish: (responses: string[]) => void,
  ) => void;
}

/**
 * Authentication request for hostbased
 */
export interface HostbasedAuth {
  type: 'hostbased';
  username: string;
  key: ParsedKey;
  localHostname: string;
  localUsername: string;
}

/**
 * Authentication request for none
 */
export interface NoneAuth {
  type: 'none';
  username: string;
}

/** Union type of all supported SSH authentication methods. */
export type AuthRequest =
  | PasswordAuth
  | PublicKeyAuth
  | AgentAuth
  | KeyboardInteractiveAuth
  | HostbasedAuth
  | NoneAuth;

/**
 * Authentication handler context
 */
export interface AuthContext {
  username: string;
  method: AuthMethod;
  partialSuccess: boolean;
  allowed: AuthMethod[];
}

/**
 * Authentication handler function
 */
export type AuthHandler = (
  context: AuthContext,
  callback: (nextAuth: AuthRequest | false) => void,
) => void;

/**
 * Client connection configuration
 */
export interface ClientConfig {
  /** Hostname or IP to connect to */
  host?: string;
  /** Alias for host */
  hostname?: string;
  /** Port number (default: 22) */
  port?: number;
  /** Username for authentication */
  username?: string;
  /** Alias for username */
  user?: string;
  /** Password for authentication */
  password?: string;
  /** Private key for authentication */
  privateKey?: string | Uint8Array;
  /** Passphrase for encrypted private key */
  passphrase?: string;
  /** SSH agent for authentication */
  agent?: Agent | string;
  /** Enable agent forwarding */
  agentForward?: boolean;
  /** Try keyboard-interactive authentication */
  tryKeyboard?: boolean;
  /** Custom authentication handler */
  authHandler?: AuthHandler | AuthMethod[];
  /** Local hostname for hostbased auth */
  localHostname?: string;
  /** Local username for hostbased auth */
  localUsername?: string;
  /** Algorithm preferences */
  algorithms?: AlgorithmConfig;
  /** Ready timeout in milliseconds */
  readyTimeout?: number;
  /** Keepalive interval in milliseconds */
  keepaliveInterval?: number;
  /** Max keepalive failures before disconnect */
  keepaliveCountMax?: number;
  /** Custom identification string */
  ident?: string;
  /** Strict vendor checking */
  strictVendor?: boolean;
  /** Host key verifier - return true/false or a Promise resolving to boolean */
  hostVerifier?: (key: Uint8Array | string) => boolean | Promise<boolean>;
  /** Hash algorithm for host key verification */
  hostHash?: 'md5' | 'sha1' | 'sha256' | 'sha512';
  /** Debug logging function */
  debug?: (msg: string) => void;
  /** Pre-connected transport */
  transport?: Transport;
}

/**
 * Exec options
 */
export interface ExecOptions {
  /** Environment variables */
  env?: Record<string, string>;
  /** Pseudo-TTY settings */
  pty?: PtyOptions | boolean;
  /** X11 forwarding settings */
  x11?: X11Options | boolean;
  /** Agent forwarding */
  agentForward?: boolean;
}

/**
 * PTY options
 */
export interface PtyOptions {
  rows?: number;
  cols?: number;
  height?: number;
  width?: number;
  term?: string;
  modes?: Record<string, number>;
}

/**
 * X11 forwarding options
 */
export interface X11Options {
  single?: boolean;
  screen?: number;
  protocol?: string;
  cookie?: string | Uint8Array;
}

/**
 * Shell options
 */
export interface ShellOptions {
  /** Environment variables */
  env?: Record<string, string>;
  /** Pseudo-TTY settings */
  pty?: PtyOptions | boolean;
  /** X11 forwarding settings */
  x11?: X11Options | boolean;
  /** Agent forwarding */
  agentForward?: boolean;
}

/**
 * Forward options
 */
export interface ForwardOptions {
  /** Remote bind address */
  bindAddr: string;
  /** Remote bind port */
  bindPort: number;
}

/**
 * Client events
 */
export interface ClientEvents {
  connect: [];
  ready: [];
  error: [Error];
  end: [];
  close: [];
  timeout: [];
  banner: [string];
  greeting: [string];
  handshake: [unknown];
  rekey: [];
  hostkeys: [ParsedKey[]];
  'change password': [string, (newPassword: string) => void];
  'keyboard-interactive': [
    string,
    string,
    string,
    Array<{ prompt: string; echo: boolean }>,
    (responses: string[]) => void,
  ];
  'tcp connection': [unknown, () => Channel, () => void];
  'unix connection': [unknown, () => Channel, () => void];
  x11: [unknown, () => Channel, () => void];
}

/**
 * SSH Client
 *
 * High-level API for SSH connections.
 */
export class Client extends EventEmitter<ClientEvents> {
  private _transport?: Transport;
  private _protocol?: Protocol;
  private _chanMgr: ChannelManager;
  private _callbacks: Array<(err: Error | boolean, data?: Uint8Array) => void> = [];
  private _forwarding: Map<string, boolean> = new Map();
  private _acceptX11 = 0;
  private _readyTimeout?: number;
  private _keepaliveTimer?: number;
  private _keepaliveCount = 0;
  private _agent?: Agent;
  private _agentCtx?: AgentContext;
  private _agentKey?: ParsedKey;
  private _privateKey?: ParsedKey;
  private _remoteVer?: string;
  private _exchanges = 0;
  private _config:
    & Required<
      Pick<
        ClientConfig,
        'host' | 'port' | 'username' | 'readyTimeout' | 'keepaliveInterval' | 'keepaliveCountMax'
      >
    >
    & ClientConfig;

  constructor() {
    super();
    this._chanMgr = new ChannelManager();
    this._config = {
      host: 'localhost',
      port: 22,
      username: '',
      readyTimeout: 20000,
      keepaliveInterval: 0,
      keepaliveCountMax: 3,
    };
  }

  /**
   * Connect to an SSH server
   */
  async connect(config: ClientConfig): Promise<void> {
    // Parse configuration
    this._config = {
      ...this._config,
      host: config.hostname || config.host || 'localhost',
      port: config.port || 22,
      username: config.username || config.user || '',
      readyTimeout: config.readyTimeout ?? 20000,
      keepaliveInterval: config.keepaliveInterval ?? 0,
      keepaliveCountMax: config.keepaliveCountMax ?? 3,
      ...config,
    };

    if (typeof this._config.username !== 'string') {
      throw new Error('Invalid username');
    }

    // Parse private key if provided
    if (config.privateKey) {
      let key: ParsedKey | Error;
      if (config.passphrase) {
        key = await parseKey(config.privateKey, config.passphrase);
      } else {
        key = parseKey(config.privateKey);
      }
      if (key instanceof Error) {
        throw new Error(`Cannot parse privateKey: ${key.message}`);
      }
      const privateKey = Array.isArray(key) ? key[0] : key;
      if (privateKey.getPrivatePEM() === null) {
        throw new Error('privateKey value does not contain a (valid) private key');
      }
      this._privateKey = privateKey;
    }

    // Set up agent
    if (typeof config.agent === 'string' && config.agent.length) {
      this._agent = createAgent(config.agent);
    } else if (isAgent(config.agent)) {
      this._agent = config.agent;
    }

    if (config.agentForward && !this._agent) {
      throw new Error('You must set a valid agent path to allow agent forwarding');
    }

    // Build algorithm offer
    const algorithms = this._buildAlgorithms(config.algorithms);

    // Set up host verifier
    const hostVerifier = this._buildHostVerifier(config);

    // Get or create transport
    if (config.transport) {
      this._transport = config.transport;
    } else {
      // Use Deno transport
      const { denoTransport } = await import('./adapters/deno.ts');
      this._transport = await denoTransport.connect({
        host: this._config.host,
        port: this._config.port,
        timeout: this._config.readyTimeout,
      });
    }

    // Set up protocol
    this._setupProtocol(algorithms, hostVerifier, config.debug);

    // Start reading from transport
    this._startReading();

    // Start protocol (send identification string)
    this._protocol!.start?.();
  }

  /**
   * Build algorithm configuration
   */
  private _buildAlgorithms(config?: AlgorithmConfig) {
    const cs = {
      cipher: config?.cipher
        ? generateAlgorithmList(config.cipher, DEFAULT_CIPHER, SUPPORTED_CIPHER)
        : DEFAULT_CIPHER,
      mac: config?.hmac
        ? generateAlgorithmList(config.hmac, DEFAULT_MAC, SUPPORTED_MAC)
        : DEFAULT_MAC,
      compress: config?.compress
        ? generateAlgorithmList(config.compress, DEFAULT_COMPRESSION, SUPPORTED_COMPRESSION)
        : DEFAULT_COMPRESSION,
      lang: [] as string[],
    };

    return {
      // Always include kex-strict-c-v00@openssh.com for strict KEX mode (RFC 9700)
      kex:
        (config?.kex ? generateAlgorithmList(config.kex, DEFAULT_KEX, SUPPORTED_KEX) : DEFAULT_KEX)
          .concat(['kex-strict-c-v00@openssh.com']),
      serverHostKey: config?.serverHostKey
        ? generateAlgorithmList(
          config.serverHostKey,
          DEFAULT_SERVER_HOST_KEY,
          SUPPORTED_SERVER_HOST_KEY,
        )
        : DEFAULT_SERVER_HOST_KEY,
      cs,
      sc: cs, // Server-to-client uses same algorithms as client-to-server
    };
  }

  /**
   * Build host verifier function
   */
  private _buildHostVerifier(config: ClientConfig) {
    if (!config.hostVerifier) return undefined;

    const verifier = config.hostVerifier;
    const hashAlgo = config.hostHash;

    return async (key: Uint8Array): Promise<boolean> => {
      let keyData: Uint8Array | string = key;
      if (hashAlgo) {
        const hashed = await hash(hashAlgo, key);
        // Convert to hex string
        keyData = Array.from(hashed)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      }
      return verifier(keyData);
    };
  }

  /**
   * Set up protocol handlers
   */
  private _setupProtocol(
    algorithms: ReturnType<typeof this._buildAlgorithms>,
    hostVerifier: ((key: Uint8Array) => boolean | Promise<boolean>) | undefined,
    debug?: (msg: string) => void,
  ) {
    const config: ProtocolConfig = {
      server: false,
      ident: this._config.ident,
      offer: algorithms,
      onWrite: (data) => {
        this._writeToTransport(data);
      },
      onError: (err) => {
        this._clearTimers();
        this.emit('error', err);
        this.end();
      },
      onHeader: (header) => {
        this._remoteVer = header.greeting;
        if (header.greeting) {
          this.emit('greeting', header.greeting);
        }
      },
      onHandshakeComplete: () => {
        this._exchanges++;
        this.emit('handshake', {});
        if (this._exchanges === 1) {
          // Request user auth service only on first handshake
          this._protocol!.service('ssh-userauth');
        } else {
          // Emit rekey event on subsequent handshakes
          this.emit('rekey');
        }
      },
      debug,
      hostVerifier,
    };

    this._protocol = new Protocol(config);

    // Set up message handlers
    this._setupMessageHandlers();
  }

  /**
   * Set up protocol message handlers
   */
  private _setupMessageHandlers() {
    if (!this._protocol) return;

    const handlers = this._protocol._handlers;

    handlers.DISCONNECT = (_p, reason, desc) => {
      if (reason !== DISCONNECT_REASON.BY_APPLICATION) {
        const description = desc || DISCONNECT_REASON_BY_VALUE[reason] ||
          `Unexpected disconnection: ${reason}`;
        const err = new Error(description) as Error & { code: number };
        err.code = reason;
        this.emit('error', err);
      }
      this.end();
    };

    handlers.SERVICE_ACCEPT = (_p, name) => {
      if (name === 'ssh-userauth') {
        this._startAuth();
      }
    };

    handlers.USERAUTH_BANNER = (_p, msg) => {
      this.emit('banner', msg);
    };

    handlers.USERAUTH_SUCCESS = () => {
      this._clearTimers();
      this._startKeepalive();
      // Clear agent state
      this._agentCtx = undefined;
      this._agentKey = undefined;
      this.emit('ready');
    };

    handlers.USERAUTH_FAILURE = (_p, authMethods, _partialSuccess) => {
      // Try next auth method
      this._tryNextAuth(authMethods);
    };

    handlers.USERAUTH_PK_OK = (_p, keyAlgo, _keyData) => {
      // Server accepted our public key query, now send the actual auth with signature
      if (this._agentCtx && this._agentKey && this._protocol) {
        // Use agent to sign
        this._protocol.authPKSignWithAgent(
          this._config.username,
          this._agentKey,
          this._agentCtx,
          keyAlgo,
        ).catch((err: unknown) => {
          this._config.debug?.(`Agent sign error: ${(err as Error).message}`);
          // Try next agent key
          this._tryAgentAuth();
        });
      } else if (this._privateKey && this._protocol) {
        this._protocol.authPKSign(this._config.username, this._privateKey, keyAlgo)
          .catch((err: unknown) => {
            this.emit('error', err instanceof Error ? err : new Error(String(err)));
            this.end();
          });
      }
    };

    handlers.USERAUTH_INFO_REQUEST = (_p, name, instructions, prompts) => {
      // Server is requesting keyboard-interactive input
      const finish = (responses: string[]) => {
        this._protocol?.authInfoResponse(responses);
      };
      // Emit keyboard-interactive event with name, instructions, lang, prompts, finish callback
      this.emit('keyboard-interactive', name, instructions, '', prompts, finish);
    };

    handlers.REQUEST_SUCCESS = (_p, data) => {
      if (this._callbacks.length) {
        this._callbacks.shift()!(false, data || undefined);
      }
    };

    handlers.REQUEST_FAILURE = () => {
      if (this._callbacks.length) {
        this._callbacks.shift()!(true);
      }
    };

    handlers.CHANNEL_OPEN = (_p, info) => {
      this._handleChannelOpen(info);
    };

    handlers.CHANNEL_OPEN_CONFIRMATION = (_p, info) => {
      this._handleChannelOpenConfirmation(info);
    };

    handlers.CHANNEL_OPEN_FAILURE = (_p, recipient, reason, description) => {
      const channel = this._chanMgr.get(recipient);
      if (typeof channel === 'function') {
        onChannelOpenFailure(this._chanMgr, recipient, { reason, description }, channel);
      }
    };

    handlers.CHANNEL_DATA = (_p, recipient, data) => {
      const channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      // Check if this is an SFTP instance (has push method and type is 'sftp')
      // deno-lint-ignore no-explicit-any
      const obj = channel as any;
      if (typeof obj.push === 'function' && obj.type === 'sftp') {
        obj.push(data);
        return;
      }

      const chan = channel as Channel;
      if (chan.incoming.window === 0) return;

      chan.pushData(data);
    };

    handlers.CHANNEL_EXTENDED_DATA = (_p, recipient, data, type) => {
      if (type !== STDERR) return;

      const channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      const chan = channel as Channel;
      if (chan.incoming.window === 0) return;

      chan.pushData(data, true);
    };

    handlers.CHANNEL_WINDOW_ADJUST = (_p, recipient, amount) => {
      const channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      (channel as Channel).adjustWindow(amount);
    };

    handlers.CHANNEL_SUCCESS = (_p, recipient) => {
      this._resetKeepalive();
      const channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;
      // Handle channel success callback
    };

    handlers.CHANNEL_FAILURE = (_p, recipient) => {
      this._resetKeepalive();
      const channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;
      // Handle channel failure callback
    };

    handlers.CHANNEL_REQUEST = (_p, recipient, type, _wantReply, data) => {
      const channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      const chan = channel as Channel;
      if (type === 'exit-status' && typeof data === 'number') {
        chan.handleExitStatus(data);
      } else if (type === 'exit-signal' && typeof data === 'object' && data !== null) {
        const signalData = data as { signal: string; coreDumped: boolean; errorMessage: string };
        chan.handleExitSignal(
          `SIG${signalData.signal}`,
          signalData.coreDumped,
          signalData.errorMessage,
        );
      }
    };

    handlers.CHANNEL_EOF = (_p, recipient) => {
      const channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      // Check if this is an SFTP instance (has push method and type is 'sftp')
      // deno-lint-ignore no-explicit-any
      const obj = channel as any;
      if (typeof obj.push === 'function' && obj.type === 'sftp') {
        obj.push(null);
        return;
      }

      (channel as Channel).handleEOF();
    };

    handlers.CHANNEL_CLOSE = (_p, recipient) => {
      const channel = this._chanMgr.get(recipient);
      if (channel) {
        onChannelClose(this._chanMgr, recipient, channel as ChannelOrCallback);
      }
    };
  }

  /**
   * Start reading from transport
   */
  private async _startReading() {
    if (!this._transport) return;

    const reader = this._transport.readable.getReader();

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        try {
          await this._protocol?.parse(value, 0, value.length);
        } catch (err) {
          this.emit('error', err as Error);
          this.end();
          break;
        }
      }
    } catch (err) {
      if (!this._transport?.closed) {
        this.emit('error', err as Error);
      }
    } finally {
      reader.releaseLock();
      this._cleanup(new Error('Connection lost'));
      this.emit('end');
      this.emit('close');
    }
  }

  /** Write queue for sequential writes */
  private _writeQueue: Uint8Array[] = [];
  private _writeInProgress = false;

  /**
   * Write data to transport (queued for sequential writes)
   */
  private _writeToTransport(data: Uint8Array): void {
    if (!this._transport || this._transport.closed) return;
    this._writeQueue.push(data);
    this._processWriteQueue();
  }

  /**
   * Process the write queue
   */
  private async _processWriteQueue(): Promise<void> {
    if (this._writeInProgress) {
      return;
    }
    if (!this._transport || this._transport.closed) return;

    this._writeInProgress = true;
    let writer: WritableStreamDefaultWriter<Uint8Array> | undefined;

    try {
      writer = this._transport.writable.getWriter();

      while (this._writeQueue.length > 0) {
        const data = this._writeQueue.shift()!;
        await writer.write(data);
      }
    } catch (err) {
      // Clear the queue to prevent infinite recursion when transport is closed
      this._writeQueue.length = 0;
      this.emit('error', err as Error);
    } finally {
      // Always release the writer lock, even on error
      writer?.releaseLock();
      this._writeInProgress = false;
      // Check if more data arrived while we were processing
      if (this._writeQueue.length > 0) {
        this._processWriteQueue();
      }
    }
  }

  /**
   * Start authentication
   */
  private _startAuth() {
    // Build list of allowed auth methods
    const authMethods: AuthMethod[] = ['none'];

    if (this._config.password) {
      authMethods.push('password');
    }
    if (this._privateKey) {
      authMethods.push('publickey');
    }
    if (this._agent) {
      authMethods.push('agent');
    }
    if (this._config.tryKeyboard) {
      authMethods.push('keyboard-interactive');
    }
    if (this._privateKey && this._config.localHostname && this._config.localUsername) {
      authMethods.push('hostbased');
    }

    this._tryNextAuth(authMethods);
  }

  /**
   * Try next authentication method
   */
  private _tryNextAuth(allowedMethods: string[]) {
    // Simple auth handler - try methods in order
    const methods = allowedMethods as AuthMethod[];

    for (const method of methods) {
      switch (method) {
        case 'none':
          this._protocol?.authNone(this._config.username);
          return;

        case 'password':
          if (this._config.password) {
            this._protocol?.authPassword(this._config.username, this._config.password);
            return;
          }
          break;

        case 'publickey':
          // Try privateKey first, then agent (agent uses publickey protocol)
          if (this._privateKey) {
            this._protocol?.authPK(this._config.username, this._privateKey);
            return;
          }
          if (this._agent) {
            this._tryAgentAuth();
            return;
          }
          break;

        case 'agent':
          // Agent uses publickey protocol
          if (this._agent) {
            this._tryAgentAuth();
            return;
          }
          break;

        case 'keyboard-interactive':
          if (this._config.tryKeyboard) {
            this._protocol?.authKeyboard(this._config.username);
            return;
          }
          break;

        case 'hostbased':
          if (this._privateKey && this._config.localHostname) {
            this._protocol?.authHostbased(
              this._config.username!,
              this._privateKey,
              this._config.localHostname,
              this._config.localUsername || this._config.username!,
            );
            return;
          }
          break;
      }
    }

    // No more auth methods
    const err = new Error('All configured authentication methods failed') as Error & {
      level: string;
    };
    err.level = 'client-authentication';
    this.emit('error', err);
    this.end();
  }

  /**
   * Try agent authentication
   */
  private async _tryAgentAuth() {
    if (!this._agent) return;

    try {
      // Create or reuse agent context
      if (!this._agentCtx) {
        this._agentCtx = new AgentContext(this._agent);
        await this._agentCtx.init();
      }

      const key = this._agentCtx.nextKey();
      if (key) {
        this._agentKey = key;
        this._protocol?.authPK(this._config.username, key);
      } else {
        // No more agent keys, clear context and try next auth method
        this._agentCtx = undefined;
        this._agentKey = undefined;
        this._tryNextAuth([]);
      }
    } catch (err) {
      this._config.debug?.(`Agent auth error: ${(err as Error).message}`);
      this._agentCtx = undefined;
      this._agentKey = undefined;
      this._tryNextAuth([]);
    }
  }

  /**
   * Handle incoming channel open request
   */
  private _handleChannelOpen(info: {
    type: string;
    sender: number;
    window: number;
    packetSize: number;
    data?: unknown;
  }) {
    switch (info.type) {
      case 'forwarded-tcpip':
        this._handleForwardedTcpip(info);
        break;
      case 'forwarded-streamlocal@openssh.com':
        this._handleForwardedUnix(info);
        break;
      case 'x11':
        this._handleX11(info);
        break;
      default:
        // Reject unknown channel types
        this._protocol?.channelOpenFail(
          info.sender,
          CHANNEL_OPEN_FAILURE.UNKNOWN_CHANNEL_TYPE,
          'Unknown channel type',
          '',
        );
    }
  }

  /**
   * Handle forwarded TCP connection
   */
  private _handleForwardedTcpip(info: {
    sender: number;
    window: number;
    packetSize: number;
    data?: unknown;
  }) {
    const accept = () => this._acceptChannel(info);
    const reject = () => {
      this._protocol?.channelOpenFail(
        info.sender,
        CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED,
        'Connection rejected',
        '',
      );
    };

    this.emit('tcp connection', info.data, accept, reject);
  }

  /**
   * Handle forwarded Unix connection
   */
  private _handleForwardedUnix(info: {
    sender: number;
    window: number;
    packetSize: number;
    data?: unknown;
  }) {
    const accept = () => this._acceptChannel(info);
    const reject = () => {
      this._protocol?.channelOpenFail(
        info.sender,
        CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED,
        'Connection rejected',
        '',
      );
    };

    this.emit('unix connection', info.data, accept, reject);
  }

  /**
   * Handle X11 connection
   */
  private _handleX11(info: {
    sender: number;
    window: number;
    packetSize: number;
    data?: unknown;
  }) {
    if (this._acceptX11 === 0) {
      this._protocol?.channelOpenFail(
        info.sender,
        CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED,
        'X11 forwarding not enabled',
        '',
      );
      return;
    }

    const accept = () => this._acceptChannel(info);
    const reject = () => {
      this._protocol?.channelOpenFail(
        info.sender,
        CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED,
        'X11 connection rejected',
        '',
      );
    };

    this.emit('x11', info.data, accept, reject);
  }

  /**
   * Accept an incoming channel
   */
  private _acceptChannel(info: {
    sender: number;
    window: number;
    packetSize: number;
  }): Channel {
    const localId = this._chanMgr.add();
    if (localId === -1) {
      throw new Error('No available channel IDs');
    }

    const chanInfo: ChannelInfo = {
      type: 'forwarded',
      incoming: {
        id: localId,
        window: MAX_WINDOW,
        packetSize: PACKET_SIZE,
        state: 'open',
      },
      outgoing: {
        id: info.sender,
        window: info.window,
        packetSize: info.packetSize,
        state: 'open',
      },
    };

    const channel = new Channel(
      { _protocol: this._protocol! },
      chanInfo,
    );

    this._chanMgr.update(localId, channel);

    this._protocol?.channelOpenConfirm(
      info.sender,
      localId,
      MAX_WINDOW,
      PACKET_SIZE,
    );

    return channel;
  }

  /**
   * Handle channel open confirmation
   */
  private _handleChannelOpenConfirmation(info: {
    recipient: number;
    sender: number;
    window: number;
    packetSize: number;
  }) {
    const callback = this._chanMgr.get(info.recipient);
    if (typeof callback !== 'function') return;

    const chanInfo: ChannelInfo = {
      type: 'session',
      incoming: {
        id: info.recipient,
        window: MAX_WINDOW,
        packetSize: PACKET_SIZE,
        state: 'open',
      },
      outgoing: {
        id: info.sender,
        window: info.window,
        packetSize: info.packetSize,
        state: 'open',
      },
    };

    const channel = new Channel(
      { _protocol: this._protocol! },
      chanInfo,
    );

    this._chanMgr.update(info.recipient, channel);
    (callback as (err: Error | undefined, channel: Channel) => void)(undefined, channel);
  }

  /**
   * Start keepalive timer
   */
  private _startKeepalive() {
    if (this._config.keepaliveInterval <= 0) return;

    this._keepaliveCount = 0;
    this._keepaliveTimer = setInterval(() => {
      if (++this._keepaliveCount > this._config.keepaliveCountMax) {
        this._clearTimers();
        const err = new Error('Keepalive timeout') as Error & { level: string };
        err.level = 'client-timeout';
        this.emit('error', err);
        this.end();
        return;
      }

      this._callbacks.push(() => this._resetKeepalive());
      this._protocol?.ping();
    }, this._config.keepaliveInterval);
  }

  /**
   * Reset keepalive counter
   */
  private _resetKeepalive() {
    this._keepaliveCount = 0;
  }

  /**
   * Clear all timers
   */
  private _clearTimers() {
    if (this._readyTimeout) {
      clearTimeout(this._readyTimeout);
      this._readyTimeout = undefined;
    }
    if (this._keepaliveTimer) {
      clearInterval(this._keepaliveTimer);
      this._keepaliveTimer = undefined;
    }
  }

  /**
   * Open a new session channel
   */
  private _openChannel(
    type: string,
    callback: (err: Error | undefined, channel: Channel) => void,
  ) {
    const localId = this._chanMgr.add(callback as unknown as ChannelOrCallback);
    if (localId === -1) {
      callback(new Error('No available channel IDs'), undefined as unknown as Channel);
      return;
    }

    this._protocol?.channelOpen(type, localId, MAX_WINDOW, PACKET_SIZE);
  }

  /**
   * Execute a command on the server
   */
  exec(command: string, options?: ExecOptions): Promise<Channel> {
    return new Promise((resolve, reject) => {
      this._openChannel('session', (err, channel) => {
        if (err) return reject(err);

        // Send environment variables if specified
        if (options?.env) {
          for (const [name, value] of Object.entries(options.env)) {
            this._protocol?.env(channel.outgoing.id!, name, value);
          }
        }

        // Set up PTY if requested
        if (options?.pty) {
          const ptyOpts = typeof options.pty === 'boolean' ? {} : options.pty;
          this._protocol?.pty(
            channel.outgoing.id!,
            ptyOpts.rows || 24,
            ptyOpts.cols || 80,
            ptyOpts.height || 480,
            ptyOpts.width || 640,
            ptyOpts.term || 'xterm',
            ptyOpts.modes || null,
          );
        }

        // Request agent forwarding if specified
        if (options?.agentForward) {
          this._protocol?.authAgentRequest(channel.outgoing.id!);
        }

        // Execute command
        this._protocol?.exec(channel.outgoing.id!, command, true);
        channel.subtype = 'exec';
        resolve(channel);
      });
    });
  }

  /**
   * Start an interactive shell
   */
  shell(options?: ShellOptions): Promise<Channel> {
    return new Promise((resolve, reject) => {
      this._openChannel('session', (err, channel) => {
        if (err) return reject(err);

        // Send environment variables if specified
        if (options?.env) {
          for (const [name, value] of Object.entries(options.env)) {
            this._protocol?.env(channel.outgoing.id!, name, value);
          }
        }

        // Set up PTY
        const ptyOpts = options?.pty === false
          ? null
          : (typeof options?.pty === 'object' ? options.pty : {});
        if (ptyOpts !== null) {
          this._protocol?.pty(
            channel.outgoing.id!,
            ptyOpts.rows || 24,
            ptyOpts.cols || 80,
            ptyOpts.height || 480,
            ptyOpts.width || 640,
            ptyOpts.term || 'xterm',
            ptyOpts.modes || null,
          );
        }

        // Request agent forwarding if specified
        if (options?.agentForward) {
          this._protocol?.authAgentRequest(channel.outgoing.id!);
        }

        // Start shell
        this._protocol?.shell(channel.outgoing.id!, true);
        channel.subtype = 'shell';
        resolve(channel);
      });
    });
  }

  /**
   * Start an SFTP session
   */
  sftp(): Promise<SFTP> {
    return new Promise((resolve, reject) => {
      this._openChannel('session', (err, channel) => {
        if (err) return reject(err);

        // Create channel info for SFTP (with required id fields)
        const chanInfo = {
          type: 'sftp',
          incoming: {
            id: channel.incoming.id!,
            window: channel.incoming.window,
            packetSize: channel.incoming.packetSize,
            state: channel.incoming.state,
          },
          outgoing: {
            id: channel.outgoing.id!,
            window: channel.outgoing.window,
            packetSize: channel.outgoing.packetSize,
            state: channel.outgoing.state,
          },
        };

        // Get remote ident for OpenSSH detection
        const remoteIdent = this._protocol?.remoteIdent;
        const remoteIdentStr = remoteIdent ? new TextDecoder().decode(remoteIdent) : undefined;

        // Create SFTP instance
        const sftp = new SFTP(
          {
            protocol: this._protocol!,
            remoteIdentRaw: remoteIdentStr,
          },
          chanInfo,
          { debug: this._config.debug },
        );

        // Update channel manager with SFTP instance
        this._chanMgr.update(channel.incoming.id!, sftp as unknown as Channel);

        // Set up event handlers
        const onReady = () => {
          removeListeners();
          resolve(sftp);
        };

        const onError = (err: Error) => {
          removeListeners();
          reject(err);
        };

        const onClose = () => {
          removeListeners();
          reject(new Error('SFTP session closed unexpectedly'));
        };

        const removeListeners = () => {
          sftp.removeListener('ready', onReady);
          sftp.removeListener('error', onError);
          sftp.removeListener('close', onClose);
        };

        sftp.on('ready', onReady);
        sftp.on('error', onError);
        sftp.on('close', onClose);

        // Request SFTP subsystem then initialize
        this._protocol?.subsystem(channel.outgoing.id!, 'sftp', true);

        // Initialize SFTP protocol (sends version packet)
        sftp._init();
      });
    });
  }

  /**
   * Request TCP port forwarding
   */
  forwardIn(bindAddr: string, bindPort: number): Promise<number> {
    return new Promise((resolve, reject) => {
      this._callbacks.push((err, data) => {
        if (err) {
          reject(new Error('Forward request failed'));
          return;
        }

        let port = bindPort;
        if (data && data.length >= 4) {
          bufferParser.init(data, 0);
          port = bufferParser.readUInt32BE() || bindPort;
          bufferParser.clear();
        }

        this._forwarding.set(`${bindAddr}:${port}`, true);
        resolve(port);
      });

      this._protocol?.tcpipForward(bindAddr, bindPort, true);
    });
  }

  /**
   * Cancel TCP port forwarding
   */
  unforwardIn(bindAddr: string, bindPort: number): Promise<void> {
    return new Promise((resolve, reject) => {
      this._callbacks.push((err) => {
        if (err) {
          reject(new Error('Unforward request failed'));
          return;
        }

        this._forwarding.delete(`${bindAddr}:${bindPort}`);
        resolve();
      });

      this._protocol?.cancelTcpipForward(bindAddr, bindPort, true);
    });
  }

  /**
   * Create a direct TCP connection
   */
  forwardOut(
    srcAddr: string,
    srcPort: number,
    dstAddr: string,
    dstPort: number,
  ): Promise<Channel> {
    return new Promise((resolve, reject) => {
      const cb = (err: Error | undefined, channel: Channel) => {
        if (err) reject(err);
        else resolve(channel);
      };
      const localId = this._chanMgr.add(cb as unknown as ChannelOrCallback);
      if (localId === -1) {
        reject(new Error('No available channel IDs'));
        return;
      }

      this._protocol?.directTcpip(
        localId,
        MAX_WINDOW,
        PACKET_SIZE,
        dstAddr,
        dstPort,
        srcAddr,
        srcPort,
      );
    });
  }

  /**
   * Get the remote server's SSH version string
   */
  get remoteVersion(): string | undefined {
    return this._remoteVer;
  }

  /**
   * Initiate rekeying
   */
  rekey(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this._protocol!.rekey();
        this.once('rekey', () => resolve());
      } catch (err) {
        reject(err);
      }
    });
  }

  /**
   * Request forwarding of connections to a UNIX socket (OpenSSH extension)
   */
  openssh_forwardInStreamLocal(socketPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this._callbacks.push((err) => {
        if (err) {
          reject(new Error('Streamlocal forward request failed'));
          return;
        }

        this._forwarding.set(`unix:${socketPath}`, true);
        resolve();
      });

      this._protocol?.streamlocalForward(socketPath, true);
    });
  }

  /**
   * Cancel forwarding of connections to a UNIX socket (OpenSSH extension)
   */
  openssh_unforwardInStreamLocal(socketPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this._callbacks.push((err) => {
        if (err) {
          reject(new Error('Streamlocal unforward request failed'));
          return;
        }

        this._forwarding.delete(`unix:${socketPath}`);
        resolve();
      });

      this._protocol?.cancelStreamlocalForward(socketPath, true);
    });
  }

  /**
   * Connect to a UNIX socket on the server (OpenSSH extension)
   */
  openssh_forwardOutStreamLocal(socketPath: string): Promise<Channel> {
    return new Promise((resolve, reject) => {
      const cb = (err: Error | undefined, channel: Channel) => {
        if (err) reject(err);
        else resolve(channel);
      };
      const localId = this._chanMgr.add(cb as unknown as ChannelOrCallback);
      if (localId === -1) {
        reject(new Error('No available channel IDs'));
        return;
      }

      this._protocol?.directStreamlocal(
        localId,
        MAX_WINDOW,
        PACKET_SIZE,
        socketPath,
      );
    });
  }

  /**
   * End the connection
   */
  end(): void {
    this._clearTimers();
    this._cleanup(new Error('Connection closed'));

    if (this._protocol) {
      this._protocol.disconnect(DISCONNECT_REASON.BY_APPLICATION);
      this._protocol = undefined;
    }

    if (this._transport) {
      this._transport.close();
      this._transport = undefined;
    }
  }

  /**
   * Clean up pending callbacks and channels
   */
  private _cleanup(err: Error): void {
    // Clean up channel manager (will call pending channel open callbacks)
    this._chanMgr.cleanup(err);

    // Clean up global request callbacks
    const callbacks = this._callbacks;
    this._callbacks = [];
    for (const cb of callbacks) {
      try {
        cb(err);
      } catch {
        // Ignore errors in callbacks
      }
    }
  }

  /**
   * Destroy the connection immediately
   */
  destroy(): void {
    this.end();
  }
}
