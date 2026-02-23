/**
 * SSH Channel Implementation
 *
 * Provides bidirectional data streams over SSH using Web Streams API.
 * Handles SSH window management for flow control.
 */

import { CHANNEL_EXTENDED_DATATYPE } from './protocol/constants.ts';
import { EventEmitter } from './utils/events.ts';

const STDERR = CHANNEL_EXTENDED_DATATYPE.STDERR;

/** Maximum SSH window size */
export const MAX_WINDOW = 2 * 1024 * 1024;

/** Default packet size */
export const PACKET_SIZE = 32 * 1024;

/** Window threshold for adjustment */
export const WINDOW_THRESHOLD = MAX_WINDOW / 2;

/**
 * Channel state
 */
export type ChannelState = 'closed' | 'open' | 'eof' | 'closing';

/**
 * Channel endpoint info (incoming or outgoing)
 */
export interface ChannelEndpoint {
  id: number | undefined;
  window: number;
  packetSize: number;
  state: ChannelState;
}

/**
 * Channel info for creation
 */
export interface ChannelInfo {
  type: string;
  incoming: ChannelEndpoint;
  outgoing: ChannelEndpoint;
}

/**
 * Channel options
 */
export interface ChannelOptions {
  server?: boolean;
  allowHalfOpen?: boolean;
}

/**
 * Exit info for session channels
 */
export interface ExitInfo {
  code?: number;
  signal?: string;
  dump?: boolean;
  desc?: string;
}

/**
 * Protocol interface for channel operations
 */
export interface ChannelProtocol {
  channelData(id: number, data: Uint8Array): void;
  channelExtData(id: number, data: Uint8Array, type: number): void;
  channelEOF(id: number): void;
  channelClose(id: number): void;
  channelWindowAdjust(id: number, amount: number): void;
  windowChange?(id: number, rows: number, cols: number, height: number, width: number): void;
  signal?(id: number, signalName: string): void;
  exitStatus?(id: number, status: number): void;
  exitSignal?(id: number, signal: string, coreDumped: boolean, msg: string): void;
}

/**
 * Client interface for channel
 */
export interface ChannelClient {
  _protocol: ChannelProtocol;
}

/**
 * Channel events
 */
export interface ChannelEvents {
  close: [];
  eof: [];
  end: [];
  error: [Error];
  data: [Uint8Array];
  drain: [];
  'exit-status': [number];
  'exit-signal': [string, boolean, string];
}

/**
 * Valid SSH signals (RFC 4254)
 */
const VALID_SIGNALS = new Set([
  'ABRT',
  'ALRM',
  'FPE',
  'HUP',
  'ILL',
  'INT',
  'KILL',
  'PIPE',
  'QUIT',
  'SEGV',
  'TERM',
  'USR1',
  'USR2',
]);

/**
 * Stderr wrapper for server-side channels
 * Provides Node.js-style write() method
 */
export interface StderrWritable {
  write(data: Uint8Array | string): void;
}

/**
 * Encode string to Uint8Array
 */
function encodeData(data: Uint8Array | string): Uint8Array {
  if (typeof data === 'string') {
    return new TextEncoder().encode(data);
  }
  return data;
}

/**
 * SSH Channel
 *
 * Provides bidirectional communication over an SSH connection using Web Streams.
 * Handles SSH-level flow control via window management.
 */
export class Channel extends EventEmitter<ChannelEvents> {
  /** Channel type (session, direct-tcpip, etc.) */
  readonly type: string;

  /** Channel subtype (shell, exec, subsystem) */
  subtype?: string;

  /** Whether this is server-side */
  readonly server: boolean;

  /** Allow half-open connections */
  readonly allowHalfOpen: boolean;

  /** Incoming endpoint state */
  readonly incoming: ChannelEndpoint;

  /** Outgoing endpoint state */
  readonly outgoing: ChannelEndpoint;

  /** Exit information */
  readonly exitInfo: ExitInfo = {};

  /** Pending callbacks */
  private _callbacks: Array<() => void> = [];

  /** Client connection */
  private _client: ChannelClient;

  /** Has X11 forwarding */
  private _hasX11 = false;

  /** Waiting for window space */
  private _waitWindow = false;

  /** Waiting for channel drain */
  private _waitChanDrain = false;

  /** Pending data chunk */
  private _chunk?: Uint8Array;
  private _chunkcb?: () => void;

  /** Pending stderr chunk */
  private _chunkErr?: Uint8Array;
  private _chunkcbErr?: () => void;

  /** ReadableStream for incoming data (stdout) */
  private _readable: ReadableStream<Uint8Array>;
  private _readableController?: ReadableStreamDefaultController<Uint8Array>;

  /** WritableStream for outgoing data (stdin) */
  private _writable: WritableStream<Uint8Array>;

  /** Stderr stream */
  private _stderr: ReadableStream<Uint8Array> | WritableStream<Uint8Array>;
  private _stderrController?: ReadableStreamDefaultController<Uint8Array>;

  /** Server-side stderr wrapper with write() method */
  private _stderrWritable?: StderrWritable;

  /** Stream state */
  private _readableClosed = false;
  private _writableClosed = false;

  constructor(client: ChannelClient, info: ChannelInfo, opts?: ChannelOptions) {
    super();

    this._client = client;
    this.type = info.type;
    this.incoming = info.incoming;
    this.outgoing = info.outgoing;
    this.server = opts?.server ?? false;
    this.allowHalfOpen = opts?.allowHalfOpen ?? true;

    // Create readable stream for incoming data (stdout)
    this._readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this._readableController = controller;
      },
      pull: () => {
        // Called when consumer wants more data
        if (this._waitChanDrain) {
          this._waitChanDrain = false;
          if (this.incoming.window <= WINDOW_THRESHOLD) {
            this._windowAdjust();
          }
        }
      },
      cancel: () => {
        this._readableClosed = true;
        this._handleClose();
      },
    });

    // Create writable stream for outgoing data (stdin)
    this._writable = new WritableStream<Uint8Array>({
      write: async (chunk) => {
        await this._writeData(chunk, false);
      },
      close: () => {
        this._writableClosed = true;
        this.eof();
        if (this.server || !this.allowHalfOpen) {
          this.close();
        }
      },
      abort: () => {
        this._writableClosed = true;
        this.close();
      },
    });

    // Create stderr stream
    if (this.server) {
      // Server: writable stderr (send to client)
      this._stderr = new WritableStream<Uint8Array>({
        write: async (chunk) => {
          await this._writeData(chunk, true);
        },
      });
      // Create Node.js-style stderr wrapper for server-side
      this._stderrWritable = {
        write: (data: Uint8Array | string) => {
          this._writeDataSync(encodeData(data), true);
        },
      };
    } else {
      // Client: readable stderr (receive from server)
      this._stderr = new ReadableStream<Uint8Array>({
        start: (controller) => {
          this._stderrController = controller;
        },
        pull: () => {
          if (this._waitChanDrain) {
            this._waitChanDrain = false;
            if (this.incoming.window <= WINDOW_THRESHOLD) {
              this._windowAdjust();
            }
          }
        },
      });
    }
  }

  /** Get readable stream (stdout) */
  get readable(): ReadableStream<Uint8Array> {
    return this._readable;
  }

  /** Get writable stream (stdin) */
  get writable(): WritableStream<Uint8Array> {
    return this._writable;
  }

  /** Alias for readable (stdout) */
  get stdout(): ReadableStream<Uint8Array> {
    return this._readable;
  }

  /** Alias for writable (stdin) */
  get stdin(): WritableStream<Uint8Array> {
    return this._writable;
  }

  /** Get stderr stream */
  get stderr(): ReadableStream<Uint8Array> | WritableStream<Uint8Array> | StderrWritable {
    // For server-side, return the wrapper with write() method
    if (this.server && this._stderrWritable) {
      return this._stderrWritable;
    }
    return this._stderr;
  }

  /**
   * Write data to the channel
   */
  private async _writeData(data: Uint8Array, isStderr: boolean): Promise<void> {
    const protocol = this._client._protocol;
    const outgoing = this.outgoing;
    const packetSize = outgoing.packetSize;
    const id = outgoing.id;

    if (id === undefined || outgoing.state !== 'open') {
      return;
    }

    let window = outgoing.window;
    const len = data.length;
    let p = 0;

    while (len - p > 0 && window > 0) {
      let sliceLen = len - p;
      if (sliceLen > window) sliceLen = window;
      if (sliceLen > packetSize) sliceLen = packetSize;

      const chunk = p === 0 && sliceLen === len ? data : data.subarray(p, p + sliceLen);

      if (isStderr) {
        protocol.channelExtData(id, chunk, STDERR);
      } else {
        protocol.channelData(id, chunk);
      }

      p += sliceLen;
      window -= sliceLen;
    }

    outgoing.window = window;

    // If we still have data to send, wait for window space
    if (len - p > 0) {
      if (window === 0) {
        this._waitWindow = true;
      }

      // Store pending data
      const remaining = p > 0 ? data.subarray(p, len) : data;

      return new Promise<void>((resolve) => {
        if (isStderr) {
          this._chunkErr = remaining;
          this._chunkcbErr = resolve;
        } else {
          this._chunk = remaining;
          this._chunkcb = resolve;
        }
      });
    }
  }

  /**
   * Write data synchronously (non-blocking, fire-and-forget)
   * Used for Node.js-style write() compatibility
   */
  private _writeDataSync(data: Uint8Array, isStderr: boolean): void {
    const protocol = this._client._protocol;
    const outgoing = this.outgoing;
    const packetSize = outgoing.packetSize;
    const id = outgoing.id;

    if (id === undefined || outgoing.state !== 'open') {
      return;
    }

    let window = outgoing.window;
    const len = data.length;
    let p = 0;

    while (len - p > 0 && window > 0) {
      let sliceLen = len - p;
      if (sliceLen > window) sliceLen = window;
      if (sliceLen > packetSize) sliceLen = packetSize;

      const chunk = p === 0 && sliceLen === len ? data : data.subarray(p, p + sliceLen);

      if (isStderr) {
        protocol.channelExtData(id, chunk, STDERR);
      } else {
        protocol.channelData(id, chunk);
      }

      p += sliceLen;
      window -= sliceLen;
    }

    outgoing.window = window;

    // Queue remaining data for later (when window opens)
    if (len - p > 0) {
      if (window === 0) {
        this._waitWindow = true;
      }
      const remaining = p > 0 ? data.subarray(p, len) : data;
      if (isStderr) {
        this._chunkErr = remaining;
        this._chunkcbErr = () => {};
      } else {
        this._chunk = remaining;
        this._chunkcb = () => {};
      }
    }
  }

  /**
   * Adjust the SSH window
   */
  private _windowAdjust(): void {
    if (this.outgoing.state === 'closed' || this.outgoing.id === undefined) {
      return;
    }
    const amt = MAX_WINDOW - this.incoming.window;
    if (amt <= 0) {
      return;
    }
    this.incoming.window += amt;
    this._client._protocol.channelWindowAdjust(this.outgoing.id, amt);
  }

  /**
   * Handle close event
   */
  private _handleClose(): void {
    if (this._readableClosed && this._writableClosed) {
      this.emit('close');
    }
  }

  /**
   * Push incoming data to the readable stream
   */
  pushData(data: Uint8Array, isStderr = false): boolean {
    if (isStderr) {
      if (this._stderrController) {
        this._stderrController.enqueue(data);
        return true;
      }
      return false;
    }

    if (this._readableController) {
      this._readableController.enqueue(data);
      this.incoming.window -= data.length;

      // Check if we need backpressure
      if (this.incoming.window <= WINDOW_THRESHOLD) {
        this._waitChanDrain = true;
      }

      return true;
    }

    return false;
  }

  /**
   * Handle window adjustment from remote
   */
  adjustWindow(amount: number): void {
    this.outgoing.window += amount;

    // Resume pending writes if we have data waiting
    if (this._waitWindow && this.outgoing.window > 0) {
      this._waitWindow = false;

      // Flush pending data
      if (this._chunk && this._chunkcb) {
        const chunk = this._chunk;
        const cb = this._chunkcb;
        this._chunk = undefined;
        this._chunkcb = undefined;
        this._writeData(chunk, false).then(cb);
      }

      if (this._chunkErr && this._chunkcbErr) {
        const chunk = this._chunkErr;
        const cb = this._chunkcbErr;
        this._chunkErr = undefined;
        this._chunkcbErr = undefined;
        this._writeData(chunk, true).then(cb);
      }

      this.emit('drain');
    }
  }

  /**
   * Signal end of file (no more data to send)
   */
  eof(): void {
    if (this.outgoing.state === 'open' && this.outgoing.id !== undefined) {
      this.outgoing.state = 'eof';
      this._client._protocol.channelEOF(this.outgoing.id);
      this.emit('eof');
    }
  }

  /**
   * Handle incoming EOF
   */
  handleEOF(): void {
    if (this._readableController) {
      this._readableController.close();
      this._readableClosed = true;
    }
    if (this._stderrController) {
      this._stderrController.close();
    }
    this.emit('end');
  }

  /**
   * Close the channel
   */
  close(): void {
    if (
      (this.outgoing.state === 'open' || this.outgoing.state === 'eof') &&
      this.outgoing.id !== undefined
    ) {
      this.outgoing.state = 'closing';
      this._client._protocol.channelClose(this.outgoing.id);
    }
  }

  /**
   * Handle incoming close
   */
  handleClose(): void {
    this.incoming.state = 'closed';
    this.outgoing.state = 'closed';

    if (this._readableController && !this._readableClosed) {
      try {
        this._readableController.close();
      } catch {
        // Already closed
      }
      this._readableClosed = true;
    }

    if (this._stderrController) {
      try {
        this._stderrController.close();
      } catch {
        // Already closed
      }
    }

    this._writableClosed = true;
    this.emit('close');
  }

  /**
   * Destroy the channel
   */
  destroy(): void {
    this.close();
  }

  // Node.js-style compatibility methods =======================================

  /**
   * Write data to the channel (Node.js-style synchronous write)
   * For server-side use with exec/shell sessions
   */
  write(data: Uint8Array | string): void {
    this._writeDataSync(encodeData(data), false);
  }

  /**
   * End the channel (close write side and send EOF)
   * For server-side use with exec/shell sessions
   */
  end(): void {
    this.eof();
    this.close();
  }

  /**
   * Send exit status or signal (server only, Node.js-style)
   * @param code - Exit code (number) or signal name (string like "SIGKILL" or "KILL")
   */
  exit(code: number | string): void {
    if (!this.server) {
      throw new Error('Server-only method called in client mode');
    }

    if (typeof code === 'number') {
      this.sendExit(code);
    } else {
      // Validate and normalize signal name
      let signal = code;
      if (signal.startsWith('SIG')) {
        signal = signal.slice(3);
      }
      if (!VALID_SIGNALS.has(signal)) {
        throw new Error(`Invalid signal: ${code}`);
      }
      this.sendExit(signal);
    }
  }

  // Session type-specific methods =============================================

  /**
   * Set terminal window size (client only)
   */
  setWindow(rows: number, cols: number, height: number, width: number): void {
    if (this.server) {
      throw new Error('Client-only method called in server mode');
    }

    if (
      this.type === 'session' &&
      (this.subtype === 'shell' || this.subtype === 'exec') &&
      this.outgoing.state === 'open' &&
      this.outgoing.id !== undefined
    ) {
      this._client._protocol.windowChange?.(this.outgoing.id, rows, cols, height, width);
    }
  }

  /**
   * Send a signal to the remote process (client only)
   */
  signal(signalName: string): void {
    if (this.server) {
      throw new Error('Client-only method called in server mode');
    }

    if (
      this.type === 'session' &&
      this.outgoing.state === 'open' &&
      this.outgoing.id !== undefined
    ) {
      this._client._protocol.signal?.(this.outgoing.id, signalName);
    }
  }

  /**
   * Send exit status or signal (server only)
   */
  sendExit(statusOrSignal: number | string, coreDumped?: boolean, msg?: string): void {
    if (!this.server) {
      throw new Error('Server-only method called in client mode');
    }

    if (
      this.type === 'session' &&
      this.outgoing.state === 'open' &&
      this.outgoing.id !== undefined
    ) {
      if (typeof statusOrSignal === 'number') {
        this._client._protocol.exitStatus?.(this.outgoing.id, statusOrSignal);
      } else {
        this._client._protocol.exitSignal?.(
          this.outgoing.id,
          statusOrSignal,
          coreDumped ?? false,
          msg ?? '',
        );
      }
    }
  }

  /**
   * Handle exit status from remote
   */
  handleExitStatus(code: number): void {
    this.exitInfo.code = code;
    this.emit('exit-status', code);
  }

  /**
   * Handle exit signal from remote
   */
  handleExitSignal(signal: string, coreDumped: boolean, desc: string): void {
    this.exitInfo.signal = signal;
    this.exitInfo.dump = coreDumped;
    this.exitInfo.desc = desc;
    this.emit('exit-signal', signal, coreDumped, desc);
  }

  /** Whether X11 forwarding is enabled */
  get hasX11(): boolean {
    return this._hasX11;
  }

  set hasX11(value: boolean) {
    this._hasX11 = value;
  }

  /** Add a callback to be called when channel closes */
  addCallback(cb: () => void): void {
    this._callbacks.push(cb);
  }

  /** Call and clear all pending callbacks */
  flushCallbacks(): void {
    const callbacks = this._callbacks;
    this._callbacks = [];
    for (const cb of callbacks) {
      cb();
    }
  }
}

/**
 * Adjust window for a channel
 */
export function windowAdjust(channel: Channel): void {
  // Access private method via type assertion
  (channel as unknown as { _windowAdjust(): void })._windowAdjust();
}
