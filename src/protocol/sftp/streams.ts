/**
 * SFTP Stream Implementations
 *
 * Provides ReadStream and WriteStream for streaming file transfers.
 */

import { EventEmitter } from '../../utils/events.ts';
import type { SFTP } from './SFTP.ts';
import type { ReadStreamOptions, SFTPHandle, WriteStreamOptions } from './types.ts';
import { stringToFlags } from './types.ts';

const DEFAULT_HIGH_WATER_MARK = 64 * 1024;

/**
 * Validate position values
 */
function checkPosition(pos: number | undefined, name: string): void {
  if (pos === undefined) return;
  if (!Number.isSafeInteger(pos) || pos < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
}

/**
 * ReadStream for reading files from SFTP
 */
export class ReadStream extends EventEmitter {
  /** File path */
  readonly path: string;

  /** Open flags */
  readonly flags: string | number;

  /** File mode */
  readonly mode: number;

  /** Start position */
  readonly start?: number;

  /** End position */
  readonly end: number;

  /** Auto close handle on end/error */
  readonly autoClose: boolean;

  /** High water mark for buffering */
  readonly highWaterMark: number;

  /** Current position in file */
  pos: number;

  /** Total bytes read */
  bytesRead = 0;

  /** Whether stream is closed */
  isClosed = false;

  /** File handle */
  handle: SFTPHandle | null;

  /** SFTP instance */
  readonly sftp: SFTP;

  /** Whether currently opening */
  private _opening = false;

  /** Whether destroyed */
  private _destroyed = false;

  /** Whether readable */
  readable = true;

  /** Whether currently reading */
  private _reading = false;

  constructor(sftp: SFTP, path: string, options?: ReadStreamOptions) {
    super();

    this.sftp = sftp;
    this.path = path;
    this.flags = options?.flags ?? 'r';
    this.mode = options?.mode ?? 0o666;
    this.start = options?.start;
    this.end = options?.end ?? Infinity;
    this.autoClose = options?.autoClose ?? true;
    this.highWaterMark = options?.highWaterMark ?? DEFAULT_HIGH_WATER_MARK;
    this.handle = options?.handle ?? null;
    this.pos = 0;

    if (this.start !== undefined) {
      checkPosition(this.start, 'start');
      this.pos = this.start;
    }

    if (this.end !== Infinity) {
      checkPosition(this.end, 'end');
      if (this.start !== undefined && this.start > this.end) {
        throw new RangeError(`start (${this.start}) must be <= end (${this.end})`);
      }
    }

    this.on('end', () => {
      if (this.autoClose) {
        this.destroy();
      }
    });

    if (!this.handle) {
      this.open();
    }
  }

  /** Whether the handle is pending */
  get pending(): boolean {
    return this.handle === null;
  }

  /**
   * Open the file
   */
  open(): void {
    if (this._opening) return;
    this._opening = true;

    const flags = typeof this.flags === 'number' ? this.flags : stringToFlags(this.flags);
    if (flags === null) {
      this._opening = false;
      this.emit('error', new Error(`Unknown flags: ${this.flags}`));
      return;
    }

    this.sftp.open(this.path, flags, { mode: this.mode }).then((handle) => {
      this._opening = false;
      this.handle = handle;
      this.emit('open', handle);
      this.emit('ready');
    }).catch((err) => {
      this._opening = false;
      this.emit('error', err);
      if (this.autoClose) {
        this.destroy();
      }
    });
  }

  /**
   * Read data from file
   * Emits 'data' events with chunks
   */
  read(): void {
    if (this._reading || this._destroyed || !this.readable) return;
    if (!this.handle) {
      this.once('open', () => this.read());
      return;
    }

    this._reading = true;
    this._doRead();
  }

  private _doRead(): void {
    if (this._destroyed || !this.readable) {
      this._reading = false;
      return;
    }

    // Calculate bytes to read
    let toRead = this.highWaterMark;
    if (this.end !== Infinity) {
      toRead = Math.min(toRead, this.end - this.pos + 1);
    }

    if (toRead <= 0) {
      this._reading = false;
      this.push(null);
      return;
    }

    const buffer = new Uint8Array(toRead);

    this.sftp.read(this.handle!, buffer, 0, toRead, this.pos).then((bytesRead) => {
      if (!bytesRead || bytesRead === 0) {
        this._reading = false;
        this.push(null);
        return;
      }

      this.bytesRead += bytesRead;
      this.pos += bytesRead;

      const chunk = bytesRead < buffer.length ? buffer.subarray(0, bytesRead) : buffer;
      this.push(chunk);

      // Continue reading
      if (this.readable && !this._destroyed) {
        // Use queueMicrotask to prevent stack overflow
        queueMicrotask(() => this._doRead());
      } else {
        this._reading = false;
      }
    }).catch((err) => {
      this._reading = false;
      this.emit('error', err);
      if (this.autoClose) {
        this.destroy();
      }
    });
  }

  /**
   * Push data or null (EOF)
   */
  push(chunk: Uint8Array | null): void {
    if (chunk === null) {
      this.readable = false;
      this.emit('end');
    } else {
      this.emit('data', chunk);
    }
  }

  /**
   * Pause reading
   */
  pause(): this {
    this.readable = false;
    return this;
  }

  /**
   * Resume reading
   */
  resume(): this {
    if (!this._destroyed) {
      this.readable = true;
      this.read();
    }
    return this;
  }

  /**
   * Close the stream
   */
  close(cb?: (err?: Error | null) => void): void {
    this.destroy(undefined, cb);
  }

  /**
   * Destroy the stream
   */
  destroy(err?: Error, cb?: (err?: Error | null) => void): void {
    if (this._destroyed) {
      if (cb) cb(err);
      return;
    }

    this._destroyed = true;
    this.readable = false;

    if (this._opening && !this.handle) {
      this.once('open', () => this._closeHandle(err, cb));
      return;
    }

    this._closeHandle(err, cb);
  }

  private _closeHandle(err?: Error, cb?: (err?: Error | null) => void): void {
    if (!this.handle) {
      this.handle = null;
      this.isClosed = true;
      if (cb) cb(err);
      if (!err) this.emit('close');
      return;
    }

    this.sftp.close(this.handle).then(() => {
      this.handle = null;
      this.isClosed = true;
      if (cb) cb(err);
      if (!err) this.emit('close');
    }).catch((closeErr) => {
      this.handle = null;
      this.isClosed = true;
      const finalErr = closeErr || err;
      if (cb) cb(finalErr);
      if (!finalErr) this.emit('close');
    });
  }

  /**
   * Async iterator for reading chunks
   */
  async *[Symbol.asyncIterator](): AsyncIterableIterator<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let ended = false;
    let error: Error | null = null;
    let resolveWait: (() => void) | null = null;

    const onData = (chunk: Uint8Array) => {
      chunks.push(chunk);
      if (resolveWait) {
        resolveWait();
        resolveWait = null;
      }
    };

    const onEnd = () => {
      ended = true;
      if (resolveWait) {
        resolveWait();
        resolveWait = null;
      }
    };

    const onError = (err: Error) => {
      error = err;
      if (resolveWait) {
        resolveWait();
        resolveWait = null;
      }
    };

    this.on('data', onData);
    this.on('end', onEnd);
    this.on('error', onError);

    // Start reading
    this.read();

    try {
      while (!ended && !error) {
        if (chunks.length > 0) {
          yield chunks.shift()!;
        } else {
          await new Promise<void>((resolve) => {
            resolveWait = resolve;
          });
        }
      }

      // Yield remaining chunks
      while (chunks.length > 0) {
        yield chunks.shift()!;
      }

      if (error) throw error;
    } finally {
      this.removeListener('data', onData);
      this.removeListener('end', onEnd);
      this.removeListener('error', onError);
    }
  }
}

/**
 * WriteStream for writing files to SFTP
 */
export class WriteStream extends EventEmitter {
  /** File path */
  readonly path: string;

  /** Open flags */
  readonly flags: string | number;

  /** File mode */
  readonly mode: number;

  /** Start position */
  readonly start?: number;

  /** Auto close handle on end/error */
  readonly autoClose: boolean;

  /** High water mark for buffering */
  readonly highWaterMark: number;

  /** Current position in file */
  pos: number;

  /** Total bytes written */
  bytesWritten = 0;

  /** Whether stream is closed */
  isClosed = false;

  /** File handle */
  handle: SFTPHandle | null;

  /** SFTP instance */
  readonly sftp: SFTP;

  /** Whether currently opening */
  private _opening = false;

  /** Whether destroyed */
  private _destroyed = false;

  /** Whether writable */
  writable = true;

  /** Pending writes queue */
  private _writeQueue: Array<{
    data: Uint8Array;
    cb?: (err?: Error | null) => void;
  }> = [];

  /** Whether currently writing */
  private _writing = false;

  constructor(sftp: SFTP, path: string, options?: WriteStreamOptions) {
    super();

    this.sftp = sftp;
    this.path = path;
    this.flags = options?.flags ?? 'w';
    this.mode = options?.mode ?? 0o666;
    this.start = options?.start;
    this.autoClose = options?.autoClose ?? true;
    this.highWaterMark = options?.highWaterMark ?? DEFAULT_HIGH_WATER_MARK;
    this.handle = options?.handle ?? null;
    this.pos = 0;

    if (this.start !== undefined) {
      checkPosition(this.start, 'start');
      this.pos = this.start;
    }

    if (!this.handle) {
      this.open();
    }
  }

  /** Whether the handle is pending */
  get pending(): boolean {
    return this.handle === null;
  }

  /**
   * Open the file
   */
  open(): void {
    if (this._opening) return;
    this._opening = true;

    const flags = typeof this.flags === 'number' ? this.flags : stringToFlags(this.flags);
    if (flags === null) {
      this._opening = false;
      this.emit('error', new Error(`Unknown flags: ${this.flags}`));
      return;
    }

    this.sftp.open(this.path, flags, { mode: this.mode }).then(async (handle) => {
      this._opening = false;
      this.handle = handle;

      // For append mode, get current file size
      const flagStr = typeof this.flags === 'string' ? this.flags : '';
      if (flagStr.startsWith('a')) {
        try {
          const stats = await this.sftp.fstat(handle);
          this.pos = typeof stats.size === 'bigint' ? Number(stats.size) : (stats.size ?? 0);
        } catch {
          // Fallback to stat if fstat fails
          try {
            const stats2 = await this.sftp.stat(this.path);
            this.pos = typeof stats2.size === 'bigint' ? Number(stats2.size) : (stats2.size ?? 0);
          } catch (statErr) {
            this.emit('error', statErr);
            this.destroy();
            return;
          }
        }
      }

      this.emit('open', handle);
      this.emit('ready');
      this._processWriteQueue();
    }).catch((err) => {
      this._opening = false;
      this.emit('error', err);
      if (this.autoClose) {
        this.destroy();
      }
    });
  }

  /**
   * Write data to file
   */
  write(data: Uint8Array, cb?: (err?: Error | null) => void): boolean {
    if (this._destroyed || !this.writable) {
      const err = new Error('Stream is not writable');
      if (cb) cb(err);
      return false;
    }

    this._writeQueue.push({ data, cb });
    this._processWriteQueue();

    return this._writeQueue.length < this.highWaterMark;
  }

  private _processWriteQueue(): void {
    if (this._writing || this._destroyed || !this.writable) return;
    if (!this.handle) return; // Wait for open
    if (this._writeQueue.length === 0) return;

    this._writing = true;
    const { data, cb } = this._writeQueue.shift()!;

    this.sftp.write(this.handle!, data, 0, data.length, this.pos).then(() => {
      this._writing = false;

      this.bytesWritten += data.length;
      this.pos += data.length;

      if (cb) cb();

      // Emit drain if queue is empty
      if (this._writeQueue.length === 0) {
        this.emit('drain');
      }

      // Process next write
      this._processWriteQueue();
    }).catch((err) => {
      this._writing = false;

      if (cb) cb(err);
      this.emit('error', err);
      if (this.autoClose) {
        this.destroy();
      }
    });
  }

  /**
   * End the stream
   */
  end(data?: Uint8Array, cb?: (err?: Error | null) => void): void {
    if (data) {
      this.write(data, (err) => {
        if (err) {
          if (cb) cb(err);
          return;
        }
        this._end(cb);
      });
    } else {
      this._end(cb);
    }
  }

  private _end(cb?: (err?: Error | null) => void): void {
    this.writable = false;

    // Wait for pending writes
    if (this._writeQueue.length > 0 || this._writing) {
      this.once('drain', () => this._end(cb));
      return;
    }

    this.emit('finish');

    if (this.autoClose) {
      this.destroy(undefined, cb);
    } else if (cb) {
      cb();
    }
  }

  /**
   * Close the stream
   */
  close(cb?: (err?: Error | null) => void): void {
    if (this.isClosed) {
      if (cb) queueMicrotask(() => cb());
      return;
    }

    if (cb) {
      this.on('close', cb);
    }

    if (!this.autoClose) {
      this.once('finish', () => this.destroy());
    }

    this.end();
  }

  /**
   * Destroy the stream
   */
  destroy(err?: Error, cb?: (err?: Error | null) => void): void {
    if (this._destroyed) {
      if (cb) cb(err);
      return;
    }

    this._destroyed = true;
    this.writable = false;

    // Clear pending writes
    for (const { cb: writeCb } of this._writeQueue) {
      if (writeCb) writeCb(err || new Error('Stream destroyed'));
    }
    this._writeQueue = [];

    if (this._opening && !this.handle) {
      this.once('open', () => this._closeHandle(err, cb));
      return;
    }

    this._closeHandle(err, cb);
  }

  private _closeHandle(err?: Error, cb?: (err?: Error | null) => void): void {
    if (!this.handle) {
      this.handle = null;
      this.isClosed = true;
      if (cb) cb(err);
      if (!err) this.emit('close');
      return;
    }

    this.sftp.close(this.handle).then(() => {
      this.handle = null;
      this.isClosed = true;
      if (cb) cb(err);
      if (!err) this.emit('close');
    }).catch((closeErr) => {
      this.handle = null;
      this.isClosed = true;
      const finalErr = closeErr || err;
      if (cb) cb(finalErr);
      if (!finalErr) this.emit('close');
    });
  }

  /** Alias for end */
  destroySoon(): void {
    this.end();
  }
}
