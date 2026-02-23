/**
 * SFTP Fast Transfer Functions
 *
 * Provides high-performance file transfer using concurrent requests.
 */

import { modeNum } from './packet.ts';
import type { SFTP } from './SFTP.ts';
import type { SFTPHandle, TransferOptions, TransferProgress } from './types.ts';

const DEFAULT_CONCURRENCY = 64;
const DEFAULT_CHUNK_SIZE = 32768;

/**
 * SFTP-compatible file system interface
 * Used to abstract between local fs and remote SFTP
 */
interface FSInterface {
  open(
    path: string,
    flags: string,
    cb: (err: Error | null, handle?: SFTPHandle | number) => void,
  ): void;
  open(
    path: string,
    flags: string,
    mode: number,
    cb: (err: Error | null, handle?: SFTPHandle | number) => void,
  ): void;
  close(handle: SFTPHandle | number, cb: (err: Error | null) => void): void;
  read(
    handle: SFTPHandle | number,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | bigint,
    cb: (err: Error | null, bytesRead?: number, buffer?: Uint8Array) => void,
  ): void;
  write(
    handle: SFTPHandle | number,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | bigint,
    cb: (err: Error | null) => void,
  ): void;
  fstat(
    handle: SFTPHandle | number,
    cb: (err: Error | null, stats?: { size?: number | bigint }) => void,
  ): void;
  stat(
    path: string,
    cb: (err: Error | null, stats?: { size?: number | bigint }) => void,
  ): void;
  fchmod?(
    handle: SFTPHandle | number,
    mode: number,
    cb: (err: Error | null) => void,
  ): void;
  chmod?(
    path: string,
    mode: number,
    cb: (err: Error | null) => void,
  ): void;
}

/**
 * Local file system interface for Deno
 */
class LocalFS implements FSInterface {
  private _files = new Map<number, Deno.FsFile>();
  private _nextFd = 100;

  open(
    path: string,
    flags: string,
    modeOrCb: number | ((err: Error | null, handle?: number) => void),
    cb?: (err: Error | null, handle?: number) => void,
  ): void {
    const callback = typeof modeOrCb === 'function' ? modeOrCb : cb!;
    const mode = typeof modeOrCb === 'number' ? modeOrCb : undefined;

    const openOptions: Deno.OpenOptions = {};

    if (flags.includes('r')) {
      openOptions.read = true;
    }
    if (flags.includes('w')) {
      openOptions.write = true;
      openOptions.create = true;
      openOptions.truncate = true;
    }
    if (flags.includes('a')) {
      openOptions.write = true;
      openOptions.create = true;
      openOptions.append = true;
    }
    if (flags.includes('+')) {
      openOptions.read = true;
      openOptions.write = true;
    }
    if (flags.includes('x')) {
      openOptions.createNew = true;
    }

    (async () => {
      try {
        const file = await Deno.open(path, openOptions);
        const fd = this._nextFd++;
        this._files.set(fd, file);

        if (mode !== undefined && openOptions.create) {
          try {
            await Deno.chmod(path, mode);
          } catch {
            // Ignore chmod errors
          }
        }

        callback(null, fd);
      } catch (err) {
        callback(err as Error);
      }
    })();
  }

  close(handle: number, cb: (err: Error | null) => void): void {
    const file = this._files.get(handle);
    if (!file) {
      cb(new Error('Invalid handle'));
      return;
    }

    try {
      file.close();
      this._files.delete(handle);
      cb(null);
    } catch (err) {
      cb(err as Error);
    }
  }

  read(
    handle: number,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | bigint,
    cb: (err: Error | null, bytesRead?: number, buffer?: Uint8Array) => void,
  ): void {
    const file = this._files.get(handle);
    if (!file) {
      cb(new Error('Invalid handle'));
      return;
    }

    (async () => {
      try {
        await file.seek(Number(position), Deno.SeekMode.Start);
        const view = buffer.subarray(offset, offset + length);
        const bytesRead = await file.read(view);
        cb(null, bytesRead ?? 0, buffer);
      } catch (err) {
        cb(err as Error);
      }
    })();
  }

  write(
    handle: number,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | bigint,
    cb: (err: Error | null) => void,
  ): void {
    const file = this._files.get(handle);
    if (!file) {
      cb(new Error('Invalid handle'));
      return;
    }

    (async () => {
      try {
        await file.seek(Number(position), Deno.SeekMode.Start);
        const data = buffer.subarray(offset, offset + length);
        let written = 0;
        while (written < data.length) {
          written += await file.write(data.subarray(written));
        }
        cb(null);
      } catch (err) {
        cb(err as Error);
      }
    })();
  }

  fstat(
    handle: number,
    cb: (err: Error | null, stats?: { size?: number | bigint }) => void,
  ): void {
    const file = this._files.get(handle);
    if (!file) {
      cb(new Error('Invalid handle'));
      return;
    }

    (async () => {
      try {
        const stat = await file.stat();
        cb(null, { size: stat.size });
      } catch (err) {
        cb(err as Error);
      }
    })();
  }

  stat(
    path: string,
    cb: (err: Error | null, stats?: { size?: number | bigint }) => void,
  ): void {
    (async () => {
      try {
        const stat = await Deno.stat(path);
        cb(null, { size: stat.size });
      } catch (err) {
        cb(err as Error);
      }
    })();
  }

  chmod(
    path: string,
    mode: number,
    cb: (err: Error | null) => void,
  ): void {
    (async () => {
      try {
        await Deno.chmod(path, mode);
        cb(null);
      } catch (err) {
        cb(err as Error);
      }
    })();
  }
}

/** Shared local filesystem instance */
const localFS = new LocalFS();

/**
 * Fast transfer from source to destination
 */
function fastXfer(
  src: FSInterface,
  dst: FSInterface,
  srcPath: string,
  dstPath: string,
  opts: TransferOptions | ((err: Error | null) => void) | undefined,
  cb: ((err: Error | null) => void) | undefined,
): void {
  let concurrency = DEFAULT_CONCURRENCY;
  let chunkSize = DEFAULT_CHUNK_SIZE;
  let onStep: ((progress: TransferProgress) => void) | undefined;
  let mode: number | undefined;
  let fileSize: number | undefined;

  if (typeof opts === 'function') {
    cb = opts;
    opts = undefined;
  }

  if (opts) {
    if (typeof opts.concurrency === 'number' && opts.concurrency > 0) {
      concurrency = opts.concurrency;
    }
    if (typeof opts.chunkSize === 'number' && opts.chunkSize > 0) {
      chunkSize = opts.chunkSize;
    }
    if (typeof opts.step === 'function') {
      onStep = opts.step;
    }
    if (opts.mode !== undefined) {
      mode = modeNum(opts.mode);
    }
  }

  const callback = cb ?? (() => {});

  // State
  let fsize = 0;
  let pdst = 0;
  let total = 0;
  let hadError = false;
  let srcHandle: SFTPHandle | number | undefined;
  let dstHandle: SFTPHandle | number | undefined;
  let readBuf: Uint8Array;
  let bufsize = chunkSize * concurrency;

  function onError(err?: Error | null): void {
    if (hadError) return;
    hadError = true;

    let left = 0;
    const cbFinal = () => {
      if (--left === 0) {
        callback(err ?? null);
      }
    };

    if (srcHandle !== undefined) {
      left++;
      src.close(srcHandle, cbFinal);
    }
    if (dstHandle !== undefined) {
      left++;
      dst.close(dstHandle, cbFinal);
    }
    if (left === 0) {
      callback(err ?? null);
    }
  }

  // Open source file
  src.open(srcPath, 'r', (err, handle) => {
    if (err) return onError(err);
    srcHandle = handle!;

    if (fileSize !== undefined) {
      tryStat(null, { size: fileSize });
    } else {
      src.fstat(srcHandle, tryStat);
    }
  });

  function tryStat(err: Error | null, stats?: { size?: number | bigint }): void {
    if (err) {
      // Try stat() as fallback
      src.stat(srcPath, (err2, stats2) => {
        if (err2) return onError(err);
        tryStat(null, stats2);
      });
      return;
    }

    const size = stats?.size;
    fsize = typeof size === 'bigint' ? Number(size) : (size ?? 0);

    // Open destination file
    if (mode !== undefined) {
      dst.open(dstPath, 'w', mode, openDstCb);
    } else {
      dst.open(dstPath, 'w', openDstCb);
    }
  }

  function openDstCb(err: Error | null, handle?: SFTPHandle | number): void {
    if (err) return onError(err);
    dstHandle = handle!;

    if (fsize <= 0) {
      // Empty file
      return onError();
    }

    // Adjust buffer size for small files
    while (bufsize > fsize) {
      if (concurrency === 1) {
        bufsize = fsize;
        break;
      }
      bufsize -= chunkSize;
      concurrency--;
    }

    readBuf = new Uint8Array(bufsize);

    if (mode !== undefined && dst.fchmod) {
      dst.fchmod(dstHandle!, mode, (err) => {
        if (err && dst.chmod) {
          dst.chmod(dstPath, mode!, () => startReads());
        } else {
          startReads();
        }
      });
    } else {
      startReads();
    }
  }

  function onRead(
    err: Error | null,
    bytesRead: number | undefined,
    _data: Uint8Array | undefined,
    dstPos: number,
    dataPos: number,
    origChunkLen: number,
  ): void {
    if (err) return onError(err);

    const nb = bytesRead ?? 0;
    dst.write(dstHandle!, readBuf, dataPos, nb, dstPos, (writeErr) => {
      if (writeErr) return onError(writeErr);

      total += nb;
      if (onStep) {
        onStep({
          total: fsize,
          transferred: total,
          chunk: nb,
        });
      }

      if (nb < origChunkLen) {
        // Partial read, continue
        return singleRead(dataPos, dstPos + nb, origChunkLen - nb);
      }

      if (total === fsize) {
        // Transfer complete
        dst.close(dstHandle!, (err) => {
          dstHandle = undefined;
          if (err) return onError(err);
          src.close(srcHandle!, (err) => {
            srcHandle = undefined;
            if (err) return onError(err);
            callback(null);
          });
        });
        return;
      }

      if (pdst >= fsize) return;

      const chunk = pdst + chunkSize > fsize ? fsize - pdst : chunkSize;
      singleRead(dataPos, pdst, chunk);
      pdst += chunk;
    });
  }

  function singleRead(srcPos: number, dstPos: number, chunk: number): void {
    src.read(
      srcHandle!,
      readBuf,
      srcPos,
      chunk,
      dstPos,
      (err, bytesRead, buffer) => {
        onRead(err, bytesRead, buffer, dstPos, srcPos, chunk);
      },
    );
  }

  function startReads(): void {
    let reads = 0;
    let srcPos = 0;

    while (pdst < fsize && reads < concurrency) {
      const chunk = pdst + chunkSize > fsize ? fsize - pdst : chunkSize;
      singleRead(srcPos, pdst, chunk);
      srcPos += chunk;
      pdst += chunk;
      reads++;
    }
  }
}

/**
 * Fast download from remote SFTP to local file
 */
export function fastGet(
  sftp: SFTP,
  remotePath: string,
  localPath: string,
  opts?: TransferOptions | ((err: Error | null) => void),
  cb?: (err: Error | null) => void,
): void {
  fastXfer(sftp as unknown as FSInterface, localFS, remotePath, localPath, opts, cb);
}

/**
 * Fast upload from local file to remote SFTP
 */
export function fastPut(
  sftp: SFTP,
  localPath: string,
  remotePath: string,
  opts?: TransferOptions | ((err: Error | null) => void),
  cb?: (err: Error | null) => void,
): void {
  fastXfer(localFS, sftp as unknown as FSInterface, localPath, remotePath, opts, cb);
}
