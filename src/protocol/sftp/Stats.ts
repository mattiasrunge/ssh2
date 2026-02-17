/**
 * SFTP Stats Class
 *
 * Represents file attributes/metadata returned by stat operations.
 * Similar to Node.js fs.Stats but for SFTP.
 */

import {
  S_IFBLK,
  S_IFCHR,
  S_IFDIR,
  S_IFIFO,
  S_IFLNK,
  S_IFMT,
  S_IFREG,
  S_IFSOCK,
} from './constants.ts';
import type { ExtendedAttribute, FileAttributes } from './types.ts';

/**
 * File stats class for SFTP
 */
export class Stats implements FileAttributes {
  mode?: number;
  uid?: number;
  gid?: number;
  size?: number | bigint;
  atime?: number;
  mtime?: number;
  extended?: ExtendedAttribute[];

  constructor(initial?: FileAttributes) {
    if (initial) {
      this.mode = initial.mode;
      this.uid = initial.uid;
      this.gid = initial.gid;
      this.size = initial.size;
      // Convert Date to timestamp if needed
      if (initial.atime instanceof Date) {
        this.atime = Math.floor(initial.atime.getTime() / 1000);
      } else {
        this.atime = initial.atime as number | undefined;
      }
      if (initial.mtime instanceof Date) {
        this.mtime = Math.floor(initial.mtime.getTime() / 1000);
      } else {
        this.mtime = initial.mtime as number | undefined;
      }
      this.extended = initial.extended;
    }
  }

  /**
   * Returns true if this is a directory
   */
  isDirectory(): boolean {
    return this.mode !== undefined && (this.mode & S_IFMT) === S_IFDIR;
  }

  /**
   * Returns true if this is a regular file
   */
  isFile(): boolean {
    return this.mode !== undefined && (this.mode & S_IFMT) === S_IFREG;
  }

  /**
   * Returns true if this is a block device
   */
  isBlockDevice(): boolean {
    return this.mode !== undefined && (this.mode & S_IFMT) === S_IFBLK;
  }

  /**
   * Returns true if this is a character device
   */
  isCharacterDevice(): boolean {
    return this.mode !== undefined && (this.mode & S_IFMT) === S_IFCHR;
  }

  /**
   * Returns true if this is a symbolic link
   */
  isSymbolicLink(): boolean {
    return this.mode !== undefined && (this.mode & S_IFMT) === S_IFLNK;
  }

  /**
   * Returns true if this is a FIFO (named pipe)
   */
  isFIFO(): boolean {
    return this.mode !== undefined && (this.mode & S_IFMT) === S_IFIFO;
  }

  /**
   * Returns true if this is a socket
   */
  isSocket(): boolean {
    return this.mode !== undefined && (this.mode & S_IFMT) === S_IFSOCK;
  }

  /**
   * Get access time as Date
   */
  get atimeDate(): Date | undefined {
    return this.atime !== undefined ? new Date(this.atime * 1000) : undefined;
  }

  /**
   * Get modification time as Date
   */
  get mtimeDate(): Date | undefined {
    return this.mtime !== undefined ? new Date(this.mtime * 1000) : undefined;
  }
}
