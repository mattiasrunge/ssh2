/**
 * SFTP Protocol Constants
 *
 * Defines constants for the SSH File Transfer Protocol (SFTP) version 3.
 */

/**
 * Attribute flags for file attributes
 */
export const ATTR = {
  SIZE: 0x00000001,
  UIDGID: 0x00000002,
  PERMISSIONS: 0x00000004,
  ACMODTIME: 0x00000008,
  EXTENDED: 0x80000000,
} as const;

export type AttrFlag = (typeof ATTR)[keyof typeof ATTR];

/**
 * SFTP status codes
 */
export const STATUS_CODE = {
  OK: 0,
  EOF: 1,
  NO_SUCH_FILE: 2,
  PERMISSION_DENIED: 3,
  FAILURE: 4,
  BAD_MESSAGE: 5,
  NO_CONNECTION: 6,
  CONNECTION_LOST: 7,
  OP_UNSUPPORTED: 8,
} as const;

export type StatusCode = (typeof STATUS_CODE)[keyof typeof STATUS_CODE];

/**
 * Human-readable status code descriptions
 */
export const STATUS_CODE_STR: Record<StatusCode, string> = {
  [STATUS_CODE.OK]: 'No error',
  [STATUS_CODE.EOF]: 'End of file',
  [STATUS_CODE.NO_SUCH_FILE]: 'No such file or directory',
  [STATUS_CODE.PERMISSION_DENIED]: 'Permission denied',
  [STATUS_CODE.FAILURE]: 'Failure',
  [STATUS_CODE.BAD_MESSAGE]: 'Bad message',
  [STATUS_CODE.NO_CONNECTION]: 'No connection',
  [STATUS_CODE.CONNECTION_LOST]: 'Connection lost',
  [STATUS_CODE.OP_UNSUPPORTED]: 'Operation unsupported',
};

/**
 * Set of valid status codes for validation
 */
export const VALID_STATUS_CODES = new Set<number>(Object.values(STATUS_CODE));

/**
 * SFTP request packet types
 */
export const REQUEST = {
  INIT: 1,
  OPEN: 3,
  CLOSE: 4,
  READ: 5,
  WRITE: 6,
  LSTAT: 7,
  FSTAT: 8,
  SETSTAT: 9,
  FSETSTAT: 10,
  OPENDIR: 11,
  READDIR: 12,
  REMOVE: 13,
  MKDIR: 14,
  RMDIR: 15,
  REALPATH: 16,
  STAT: 17,
  RENAME: 18,
  READLINK: 19,
  SYMLINK: 20,
  EXTENDED: 200,
} as const;

export type RequestType = (typeof REQUEST)[keyof typeof REQUEST];

/**
 * SFTP response packet types
 */
export const RESPONSE = {
  VERSION: 2,
  STATUS: 101,
  HANDLE: 102,
  DATA: 103,
  NAME: 104,
  ATTRS: 105,
  EXTENDED: 201,
} as const;

export type ResponseType = (typeof RESPONSE)[keyof typeof RESPONSE];

/**
 * File open mode flags
 */
export const OPEN_MODE = {
  READ: 0x00000001,
  WRITE: 0x00000002,
  APPEND: 0x00000004,
  CREAT: 0x00000008,
  TRUNC: 0x00000010,
  EXCL: 0x00000020,
} as const;

export type OpenModeFlag = (typeof OPEN_MODE)[keyof typeof OPEN_MODE];

/**
 * Protocol version constants
 */
export const SFTP_VERSION = 3;

/**
 * Packet read/write overhead for buffer calculations
 */
export const PKT_RW_OVERHEAD = 2 * 1024;

/**
 * Maximum request ID before wrapping
 */
export const MAX_REQID = 2 ** 32 - 1;

/**
 * Regex to detect OpenSSH/dropbear servers
 */
export const RE_OPENSSH = /^SSH-2.0-(?:OpenSSH|dropbear)/;

/**
 * Maximum packet length for OpenSSH
 */
export const OPENSSH_MAX_PKT_LEN = 256 * 1024;

/**
 * Default maximum packet length
 */
export const DEFAULT_MAX_PKT_LEN = 34000;

/**
 * File type bits from mode (S_IFMT)
 */
export const S_IFMT = 0o170000;
export const S_IFREG = 0o100000; // Regular file
export const S_IFDIR = 0o040000; // Directory
export const S_IFCHR = 0o020000; // Character device
export const S_IFBLK = 0o060000; // Block device
export const S_IFIFO = 0o010000; // FIFO
export const S_IFLNK = 0o120000; // Symbolic link
export const S_IFSOCK = 0o140000; // Socket
