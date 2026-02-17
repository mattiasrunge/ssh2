/**
 * SSH2 - SSH2 client and server modules for Deno
 *
 * This is a TypeScript port of the ssh2 library, using Web-standard APIs.
 *
 * @module
 */

// Re-export utilities
export * from './utils/mod.ts';

// Re-export crypto utilities
export * as crypto from './crypto/mod.ts';

// Re-export protocol module
export * as protocol from './protocol/mod.ts';

// Re-export adapters (transport layer)
export * as adapters from './adapters/mod.ts';

// Re-export Channel
export * from './Channel.ts';

// Re-export utilities
export * from './utils.ts';

// Re-export key generation
export * from './keygen.ts';

// Re-export agent
export * from './agent.ts';

// Re-export client
export * from './client.ts';

// Re-export server
export * from './server.ts';

// Also re-export constants at top level for convenience
export * from './protocol/constants.ts';

// Re-export SFTP classes and constants
export { SFTP } from './protocol/sftp/SFTP.ts';
export type { SFTPClient } from './protocol/sftp/SFTP.ts';
export type { SFTPConfig } from './protocol/sftp/types.ts';
export { OPEN_MODE, STATUS_CODE, STATUS_CODE_STR } from './protocol/sftp/constants.ts';
export { Stats as SFTPStats } from './protocol/sftp/Stats.ts';
export type {
  FileAttributes,
  InputAttributes,
  SFTPExtensions,
  SFTPHandle,
} from './protocol/sftp/types.ts';
export { ReadStream, WriteStream } from './protocol/sftp/streams.ts';
