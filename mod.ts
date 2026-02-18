/**
 * SSH2 - SSH2 client and server modules for Deno
 *
 * This is a TypeScript port of the ssh2 library, using Web-standard APIs.
 *
 * @module
 */

// Re-export utilities
export * from './src/utils/mod.ts';

// Re-export crypto utilities
export * as crypto from './src/crypto/mod.ts';

// Re-export protocol module
export * as protocol from './src/protocol/mod.ts';

// Re-export adapters (transport layer)
export * as adapters from './src/adapters/mod.ts';

// Re-export Channel
export * from './src/Channel.ts';

// Re-export utilities
export * from './src/utils.ts';

// Re-export key generation
export * from './src/keygen.ts';

// Re-export agent
export * from './src/agent.ts';

// Re-export client
export * from './src/client.ts';

// Re-export server
export * from './src/server.ts';

// Also re-export constants at top level for convenience
export * from './src/protocol/constants.ts';

// Re-export SFTP classes and constants
export { SFTP } from './src/protocol/sftp/SFTP.ts';
export type { SFTPClient } from './src/protocol/sftp/SFTP.ts';
export type { SFTPConfig } from './src/protocol/sftp/types.ts';
export { OPEN_MODE, STATUS_CODE, STATUS_CODE_STR } from './src/protocol/sftp/constants.ts';
export { Stats as SFTPStats } from './src/protocol/sftp/Stats.ts';
export type {
  FileAttributes,
  InputAttributes,
  SFTPExtensions,
  SFTPHandle,
} from './src/protocol/sftp/types.ts';
export { ReadStream, WriteStream } from './src/protocol/sftp/streams.ts';
