/**
 * SSH Protocol Constants
 * Based on RFC 4250, RFC 4251, RFC 4252, RFC 4253, RFC 4254
 */

// SSH Message Types
export const MESSAGE = {
  // Transport layer protocol -- generic (1-19)
  DISCONNECT: 1,
  IGNORE: 2,
  UNIMPLEMENTED: 3,
  DEBUG: 4,
  SERVICE_REQUEST: 5,
  SERVICE_ACCEPT: 6,
  EXT_INFO: 7, // RFC 8308

  // Transport layer protocol -- algorithm negotiation (20-29)
  KEXINIT: 20,
  NEWKEYS: 21,

  // Transport layer protocol -- key exchange method-specific (30-49)
  KEXDH_INIT: 30,
  KEXDH_REPLY: 31,

  KEXDH_GEX_GROUP: 31,
  KEXDH_GEX_INIT: 32,
  KEXDH_GEX_REPLY: 33,
  KEXDH_GEX_REQUEST: 34,

  KEXECDH_INIT: 30,
  KEXECDH_REPLY: 31,

  // User auth protocol -- generic (50-59)
  USERAUTH_REQUEST: 50,
  USERAUTH_FAILURE: 51,
  USERAUTH_SUCCESS: 52,
  USERAUTH_BANNER: 53,

  // User auth protocol -- user auth method-specific (60-79)
  USERAUTH_PASSWD_CHANGEREQ: 60,
  USERAUTH_PK_OK: 60,
  USERAUTH_INFO_REQUEST: 60,
  USERAUTH_INFO_RESPONSE: 61,

  // Connection protocol -- generic (80-89)
  GLOBAL_REQUEST: 80,
  REQUEST_SUCCESS: 81,
  REQUEST_FAILURE: 82,

  // Connection protocol -- channel-related (90-127)
  CHANNEL_OPEN: 90,
  CHANNEL_OPEN_CONFIRMATION: 91,
  CHANNEL_OPEN_FAILURE: 92,
  CHANNEL_WINDOW_ADJUST: 93,
  CHANNEL_DATA: 94,
  CHANNEL_EXTENDED_DATA: 95,
  CHANNEL_EOF: 96,
  CHANNEL_CLOSE: 97,
  CHANNEL_REQUEST: 98,
  CHANNEL_SUCCESS: 99,
  CHANNEL_FAILURE: 100,
} as const;

/** Numeric value of an SSH message type. */
export type MessageType = (typeof MESSAGE)[keyof typeof MESSAGE];

/** Disconnect reason codes as defined in RFC 4253 Section 11.1. */
export const DISCONNECT_REASON = {
  HOST_NOT_ALLOWED_TO_CONNECT: 1,
  PROTOCOL_ERROR: 2,
  KEY_EXCHANGE_FAILED: 3,
  RESERVED: 4,
  MAC_ERROR: 5,
  COMPRESSION_ERROR: 6,
  SERVICE_NOT_AVAILABLE: 7,
  PROTOCOL_VERSION_NOT_SUPPORTED: 8,
  HOST_KEY_NOT_VERIFIABLE: 9,
  CONNECTION_LOST: 10,
  BY_APPLICATION: 11,
  TOO_MANY_CONNECTIONS: 12,
  AUTH_CANCELED_BY_USER: 13,
  NO_MORE_AUTH_METHODS_AVAILABLE: 14,
  ILLEGAL_USER_NAME: 15,
} as const;

/** Numeric disconnect reason code. */
export type DisconnectReason = (typeof DISCONNECT_REASON)[keyof typeof DISCONNECT_REASON];

/** Reverse mapping from disconnect reason code number to name string. */
export const DISCONNECT_REASON_BY_VALUE: Record<number, string> = Object.fromEntries(
  Object.entries(DISCONNECT_REASON).map(([key, value]) => [value, key]),
);

/** Channel open failure reason codes as defined in RFC 4254 Section 5.1. */
export const CHANNEL_OPEN_FAILURE = {
  ADMINISTRATIVELY_PROHIBITED: 1,
  CONNECT_FAILED: 2,
  UNKNOWN_CHANNEL_TYPE: 3,
  RESOURCE_SHORTAGE: 4,
} as const;

/** Numeric channel open failure reason code. */
export type ChannelOpenFailure = (typeof CHANNEL_OPEN_FAILURE)[keyof typeof CHANNEL_OPEN_FAILURE];

/** Terminal mode opcodes as defined in RFC 4254 Section 8. */
export const TERMINAL_MODE = {
  TTY_OP_END: 0,
  VINTR: 1,
  VQUIT: 2,
  VERASE: 3,
  VKILL: 4,
  VEOF: 5,
  VEOL: 6,
  VEOL2: 7,
  VSTART: 8,
  VSTOP: 9,
  VSUSP: 10,
  VDSUSP: 11,
  VREPRINT: 12,
  VWERASE: 13,
  VLNEXT: 14,
  VFLUSH: 15,
  VSWTCH: 16,
  VSTATUS: 17,
  VDISCARD: 18,
  IGNPAR: 30,
  PARMRK: 31,
  INPCK: 32,
  ISTRIP: 33,
  INLCR: 34,
  IGNCR: 35,
  ICRNL: 36,
  IUCLC: 37,
  IXON: 38,
  IXANY: 39,
  IXOFF: 40,
  IMAXBEL: 41,
  IUTF8: 42,
  ISIG: 50,
  ICANON: 51,
  XCASE: 52,
  ECHO: 53,
  ECHOE: 54,
  ECHOK: 55,
  ECHONL: 56,
  NOFLSH: 57,
  TOSTOP: 58,
  IEXTEN: 59,
  ECHOCTL: 60,
  ECHOKE: 61,
  PENDIN: 62,
  OPOST: 70,
  OLCUC: 71,
  ONLCR: 72,
  OCRNL: 73,
  ONOCR: 74,
  ONLRET: 75,
  CS7: 90,
  CS8: 91,
  PARENB: 92,
  PARODD: 93,
  TTY_OP_ISPEED: 128,
  TTY_OP_OSPEED: 129,
} as const;

/** Numeric terminal mode opcode. */
export type TerminalMode = (typeof TERMINAL_MODE)[keyof typeof TERMINAL_MODE];

/** Channel extended data type codes as defined in RFC 4254 Section 5.2. */
export const CHANNEL_EXTENDED_DATATYPE = {
  STDERR: 1,
} as const;

/** Signal names supported by the SSH protocol (RFC 4254 Section 6.9). */
export const SIGNALS: Record<string, number> = {
  ABRT: 1,
  ALRM: 1,
  FPE: 1,
  HUP: 1,
  ILL: 1,
  INT: 1,
  QUIT: 1,
  SEGV: 1,
  TERM: 1,
  USR1: 1,
  USR2: 1,
  KILL: 1,
  PIPE: 1,
};

/** Bitmask flags for working around quirks in specific SSH implementations. */
export const COMPAT = {
  BAD_DHGEX: 1 << 0,
  OLD_EXIT: 1 << 1,
  DYN_RPORT_BUG: 1 << 2,
  BUG_DHGEX_LARGE: 1 << 3,
  IMPLY_RSA_SHA2_SIGALGS: 1 << 4,
} as const;

/** A single compatibility bitmask value. */
export type CompatFlag = (typeof COMPAT)[keyof typeof COMPAT];

/** Version pattern / compat-flag pairs used to detect known SSH implementation quirks. */
export const COMPAT_CHECKS: [string | RegExp, number][] = [
  ['Cisco-1.25', COMPAT.BAD_DHGEX],
  [/^Cisco-1[.]/, COMPAT.BUG_DHGEX_LARGE],
  [/^[0-9.]+$/, COMPAT.OLD_EXIT], // old SSH.com implementations
  [/^OpenSSH_5[.][0-9]+/, COMPAT.DYN_RPORT_BUG],
  [/^OpenSSH_7[.]4/, COMPAT.IMPLY_RSA_SHA2_SIGALGS],
];

/** Describes the parameters of an SSH cipher algorithm. */
export interface CipherInfo {
  sslName: string;
  blockLen: number;
  keyLen: number;
  ivLen: number;
  authLen: number;
  discardLen: number;
  stream: boolean;
}

const CIPHER_STREAM = 1 << 0;

function cipherInfo(
  sslName: string,
  blockLen: number,
  keyLen: number,
  ivLen: number,
  authLen: number,
  discardLen: number,
  flags: number,
): CipherInfo {
  return {
    sslName,
    blockLen,
    keyLen,
    ivLen: ivLen !== 0 || (flags & CIPHER_STREAM) ? ivLen : blockLen,
    authLen,
    discardLen,
    stream: !!(flags & CIPHER_STREAM),
  };
}

/** Map of SSH cipher name to its {@link CipherInfo} parameters. */
export const CIPHER_INFO: Record<string, CipherInfo> = {
  'chacha20-poly1305@openssh.com': cipherInfo('chacha20', 8, 64, 0, 16, 0, CIPHER_STREAM),

  'aes128-gcm': cipherInfo('aes-128-gcm', 16, 16, 12, 16, 0, CIPHER_STREAM),
  'aes256-gcm': cipherInfo('aes-256-gcm', 16, 32, 12, 16, 0, CIPHER_STREAM),
  'aes128-gcm@openssh.com': cipherInfo('aes-128-gcm', 16, 16, 12, 16, 0, CIPHER_STREAM),
  'aes256-gcm@openssh.com': cipherInfo('aes-256-gcm', 16, 32, 12, 16, 0, CIPHER_STREAM),

  'aes128-cbc': cipherInfo('aes-128-cbc', 16, 16, 0, 0, 0, 0),
  'aes192-cbc': cipherInfo('aes-192-cbc', 16, 24, 0, 0, 0, 0),
  'aes256-cbc': cipherInfo('aes-256-cbc', 16, 32, 0, 0, 0, 0),
  'rijndael-cbc@lysator.liu.se': cipherInfo('aes-256-cbc', 16, 32, 0, 0, 0, 0),

  'aes128-ctr': cipherInfo('aes-128-ctr', 16, 16, 16, 0, 0, CIPHER_STREAM),
  'aes192-ctr': cipherInfo('aes-192-ctr', 16, 24, 16, 0, 0, CIPHER_STREAM),
  'aes256-ctr': cipherInfo('aes-256-ctr', 16, 32, 16, 0, 0, CIPHER_STREAM),
};

/** Describes the parameters of an SSH MAC (Message Authentication Code) algorithm. */
export interface MACInfo {
  sslName: string;
  len: number;
  actualLen: number;
  isETM: boolean;
}

function macInfo(sslName: string, len: number, actualLen: number, isETM: boolean): MACInfo {
  return { sslName, len, actualLen, isETM };
}

/** Map of SSH MAC algorithm name to its {@link MACInfo} parameters. */
export const MAC_INFO: Record<string, MACInfo> = {
  'hmac-sha2-256-etm@openssh.com': macInfo('sha256', 32, 32, true),
  'hmac-sha2-512-etm@openssh.com': macInfo('sha512', 64, 64, true),
  'hmac-sha1-etm@openssh.com': macInfo('sha1', 20, 20, true),
  'hmac-sha2-256': macInfo('sha256', 32, 32, false),
  'hmac-sha2-512': macInfo('sha512', 64, 64, false),
  'hmac-sha1': macInfo('sha1', 20, 20, false),
  'hmac-sha2-256-96': macInfo('sha256', 32, 12, false),
  'hmac-sha2-512-96': macInfo('sha512', 64, 12, false),
  'hmac-sha1-96': macInfo('sha1', 20, 12, false),
};

/** Default key-exchange algorithms (preferred order, Web Crypto API compatible). */
export const DEFAULT_KEX = [
  'curve25519-sha256',
  'curve25519-sha256@libssh.org',
  'ecdh-sha2-nistp256',
  'ecdh-sha2-nistp384',
  'ecdh-sha2-nistp521',
  'diffie-hellman-group-exchange-sha256',
  'diffie-hellman-group14-sha256',
  'diffie-hellman-group16-sha512',
  'diffie-hellman-group18-sha512',
];

/** All supported key-exchange algorithms (superset of {@link DEFAULT_KEX}). */
export const SUPPORTED_KEX = [
  ...DEFAULT_KEX,
  'diffie-hellman-group-exchange-sha1',
  'diffie-hellman-group14-sha1',
  'diffie-hellman-group1-sha1',
];

/** Default server host key algorithms (preferred order). */
export const DEFAULT_SERVER_HOST_KEY = [
  'ssh-ed25519',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'rsa-sha2-512',
  'rsa-sha2-256',
  'ssh-rsa',
];

/** All supported server host key algorithms. */
export const SUPPORTED_SERVER_HOST_KEY = [...DEFAULT_SERVER_HOST_KEY];

/** Default cipher algorithms (preferred order). */
export const DEFAULT_CIPHER = [
  'chacha20-poly1305@openssh.com',
  'aes128-gcm@openssh.com',
  'aes256-gcm@openssh.com',
  'aes128-ctr',
  'aes192-ctr',
  'aes256-ctr',
];

/** All supported cipher algorithms (superset of {@link DEFAULT_CIPHER}). */
export const SUPPORTED_CIPHER = [
  ...DEFAULT_CIPHER,
  'aes256-cbc',
  'aes192-cbc',
  'aes128-cbc',
  'aes128-gcm',
  'aes256-gcm',
];

/** Default MAC algorithms (preferred order). */
export const DEFAULT_MAC = [
  'hmac-sha2-256-etm@openssh.com',
  'hmac-sha2-512-etm@openssh.com',
  'hmac-sha1-etm@openssh.com',
  'hmac-sha2-256',
  'hmac-sha2-512',
  'hmac-sha1',
];

/** All supported MAC algorithms (superset of {@link DEFAULT_MAC}). */
export const SUPPORTED_MAC = [
  ...DEFAULT_MAC,
  'hmac-sha2-256-96',
  'hmac-sha2-512-96',
  'hmac-sha1-96',
];

/** Default compression algorithms (preferred order). */
export const DEFAULT_COMPRESSION = [
  'none',
  'zlib@openssh.com',
  'zlib',
];

/** All supported compression algorithms. */
export const SUPPORTED_COMPRESSION = [...DEFAULT_COMPRESSION];

/** Whether Curve25519 key exchange is supported (always true; provided via @noble/curves). */
export const curve25519Supported = true;
/** Whether Ed25519 signatures are supported (always true; provided via @noble/curves). */
export const eddsaSupported = true;
