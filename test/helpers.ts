/**
 * Test Helpers
 *
 * Common utilities for Deno tests
 */

import { toBase64 } from '../src/utils/binary.ts';

/**
 * Path to test fixtures directory
 */
export const FIXTURES_PATH = new URL('./fixtures', import.meta.url).pathname;

/**
 * Path to keyParser fixtures directory
 */
export const KEY_PARSER_FIXTURES_PATH = `${FIXTURES_PATH}/keyParser`;

/**
 * Read a fixture file as Uint8Array
 */
export async function readFixture(path: string): Promise<Uint8Array> {
  return await Deno.readFile(path);
}

/**
 * Read a fixture file as text
 */
export async function readFixtureText(path: string): Promise<string> {
  return await Deno.readTextFile(path);
}

/**
 * Read a JSON fixture file
 */
export async function readFixtureJson<T>(path: string): Promise<T> {
  const text = await Deno.readTextFile(path);
  return JSON.parse(text);
}

/**
 * List files in a directory
 */
export async function listDir(path: string): Promise<string[]> {
  const entries: string[] = [];
  for await (const entry of Deno.readDir(path)) {
    entries.push(entry.name);
  }
  return entries;
}

/**
 * Check if Ed25519 is supported
 */
export const EDDSA_SUPPORTED = true;

/**
 * Expected key details from keyParser tests
 */
export interface KeyDetails {
  type: string;
  comment: string;
  public: string | null;
  publicSSH: string | null;
  private: string | null;
}

/**
 * Convert parsed key to details object for comparison
 */
export function keyToDetails(key: {
  type: string;
  comment: string;
  getPublicPEM(): string | null;
  getPublicSSH(): Uint8Array | null;
  getPrivatePEM(): string | null;
}): KeyDetails {
  const pubSSH = key.getPublicSSH();
  return {
    type: key.type,
    comment: key.comment,
    public: key.getPublicPEM(),
    publicSSH: pubSSH ? toBase64(pubSSH) : null,
    private: key.getPrivatePEM(),
  };
}
