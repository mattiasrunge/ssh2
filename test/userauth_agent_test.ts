/**
 * User Authentication Agent Tests
 *
 * Tests for SSH agent authentication using custom agents and the AgentProtocol.
 * Converted from test/test-userauth-agent.js
 */

import { assertEquals, assertExists } from '@std/assert';

import { Client } from '../src/client.ts';
import {
  type Connection,
  type PKAuthContext,
  Server,
  type ServerAuthContext,
} from '../src/server.ts';
import {
  type AgentInboundRequest,
  AgentProtocol,
  BaseAgent,
  type SignOptions,
} from '../src/agent.ts';
import { type ParsedKey, parseKey } from '../src/protocol/keyParser.ts';
import {
  clearMustCallChecks,
  generateTestHostKeyEd25519,
  mustCall,
  verifyMustCallChecks,
} from './integration_helpers.ts';

const DEBUG = false;
const FIXTURES_DIR = new URL('./fixtures/', import.meta.url).pathname;

// =============================================================================
// Custom Agent Tests
// =============================================================================

Deno.test({
  name: 'userauth-agent: Custom agent authentication',
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    clearMustCallChecks();

    const hostKey = await generateTestHostKeyEd25519();
    const clientKeyData = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);

    // Parse client key
    const clientKeyResult = parseKey(clientKeyData);
    if (clientKeyResult instanceof Error) {
      throw new Error(`Failed to parse client key: ${clientKeyResult.message}`);
    }
    const clientKey = clientKeyResult;

    let getIdentitiesCount = 0;
    let signCount = 0;

    class MyAgent extends BaseAgent {
      override async getIdentities(): Promise<ParsedKey[]> {
        getIdentitiesCount++;
        assertEquals(getIdentitiesCount, 1);

        // Return public key only (re-parse public SSH format)
        const pubSSH = clientKey.getPublicSSH();
        if (pubSSH === null) {
          throw new Error('Failed to get public SSH key');
        }
        const parsed = parseKey(pubSSH);
        if (parsed instanceof Error) {
          throw new Error(`Failed to parse public key: ${parsed.message}`);
        }
        return [parsed];
      }

      override async sign(
        pubKey: ParsedKey | Uint8Array,
        data: Uint8Array,
        options?: SignOptions,
      ): Promise<Uint8Array> {
        signCount++;
        assertEquals(signCount, 1);

        // Verify the pubKey matches
        let keyToVerify: ParsedKey;
        if (pubKey instanceof Uint8Array) {
          const parsed = parseKey(pubKey);
          if (parsed instanceof Error) {
            throw new Error('Failed to parse pubKey');
          }
          keyToVerify = parsed;
        } else {
          keyToVerify = pubKey;
        }

        const expectedPEM = clientKey.getPublicPEM();
        const actualPEM = keyToVerify.getPublicPEM();
        assertEquals(actualPEM, expectedPEM);

        // Sign with the client key
        const sig = await clientKey.sign(data, options?.hash);
        if (sig instanceof Error) {
          throw sig;
        }
        return sig;
      }
    }

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    if (!DEBUG) {
      server.on('error', () => {});
      client.on('error', () => {});
    }

    await server.listen(0, '127.0.0.1');
    const addr = server.address()!;

    const username = 'Agent User';

    try {
      const serverDone = new Promise<void>((resolve) => {
        let authAttempt = 0;

        server.on(
          'connection',
          mustCall((conn: Connection) => {
            conn.on(
              'authentication',
              mustCall(async (ctx: ServerAuthContext) => {
                assertEquals(ctx.username, username);
                authAttempt++;

                switch (authAttempt) {
                  case 1:
                    // First attempt is 'none'
                    assertEquals(ctx.method, 'none');
                    ctx.reject(['publickey']);
                    break;
                  case 2: {
                    // Second attempt is publickey (no signature yet)
                    assertEquals(ctx.method, 'publickey');
                    const pkCtx = ctx as PKAuthContext;
                    assertEquals(pkCtx.key?.algo, clientKey.type);
                    // Accept to request signature
                    ctx.accept();
                    break;
                  }
                  case 3: {
                    // Third attempt has signature
                    assertEquals(ctx.method, 'publickey');
                    const pkCtx = ctx as PKAuthContext;
                    assertExists(pkCtx.signature);

                    // Verify signature
                    const verifyResult = await clientKey.verify(
                      pkCtx.blob!,
                      pkCtx.signature!,
                      pkCtx.hashAlgo,
                    );
                    assertEquals(verifyResult, true);

                    ctx.accept();
                    break;
                  }
                }
              }, 3),
            );

            conn.on(
              'ready',
              mustCall(() => {
                assertEquals(getIdentitiesCount, 1);
                assertEquals(signCount, 1);
                conn.end();
                resolve();
              }),
            );
          }),
        );
      });

      const clientDone = new Promise<void>((resolve) => {
        client.on(
          'close',
          mustCall(() => {
            resolve();
          }),
        );
      });

      await client.connect({
        host: addr.hostname,
        port: addr.port,
        username,
        agent: new MyAgent(),
        debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
      });

      await Promise.all([serverDone, clientDone]);
    } finally {
      try {
        client.end();
      } catch { /* ignore */ }
      try {
        await server.close();
      } catch { /* ignore */ }
      verifyMustCallChecks();
    }
  },
});

// =============================================================================
// AgentProtocol Tests
// =============================================================================

Deno.test('userauth-agent: AgentProtocol - identities failure', async () => {
  clearMustCallChecks();

  const client = new AgentProtocol(true);
  const server = new AgentProtocol(false);

  const identitiesCalled = new Promise<void>((resolve) => {
    server.on(
      'identities',
      mustCall((req: AgentInboundRequest) => {
        // Reply with failure
        const failResp = server.createFailureResponse(req);
        client.processData(failResp);
        resolve();
      }),
    );
  });

  // Create identities request manually
  // Message: length (4) + type (1) = SSH_AGENTC_REQUEST_IDENTITIES (11)
  const request = new Uint8Array([0, 0, 0, 1, 11]);
  server.processData(request);

  await identitiesCalled;
  verifyMustCallChecks();
});

Deno.test('userauth-agent: AgentProtocol - identities success', async () => {
  clearMustCallChecks();

  const clientKeyData = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
  const clientKey = parseKey(clientKeyData);
  if (clientKey instanceof Error) {
    throw clientKey;
  }

  const client = new AgentProtocol(true);
  const server = new AgentProtocol(false);

  let receivedKeys: ParsedKey[] | undefined;

  const identitiesCalled = new Promise<void>((resolve) => {
    server.on(
      'identities',
      mustCall((req: AgentInboundRequest) => {
        // Reply with keys
        const resp = server.createIdentitiesResponse(req, [clientKey]);
        client.processData(resp);

        // Parse the response to verify keys
        // Response format: SSH_AGENT_IDENTITIES_ANSWER (12), nkeys (4), for each: keyblob_len, keyblob, comment_len, comment
        const data = resp.subarray(4); // Skip length prefix
        assertEquals(data[0], 12); // SSH_AGENT_IDENTITIES_ANSWER

        const nkeys = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];
        assertEquals(nkeys, 1);

        // Parse first key
        let offset = 5;
        const keyLen = (data[offset] << 24) | (data[offset + 1] << 16) |
          (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        const keyBlob = data.subarray(offset, offset + keyLen);

        const parsed = parseKey(keyBlob);
        if (!(parsed instanceof Error)) {
          receivedKeys = [parsed];
          assertEquals(parsed.isPrivateKey(), false);
          assertEquals(parsed.getPublicPEM(), clientKey.getPublicPEM());
        }

        resolve();
      }),
    );
  });

  // Create identities request
  const request = new Uint8Array([0, 0, 0, 1, 11]); // SSH_AGENTC_REQUEST_IDENTITIES
  server.processData(request);

  await identitiesCalled;
  assertExists(receivedKeys);
  assertEquals(receivedKeys!.length, 1);
  verifyMustCallChecks();
});

Deno.test('userauth-agent: AgentProtocol - sign failure', async () => {
  clearMustCallChecks();

  const clientKeyData = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
  const clientKey = parseKey(clientKeyData);
  if (clientKey instanceof Error) {
    throw clientKey;
  }

  const client = new AgentProtocol(true);
  const server = new AgentProtocol(false);

  const buf = new TextEncoder().encode('data to sign');

  const signCalled = new Promise<void>((resolve) => {
    server.on(
      'sign',
      mustCall((
        req: AgentInboundRequest,
        pubKey: ParsedKey,
        data: Uint8Array,
        options: { hash?: string },
      ) => {
        assertEquals(pubKey.getPublicPEM(), clientKey.getPublicPEM());
        assertEquals(data.length, buf.length);
        assertEquals(options.hash, undefined);

        // Reply with failure
        const failResp = server.createFailureResponse(req);
        client.processData(failResp);
        resolve();
      }),
    );
  });

  // Create sign request manually
  // Message: SSH_AGENTC_SIGN_REQUEST (13), key_blob, data, flags
  const pubSSH = clientKey.getPublicSSH()!;

  const msgLen = 1 + 4 + pubSSH.length + 4 + buf.length + 4;
  const request = new Uint8Array(4 + msgLen);
  let pos = 0;

  // Length
  request[pos++] = (msgLen >> 24) & 0xff;
  request[pos++] = (msgLen >> 16) & 0xff;
  request[pos++] = (msgLen >> 8) & 0xff;
  request[pos++] = msgLen & 0xff;

  // Type
  request[pos++] = 13; // SSH_AGENTC_SIGN_REQUEST

  // Key blob
  request[pos++] = (pubSSH.length >> 24) & 0xff;
  request[pos++] = (pubSSH.length >> 16) & 0xff;
  request[pos++] = (pubSSH.length >> 8) & 0xff;
  request[pos++] = pubSSH.length & 0xff;
  request.set(pubSSH, pos);
  pos += pubSSH.length;

  // Data
  request[pos++] = (buf.length >> 24) & 0xff;
  request[pos++] = (buf.length >> 16) & 0xff;
  request[pos++] = (buf.length >> 8) & 0xff;
  request[pos++] = buf.length & 0xff;
  request.set(buf, pos);
  pos += buf.length;

  // Flags (0 = no special flags)
  request[pos++] = 0;
  request[pos++] = 0;
  request[pos++] = 0;
  request[pos++] = 0;

  server.processData(request);

  await signCalled;
  verifyMustCallChecks();
});

Deno.test('userauth-agent: AgentProtocol - sign success', async () => {
  clearMustCallChecks();

  const clientKeyData = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
  const clientKey = parseKey(clientKeyData);
  if (clientKey instanceof Error) {
    throw clientKey;
  }

  const client = new AgentProtocol(true);
  const server = new AgentProtocol(false);

  const buf = new TextEncoder().encode('data to sign');
  let receivedSignature: Uint8Array | undefined;

  const signCalled = new Promise<void>((resolve) => {
    server.on(
      'sign',
      mustCall(async (
        req: AgentInboundRequest,
        pubKey: ParsedKey,
        data: Uint8Array,
        _options: { hash?: string },
      ) => {
        assertEquals(pubKey.getPublicPEM(), clientKey.getPublicPEM());

        // Sign the data
        const sig = await clientKey.sign(data);
        if (sig instanceof Error) {
          throw sig;
        }

        // Reply with signature
        const signResp = server.createSignResponse(req, sig);

        // Parse the response to extract signature
        // Format: length (4), type (1 = SSH_AGENT_SIGN_RESPONSE), sig_len (4), sig_format_len (4), sig_format, actual_sig_len (4), actual_sig
        const respData = signResp.subarray(4); // Skip outer length
        assertEquals(respData[0], 14); // SSH_AGENT_SIGN_RESPONSE

        // Parse to extract signature for verification
        let offset = 1;
        // Skip total sig length
        offset += 4;

        // Skip format
        const formatLen = (respData[offset] << 24) | (respData[offset + 1] << 16) |
          (respData[offset + 2] << 8) | respData[offset + 3];
        offset += 4 + formatLen;

        // Get signature
        const sigLen = (respData[offset] << 24) | (respData[offset + 1] << 16) |
          (respData[offset + 2] << 8) | respData[offset + 3];
        offset += 4;
        receivedSignature = respData.subarray(offset, offset + sigLen);

        // Verify the signature
        const pubParsed = parseKey(pubKey.getPublicSSH()!);
        if (pubParsed instanceof Error) {
          throw pubParsed;
        }
        const verifyResult = await pubParsed.verify(buf, receivedSignature);
        assertEquals(verifyResult, true);

        client.processData(signResp);
        resolve();
      }),
    );
  });

  // Create sign request
  const pubSSH = clientKey.getPublicSSH()!;

  const msgLen = 1 + 4 + pubSSH.length + 4 + buf.length + 4;
  const request = new Uint8Array(4 + msgLen);
  let pos = 0;

  // Length
  request[pos++] = (msgLen >> 24) & 0xff;
  request[pos++] = (msgLen >> 16) & 0xff;
  request[pos++] = (msgLen >> 8) & 0xff;
  request[pos++] = msgLen & 0xff;

  // Type
  request[pos++] = 13; // SSH_AGENTC_SIGN_REQUEST

  // Key blob
  request[pos++] = (pubSSH.length >> 24) & 0xff;
  request[pos++] = (pubSSH.length >> 16) & 0xff;
  request[pos++] = (pubSSH.length >> 8) & 0xff;
  request[pos++] = pubSSH.length & 0xff;
  request.set(pubSSH, pos);
  pos += pubSSH.length;

  // Data
  request[pos++] = (buf.length >> 24) & 0xff;
  request[pos++] = (buf.length >> 16) & 0xff;
  request[pos++] = (buf.length >> 8) & 0xff;
  request[pos++] = buf.length & 0xff;
  request.set(buf, pos);
  pos += buf.length;

  // Flags
  request[pos++] = 0;
  request[pos++] = 0;
  request[pos++] = 0;
  request[pos++] = 0;

  server.processData(request);

  await signCalled;
  assertExists(receivedSignature);
  verifyMustCallChecks();
});
