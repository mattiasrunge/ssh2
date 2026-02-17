/**
 * SFTP Integration Tests
 *
 * Tests the SFTP protocol by connecting a mock client and server.
 * Converted from test/test-sftp.js
 */

import { assertEquals, assertExists, assertRejects } from '@std/assert';

import {
  type FileAttributes,
  OPEN_MODE,
  SFTP,
  type SFTPHandle,
  STATUS_CODE,
} from '../src/protocol/sftp/mod.ts';

const DEBUG = false;

// =============================================================================
// Mock SFTP Setup
// =============================================================================

interface MockChannelInfo {
  type: string;
  incoming: {
    id: number;
    window: number;
    packetSize: number;
    state: string;
  };
  outgoing: {
    id: number;
    window: number;
    packetSize: number;
    state: string;
  };
}

/**
 * Create a mock SFTP client-server pair connected via in-memory pipes
 */
function createSFTPPair(): { client: SFTP; server: SFTP; cleanup: () => void } {
  const chanInfo: MockChannelInfo = {
    type: 'sftp',
    incoming: { id: 0, window: 2 * 1024 * 1024, packetSize: 32768, state: 'open' },
    outgoing: { id: 0, window: 2 * 1024 * 1024, packetSize: 32768, state: 'open' },
  };

  // Create mock protocol that pipes data to the other side
  let clientToServer: ((data: Uint8Array) => void) | null = null;
  let serverToClient: ((data: Uint8Array) => void) | null = null;

  const clientProtocol = {
    channelData: (_id: number, data: Uint8Array) => {
      if (DEBUG) console.log('[CLIENT->SERVER]', data.length, 'bytes');
      // Queue to avoid synchronous recursion
      queueMicrotask(() => clientToServer?.(data));
    },
    channelClose: () => {},
  };

  const serverProtocol = {
    channelData: (_id: number, data: Uint8Array) => {
      if (DEBUG) console.log('[SERVER->CLIENT]', data.length, 'bytes');
      queueMicrotask(() => serverToClient?.(data));
    },
    channelClose: () => {},
  };

  const client = new SFTP(
    { protocol: clientProtocol },
    chanInfo,
    { debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined },
  );

  const server = new SFTP(
    { protocol: serverProtocol },
    { ...chanInfo },
    {
      server: true,
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    },
  );

  // Wire up the data pipes
  clientToServer = (data: Uint8Array) => server.push(data);
  serverToClient = (data: Uint8Array) => client.push(data);

  const cleanup = () => {
    clientToServer = null;
    serverToClient = null;
  };

  return { client, server, cleanup };
}

/**
 * Run an SFTP test with client and server
 */
async function runSFTPTest(
  _name: string,
  testFn: (client: SFTP, server: SFTP) => Promise<void> | void,
): Promise<void> {
  const { client, server, cleanup } = createSFTPPair();

  try {
    // Wait for both sides to be ready
    const clientReady = new Promise<void>((resolve) => client.once('ready', resolve));
    const serverReady = new Promise<void>((resolve) => server.once('ready', resolve));

    // Initialize - client sends version, server responds
    client._init();

    await Promise.all([clientReady, serverReady]);

    // Run the test
    await testFn(client, server);
  } finally {
    cleanup();
  }
}

// =============================================================================
// SFTP Protocol Tests
// =============================================================================

Deno.test('SFTP: open', async () => {
  await runSFTPTest('open', async (client, server) => {
    const path = '/tmp/foo.txt';
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"
    const expectedFlags = OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.WRITE;

    server.on('OPEN', (id: number, reqPath: string, pflags: number, _attrs: FileAttributes) => {
      assertEquals(id, 0);
      assertEquals(reqPath, path);
      assertEquals(pflags, expectedFlags);
      server.handle(id, handle);
    });

    const returnedHandle = await client.open(path, 'w');
    assertExists(returnedHandle);
    assertEquals(new TextDecoder().decode(returnedHandle), 'node.js');
  });
});

Deno.test('SFTP: close', async () => {
  await runSFTPTest('close', async (client, server) => {
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"

    server.on('CLOSE', (id: number, reqHandle: SFTPHandle) => {
      assertEquals(id, 0);
      assertEquals(new TextDecoder().decode(reqHandle), 'node.js');
      server.status(id, STATUS_CODE.OK);
    });

    await client.close(handle);
  });
});

Deno.test('SFTP: read', async () => {
  await runSFTPTest('read', async (client, server) => {
    const expected = new TextEncoder().encode('node.jsnode.jsnode.jsnode.jsnode.jsnode.js');
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"
    const buf = new Uint8Array(expected.length);

    server.on('READ', (id: number, reqHandle: SFTPHandle, offset: number, len: number) => {
      assertEquals(id, 0);
      assertEquals(new TextDecoder().decode(reqHandle), 'node.js');
      assertEquals(offset, 5);
      assertEquals(len, buf.length);
      server.data(id, expected);
    });

    const bytesRead = await client.read(handle, buf, 0, buf.length, 5);
    assertEquals(bytesRead, expected.length);
  });
});

Deno.test('SFTP: write', async () => {
  await runSFTPTest('write', async (client, server) => {
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"
    const buf = new TextEncoder().encode('node.jsnode.jsnode.jsnode.jsnode.jsnode.js');

    server.on('WRITE', (id: number, reqHandle: SFTPHandle, offset: number, data: Uint8Array) => {
      assertEquals(id, 0);
      assertEquals(new TextDecoder().decode(reqHandle), 'node.js');
      assertEquals(offset, 5);
      assertEquals(new TextDecoder().decode(data), new TextDecoder().decode(buf));
      server.status(id, STATUS_CODE.OK);
    });

    await client.write(handle, buf, 0, buf.length, 5);
  });
});

Deno.test('SFTP: lstat', async () => {
  await runSFTPTest('lstat', async (client, server) => {
    const path = '/foo/bar/baz';
    const attrs: FileAttributes = {
      size: 10 * 1024,
      uid: 9001,
      gid: 9001,
      atime: Math.floor(Date.now() / 1000),
      mtime: Math.floor(Date.now() / 1000),
    };

    server.on('LSTAT', (id: number, reqPath: string) => {
      assertEquals(id, 0);
      assertEquals(reqPath, path);
      server.attrs(id, attrs);
    });

    const returnedStats = await client.lstat(path);
    assertExists(returnedStats);
    assertEquals(returnedStats.size, attrs.size);
    assertEquals(returnedStats.uid, attrs.uid);
    assertEquals(returnedStats.gid, attrs.gid);
  });
});

Deno.test('SFTP: fstat', async () => {
  await runSFTPTest('fstat', async (client, server) => {
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"
    const attrs: FileAttributes = {
      size: 10 * 1024,
      uid: 9001,
      gid: 9001,
      atime: Math.floor(Date.now() / 1000),
      mtime: Math.floor(Date.now() / 1000),
    };

    server.on('FSTAT', (id: number, reqHandle: SFTPHandle) => {
      assertEquals(id, 0);
      assertEquals(new TextDecoder().decode(reqHandle), 'node.js');
      server.attrs(id, attrs);
    });

    const returnedStats = await client.fstat(handle);
    assertExists(returnedStats);
    assertEquals(returnedStats.size, attrs.size);
  });
});

Deno.test('SFTP: stat', async () => {
  await runSFTPTest('stat', async (client, server) => {
    const path = '/foo/bar/baz';
    const attrs: FileAttributes = {
      size: 5000,
      mode: 0o100644,
    };

    server.on('STAT', (id: number, reqPath: string) => {
      assertEquals(id, 0);
      assertEquals(reqPath, path);
      server.attrs(id, attrs);
    });

    const returnedStats = await client.stat(path);
    assertExists(returnedStats);
    assertEquals(returnedStats.size, attrs.size);
    assertEquals(returnedStats.mode, attrs.mode);
  });
});

Deno.test('SFTP: mkdir', async () => {
  await runSFTPTest('mkdir', async (client, server) => {
    const path = '/foo/bar';

    server.on('MKDIR', (id: number, reqPath: string, _attrs: FileAttributes) => {
      assertEquals(id, 0);
      assertEquals(reqPath, path);
      server.status(id, STATUS_CODE.OK);
    });

    await client.mkdir(path);
  });
});

Deno.test('SFTP: rmdir', async () => {
  await runSFTPTest('rmdir', async (client, server) => {
    const path = '/foo/bar';

    server.on('RMDIR', (id: number, reqPath: string) => {
      assertEquals(id, 0);
      assertEquals(reqPath, path);
      server.status(id, STATUS_CODE.OK);
    });

    await client.rmdir(path);
  });
});

Deno.test('SFTP: remove', async () => {
  await runSFTPTest('remove', async (client, server) => {
    const path = '/foo/bar/file.txt';

    server.on('REMOVE', (id: number, reqPath: string) => {
      assertEquals(id, 0);
      assertEquals(reqPath, path);
      server.status(id, STATUS_CODE.OK);
    });

    await client.remove(path);
  });
});

Deno.test('SFTP: rename', async () => {
  await runSFTPTest('rename', async (client, server) => {
    const oldPath = '/foo/bar/old.txt';
    const newPath = '/foo/bar/new.txt';

    server.on('RENAME', (id: number, reqOldPath: string, reqNewPath: string) => {
      assertEquals(id, 0);
      assertEquals(reqOldPath, oldPath);
      assertEquals(reqNewPath, newPath);
      server.status(id, STATUS_CODE.OK);
    });

    await client.rename(oldPath, newPath);
  });
});

Deno.test('SFTP: realpath', async () => {
  await runSFTPTest('realpath', async (client, server) => {
    const path = './relative/../path';
    const resolvedPath = '/absolute/resolved/path';

    server.on('REALPATH', (id: number, reqPath: string) => {
      assertEquals(id, 0);
      assertEquals(reqPath, path);
      server.name(id, { filename: resolvedPath });
    });

    const result = await client.realpath(path);
    assertEquals(result, resolvedPath);
  });
});

Deno.test('SFTP: opendir', async () => {
  await runSFTPTest('opendir', async (client, server) => {
    const path = '/foo/bar';
    const handle = new Uint8Array([100, 105, 114, 104, 97, 110, 100, 108, 101]); // "dirhandle"

    server.on('OPENDIR', (id: number, reqPath: string) => {
      assertEquals(id, 0);
      assertEquals(reqPath, path);
      server.handle(id, handle);
    });

    const returnedHandle = await client.opendir(path);
    assertExists(returnedHandle);
    assertEquals(new TextDecoder().decode(returnedHandle), 'dirhandle');
  });
});

Deno.test('SFTP: symlink', async () => {
  await runSFTPTest('symlink', async (client, server) => {
    const targetPath = '/foo/target';
    const linkPath = '/foo/link';

    server.on('SYMLINK', (id: number, _target: string, _link: string) => {
      assertEquals(id, 0);
      // Note: OpenSSH reverses the arguments
      server.status(id, STATUS_CODE.OK);
    });

    await client.symlink(targetPath, linkPath);
  });
});

Deno.test('SFTP: readlink', async () => {
  await runSFTPTest('readlink', async (client, server) => {
    const path = '/foo/link';
    const targetPath = '/foo/target';

    server.on('READLINK', (id: number, reqPath: string) => {
      assertEquals(id, 0);
      assertEquals(reqPath, path);
      server.name(id, { filename: targetPath });
    });

    const result = await client.readlink(path);
    assertEquals(result, targetPath);
  });
});

Deno.test('SFTP: setstat', async () => {
  await runSFTPTest('setstat', async (client, server) => {
    const path = '/foo/bar/file.txt';
    const attrs: FileAttributes = {
      mode: 0o755,
    };

    server.on('SETSTAT', (id: number, reqPath: string, reqAttrs: FileAttributes) => {
      assertEquals(id, 0);
      assertEquals(reqPath, path);
      assertEquals(reqAttrs.mode, attrs.mode);
      server.status(id, STATUS_CODE.OK);
    });

    await client.setstat(path, attrs);
  });
});

Deno.test('SFTP: fsetstat', async () => {
  await runSFTPTest('fsetstat', async (client, server) => {
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"
    const attrs: FileAttributes = {
      mode: 0o644,
    };

    server.on('FSETSTAT', (id: number, reqHandle: SFTPHandle, reqAttrs: FileAttributes) => {
      assertEquals(id, 0);
      assertEquals(new TextDecoder().decode(reqHandle), 'node.js');
      assertEquals(reqAttrs.mode, attrs.mode);
      server.status(id, STATUS_CODE.OK);
    });

    await client.fsetstat(handle, attrs);
  });
});

Deno.test('SFTP: exists (true)', async () => {
  await runSFTPTest('exists', async (client, server) => {
    const path = '/foo/bar/file.txt';

    server.on('STAT', (id: number, reqPath: string) => {
      assertEquals(reqPath, path);
      server.attrs(id, { mode: 0o100644 });
    });

    const exists = await client.exists(path);
    assertEquals(exists, true);
  });
});

Deno.test('SFTP: exists (false)', async () => {
  await runSFTPTest('exists', async (client, server) => {
    const path = '/nonexistent';

    server.on('STAT', (id: number, _reqPath: string) => {
      server.status(id, STATUS_CODE.NO_SUCH_FILE);
    });

    const exists = await client.exists(path);
    assertEquals(exists, false);
  });
});

Deno.test('SFTP: chmod', async () => {
  await runSFTPTest('chmod', async (client, server) => {
    const path = '/foo/bar/file.txt';
    const mode = 0o755;

    server.on('SETSTAT', (id: number, reqPath: string, reqAttrs: FileAttributes) => {
      assertEquals(reqPath, path);
      assertEquals(reqAttrs.mode, mode);
      server.status(id, STATUS_CODE.OK);
    });

    await client.chmod(path, mode);
  });
});

Deno.test('SFTP: chown', async () => {
  await runSFTPTest('chown', async (client, server) => {
    const path = '/foo/bar/file.txt';
    const uid = 1000;
    const gid = 1000;

    server.on('SETSTAT', (id: number, reqPath: string, reqAttrs: FileAttributes) => {
      assertEquals(reqPath, path);
      assertEquals(reqAttrs.uid, uid);
      assertEquals(reqAttrs.gid, gid);
      server.status(id, STATUS_CODE.OK);
    });

    await client.chown(path, uid, gid);
  });
});

Deno.test('SFTP: error response', async () => {
  await runSFTPTest('error', async (client, server) => {
    const path = '/nonexistent';

    server.on('STAT', (id: number, _reqPath: string) => {
      server.status(id, STATUS_CODE.NO_SUCH_FILE, 'File not found');
    });

    const err = await assertRejects(() => client.stat(path));
    assertEquals((err as Error & { code: number }).code, STATUS_CODE.NO_SUCH_FILE);
  });
});

// =============================================================================
// Readdir Tests
// =============================================================================

Deno.test('SFTP: readdir', async () => {
  await runSFTPTest('readdir', async (client, server) => {
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"
    const list = [
      {
        filename: '.',
        longname: 'drwxr-xr-x  56 nodejs nodejs      4096 Nov 10 01:05 .',
        attrs: {
          mode: 0o40755,
          size: 4096,
          uid: 9001,
          gid: 8001,
          atime: 1415599549,
          mtime: 1415599590,
        },
      },
      {
        filename: '..',
        longname: 'drwxr-xr-x   4 root   root        4096 May 16  2013 ..',
        attrs: { mode: 0o40755, size: 4096, uid: 0, gid: 0, atime: 1368729954, mtime: 1368729999 },
      },
      {
        filename: 'foo',
        longname: 'drwxrwxrwx   2 nodejs nodejs      4096 Mar  8  2009 foo',
        attrs: {
          mode: 0o40777,
          size: 4096,
          uid: 9001,
          gid: 8001,
          atime: 1368729954,
          mtime: 1368729999,
        },
      },
      {
        filename: 'bar',
        longname: '-rw-r--r--   1 nodejs nodejs 513901992 Dec  4  2009 bar',
        attrs: {
          mode: 0o100644,
          size: 513901992,
          uid: 9001,
          gid: 8001,
          atime: 1259972199,
          mtime: 1259972199,
        },
      },
    ];

    server.on('READDIR', (id: number, reqHandle: SFTPHandle) => {
      assertEquals(id, 0);
      assertEquals(new TextDecoder().decode(reqHandle), 'node.js');
      server.name(id, list);
    });

    const returnedList = await client.readdir(handle);
    assertExists(returnedList);
    // Default readdir excludes . and ..
    assertEquals(returnedList.length, 2);
    assertEquals(returnedList[0].filename, 'foo');
    assertEquals(returnedList[1].filename, 'bar');
  });
});

Deno.test('SFTP: readdir (full)', async () => {
  await runSFTPTest('readdir', async (client, server) => {
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"
    const list = [
      {
        filename: '.',
        longname: 'drwxr-xr-x  56 nodejs nodejs      4096 Nov 10 01:05 .',
        attrs: {
          mode: 0o40755,
          size: 4096,
          uid: 9001,
          gid: 8001,
          atime: 1415599549,
          mtime: 1415599590,
        },
      },
      {
        filename: '..',
        longname: 'drwxr-xr-x   4 root   root        4096 May 16  2013 ..',
        attrs: { mode: 0o40755, size: 4096, uid: 0, gid: 0, atime: 1368729954, mtime: 1368729999 },
      },
      {
        filename: 'foo',
        longname: 'drwxrwxrwx   2 nodejs nodejs      4096 Mar  8  2009 foo',
        attrs: {
          mode: 0o40777,
          size: 4096,
          uid: 9001,
          gid: 8001,
          atime: 1368729954,
          mtime: 1368729999,
        },
      },
    ];

    server.on('READDIR', (id: number, _reqHandle: SFTPHandle) => {
      server.name(id, list);
    });

    const returnedList = await client.readdir(handle, { full: true });
    assertExists(returnedList);
    // Full mode includes . and ..
    assertEquals(returnedList.length, 3);
    assertEquals(returnedList[0].filename, '.');
    assertEquals(returnedList[1].filename, '..');
    assertEquals(returnedList[2].filename, 'foo');
  });
});

Deno.test('SFTP: readdir (EOF)', async () => {
  await runSFTPTest('readdir', async (client, server) => {
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"

    server.on('READDIR', (id: number, _reqHandle: SFTPHandle) => {
      server.status(id, STATUS_CODE.EOF);
    });

    try {
      await client.readdir(handle);
      throw new Error('Expected readdir to reject');
    } catch (err) {
      assertEquals((err as Error & { code: number }).code, STATUS_CODE.EOF);
    }
  });
});

// =============================================================================
// Read/Write Edge Cases
// =============================================================================

Deno.test('SFTP: read (partial)', async () => {
  await runSFTPTest('read partial', async (client, server) => {
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"
    const expected = new TextEncoder().encode('partial');
    const buf = new Uint8Array(100); // Request more than we'll get

    server.on('READ', (id: number, _reqHandle: SFTPHandle, _offset: number, _len: number) => {
      // Return less data than requested
      server.data(id, expected);
    });

    const bytesRead = await client.read(handle, buf, 0, buf.length, 0);
    assertEquals(bytesRead, expected.length);
    assertEquals(new TextDecoder().decode(buf.subarray(0, bytesRead)), 'partial');
  });
});

Deno.test('SFTP: read (EOF)', async () => {
  await runSFTPTest('read EOF', async (client, server) => {
    const handle = new Uint8Array([110, 111, 100, 101, 46, 106, 115]); // "node.js"
    const buf = new Uint8Array(100);

    server.on('READ', (id: number, _reqHandle: SFTPHandle, _offset: number, _len: number) => {
      server.status(id, STATUS_CODE.EOF);
    });

    // EOF now returns 0 bytes read instead of error
    const bytesRead = await client.read(handle, buf, 0, buf.length, 0);
    assertEquals(bytesRead, 0);
  });
});

// =============================================================================
// High-level API Tests
// =============================================================================

Deno.test('SFTP: readFile', async () => {
  await runSFTPTest('readFile', async (client, server) => {
    const path = '/test/file.txt';
    const content = new TextEncoder().encode('Hello, World!');
    const handle = new Uint8Array([1, 2, 3, 4]);

    server.on('OPEN', (id: number, _reqPath: string) => {
      server.handle(id, handle);
    });

    server.on('FSTAT', (id: number, _reqHandle: SFTPHandle) => {
      server.attrs(id, { size: content.length });
    });

    server.on('READ', (id: number, _reqHandle: SFTPHandle, offset: number) => {
      if (offset >= content.length) {
        server.status(id, STATUS_CODE.EOF);
      } else {
        server.data(id, content.subarray(offset));
      }
    });

    server.on('CLOSE', (id: number, _reqHandle: SFTPHandle) => {
      server.status(id, STATUS_CODE.OK);
    });

    const data = await client.readFile(path);
    assertExists(data);
    assertEquals(new TextDecoder().decode(data), 'Hello, World!');
  });
});

Deno.test('SFTP: writeFile', async () => {
  await runSFTPTest('writeFile', async (client, server) => {
    const path = '/test/file.txt';
    const content = 'Hello, World!';
    const handle = new Uint8Array([1, 2, 3, 4]);
    let writtenData = '';

    server.on('OPEN', (id: number, _reqPath: string) => {
      server.handle(id, handle);
    });

    server.on('WRITE', (id: number, _reqHandle: SFTPHandle, _offset: number, data: Uint8Array) => {
      writtenData = new TextDecoder().decode(data);
      server.status(id, STATUS_CODE.OK);
    });

    server.on('CLOSE', (id: number, _reqHandle: SFTPHandle) => {
      server.status(id, STATUS_CODE.OK);
    });

    await client.writeFile(path, content);
    assertEquals(writtenData, content);
  });
});

Deno.test('SFTP: appendFile', async () => {
  await runSFTPTest('appendFile', async (client, server) => {
    const path = '/test/file.txt';
    const content = 'Appended content';
    const handle = new Uint8Array([1, 2, 3, 4]);
    let writtenData = '';

    server.on('OPEN', (id: number, _reqPath: string, pflags: number) => {
      // Verify append flag is set
      assertEquals((pflags & OPEN_MODE.APPEND) !== 0, true);
      server.handle(id, handle);
    });

    server.on('WRITE', (id: number, _reqHandle: SFTPHandle, _offset: number, data: Uint8Array) => {
      writtenData = new TextDecoder().decode(data);
      server.status(id, STATUS_CODE.OK);
    });

    server.on('CLOSE', (id: number, _reqHandle: SFTPHandle) => {
      server.status(id, STATUS_CODE.OK);
    });

    await client.appendFile(path, content);
    assertEquals(writtenData, content);
  });
});

Deno.test('SFTP: unlink', async () => {
  await runSFTPTest('unlink', async (client, server) => {
    const path = '/foo/bar/file.txt';

    server.on('REMOVE', (id: number, reqPath: string) => {
      assertEquals(reqPath, path);
      server.status(id, STATUS_CODE.OK);
    });

    await client.unlink(path);
  });
});

Deno.test('SFTP: utimes', async () => {
  await runSFTPTest('utimes', async (client, server) => {
    const path = '/foo/bar/file.txt';
    const atime = 1609459200;
    const mtime = 1609459300;

    server.on('SETSTAT', (id: number, reqPath: string, reqAttrs: FileAttributes) => {
      assertEquals(reqPath, path);
      assertEquals(reqAttrs.atime, atime);
      assertEquals(reqAttrs.mtime, mtime);
      server.status(id, STATUS_CODE.OK);
    });

    await client.utimes(path, atime, mtime);
  });
});
