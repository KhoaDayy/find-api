'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'resolve-'));
process.env.DATABASE_PATH = path.join(tmpDir, 'r.db');
process.env.ENABLE_FACE_CACHE = 'true';
process.env.CACHE_STORE_LONG_CODE = 'true';

const { parseShortCode, isFilePickerObjectKey } = require('../src/parsers/shortCodeParser');
const { regionIdFromShortPrefix, cdnHostsForShortPrefix, allCdnHosts } = require('../src/config/regions');
const {
  extractFaceFromBody,
} = require('../src/wwm/services/shortCodeResolveService');
const {
  assertSafeObjectKey,
  assertAllowlistedHost,
  ALLOWLIST,
} = require('../src/wwm/services/filePickerDownloadService');
const { UpstreamError } = require('../src/wwm/errors');
const { openDatabase, closeDatabase } = require('../src/storage/database');
const faceRepo = require('../src/storage/repositories/faceRepository');
const codeRepo = require('../src/storage/repositories/codeRepository');
const { hashFaceData } = require('../src/utils/hash');

// Mock download by monkeypatching after require of service internals via dependency injection-less override
const downloadService = require('../src/wwm/services/filePickerDownloadService');
const resolveService = require('../src/wwm/services/shortCodeResolveService');

function test(name, fn) {
  try {
    fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    console.error(`  FAIL ${name}`);
    console.error(e);
    process.exitCode = 1;
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    console.error(`  FAIL ${name}`);
    console.error(e);
    process.exitCode = 1;
  }
}

console.log('short-code resolve');

const GLOB =
  'wwm_facedata_R37_6a47e2900f5db520d85f5f3ahqdzOR1h03';
const CN =
  'yysls_facedata_R37_6a527f86e0d2f8e5305227f82gvxhbPw07';
const FD = 'R67ResolveTestPayload|*|a|*|b|*|2|*|c';
const FD_D = 'D67OldPayload|*|a|*|b|*|2|*|c';

test('parse Global short', () => {
  const r = parseShortCode(GLOB);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.type, 'global');
  assert.strictEqual(r.revision, 37);
});

test('parse China short', () => {
  const r = parseShortCode(CN);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.type, 'china');
});

test('prefix decides region, not suffix', () => {
  assert.strictEqual(regionIdFromShortPrefix('wwm'), 'GLOBAL');
  assert.strictEqual(regionIdFromShortPrefix('yysls'), 'CN');
  // suffix 06 still CN if prefix yysls
  const weird = 'yysls_facedata_R37_6a527f86e0d2f8e5305227f82gvxhbPw06';
  const p = parseShortCode(weird);
  assert.strictEqual(p.ok, true);
  assert.strictEqual(regionIdFromShortPrefix(p.prefix), 'CN');
  assert.ok(cdnHostsForShortPrefix('yysls').length >= 1);
});

test('plain R67 extract', () => {
  const r = extractFaceFromBody(Buffer.from(FD, 'utf8'), 'text/plain');
  assert.strictEqual(r.contentKind, 'plain_face_data');
  assert.ok(r.longCode.startsWith('R67'));
});

test('plain D67 extract', () => {
  const r = extractFaceFromBody(Buffer.from(FD_D, 'utf8'), 'text/plain');
  assert.ok(r.longCode.startsWith('D67'));
});

test('JSON face_data extract', () => {
  const body = JSON.stringify({ face_data: FD, plan_id: 'x' });
  const r = extractFaceFromBody(Buffer.from(body), 'application/json');
  assert.strictEqual(r.contentKind, 'json_face_data');
});

test('JSON view_data.face_data extract', () => {
  const body = JSON.stringify({ view_data: JSON.stringify({ face_data: FD }) });
  const r = extractFaceFromBody(Buffer.from(body), 'application/json');
  assert.ok(r.longCode.startsWith('R67'));
});

test('HTML reject', () => {
  assert.throws(
    () => extractFaceFromBody(Buffer.from('<html>nope</html>'), 'text/html'),
    (e) => e instanceof UpstreamError
  );
});

test('binary reject', () => {
  assert.throws(
    () => extractFaceFromBody(Buffer.from([0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]), 'application/octet-stream'),
    (e) => e.code === 'FILEPICKER_INVALID_BODY'
  );
});

test('path traversal objectKey reject', () => {
  assert.throws(() => assertSafeObjectKey('../etc/passwd0000000000000000000000ab'), () => true);
  assert.throws(() => assertSafeObjectKey('6a47e2900f5db520d85f5f3a/hqdzOR1h03'), () => true);
});

test('host outside allowlist reject', () => {
  assert.throws(() => assertAllowlistedHost('evil.example.com'), (e) => e.code === 'UNSUPPORTED_REGION');
  assert.ok(ALLOWLIST.has('h72sg.fp.ps.easebar.com'));
});

test('allowlist covers configured CDNs', () => {
  for (const h of allCdnHosts()) assert.ok(ALLOWLIST.has(h));
});

// --- async resolve with mocked download ---
const origDownload = downloadService.downloadFaceObject;

async function withMockBody(body, contentType, fn) {
  downloadService.downloadFaceObject = async () => ({
    host: 'h72sg.fp.ps.easebar.com',
    status: 200,
    contentType,
    body: Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8'),
    fallbackCount: 0,
  });
  // re-bind used module (same object export)
  try {
    return await fn();
  } finally {
    downloadService.downloadFaceObject = origDownload;
  }
}

// shortCodeResolveService closed over require — need to patch its required download
// It requires downloadFaceObject at load time as binding.
// Patch via require cache module exports is enough if it calls downloadService.downloadFaceObject
// Looking at shortCodeResolveService: const { downloadFaceObject } = require('./filePickerDownloadService');
// That's a live binding only for ESM; CJS copies the function reference.
// So we must re-require after patch OR patch resolveService's dependency.
// Fix: patch by replacing method used through re-require of resolve after hack.

delete require.cache[require.resolve('../src/wwm/services/shortCodeResolveService')];
// We'll inject by wrapping resolveShortCode tests via dynamic re-require each time.

function loadResolveWithMock(impl) {
  downloadService.downloadFaceObject = impl;
  delete require.cache[require.resolve('../src/wwm/services/shortCodeResolveService')];
  return require('../src/wwm/services/shortCodeResolveService');
}

(async () => {
  openDatabase();

  await testAsync('resolve plain R67 → verified code', async () => {
    const svc = loadResolveWithMock(async () => ({
      host: 'h72sg.fp.ps.easebar.com',
      status: 200,
      contentType: 'text/plain',
      body: Buffer.from(FD),
      fallbackCount: 0,
    }));
    const r = await svc.resolveShortCode({ input: GLOB, persist: true });
    assert.strictEqual(r.success, true);
    assert.strictEqual(r.face.face_hash, `sha256:${hashFaceData(FD)}`);
    assert.ok(r.regional_codes.GLOBAL);
    assert.strictEqual(r.regional_codes.GLOBAL.status, 'verified');
    assert.strictEqual(r.cache.persisted, true);
  });

  await testAsync('same code twice no duplicate', async () => {
    const svc = loadResolveWithMock(async () => ({
      host: 'h72sg.fp.ps.easebar.com',
      status: 200,
      contentType: 'text/plain',
      body: Buffer.from(FD),
      fallbackCount: 0,
    }));
    await svc.resolveShortCode({ input: GLOB, persist: true });
    const db = openDatabase();
    const before = db.prepare('SELECT COUNT(*) AS c FROM regional_codes').get().c;
    await svc.resolveShortCode({ input: GLOB, persist: true });
    const after = db.prepare('SELECT COUNT(*) AS c FROM regional_codes').get().c;
    assert.strictEqual(before, after);
  });

  await testAsync('CN + Global same hash join one face', async () => {
    const svc = loadResolveWithMock(async ({ prefix }) => ({
      host: prefix === 'yysls' ? 'h72.fp.ps.netease.com' : 'h72sg.fp.ps.easebar.com',
      status: 200,
      contentType: 'text/plain',
      body: Buffer.from(FD),
      fallbackCount: 0,
    }));
    await svc.resolveShortCode({ input: GLOB, persist: true });
    await svc.resolveShortCode({ input: CN, persist: true });
    const db = openDatabase();
    const faces = db.prepare('SELECT COUNT(*) AS c FROM faces WHERE face_hash = ?').get(hashFaceData(FD)).c;
    assert.strictEqual(faces, 1);
    const codes = db.prepare('SELECT COUNT(*) AS c FROM regional_codes WHERE face_id = (SELECT id FROM faces WHERE face_hash=?)').get(hashFaceData(FD)).c;
    assert.ok(codes >= 2);
  });

  await testAsync('include_long_code=false omits payload', async () => {
    const svc = loadResolveWithMock(async () => ({
      host: 'h72sg.fp.ps.easebar.com',
      status: 200,
      contentType: 'text/plain',
      body: Buffer.from(FD),
      fallbackCount: 0,
    }));
    const r = await svc.resolveShortCode({
      input: GLOB,
      includeLongCode: false,
      persist: false,
    });
    assert.strictEqual(r.face.long_code, null);
    assert.ok(r.face.face_data_length > 0);
  });

  await testAsync('persist=false does not require write', async () => {
    const svc = loadResolveWithMock(async () => ({
      host: 'h72sg.fp.ps.easebar.com',
      status: 200,
      contentType: 'text/plain',
      body: Buffer.from(FD + 'X|*|1'),
      fallbackCount: 0,
    }));
    // unique payload
    const payload = 'R67PersistFalseOnly|*|a|*|b|*|2|*|c';
    downloadService.downloadFaceObject = async () => ({
      host: 'h72sg.fp.ps.easebar.com',
      status: 200,
      contentType: 'text/plain',
      body: Buffer.from(payload),
      fallbackCount: 0,
    });
    delete require.cache[require.resolve('../src/wwm/services/shortCodeResolveService')];
    const svc2 = require('../src/wwm/services/shortCodeResolveService');
    // patch again after re-require: CJS copied binding — patch module.exports used inside by rewriting resolve path
    // Use loadResolveWithMock helper
    const svc3 = loadResolveWithMock(async () => ({
      host: 'h72sg.fp.ps.easebar.com',
      status: 200,
      contentType: 'text/plain',
      body: Buffer.from(payload),
      fallbackCount: 0,
    }));
    const r = await svc3.resolveShortCode({ input: GLOB, persist: false });
    assert.strictEqual(r.cache.persisted, false);
  });

  await testAsync('CDN 404 maps FILEPICKER_NOT_FOUND', async () => {
    const svc = loadResolveWithMock(async () => {
      throw new UpstreamError('FILEPICKER_NOT_FOUND', 'missing', { retryable: false });
    });
    try {
      await svc.resolveShortCode({ input: GLOB, persist: false });
      assert.fail('should throw');
    } catch (e) {
      assert.strictEqual(e.code, 'FILEPICKER_NOT_FOUND');
    }
  });

  await testAsync('timeout is not 404', async () => {
    const svc = loadResolveWithMock(async () => {
      throw new UpstreamError('FILEPICKER_TIMEOUT', 't', { retryable: true });
    });
    try {
      await svc.resolveShortCode({ input: GLOB, persist: false });
      assert.fail('should throw');
    } catch (e) {
      assert.strictEqual(e.code, 'FILEPICKER_TIMEOUT');
      assert.notStrictEqual(e.code, 'FILEPICKER_NOT_FOUND');
    }
  });

  downloadService.downloadFaceObject = origDownload;
  closeDatabase();
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }

  if (process.exitCode) {
    console.error('\nSome resolve tests failed');
    process.exit(1);
  }
  console.log('\nAll resolve tests passed');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
