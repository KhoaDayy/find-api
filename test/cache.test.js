'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Isolate DB for tests
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'faces-cache-'));
const dbPath = path.join(tmpDir, 'test.db');
process.env.DATABASE_PATH = dbPath;
process.env.ENABLE_FACE_CACHE = 'true';
process.env.CACHE_STORE_LONG_CODE = 'true';

const { openDatabase, closeDatabase, integrityCheck, nowSec } = require('../src/storage/database');
const faceRepo = require('../src/storage/repositories/faceRepository');
const sourceRepo = require('../src/storage/repositories/sourceRepository');
const codeRepo = require('../src/storage/repositories/codeRepository');
const aliasRepo = require('../src/storage/repositories/aliasRepository');
const jobRepo = require('../src/storage/repositories/uploadJobRepository');
const { ingestInventoryResponse } = require('../src/wwm/services/cacheIngestService');
const { getByFaceHash, lookupByAlias } = require('../src/wwm/services/cacheLookupService');
const { hashFaceData, normalizeFaceData } = require('../src/utils/hash');
const { migrate } = require('../src/storage/migrations');

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

console.log('cache / sqlite');

const db = openDatabase({ path: dbPath, forceNew: false });

const FD1 = 'R67FacePayloadAAA|*|seg1|*|seg2|*|2|*|hair';
const FD1b = 'R67FacePayloadAAA|*|seg1|*|seg2|*|2|*|hair\n'; // same after normalize
const FD2 = 'R67OtherFaceBBB|*|x|*|y|*|2|*|z';
const H1 = hashFaceData(FD1);
const H2 = hashFaceData(FD2);

test('migration re-run is idempotent', () => {
  const v1 = migrate(db);
  const v2 = migrate(db);
  assert.strictEqual(v1, v2);
});

test('same face_hash insert twice → one face row', () => {
  const a = faceRepo.upsertFace(db, { faceData: FD1, faceHash: H1 });
  const b = faceRepo.upsertFace(db, { faceData: normalizeFaceData(FD1b), faceHash: H1 });
  assert.strictEqual(a.id, b.id);
  assert.strictEqual(a.inserted, true);
  assert.strictEqual(b.inserted, false);
  const count = db.prepare('SELECT COUNT(*) AS c FROM faces WHERE face_hash = ?').get(H1).c;
  assert.strictEqual(count, 1);
});

test('whitespace-normalized Face Data dedupes', () => {
  assert.strictEqual(hashFaceData(FD1), hashFaceData(FD1b));
});

test('hash mismatch throws integrity error', () => {
  assert.throws(
    () => faceRepo.upsertFace(db, { faceData: FD1, faceHash: H2 }),
    (e) => e.code === 'hash_mismatch'
  );
});

test('same hash two plan_ids → two source rows', () => {
  const face = faceRepo.getFaceByHash(db, H1);
  const s1 = sourceRepo.upsertSource(db, face.id, {
    source_type: 'player_inventory',
    region: 'CN',
    plan_id: 'planA',
    inventory_player_pid: 'player1',
    plan_owner_pid: 'ownerA',
    plan_owner_number_id: '111',
    metadata_source: 'face_plan_result.pid',
  });
  const s2 = sourceRepo.upsertSource(db, face.id, {
    source_type: 'player_inventory',
    region: 'CN',
    plan_id: 'planB',
    inventory_player_pid: 'player1',
    plan_owner_pid: 'ownerB',
    plan_owner_number_id: '222',
    metadata_source: 'face_plan_result.pid',
  });
  assert.strictEqual(s1.inserted, true);
  assert.strictEqual(s2.inserted, true);
  const sources = sourceRepo.listSourcesByFaceId(db, face.id);
  assert.ok(sources.length >= 2);
  const owners = new Set(sources.map((s) => s.plan_owner_pid));
  assert.ok(owners.has('ownerA') && owners.has('ownerB'));
});

test('same source identity updates last_seen, no duplicate', () => {
  const face = faceRepo.getFaceByHash(db, H1);
  const before = sourceRepo.listSourcesByFaceId(db, face.id).length;
  const u1 = sourceRepo.upsertSource(db, face.id, {
    source_type: 'player_inventory',
    region: 'CN',
    plan_id: 'planA',
    inventory_player_pid: 'player1',
    plan_owner_pid: 'ownerA',
    metadata_source: 'face_plan_result.pid',
  });
  assert.strictEqual(u1.inserted, false);
  const after = sourceRepo.listSourcesByFaceId(db, face.id).length;
  assert.strictEqual(before, after);
});

test('ART + plan_id aliases map correctly', () => {
  const face = faceRepo.getFaceByHash(db, H1);
  aliasRepo.upsertAlias(db, { faceId: face.id, aliasType: 'plan_id', aliasValue: 'planA', region: 'CN' });
  aliasRepo.upsertAlias(db, { faceId: face.id, aliasType: 'art_code', aliasValue: 'ARTplanA', region: 'CN' });
  aliasRepo.upsertAlias(db, { faceId: face.id, aliasType: 'face_hash', aliasValue: H1 });
  const byPlan = lookupByAlias('planA');
  assert.strictEqual(byPlan.ok, true);
  assert.strictEqual(byPlan.data.face_hash, `sha256:${H1}`);
  const byArt = lookupByAlias('ARTplanA');
  assert.strictEqual(byArt.ok, true);
  const byHash = getByFaceHash(H1);
  assert.strictEqual(byHash.ok, true);
});

test('does not create short code from plan_id or preview key', () => {
  const face = faceRepo.getFaceByHash(db, H1);
  const codes = codeRepo.listCodesByFaceId(db, face.id);
  assert.strictEqual(codes.length, 0);
  // ingest path never inserts regional_codes for plan/preview
  const stats = ingestInventoryResponse({
    player: { server: 'CN', pid: 'p', number_id: '1', nickname: 'n', hostnum: 1 },
    inventory: {
      faces: [
        {
          type: 'face',
          plan_id: 'aWqZLJcZ1Wn/fsHy',
          art_code: 'ARTaWqZLJcZ1Wn/fsHy',
          face_hash: `sha256:${H1}`,
          face_data_length: FD1.length,
          long_code: FD1,
          preview_object_key: '6a527f86e0d2f8e5305227f82gvxhbPw07',
          picture_url: 'https://x/file/6a527f86e0d2f8e5305227f82gvxhbPw07',
          author: { pid: 'o1', number_id: '9', nickname: 'N', hostnum: 1 },
          tags: [1001],
          source_lists: ['face_slots'],
          metadata_source: 'face_plan_result.pid',
        },
      ],
      makeups: [],
      unknown: [],
    },
  });
  assert.strictEqual(stats.persisted, true);
  const codes2 = codeRepo.listCodesByFaceId(db, face.id);
  assert.strictEqual(codes2.length, 0);
});

test('verified regional code requires matching verificationHash', () => {
  const face = faceRepo.getFaceByHash(db, H1);
  const short = 'yysls_facedata_R37_6a527f86e0d2f8e5305227f82gvxhbPw07';
  assert.throws(
    () =>
      codeRepo.upsertRegionalCode(db, {
        faceId: face.id,
        faceHash: H1,
        region: 'CN',
        shortCode: short,
        status: 'verified',
        verificationHash: H2,
      }),
    (e) => e.code === 'verification_hash_mismatch'
  );
  const ok = codeRepo.upsertRegionalCode(db, {
    faceId: face.id,
    faceHash: H1,
    region: 'CN',
    shortCode: short,
    status: 'verified',
    verificationHash: H1,
    sourceType: 'resolved_input',
  });
  assert.strictEqual(ok.inserted, true);
});

test('candidate does not overwrite verified', () => {
  const face = faceRepo.getFaceByHash(db, H1);
  const short = 'yysls_facedata_R37_6a527f86e0d2f8e5305227f82gvxhbPw07';
  const r = codeRepo.upsertRegionalCode(db, {
    faceId: face.id,
    faceHash: H1,
    region: 'CN',
    shortCode: short,
    status: 'candidate',
    sourceType: 'manual',
  });
  assert.strictEqual(r.skippedDowngrade, true);
  const row = db.prepare('SELECT status FROM regional_codes WHERE short_code = ?').get(short);
  assert.strictEqual(row.status, 'verified');
});

test('one short code cannot map to two faces', () => {
  faceRepo.upsertFace(db, { faceData: FD2, faceHash: H2 });
  const face2 = faceRepo.getFaceByHash(db, H2);
  const short = 'yysls_facedata_R37_6a527f86e0d2f8e5305227f82gvxhbPw07';
  assert.throws(
    () =>
      codeRepo.upsertRegionalCode(db, {
        faceId: face2.id,
        faceHash: H2,
        region: 'CN',
        shortCode: short,
        status: 'candidate',
      }),
    (e) => e.code === 'short_code_face_conflict'
  );
});

test('CN and Global codes can map same face', () => {
  const face = faceRepo.getFaceByHash(db, H1);
  const g = 'wwm_facedata_R37_6a47e2900f5db520d85f5f3ahqdzOR1h03';
  const r = codeRepo.upsertRegionalCode(db, {
    faceId: face.id,
    faceHash: H1,
    region: 'GLOBAL',
    shortCode: g,
    status: 'candidate',
    sourceType: 'imported_cache',
  });
  assert.strictEqual(r.inserted, true);
  const byReg = codeRepo.codesByRegion(db, face.id);
  assert.ok(byReg.CN);
  assert.ok(byReg.GLOBAL);
});

test('upload job lock face_id+region unique active', () => {
  const face = faceRepo.getFaceByHash(db, H1);
  const a = jobRepo.createOrGetActiveJob(db, { faceId: face.id, region: 'GLOBAL' });
  const b = jobRepo.createOrGetActiveJob(db, { faceId: face.id, region: 'GLOBAL' });
  assert.strictEqual(a.inserted, true);
  assert.strictEqual(b.inserted, false);
  assert.strictEqual(a.job.id, b.job.id);
});

test('selectPreferredSource returns reason', () => {
  const face = faceRepo.getFaceByHash(db, H1);
  const sources = sourceRepo.listSourcesByFaceId(db, face.id);
  const pref = sourceRepo.selectPreferredSource(sources);
  assert.ok(pref.source);
  assert.ok(typeof pref.preferred_source_reason === 'string');
});

test('raw metadata redacted before store', () => {
  const face = faceRepo.getFaceByHash(db, H1);
  sourceRepo.upsertSource(db, face.id, {
    source_type: 'manual',
    region: 'CN',
    plan_id: 'rawPlan',
    inventory_player_pid: 'pX',
    metadata_source: 'manual',
    raw_metadata: { session: 'supersecretvalue999', ok: 1 },
  });
  const row = db
    .prepare(`SELECT raw_metadata_json FROM face_sources WHERE plan_id = 'rawPlan'`)
    .get();
  assert.ok(row.raw_metadata_json);
  assert.ok(!row.raw_metadata_json.includes('supersecretvalue999'));
});

test('session/token not in sqlite (scan)', () => {
  // dump all text columns sample
  const tables = ['faces', 'face_sources', 'aliases', 'regional_codes', 'upload_jobs'];
  for (const t of tables) {
    const rows = db.prepare(`SELECT * FROM ${t}`).all();
    const blob = JSON.stringify(rows);
    assert.ok(!/supersecretvalue999/.test(blob));
    assert.ok(!/"session"\s*:\s*"aZ/.test(blob));
  }
});

test('include_long_code=false omits payload in lookup', () => {
  const r = getByFaceHash(H1, { includeLongCode: false });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.data.face_data, null);
  assert.ok(r.data.face_data_length > 0);
});

test('integrity_check ok', () => {
  const ic = integrityCheck(db);
  assert.strictEqual(ic.ok, true);
});

test('lookup by short code after insert', () => {
  const r = lookupByAlias('wwm_facedata_R37_6a47e2900f5db520d85f5f3ahqdzOR1h03');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.data.face_hash, `sha256:${H1}`);
});

test('ingest transaction: inventory-shaped batch', () => {
  const stats = ingestInventoryResponse({
    player: { server: 'CN', pid: 'invP', number_id: '011', nickname: 'Bot', hostnum: 10011 },
    inventory: {
      faces: [
        {
          type: 'face',
          plan_id: 'dupPlan1',
          art_code: 'ARTdupPlan1',
          face_hash: `sha256:${H1}`,
          face_data_length: FD1.length,
          long_code: FD1,
          author: { pid: 'own1', number_id: '1', nickname: 'A', hostnum: 10011 },
          tags: [1001],
          source_lists: ['face_slots'],
          metadata_source: 'face_plan_result.pid',
        },
        {
          type: 'face',
          plan_id: 'dupPlan2',
          art_code: 'ARTdupPlan2',
          face_hash: `sha256:${H1}`,
          face_data_length: FD1.length,
          long_code: FD1,
          author: { pid: 'own2', number_id: '2', nickname: 'B', hostnum: 10011 },
          tags: [1001],
          source_lists: ['face_plans'],
          metadata_source: 'face_plan_result.pid',
        },
      ],
      makeups: [],
      unknown: [],
    },
  });
  assert.strictEqual(stats.persisted, true);
  assert.strictEqual(stats.facesInserted, 0); // already existed
  assert.ok(stats.sourcesInserted + stats.sourcesUpdated >= 2);
  // still one face
  assert.strictEqual(db.prepare('SELECT COUNT(*) AS c FROM faces WHERE face_hash=?').get(H1).c, 1);
});

closeDatabase();

// cleanup temp
try {
  fs.rmSync(tmpDir, { recursive: true, force: true });
} catch {
  /* ignore */
}

if (process.exitCode) {
  console.error('\nSome cache tests failed');
  process.exit(1);
}
console.log('\nAll cache tests passed');
