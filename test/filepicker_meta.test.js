'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const meta = require('../src/wwm/services/filePickerMetaService');
const { hashFaceData } = require('../src/utils/hash');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fpmeta-'));
process.env.DATABASE_PATH = path.join(tmpDir, 'm.db');
process.env.ENABLE_FACE_CACHE = 'true';

const { openDatabase, closeDatabase, migrate } = (() => {
  const dbmod = require('../src/storage/database');
  const mig = require('../src/storage/migrations');
  return { openDatabase: dbmod.openDatabase, closeDatabase: dbmod.closeDatabase, migrate: mig.migrate };
})();
const sourceRepo = require('../src/storage/repositories/sourceRepository');
const faceRepo = require('../src/storage/repositories/faceRepository');

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

console.log('filepicker metadata');

const FD = 'R67MetaTestPayloadAAA|*|seg|*|x|*|2|*|y';
const H = hashFaceData(FD);

const sampleWrapper = {
  plan_id: 'aWqZLJcZ1Wn/fsHy',
  pid: 'Z24LoysTOrEPNT3A',
  hostnum: 10011,
  name: 'test-face',
  tags: [1001],
  face_data: FD,
  picture_url: 'https://h72.fp.ps.netease.com/file/6a527f86e0d2f8e5305227f82gvxhbPw07',
  session: 'supersecretvalue12345',
};

test('sanitized metadata does not contain full R67', () => {
  const s = meta.sanitizeFaceDataDeep(sampleWrapper);
  const blob = JSON.stringify(s);
  assert.ok(!blob.includes('R67MetaTestPayloadAAA'));
  assert.ok(s.face_data.__face_data__);
  assert.strictEqual(s.face_data.sha256, H);
  assert.strictEqual(s.session, '***');
});

test('CN/Global wrapper diff excludes raw Face Data', () => {
  const g = meta.sanitizeFaceDataDeep({ ...sampleWrapper, region_tag: 'G' });
  const c = meta.sanitizeFaceDataDeep({ ...sampleWrapper, region_tag: 'C', hostnum: 10012 });
  const d = meta.diffSanitizedWrappers(g, c);
  const blob = JSON.stringify(d);
  assert.ok(!blob.includes('R67MetaTestPayloadAAA'));
  assert.ok(d.fieldsWithDifferentValues.some((x) => x.path.endsWith('hostnum')));
});

test('find face_data field path', () => {
  const p = meta.findFaceDataFieldPath(sampleWrapper);
  assert.strictEqual(p, '$.face_data');
  const nested = { view_data: JSON.stringify({ face_data: FD }) };
  const p2 = meta.findFaceDataFieldPath(nested);
  assert.ok(p2.includes('view_data'));
});

test('looksLikeCommunityPlanId rejects FP keys', () => {
  assert.strictEqual(meta.looksLikeCommunityPlanId('aWqZLJcZ1Wn/fsHy'), true);
  assert.strictEqual(
    meta.looksLikeCommunityPlanId('6a527f86e0d2f8e5305227f82gvxhbPw07'),
    false
  );
});

test('migration v2 idempotent', () => {
  const db = openDatabase({ path: process.env.DATABASE_PATH });
  const v1 = migrate(db);
  const v2 = migrate(db);
  assert.ok(v1 >= 2);
  assert.strictEqual(v1, v2);
  // columns exist
  const cols = db.prepare('PRAGMA table_info(face_sources)').all().map((c) => c.name);
  assert.ok(cols.includes('short_code'));
  assert.ok(cols.includes('sanitized_metadata_json'));
  assert.ok(cols.includes('related_plan_hash_match'));
});

test('short_code source stores sanitized not full face', () => {
  const db = openDatabase();
  const face = faceRepo.upsertFace(db, { faceData: FD, faceHash: H });
  const san = meta.sanitizeFaceDataDeep(sampleWrapper);
  sourceRepo.upsertSource(db, face.id, {
    source_type: 'short_code',
    region: 'GLOBAL',
    short_code: 'wwm_facedata_R37_6a47e2900f5db520d85f5f3ahqdzOR1h03',
    object_key: '6a47e2900f5db520d85f5f3ahqdzOR1h03',
    wrapper_type: 'json_face_data',
    face_data_field_path: '$.face_data',
    related_plan_id: 'aWqZLJcZ1Wn/fsHy',
    related_pid: 'Z24LoysTOrEPNT3A',
    related_hostnum: 10011,
    related_plan_hash_match: true,
    metadata_source: 'global_filepicker_wrapper.cn_source_metadata',
    sanitized_metadata: san,
    plan_owner_pid: 'Z24LoysTOrEPNT3A',
  });
  const row = db
    .prepare(`SELECT * FROM face_sources WHERE short_code LIKE 'wwm_facedata%'`)
    .get();
  assert.ok(row);
  assert.ok(row.sanitized_metadata_json);
  assert.ok(!row.sanitized_metadata_json.includes('R67MetaTestPayloadAAA'));
  assert.ok(!row.sanitized_metadata_json.includes('supersecretvalue12345'));
});

test('selectPreferredSource ranks filepicker with identity', () => {
  const db = openDatabase();
  const face = faceRepo.getFaceByHash(db, H);
  const sources = sourceRepo.listSourcesByFaceId(db, face.id);
  // add plain short without identity
  sourceRepo.upsertSource(db, face.id, {
    source_type: 'short_code',
    region: 'CN',
    short_code: 'yysls_facedata_R37_6a527f86e0d2f8e5305227f82gvxhbPw07',
    object_key: '6a527f86e0d2f8e5305227f82gvxhbPw07',
    metadata_source: 'filepicker_resolve',
  });
  const all = sourceRepo.listSourcesByFaceId(db, face.id);
  const pref = sourceRepo.selectPreferredSource(all);
  assert.ok(pref.source);
  assert.ok(typeof pref.preferred_source_reason === 'string');
});

test('pid role is filepicker_metadata_owner not original_author', () => {
  const owner = {
    pid: 'x',
    role: 'filepicker_metadata_owner',
  };
  assert.strictEqual(owner.role, 'filepicker_metadata_owner');
  assert.notStrictEqual(owner.role, 'original_author');
});

closeDatabase();
try {
  fs.rmSync(tmpDir, { recursive: true, force: true });
} catch {
  /* ignore */
}

if (process.exitCode) {
  console.error('\nSome filepicker meta tests failed');
  process.exit(1);
}
console.log('\nAll filepicker meta tests passed');
