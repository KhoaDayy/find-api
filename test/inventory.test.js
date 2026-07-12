'use strict';

const assert = require('assert');
const faceService = require('../src/wwm/services/faceService');
const {
  validateInventoryQuery,
  InventoryError,
  buildItem,
} = require('../src/wwm/services/inventoryService');
const { isFilePickerObjectKey, parseArtOrPlanId } = require('../src/parsers/shortCodeParser');
const { redact } = require('../src/utils/redact');
const { hashFaceData } = require('../src/utils/hash');

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

console.log('inventory / classification / validation');

test('validate id/name exclusive', () => {
  assert.throws(() => validateInventoryQuery({}), InventoryError);
  assert.throws(() => validateInventoryQuery({ id: '1', name: 'x', server: 'CN' }), InventoryError);
  const q = validateInventoryQuery({ id: '0111452488', server: 'CN' });
  assert.strictEqual(q.id, '0111452488');
  assert.strictEqual(q.server, 'CN');
});

test('validate server', () => {
  assert.throws(() => validateInventoryQuery({ id: '1', server: 'EU' }), InventoryError);
  assert.strictEqual(validateInventoryQuery({ id: '1', server: 'SEA' }).server, 'SEA');
});

test('normalize batch shape object map', () => {
  const raw = {
    code: 0,
    result: {
      planA: {
        plan_id: 'planA',
        view_data: JSON.stringify({ face_data: 'R67abc|*|x' }),
        tags: [1001],
        pid: 'p1',
      },
      planB: {
        plan_id: 'planB',
        view_data: JSON.stringify({ face_data: 'R67def|*|y' }),
        tags: [1002],
        pid: 'p2',
      },
    },
  };
  const map = faceService.normalizePlanResults(raw);
  assert.strictEqual(map.size, 2);
  assert.ok(map.get('planA').result.view_data);
});

test('dedupe plan IDs keep source_lists', () => {
  const designer = {
    face_slots: ['A', 'B'],
    face_plans: ['A'],
    plans_public: ['B', 'C'],
  };
  const deduped = faceService.collectPlanIdsDeduped(designer);
  const a = deduped.find((p) => p.plan_id === 'A');
  assert.deepStrictEqual(a.source_lists.sort(), ['face_plans', 'face_slots'].sort());
  assert.ok(a.source_indexes.length >= 2);
  assert.strictEqual(deduped.length, 3);
});

test('tag 1002 in face_slots classifies makeup', () => {
  const c = faceService.classifyPlanType({
    sourceLists: ['face_slots'],
    tags: [1002],
    planType: 1,
  });
  assert.strictEqual(c.type, 'makeup');
  assert.strictEqual(c.type_source, 'tag:1002');
});

test('conflicting tags 1001+1002 → unknown', () => {
  const c = faceService.classifyPlanType({
    sourceLists: ['face_slots'],
    tags: [1001, 1002],
  });
  assert.strictEqual(c.type, 'unknown');
  assert.strictEqual(c.type_source, 'conflicting_tags');
  assert.deepStrictEqual(c.type_candidates, ['face', 'makeup']);
});

test('empty face_data excluded by buildItem flag', () => {
  const item = buildItem({
    planMeta: { plan_id: 'x', source_lists: ['plans_public'], source_indexes: [] },
    planResult: { plan_id: 'x', tags: [1008], view_data: null, name: 'cam' },
    classification: { type: 'unknown', type_source: 'plan_type:2', type_candidates: [] },
    author: null,
    includeLongCode: true,
    includeRaw: false,
  });
  assert.strictEqual(item._has_face_data, false);
  assert.strictEqual(item.face_data_length, 0);
});

test('active slot fields always null without source', () => {
  const item = buildItem({
    planMeta: { plan_id: 'p', source_lists: ['face_slots'], source_indexes: [{ source: 'face_slots', index: 0 }] },
    planResult: {
      plan_id: 'p',
      tags: [1001],
      view_data: JSON.stringify({ face_data: 'R67FvlZtest|*|a|*|b|*|2|*|c' }),
      picture_url: 'https://h72.fp.ps.netease.com/file/6a527f86e0d2f8e5305227f82gvxhbPw07',
      pid: 'auth1',
      hostnum: 10011,
    },
    classification: { type: 'face', type_source: 'tag:1001', type_candidates: [] },
    author: {
      pid: 'auth1',
      number_id: '011',
      nickname: 'N',
      hostnum: 10011,
      account: null,
      resolved: true,
      source: 'redis_player',
    },
    includeLongCode: true,
    includeRaw: false,
  });
  assert.strictEqual(item.is_active, null);
  assert.strictEqual(item.short_code_status, 'unavailable');
  assert.strictEqual(item.short_codes.china, null);
});

test('does not build short code from plan_id', () => {
  const planId = 'aWqZLJcZ1Wn/fsHy';
  assert.strictEqual(isFilePickerObjectKey(planId), false);
  assert.strictEqual(parseArtOrPlanId('ART' + planId).ok, true);
  const item = buildItem({
    planMeta: { plan_id: planId, source_lists: ['face_slots'], source_indexes: [] },
    planResult: {
      plan_id: planId,
      tags: [1001],
      view_data: JSON.stringify({ face_data: 'R67abc|*|1' }),
    },
    classification: { type: 'face', type_source: 'tag:1001', type_candidates: [] },
    author: null,
    includeLongCode: true,
    includeRaw: false,
  });
  assert.strictEqual(item.short_codes.china, null);
  assert.strictEqual(item.short_codes.global, null);
  assert.notStrictEqual(item.plan_id, item.preview_object_key);
});

test('picture_url key only in preview_object_key', () => {
  const key = '6a527f86e0d2f8e5305227f82gvxhbPw07';
  const item = buildItem({
    planMeta: { plan_id: 'p', source_lists: ['face_slots'], source_indexes: [] },
    planResult: {
      plan_id: 'p',
      tags: [1001],
      view_data: JSON.stringify({ face_data: 'R67abc|*|1' }),
      picture_url: `https://h72face-cn.fp.ps.netease.com/file/${key}`,
    },
    classification: { type: 'face', type_source: 'tag:1001', type_candidates: [] },
    author: null,
    includeLongCode: true,
    includeRaw: false,
  });
  assert.strictEqual(item.preview_object_key, key);
  assert.strictEqual(item.preview_object_key_verified, true);
  assert.strictEqual(item.short_codes.china, null);
  assert.ok(!Object.prototype.hasOwnProperty.call(item, 'object_key'));
  assert.ok(!Object.prototype.hasOwnProperty.call(item, 'face_object_key'));
});

test('include_long_code false keeps hash, drops payload', () => {
  const fd = 'R67FvlZMbg9jg9kAeRip|*|FvlJ|*|2|*|x';
  const item = buildItem({
    planMeta: { plan_id: 'p', source_lists: ['face_slots'], source_indexes: [] },
    planResult: {
      plan_id: 'p',
      tags: [1001],
      view_data: JSON.stringify({ face_data: fd }),
    },
    classification: { type: 'face', type_source: 'tag:1001', type_candidates: [] },
    author: null,
    includeLongCode: false,
    includeRaw: false,
  });
  assert.strictEqual(item.long_code, null);
  assert.ok(item.face_hash.startsWith('sha256:'));
  assert.ok(item.face_data_length > 0);
  assert.strictEqual(item.face_hash, `sha256:${hashFaceData(fd)}`);
});

test('include_raw is redacted', () => {
  const item = buildItem({
    planMeta: { plan_id: 'p', source_lists: ['face_slots'], source_indexes: [] },
    planResult: {
      plan_id: 'p',
      tags: [1001],
      session: 'supersecretvalue12345',
      view_data: JSON.stringify({ face_data: 'R67abc|*|1' }),
    },
    classification: { type: 'face', type_source: 'tag:1001', type_candidates: [] },
    author: null,
    includeLongCode: true,
    includeRaw: true,
  });
  assert.ok(item.raw);
  assert.ok(!JSON.stringify(item.raw).includes('supersecretvalue12345'));
});

test('two same face_hash not collapsed in diagnostics structure', () => {
  const fd = 'R67samepayload|*|1|*|2|*|3';
  const h = `sha256:${hashFaceData(fd)}`;
  const map = new Map();
  for (const id of ['p1', 'p2']) {
    if (!map.has(h)) map.set(h, []);
    map.get(h).push(id);
  }
  const dups = [...map.entries()]
    .filter(([, ids]) => ids.length > 1)
    .map(([face_hash, plan_ids]) => ({ face_hash, plan_ids }));
  assert.strictEqual(dups.length, 1);
  assert.deepStrictEqual(dups[0].plan_ids, ['p1', 'p2']);
});

test('author pair dedupe keys', () => {
  const pairs = [
    { pid: 'A', hostnum: 1 },
    { pid: 'A', hostnum: 1 },
    { pid: 'B', hostnum: 1 },
    { pid: 'A', hostnum: 2 },
  ];
  const unique = new Map();
  for (const p of pairs) {
    const key = `${p.pid}@${p.hostnum}`;
    if (!unique.has(key)) unique.set(key, p);
  }
  assert.strictEqual(unique.size, 3);
});

test('unresolved author keeps plan.pid', () => {
  const item = buildItem({
    planMeta: { plan_id: 'p', source_lists: ['face_slots'], source_indexes: [] },
    planResult: {
      plan_id: 'p',
      tags: [1001],
      pid: 'authorPidOnly',
      hostnum: 10011,
      view_data: JSON.stringify({ face_data: 'R67abc|*|1' }),
    },
    classification: { type: 'face', type_source: 'tag:1001', type_candidates: [] },
    author: {
      pid: 'authorPidOnly',
      number_id: null,
      nickname: null,
      hostnum: 10011,
      account: null,
      resolved: false,
      source: 'face_plan_result',
    },
    includeLongCode: true,
    includeRaw: false,
  });
  assert.strictEqual(item.author.pid, 'authorPidOnly');
  assert.strictEqual(item.author.resolved, false);
  assert.strictEqual(item.author.number_id, null);
});

test('redact session in generic objects', () => {
  const out = redact({ session: 'abcdefghijklmnop', token: 'zzzzzzzzzzzzzzzz' });
  assert.ok(!JSON.stringify(out).includes('abcdefghijklmnop'));
  assert.ok(!JSON.stringify(out).includes('zzzzzzzzzzzzzzzz'));
});

if (process.exitCode) {
  console.error('\nSome inventory tests failed');
  process.exit(1);
}
console.log('\nAll inventory tests passed');
