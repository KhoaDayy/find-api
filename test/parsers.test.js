'use strict';

const assert = require('assert');
const {
  parseShortCode,
  parseArtOrPlanId,
  parseInput,
  isFilePickerObjectKey,
  buildShortCode,
} = require('../src/parsers/shortCodeParser');
const { parseLongFaceData, isLongFaceData } = require('../src/parsers/faceDataParser');
const { normalizeFaceData, hashFaceData } = require('../src/utils/hash');
const { redact } = require('../src/utils/redact');

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

console.log('parsers / hash / redact');

test('parse China short code', () => {
  const r = parseShortCode('yysls_facedata_R37_6a527f86e0d2f8e5305227f82gvxhbPw07');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.type, 'china');
  assert.strictEqual(r.revision, 37);
  assert.strictEqual(r.objectKey, '6a527f86e0d2f8e5305227f82gvxhbPw07');
});

test('parse Global short code', () => {
  const r = parseShortCode('wwm_facedata_R37_6a47e2900f5db520d85f5f3ahqdzOR1h03');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.type, 'global');
  assert.strictEqual(r.objectKey, '6a47e2900f5db520d85f5f3ahqdzOR1h03');
});

test('reject malformed short code', () => {
  assert.strictEqual(parseShortCode('wwm_facedata_R37_short').ok, false);
  assert.strictEqual(parseShortCode('facedata_R37_6a47e2900f5db520d85f5f3ahqdzOR1h03').ok, false);
  assert.strictEqual(parseShortCode('').ok, false);
});

test('plan_id is NOT a FilePicker object key', () => {
  const planId = 'aWqZLJcZ1Wn/fsHy';
  assert.strictEqual(isFilePickerObjectKey(planId), false);
  const art = parseArtOrPlanId('ART' + planId);
  assert.strictEqual(art.ok, true);
  assert.strictEqual(art.planId, planId);
  // must not be accepted as short code
  assert.strictEqual(parseShortCode(planId).ok, false);
  assert.strictEqual(parseShortCode('yysls_facedata_R37_' + planId).ok, false);
});

test('valid object key morphology', () => {
  assert.strictEqual(isFilePickerObjectKey('699c2b25a51ed05d75e5ce58Q6EmoiML03'), true);
  assert.strictEqual(isFilePickerObjectKey('699d8faa908f1d15b83c03deMgswatAd07'), true);
  assert.strictEqual(isFilePickerObjectKey('aWqZLJcZ1Wn/fsHy'), false);
  assert.strictEqual(isFilePickerObjectKey('aZ2KY+6l/oxXCB0d'), false);
});

test('normalize Face Data strips Discord newlines; same hash', () => {
  const base =
    'R67FvlZMbg9jg9kAeRipSaFaSgkujiO/WleaUH9jmBkeuGLmjDQs4DhnIeKJ4nfX|*|FvlJ6bx55x984Y|*|2|*|Fvl3ZWFzZV4=';
  const withNewlines = base.slice(0, 40) + '\r\n' + base.slice(40, 80) + '\n ' + base.slice(80);
  const withSpaces = base.replace(/(.{20})/g, '$1 '); // wrap spaces
  assert.strictEqual(normalizeFaceData(withNewlines), normalizeFaceData(base));
  // spaces removed by normalize (face payload has no spaces)
  assert.strictEqual(hashFaceData(withNewlines), hashFaceData(base));
  assert.strictEqual(hashFaceData(withSpaces), hashFaceData(base));
  assert.ok(isLongFaceData(base));
  const parsed = parseLongFaceData(withNewlines);
  assert.strictEqual(parsed.ok, true);
  assert.strictEqual(parsed.version, 'R67');
  assert.strictEqual(parsed.faceHash, hashFaceData(base));
});

test('parseInput classifies ART / short / long', () => {
  assert.strictEqual(parseInput('ARTaWqZLJcZ1Wn/fsHy').inputType, 'art');
  assert.strictEqual(parseInput('aWqZLJcZ1Wn/fsHy').inputType, 'plan_id');
  assert.strictEqual(
    parseInput('wwm_facedata_R37_6a47e2900f5db520d85f5f3ahqdzOR1h03').inputType,
    'global_short'
  );
  assert.strictEqual(parseInput('R67abc|*|def').type, 'long_face');
});

test('buildShortCode rejects plan_id as object key', () => {
  assert.throws(() => buildShortCode('global', 37, 'aWqZLJcZ1Wn/fsHy'));
  const code = buildShortCode('china', 37, '6a527f86e0d2f8e5305227f82gvxhbPw07');
  assert.strictEqual(code, 'yysls_facedata_R37_6a527f86e0d2f8e5305227f82gvxhbPw07');
});

test('redact hides session/token fields', () => {
  const out = redact({
    session: 'supersecretvalue123',
    server_token: '_face_123_face_ABCDEFG',
    path: '/x?session=supersecretvalue123&ok=1',
    face_data: 'R67keep',
  });
  assert.ok(!JSON.stringify(out).includes('supersecretvalue123'));
  assert.ok(!JSON.stringify(out).includes('ABCDEFG'));
  assert.ok(String(out.face_data).includes('R67'));
});

if (process.exitCode) {
  console.error('\nSome tests failed');
  process.exit(1);
}
console.log('\nAll parser tests passed');
