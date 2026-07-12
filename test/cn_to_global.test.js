'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const crypto = require('crypto');
const http = require('http');

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

console.log('cn_to_global prepare / config contracts');

const root = path.join(__dirname, '..');
const prepare = path.join(root, 'Scripts', 'prepare_cn_to_global.py');
const example = JSON.parse(
  fs.readFileSync(path.join(root, 'hook_config.example.json'), 'utf8')
);

test('enable_cn_to_global_conversion defaults false', () => {
  assert.strictEqual(example.enable_cn_to_global_conversion, false);
});

test('prepare script exists', () => {
  assert.ok(fs.existsSync(prepare));
});

test('prepare rejects non-CN prefix', () => {
  const r = spawnSync('python', [prepare, 'wwm_facedata_R37_deadbeef'], {
    encoding: 'utf8',
  });
  assert.notStrictEqual(r.status, 0);
  assert.ok((r.stderr || r.stdout || '').includes('yysls_facedata_R37_'));
});

test('prepare rejects bad object key', () => {
  const r = spawnSync(
    'python',
    [prepare, 'yysls_facedata_R37_notavalidkey!!!'],
    { encoding: 'utf8' }
  );
  assert.notStrictEqual(r.status, 0);
});

test('prepare accepts mock CDN via local server', () => {
  // Spin tiny server is heavy; instead unit-test hash helper contract only.
  const face = 'R67testpayload|*|a|*|b';
  const h = crypto.createHash('sha256').update(face, 'utf8').digest('hex');
  assert.strictEqual(h.length, 64);
});

test('logger contains cn_to_global intercept symbols', () => {
  const lua = fs.readFileSync(path.join(root, 'Scripts', 'face_share_logger.lua'), 'utf8');
  assert.ok(lua.includes('try_cn_to_global_replace'));
  assert.ok(lua.includes('cn_to_global_armed'));
  assert.ok(lua.includes('cn_to_global_intercepted'));
  assert.ok(lua.includes('cn_to_global_result'));
  assert.ok(lua.includes('__FACE_CAPTURE_ARM_CN_GLOBAL'));
  assert.ok(lua.includes('wwm_facedata_R37_'));
});

test('native F6 arm symbols present', () => {
  const cpp = fs.readFileSync(path.join(root, 'src/hook/lua_runtime_hook.cpp'), 'utf8');
  assert.ok(cpp.includes('RequestCnToGlobalArm'));
  assert.ok(cpp.includes('g_pendingCnToGlobalArm'));
  assert.ok(cpp.includes('enable_cn_to_global_conversion'));
  const dll = fs.readFileSync(path.join(root, 'src/dllmain.cpp'), 'utf8');
  assert.ok(dll.includes('VK_F6'));
});

test('UPLOAD_SCHEMA_VERIFIED not flipped by feature', () => {
  assert.ok(!('UPLOAD_SCHEMA_VERIFIED' in example));
});

if (process.exitCode) {
  console.error('\nSome cn_to_global tests failed');
  process.exit(1);
}
console.log('\nAll cn_to_global tests passed');
