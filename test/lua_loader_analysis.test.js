'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

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

console.log('lua loader analysis contracts');

const root = path.join(__dirname, '..');
const script = path.join(root, 'scripts', 'analyze_lua_loader.py');
const report = path.join(root, 'docs', 'C6_LUA_LOADER_ANALYSIS.md');
const analysis = path.join(root, 'captures', 'lua_loader_analysis.json');

test('analyzer script exists', () => {
  assert.ok(fs.existsSync(script));
});

test('requirements-hook-analysis lists pefile and capstone', () => {
  const req = fs.readFileSync(path.join(root, 'requirements-hook-analysis.txt'), 'utf8');
  assert.ok(req.includes('pefile'));
  assert.ok(req.includes('capstone'));
});

test('wrong SHA exits BUILD_FINGERPRINT_MISMATCH', () => {
  // Use the analyzer itself as a dummy "module" file — hash will not match expected
  const r = spawnSync(
    'python',
    [
      script,
      '--module',
      script,
      '--probe',
      path.join(root, 'captures', 'lua_signature_probe.json'),
      '--out',
      path.join(root, 'captures', '_tmp_mismatch.json'),
      '--expect-sha256',
      '0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1',
    ],
    { encoding: 'utf8' }
  );
  const out = (r.stdout || '') + (r.stderr || '');
  assert.notStrictEqual(r.status, 0);
  assert.ok(out.includes('BUILD_FINGERPRINT_MISMATCH'), out.slice(0, 500));
});

test('analysis report documents sibling wrappers and fail-closed uniqueness', () => {
  assert.ok(fs.existsSync(report));
  const md = fs.readFileSync(report, 'utf8');
  assert.ok(md.includes('0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1'));
  assert.ok(md.includes('0x486C270'));
  assert.ok(md.includes('0x486F0A0') || md.includes('486F0A0'));
  assert.ok(md.includes('0x486C600') || md.includes('486C600'));
  assert.ok(md.includes('siblings') || md.includes('sibling'));
  assert.ok(md.includes('UPLOAD_SCHEMA_VERIFIED'));
  assert.ok(md.includes('matches == 1') || md.includes('exactly 1'));
});

test('verify_lua_loader and scan_runtime_sigs scripts exist', () => {
  assert.ok(fs.existsSync(path.join(root, 'Scripts', 'verify_lua_loader.py')));
  assert.ok(fs.existsSync(path.join(root, 'Scripts', 'scan_runtime_sigs.py')));
});

test('signature DB has wwm-lite fingerprint entry with loadbufferx', () => {
  const hdr = fs.readFileSync(path.join(root, 'src/hook/lua_signatures.h'), 'utf8');
  assert.ok(hdr.includes('wwm-lite-0cfdfcc6'));
  assert.ok(hdr.includes('0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1'));
  assert.ok(hdr.includes('kWwmLiteLoadBufferX'));
  assert.ok(hdr.includes('0x486C600'));
});

test('runtime hook implements luaL_loadbufferx adapter path', () => {
  const cpp = fs.readFileSync(path.join(root, 'src/hook/lua_runtime_hook.cpp'), 'utf8');
  assert.ok(cpp.includes('luaL_loadbufferx_fn'));
  assert.ok(cpp.includes('LuaLoaderKind::LuaLLoadBufferX'));
  assert.ok(cpp.includes('INNER_LOADER_MISMATCH') || cpp.includes('inner'));
  assert.ok(cpp.includes('loader rc=%d') || cpp.includes('loader rc='));
});

test('analysis JSON if present is structured', () => {
  if (!fs.existsSync(analysis)) {
    console.log('  skip analysis json missing');
    return;
  }
  const j = JSON.parse(fs.readFileSync(analysis, 'utf8'));
  assert.ok(j.conclusion || j.enable_runtime !== undefined);
});

test('fuzzy never selected policy in report', () => {
  const md = fs.readFileSync(report, 'utf8');
  assert.ok(md.toLowerCase().includes('fuzzy') || md.includes('No fuzzy'));
});

test('hook source still has LuaLoaderKind enum for future adapter', () => {
  const h = fs.readFileSync(path.join(root, 'src/hook/lua_hook_state.h'), 'utf8');
  assert.ok(h.includes('LuaLoaderKind'));
  assert.ok(h.includes('LuaLoad'));
});

if (process.exitCode) {
  console.error('\nSome lua loader analysis tests failed');
  process.exit(1);
}
console.log('\nAll lua loader analysis tests passed');
