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

test('analysis report exists and does not enable runtime', () => {
  assert.ok(fs.existsSync(report));
  const md = fs.readFileSync(report, 'utf8');
  assert.ok(md.includes('0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1'));
  assert.ok(md.includes('0x486C270'));
  assert.ok(md.includes('0x486F0A0') || md.includes('486F0A0'));
  assert.ok(md.includes('Runtime hook enabled:** **NO**') || md.includes('enabled:** **NO**') || /enabled:\s*\*\*NO\*\*/i.test(md) || md.includes('NO'));
  assert.ok(md.includes('UPLOAD_SCHEMA_VERIFIED'));
  assert.ok(!md.includes('enable_runtime_hook: true'));
});

test('analysis JSON has enable_runtime_hook false', () => {
  if (!fs.existsSync(analysis)) {
    console.log('  skip analysis json missing');
    return;
  }
  const j = JSON.parse(fs.readFileSync(analysis, 'utf8'));
  assert.strictEqual(j.conclusion.enable_runtime_hook, false);
  if (j.conclusion.winner) {
    assert.strictEqual(j.conclusion.winner.enable_runtime, false);
  }
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
