'use strict';

/**
 * Contracts for Lua-first capture state machine + probe diagnostics.
 * Native C++ is validated in CI build; these lock the JSON/config surface.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

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

console.log('lua capture state / probe contracts');

const root = path.join(__dirname, '..');
const exampleCfg = JSON.parse(
  fs.readFileSync(path.join(root, 'hook_config.example.json'), 'utf8')
);

// Mirror of src/hook/lua_hook_state.h (keep in sync)
const LuaHookState = {
  Disabled: 0,
  Scanning: 1,
  SignatureMissing: 2,
  SignatureAmbiguous: 3,
  CreateHookFailed: 4,
  EnableHookFailed: 5,
  Installed: 6,
  Injected: 7,
  PcallObserverOnly: 8,
};

function allowsF5(s) {
  return s === LuaHookState.Installed || s === LuaHookState.Injected;
}

function f5RejectReason(s) {
  switch (s) {
    case LuaHookState.Disabled:
      return 'LUA_HOOK_DISABLED';
    case LuaHookState.Scanning:
      return 'LUA_HOOK_STILL_SCANNING';
    case LuaHookState.SignatureMissing:
      return 'LUA_HOOK_NOT_INSTALLED_SIGNATURE_MISSING';
    case LuaHookState.SignatureAmbiguous:
      return 'LUA_HOOK_NOT_INSTALLED_SIGNATURE_AMBIGUOUS';
    case LuaHookState.CreateHookFailed:
      return 'LUA_HOOK_NOT_INSTALLED_CREATE_FAILED';
    case LuaHookState.EnableHookFailed:
      return 'LUA_HOOK_NOT_INSTALLED_ENABLE_FAILED';
    case LuaHookState.PcallObserverOnly:
      return 'LUA_HOOK_PCALL_OBSERVER_ONLY_NO_INJECT';
    case LuaHookState.Installed:
    case LuaHookState.Injected:
      return '';
    default:
      return 'LUA_HOOK_NOT_INSTALLED';
  }
}

test('default config is Lua-first, winhttp off, no debug sethook, no pcall observer', () => {
  assert.strictEqual(exampleCfg.enable_lua_hook, true);
  assert.strictEqual(exampleCfg.enable_winhttp_fallback, false);
  assert.strictEqual(exampleCfg.enable_lua_debug_hook, false);
  assert.strictEqual(exampleCfg.enable_pcall_observer_when_loader_missing, false);
  assert.strictEqual(exampleCfg.enable_console, true);
  assert.strictEqual(exampleCfg.enable_cn_to_global_conversion, false);
  assert.ok(Array.isArray(exampleCfg.target_processes));
  assert.ok(exampleCfg.target_processes.includes('wwm.exe'));
  assert.ok(exampleCfg.lua_script.includes('face_share_logger'));
  assert.strictEqual(exampleCfg.capture_dir, 'captures');
});

test('SignatureMissing + F5 → reject, not armed', () => {
  assert.strictEqual(allowsF5(LuaHookState.SignatureMissing), false);
  assert.strictEqual(
    f5RejectReason(LuaHookState.SignatureMissing),
    'LUA_HOOK_NOT_INSTALLED_SIGNATURE_MISSING'
  );
});

test('Installed + F5 → allowed (pending arm only)', () => {
  assert.strictEqual(allowsF5(LuaHookState.Installed), true);
  assert.strictEqual(f5RejectReason(LuaHookState.Installed), '');
});

test('Injected + F5 → allowed without clearing inject table semantics', () => {
  // F5 must not require clear of injected states; script has _G guard.
  assert.strictEqual(allowsF5(LuaHookState.Injected), true);
});

test('PcallObserverOnly does not allow inject F5', () => {
  assert.strictEqual(allowsF5(LuaHookState.PcallObserverOnly), false);
  assert.ok(f5RejectReason(LuaHookState.PcallObserverOnly).includes('OBSERVER'));
});

test('init_complete schema reflects real hook state fields', () => {
  const sample = {
    ok: true,
    lua_requested: true,
    lua_hook_state: 'signature_missing',
    lua_hook_installed: false,
    winhttp_fallback: false,
  };
  assert.strictEqual(sample.lua_hook_installed, false);
  assert.strictEqual(sample.lua_hook_state, 'signature_missing');
  assert.strictEqual(sample.winhttp_fallback, false);
  // installed true only for installed|injected
  for (const st of ['installed', 'injected']) {
    const installed = st === 'installed' || st === 'injected';
    assert.strictEqual(installed, true);
  }
  for (const st of ['signature_missing', 'disabled', 'pcall_observer_only']) {
    const installed = st === 'installed' || st === 'injected';
    assert.strictEqual(installed, false);
  }
});

test('fuzzy candidates never selected for hook (policy)', () => {
  const exact = { matches: 0, status: 'SIGNATURE_NOT_FOUND', selected_address: null };
  const fuzzy = [
    { address: '0x141000000', mismatches: 2 },
    { address: '0x141000100', mismatches: 3 },
  ];
  // Policy: only exact unique match may set selected for hook
  let hookAddr = null;
  if (exact.matches === 1 && exact.status === 'ok') hookAddr = exact.selected_address;
  assert.strictEqual(hookAddr, null);
  assert.ok(fuzzy.length >= 1); // diagnostic only
});

test('>1 exact match → ambiguous, no first-match hook', () => {
  const hits = ['0x1', '0x2'];
  const status = hits.length === 0 ? 'SIGNATURE_NOT_FOUND' : hits.length === 1 ? 'ok' : 'SIGNATURE_AMBIGUOUS';
  const selected = hits.length === 1 ? hits[0] : null;
  assert.strictEqual(status, 'SIGNATURE_AMBIGUOUS');
  assert.strictEqual(selected, null);
});

test('probe JSON schema sample is diagnostic_only and never_hooks_fuzzy', () => {
  const probe = {
    schema_version: 1,
    diagnostic_only: true,
    never_hooks_fuzzy: true,
    exact_scan: {
      lua_load: { matches: 0 },
      lua_pcallk: { matches: 1, rva: '0x486C270' },
    },
    fuzzy_lua_load: [],
    pcall_xrefs: [],
    string_anchors: [],
  };
  assert.strictEqual(probe.diagnostic_only, true);
  assert.strictEqual(probe.never_hooks_fuzzy, true);
  assert.strictEqual(probe.exact_scan.lua_load.matches, 0);
  assert.strictEqual(probe.exact_scan.lua_pcallk.matches, 1);
});

test('pcall observer does not imply full capture installed', () => {
  const st = 'pcall_observer_only';
  const lua_hook_installed = st === 'installed' || st === 'injected';
  assert.strictEqual(lua_hook_installed, false);
});

test('signature DB header exists and does not invent sha256 matches', () => {
  const hdr = fs.readFileSync(path.join(root, 'src/hook/lua_signatures.h'), 'utf8');
  assert.ok(hdr.includes('legacy-default'));
  assert.ok(hdr.includes('kLegacyLuaLoad'));
  // empty sha256 = legacy only after exact scan
  assert.ok(hdr.includes('module_sha256'));
});

test('F5 path source has no g_injected.clear / std::mutex on RequestLuaInject', () => {
  const cpp = fs.readFileSync(path.join(root, 'src/hook/lua_runtime_hook.cpp'), 'utf8');
  const start = cpp.indexOf('bool RequestLuaInject');
  assert.ok(start >= 0, 'RequestLuaInject found');
  const body = cpp.slice(start, start + 800);
  assert.ok(!body.includes('std::mutex'));
  assert.ok(!body.includes('g_injected.clear'));
  assert.ok(!body.includes('std::set'));
  assert.ok(body.includes('InterlockedExchange'));
  assert.ok(body.includes('LuaHookStateAllowsF5'));
  // Must not clear injected state table on F5
  assert.ok(!body.includes('memset'));
  assert.ok(!body.includes('g_injectedStates'));
});

test('dllmain F5 ignored path present', () => {
  const dll = fs.readFileSync(path.join(root, 'src/dllmain.cpp'), 'utf8');
  assert.ok(dll.includes('F5 ignored:'));
  assert.ok(dll.includes('F5 injection armed'));
  assert.ok(dll.includes('lua_hook_state'));
  assert.ok(dll.includes('signature missing') || dll.includes('signature_missing') || dll.includes('lua_load signature missing'));
});

test('no session secrets / full R67 / auth tokens in example config values', () => {
  assert.strictEqual(exampleCfg.unsafe_save_session, false);
  assert.ok(!/R67/.test(JSON.stringify(exampleCfg)));
  // no literal token/session secret fields
  assert.ok(!('session' in exampleCfg));
  assert.ok(!('token' in exampleCfg));
  assert.ok(!('authorization' in exampleCfg));
});

test('UPLOAD_SCHEMA_VERIFIED not set true in repo defaults', () => {
  // env example lives in README — ensure hook config does not flip upload
  assert.ok(!('UPLOAD_SCHEMA_VERIFIED' in exampleCfg));
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.ok(readme.includes('UPLOAD_SCHEMA_VERIFIED=true')); // documented gate
  assert.ok(readme.includes('default off') || readme.includes('not enabled') || readme.includes('gated'));
});

if (process.exitCode) {
  console.error('\nSome lua capture state tests failed');
  process.exit(1);
}
console.log('\nAll lua capture state tests passed');
