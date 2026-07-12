'use strict';

/**
 * JS-side tests for capture redaction / JSONL schema used by the hook pipeline.
 * Native C++ unit tests require a compiled test harness; these lock the contract
 * that captures must satisfy before UPLOAD_SCHEMA_VERIFIED can be set.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { parseCapture } = require('../src/wwm/services/filePickerCaptureParser');
const { sanitizeFaceDataDeep } = require('../src/wwm/services/filePickerMetaService');
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

console.log('hook capture contract');

const FD = 'R67HookCaptureContractTest|*|a|*|b|*|2|*|c';

test('redact session query style strings in JSONL event', () => {
  const line = JSON.stringify({
    schema_version: 1,
    event: 'http_exchange',
    source: 'winhttp',
    data: {
      path: '/x?session=supersecretvalue999&ok=1',
      headers: { Authorization: '_face_123_face_TOKENSECRET' },
    },
  });
  // capture pipeline must never leave raw token when re-parsed through our tools
  const san = sanitizeFaceDataDeep({
    Authorization: '_face_123_face_TOKENSECRET',
    face_data: FD,
  });
  assert.ok(san.face_data.__face_data__);
  assert.ok(!JSON.stringify(san).includes('R67HookCaptureContractTest'));
});

test('JSONL face share events parse into upload/token fields', () => {
  const jsonl = [
    {
      schema_version: 1,
      event: 'face_share_start',
      source: 'lua',
      share_id: '1-1',
      data: { share_id: '1-1' },
    },
    {
      schema_version: 1,
      event: 'upload_plain_text',
      source: 'lua',
      share_id: '1-1',
      data: {
        content: {
          content_kind: 'json_wrapper',
          content_keys: ['pid', 'face_data', 'dressing', 'hostnum', 'face_share_type'],
          pid: 'Z24',
          hostnum: 10011,
          face_share_type: 2,
          has_dressing: true,
          face_data: { __face_data__: true, length: 100, sha256: 'abc' },
        },
        from: 'pic_from_system',
      },
    },
    {
      schema_version: 1,
      event: 'token_rpc_response',
      source: 'lua',
      share_id: '1-1',
      data: {
        token_tagged: true,
        token_prefix: '_face_123_face_',
        token_length: 40,
        token: '_face_123_face_***',
        usage: 1,
        url: 'https://fp.ps.netease.com/h72face/file/new/',
        review: 0,
      },
    },
    {
      schema_version: 1,
      event: 'http_exchange',
      source: 'winhttp',
      share_id: '1-1',
      data: {
        method: 'POST',
        host: 'fp.ps.netease.com',
        path: '/h72face/file/new/',
        headers: { Authorization: '***' },
        request_body: {
          body_kind: 'json',
          body_length: 200,
          face_data: { __face_data__: true, length: 100, sha256: 'abc' },
          pid: 'Z24',
          hostnum: 10011,
          face_share_type: 2,
        },
        response_status: 200,
        pict_url: 'https://h72.fp.ps.netease.com/file/6a527f86e0d2f8e5305227f82gvxhbPw07',
        object_key: '6a527f86e0d2f8e5305227f82gvxhbPw07',
      },
    },
    {
      schema_version: 1,
      event: 'filepicker_callback',
      source: 'lua',
      share_id: '1-1',
      data: {
        success: true,
        pict_url: 'https://h72.fp.ps.netease.com/file/6a527f86e0d2f8e5305227f82gvxhbPw07',
        object_key: '6a527f86e0d2f8e5305227f82gvxhbPw07',
      },
    },
  ]
    .map((o) => JSON.stringify(o))
    .join('\n');

  const p = parseCapture(jsonl);
  assert.ok(p.events && p.events.length === 5);
  assert.ok(p.upload_request);
  assert.strictEqual(p.upload_request.body_identity.pid, 'Z24');
  assert.strictEqual(p.upload_request.body_identity.face_share_type, 2);
  assert.ok(p.token_response.tagged);
  assert.ok(!JSON.stringify(p).includes('TOKENSECRET'));
  assert.strictEqual(p.upload_response.object_key, '6a527f86e0d2f8e5305227f82gvxhbPw07');
});

test('no full R67 in sanitized capture-like object', () => {
  const s = sanitizeFaceDataDeep({
    pid: 'x',
    face_data: FD,
    dressing: {},
    hostnum: 1,
    face_share_type: 2,
  });
  assert.ok(!JSON.stringify(s).includes('R67HookCaptureContractTest'));
  assert.strictEqual(s.face_data.sha256, hashFaceData(FD));
});

test('session.txt is not part of default hook config', () => {
  const cfg = fs.readFileSync(path.join(__dirname, '..', 'hook_config.example.json'), 'utf8');
  const j = JSON.parse(cfg);
  assert.strictEqual(j.unsafe_save_session, false);
  assert.ok(j.lua_script.includes('face_share_logger'));
  assert.strictEqual(j.capture_dir, 'captures');
  assert.strictEqual(j.enable_lua_hook, true);
  assert.strictEqual(j.enable_winhttp_fallback, false);
  assert.strictEqual(j.enable_console, true);
});

test('legacy api_logger is not the default script', () => {
  const cfg = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', 'hook_config.example.json'), 'utf8')
  );
  assert.ok(!cfg.lua_script.includes('api_logger.lua'));
});

if (process.exitCode) {
  console.error('\nSome hook contract tests failed');
  process.exit(1);
}
console.log('\nAll hook contract tests passed');
