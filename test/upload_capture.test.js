'use strict';

const assert = require('assert');
const {
  parseCapture,
  classifyBody,
  correlateUploadWithDownload,
  redactToken,
  assertUploadHostAllowed,
  FACE_TAG,
  isUploadUrl,
  isDownloadUrl,
} = require('../src/wwm/services/filePickerCaptureParser');
const { sanitizeFaceDataDeep } = require('../src/wwm/services/filePickerMetaService');
const {
  buildTokenRequest,
  liveUploadAllowed,
  FilePickerTokenProvider,
} = require('../src/wwm/services/filePickerTokenProvider');
const {
  build: buildUpload,
  FilePickerUploadRequestBuilder,
} = require('../src/wwm/services/filePickerUploadRequestBuilder');
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

console.log('upload capture / dry-run');

const FD = 'R67UploadCaptureTest|*|a|*|b|*|2|*|c';
const H = hashFaceData(FD);
const wrapper = {
  pid: 'Z24LoysTOrEPNT3A',
  face_data: FD,
  dressing: { 1011: { view_no: 1, slot_no: 1, ID: 'x', owning: true } },
  hostnum: 10011,
  face_share_type: 2,
};

test('wrapper sanitizer strips face_data', () => {
  const s = sanitizeFaceDataDeep(wrapper);
  assert.ok(s.face_data.__face_data__);
  assert.ok(!JSON.stringify(s).includes('R67UploadCaptureTest'));
});

test('capture parser redacts token', () => {
  const tok = FACE_TAG + 'ABCDEFGHrealsecret';
  const r = redactToken(tok);
  assert.strictEqual(r.tagged, true);
  assert.ok(!JSON.stringify(r).includes('realsecret'));
  assert.ok(r.token_redacted.includes('***'));
});

test('does not keep Authorization/cookie/session in headers', () => {
  const parsed = parseCapture([
    {
      method: 'POST',
      url: 'https://fp.ps.netease.com/h72face/file/new/',
      headers: {
        Authorization: 'Bearer supersecret',
        Cookie: 'sid=abc',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(wrapper),
      response: { status: 200, body: { pict_url: 'https://h72.fp.ps.netease.com/file/6a527f86e0d2f8e5305227f82gvxhbPw07' } },
    },
  ]);
  const h = parsed.upload_request.headers;
  assert.strictEqual(h.Authorization, '***');
  assert.strictEqual(h.Cookie, '***');
  assert.ok(!JSON.stringify(parsed).includes('supersecret'));
  assert.ok(!JSON.stringify(parsed).includes('sid=abc'));
});

test('token tag recognized', () => {
  const r = redactToken(FACE_TAG + 'xyz');
  assert.strictEqual(r.tag_prefix, FACE_TAG);
  assert.strictEqual(r.tagged, true);
});

test('object key parse from pict_url', () => {
  const parsed = parseCapture([
    {
      method: 'POST',
      url: 'https://fp.ps.easebar.com/h72facesg/file/new/',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(wrapper),
      response: {
        status: 200,
        body: { detail: { pict_url: 'https://h72sg.fp.ps.easebar.com/file/6a47e2900f5db520d85f5f3ahqdzOR1h03' } },
      },
    },
  ]);
  assert.strictEqual(parsed.upload_response.object_key, '6a47e2900f5db520d85f5f3ahqdzOR1h03');
});

test('JSON upload body diffs with downloaded wrapper', () => {
  const up = classifyBody(JSON.stringify(wrapper), 'application/json');
  const dl = sanitizeFaceDataDeep(wrapper);
  const corr = correlateUploadWithDownload(up, dl);
  assert.strictEqual(corr.case, 'A');
  assert.strictEqual(corr.same_face_hash, true);
  assert.ok(corr.field_compare.pid.same);
  assert.ok(corr.field_compare.hostnum.same);
  assert.ok(corr.field_compare.face_share_type.same);
});

test('raw R67 body recognized', () => {
  const c = classifyBody(FD, 'text/plain');
  assert.strictEqual(c.body_type, 'raw_face_data');
  assert.strictEqual(c.face_hash, H);
  const corr = correlateUploadWithDownload(c, sanitizeFaceDataDeep(wrapper));
  assert.strictEqual(corr.case, 'B');
});

test('multipart recognized without field guessing', () => {
  const c = classifyBody('--boundary\r\nContent-Disposition: form-data\r\n\r\nhi\r\n--boundary--', 'multipart/form-data');
  assert.strictEqual(c.body_type, 'multipart');
  assert.ok(c.body_schema[0].includes('multipart'));
});

test('dressing / pid / hostnum / face_share_type preserved in dry-run JSON body', () => {
  const req = buildUpload({
    region: 'GLOBAL',
    body: wrapper,
    token: FACE_TAG + 'tok',
  });
  assert.strictEqual(req.bodyIdentity.pid, wrapper.pid);
  assert.strictEqual(req.bodyIdentity.hostnum, wrapper.hostnum);
  assert.strictEqual(req.bodyIdentity.face_share_type, 2);
  assert.strictEqual(req.bodyIdentity.has_dressing, true);
  assert.ok(req.bodyIdentity.note.includes('not rewritten'));
});

test('dry-run does not send network (build only)', () => {
  const t = buildTokenRequest({ region: 'CN' });
  assert.strictEqual(t.dry_run, true);
  assert.strictEqual(t.rpc, 'rpc_gen_filepicker_token');
  const u = buildUpload({ region: 'CN', body: wrapper });
  assert.strictEqual(u.dry_run, true);
  assert.strictEqual(u.method, 'POST');
});

test('ENABLE_LIVE_FACE_UPLOAD=true but schema unverified still blocks', () => {
  const prev1 = process.env.ENABLE_LIVE_FACE_UPLOAD;
  const prev2 = process.env.UPLOAD_SCHEMA_VERIFIED;
  process.env.ENABLE_LIVE_FACE_UPLOAD = 'true';
  process.env.UPLOAD_SCHEMA_VERIFIED = 'false';
  assert.strictEqual(liveUploadAllowed(), false);
  const t = buildTokenRequest({ region: 'CN' });
  assert.strictEqual(t.live_allowed, false);
  assert.ok(t.blocked_reason.includes('UPLOAD_SCHEMA_VERIFIED'));
  process.env.ENABLE_LIVE_FACE_UPLOAD = prev1;
  process.env.UPLOAD_SCHEMA_VERIFIED = prev2;
});

test('schema verified but live flag false still blocks', () => {
  const prev1 = process.env.ENABLE_LIVE_FACE_UPLOAD;
  const prev2 = process.env.UPLOAD_SCHEMA_VERIFIED;
  process.env.ENABLE_LIVE_FACE_UPLOAD = 'false';
  process.env.UPLOAD_SCHEMA_VERIFIED = 'true';
  assert.strictEqual(liveUploadAllowed(), false);
  process.env.ENABLE_LIVE_FACE_UPLOAD = prev1;
  process.env.UPLOAD_SCHEMA_VERIFIED = prev2;
});

test('upload host allowlist; download CDN not upload URL', () => {
  assert.strictEqual(assertUploadHostAllowed('https://fp.ps.netease.com/h72face/file/new/').ok, true);
  assert.strictEqual(assertUploadHostAllowed('https://evil.example.com/h72face/file/new/').ok, false);
  assert.strictEqual(isUploadUrl('https://fp.ps.easebar.com/h72facesg/file/new/'), true);
  assert.strictEqual(isDownloadUrl('https://h72sg.fp.ps.easebar.com/file/6a47e2900f5db520d85f5f3ahqdzOR1h03'), true);
  assert.strictEqual(isUploadUrl('https://h72sg.fp.ps.easebar.com/file/6a47e2900f5db520d85f5f3ahqdzOR1h03'), false);
});

test('does not use preview object key as upload target', () => {
  const u = buildUpload({ region: 'CN', body: wrapper });
  assert.ok(u.url.includes('/file/new'));
  assert.ok(!u.url.includes('6a527f86e0d2f8e5305227f82gvxhbPw07'));
});

test('no full R67 in dry-run output', () => {
  const u = buildUpload({ region: 'CN', body: wrapper });
  assert.ok(!JSON.stringify(u).includes('R67UploadCaptureTest'));
});

test('no raw token in dry-run output', () => {
  const u = buildUpload({
    region: 'CN',
    body: wrapper,
    token: FACE_TAG + 'SUPERSECRETTOKENVALUE',
    captureOverrides: { token_header_name: 'Authorization' },
  });
  assert.ok(!JSON.stringify(u).includes('SUPERSECRETTOKENVALUE'));
});

test('does not auto-change metadata owner for target region', () => {
  const u = buildUpload({ region: 'GLOBAL', body: { ...wrapper, hostnum: 10011 } });
  assert.strictEqual(u.bodyIdentity.hostnum, 10011);
  assert.strictEqual(u.region, 'GLOBAL');
});

test('HAR-like parse extracts upload', () => {
  const har = {
    log: {
      entries: [
        {
          request: {
            method: 'POST',
            url: 'https://fp.ps.netease.com/h72face/file/new/',
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            postData: { mimeType: 'application/json', text: JSON.stringify(wrapper) },
          },
          response: {
            status: 200,
            content: {
              text: JSON.stringify({
                pict_url: 'https://h72.fp.ps.netease.com/file/6a527f86e0d2f8e5305227f82gvxhbPw07',
              }),
            },
          },
        },
      ],
    },
  };
  const p = parseCapture(har);
  assert.ok(p.upload_request);
  assert.strictEqual(p.upload_request.body_type, 'json');
  assert.strictEqual(p.upload_response.object_key, '6a527f86e0d2f8e5305227f82gvxhbPw07');
});

(async () => {
  await testAsync('live send methods throw when blocked', async () => {
    process.env.ENABLE_LIVE_FACE_UPLOAD = 'false';
    process.env.UPLOAD_SCHEMA_VERIFIED = 'false';
    const tp = new FilePickerTokenProvider();
    await assert.rejects(() => tp.requestToken(), (e) => e.code === 'LIVE_UPLOAD_BLOCKED');
    const ub = new FilePickerUploadRequestBuilder();
    await assert.rejects(() => ub.send(), (e) => e.code === 'LIVE_UPLOAD_BLOCKED');
  });

  if (process.exitCode) {
    console.error('\nSome upload capture tests failed');
    process.exit(1);
  }
  console.log('\nAll upload capture tests passed');
})();
