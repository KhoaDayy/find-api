'use strict';

/**
 * Parse a FilePicker capture file (HAR / JSON / log).
 *
 *   node scripts/parse_filepicker_capture.js path/to/capture.har
 *   node scripts/parse_filepicker_capture.js path/to/capture.json
 *   node scripts/parse_filepicker_capture.js path/to/log.txt --correlate path/to/downloaded_wrapper.json
 */

const fs = require('fs');
const path = require('path');
const {
  parseCapture,
  correlateUploadWithDownload,
} = require('../src/wwm/services/filePickerCaptureParser');
const { sanitizeFaceDataDeep } = require('../src/wwm/services/filePickerMetaService');
const {
  buildTokenRequest,
} = require('../src/wwm/services/filePickerTokenProvider');
const {
  build: buildUpload,
} = require('../src/wwm/services/filePickerUploadRequestBuilder');

function main() {
  const args = process.argv.slice(2);
  if (!args.length || args[0] === '--help') {
    console.log(`Usage:
  node scripts/parse_filepicker_capture.js <capture.har|json|txt>
  node scripts/parse_filepicker_capture.js <capture> --correlate <wrapper.json>
  node scripts/parse_filepicker_capture.js --dry-run-token --region CN
  node scripts/parse_filepicker_capture.js --dry-run-upload --region GLOBAL --body-json <wrapper.json>
`);
    process.exit(0);
  }

  if (args[0] === '--dry-run-token') {
    const region = argValue(args, '--region') || 'CN';
    console.log(JSON.stringify(buildTokenRequest({ region }), null, 2));
    return;
  }

  if (args[0] === '--dry-run-upload') {
    const region = argValue(args, '--region') || 'CN';
    const bodyPath = argValue(args, '--body-json');
    let body = argValue(args, '--body') || '{"pid":"x","face_data":"R67test|*|a","dressing":{},"hostnum":10011,"face_share_type":2}';
    if (bodyPath) body = JSON.parse(fs.readFileSync(bodyPath, 'utf8'));
    else {
      try {
        body = JSON.parse(body);
      } catch {
        /* raw string */
      }
    }
    console.log(JSON.stringify(buildUpload({ region, body, token: '_face_123_face_DUMMYTOKEN' }), null, 2));
    return;
  }

  const file = args[0];
  const raw = fs.readFileSync(file, 'utf8');
  let input = raw;
  try {
    input = JSON.parse(raw);
  } catch {
    /* text log */
  }

  const parsed = parseCapture(input);
  console.log('=== CAPTURE PARSE (redacted) ===');
  console.log(JSON.stringify(parsed, null, 2));

  // dry-run token model from statics
  console.log('\n=== DRY-RUN TOKEN REQUEST (static model) ===');
  console.log(JSON.stringify(buildTokenRequest({ region: 'CN' }), null, 2));

  const corrPath = argValue(args, '--correlate');
  if (corrPath) {
    const wrap = JSON.parse(fs.readFileSync(corrPath, 'utf8'));
    // support our inspect_filepicker_object output
    const wrapper = wrap.sanitized || wrap.identity
      ? { ...(wrap.identity || {}), ...(wrap.sanitized || wrap) }
      : wrap;
    const uploadClassified = parsed.upload_request
      ? {
          body_type: parsed.upload_request.body_type,
          face_hash: parsed.upload_request.face_hash,
          body_identity: parsed.upload_request.body_identity,
          parsed: null,
        }
      : null;
    const corr = correlateUploadWithDownload(uploadClassified, sanitizeFaceDataDeep(wrapper));
    console.log('\n=== CORRELATE UPLOAD vs DOWNLOAD ===');
    console.log(JSON.stringify(corr, null, 2));
  }

  // write redacted summary next to input
  const out = path.join(
    path.dirname(path.resolve(file)),
    path.basename(file).replace(/\.[^.]+$/, '') + '.parsed.json'
  );
  fs.writeFileSync(out, JSON.stringify(parsed, null, 2));
  console.log('\nsaved', out);
}

function argValue(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
}

main();
