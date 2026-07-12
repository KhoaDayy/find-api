'use strict';

/**
 * Dry-run FilePicker upload request builder.
 * Live send blocked unless ENABLE_LIVE_FACE_UPLOAD && UPLOAD_SCHEMA_VERIFIED.
 */

const { REGIONS } = require('../../config/regions');
const { liveUploadAllowed, FACE_TAG } = require('./filePickerTokenProvider');
const {
  assertUploadHostAllowed,
  redactHeaders,
  classifyBody,
} = require('./filePickerCaptureParser');
const { isLongFaceData } = require('../../parsers/faceDataParser');

/**
 * Build upload request description.
 *
 * CERTAIN: POST to FACE_SERVICE_URL / FOREIGN_FACE_SERVICE_URL, body=content string
 * UNKNOWN: Content-Type, token header name, multipart vs raw
 *
 * @param {object} opts
 * @param {'CN'|'GLOBAL'|'SEA'} opts.region
 * @param {string} [opts.token] - will be redacted in output
 * @param {string|object} opts.body - raw string or JSON object/wrapper
 * @param {object} [opts.captureOverrides] - from real capture (content_type, token_header)
 */
function build({ region = 'CN', token = null, body, captureOverrides = {} } = {}) {
  const reg =
    String(region).toUpperCase() === 'GLOBAL' || String(region).toUpperCase() === 'SEA'
      ? REGIONS.SEA
      : REGIONS.CN;

  const url = captureOverrides.url || reg.faceFilePickerUploadUrl;
  const hostCheck = assertUploadHostAllowed(url);
  if (!hostCheck.ok) {
    const err = new Error(hostCheck.error);
    err.code = 'UPLOAD_HOST_REJECTED';
    err.details = hostCheck;
    throw err;
  }

  // Never rewrite metadata owner for target region without proof
  let bodyOut = body;
  let bodyType;
  let bodyLength;
  let bodySchema;
  let faceHash = null;
  let bodyIdentity = null;

  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) {
    // JSON wrapper path — preserve pid/hostnum/dressing/face_share_type as-is
    const classified = classifyBody(body, 'application/json');
    bodyType = 'json';
    bodyLength = classified.body_length;
    bodySchema = classified.body_schema;
    faceHash = classified.face_hash;
    bodyIdentity = classified.parsed
      ? {
          pid: body.pid ?? null,
          hostnum: body.hostnum ?? null,
          face_share_type: body.face_share_type ?? null,
          has_dressing: !!body.dressing,
          keys: Object.keys(body),
          note: 'identity fields preserved; not rewritten for target region',
        }
      : null;
    bodyOut = JSON.stringify(body);
  } else if (typeof body === 'string') {
    const classified = classifyBody(body, captureOverrides.content_type || 'text/plain');
    bodyType = classified.body_type;
    bodyLength = classified.body_length;
    bodySchema = classified.body_schema;
    faceHash = classified.face_hash;
    bodyOut = body;
    if (bodyType === 'raw_face_data') {
      bodyIdentity = { note: 'raw R67/D67 — server may wrap metadata (case B)' };
    }
  } else {
    const err = new Error('body required (string or object)');
    err.code = 'INVALID_BODY';
    throw err;
  }

  // Token placement UNKNOWN — only show if capture provided
  const headers = {
    // placeholders document uncertainty
    'Content-Type':
      captureOverrides.content_type ||
      (bodyType === 'json' ? 'application/json' : bodyType === 'raw_face_data' ? 'text/plain' : '<UNKNOWN>'),
  };
  if (captureOverrides.token_header_name) {
    headers[captureOverrides.token_header_name] = token
      ? token.startsWith(FACE_TAG)
        ? `${FACE_TAG}***`
        : '***'
      : '<token>';
  } else {
    headers['<UNKNOWN_TOKEN_HEADER>'] = token ? '***' : '<token required>';
  }

  // Apply any extra redacted header overrides from capture
  if (captureOverrides.headers) {
    Object.assign(headers, redactHeaders(captureOverrides.headers));
  }

  const allowed = liveUploadAllowed();

  return {
    method: 'POST',
    url,
    host: hostCheck.host,
    region: reg.id === 'SEA' ? 'GLOBAL' : 'CN',
    redactedHeaders: redactHeaders(headers),
    bodyType,
    bodyLength,
    bodySchema,
    face_hash: faceHash,
    bodyIdentity,
    // never return raw body with secrets; for dry-run return schema only
    bodyPreview: summarizeBodyPreview(bodyOut, bodyType),
    dry_run: true,
    live_allowed: allowed,
    blocked_reason: allowed
      ? null
      : process.env.ENABLE_LIVE_FACE_UPLOAD !== 'true'
        ? 'ENABLE_LIVE_FACE_UPLOAD!=true'
        : 'UPLOAD_SCHEMA_VERIFIED!=true',
    static_certainty: {
      method: 'CERTAIN',
      url_host: 'CERTAIN',
      body_is_content_string: 'CERTAIN',
      content_type: captureOverrides.content_type ? 'FROM_CAPTURE' : 'UNKNOWN',
      token_placement: captureOverrides.token_header_name ? 'FROM_CAPTURE' : 'UNKNOWN',
      wrapper_vs_raw: bodyType === 'json' ? 'ASSUME_CASE_A_IF_CAPTURE_MATCHES' : bodyType === 'raw_face_data' ? 'ASSUME_CASE_B' : 'UNKNOWN',
    },
  };
}

function summarizeBodyPreview(bodyStr, bodyType) {
  if (!bodyStr) return null;
  if (bodyType === 'raw_face_data' || isLongFaceData(bodyStr)) {
    return { type: 'face_data', length: bodyStr.length, head: bodyStr.slice(0, 8) + '…' };
  }
  if (bodyType === 'json') {
    try {
      const j = JSON.parse(bodyStr);
      return {
        type: 'json',
        keys: Object.keys(j),
        pid: j.pid ?? null,
        hostnum: j.hostnum ?? null,
        face_share_type: j.face_share_type ?? null,
        has_dressing: !!j.dressing,
        face_data_length: typeof j.face_data === 'string' ? j.face_data.length : null,
      };
    } catch {
      return { type: 'json_invalid', length: bodyStr.length };
    }
  }
  return { type: bodyType, length: bodyStr.length };
}

class FilePickerUploadRequestBuilder {
  build(opts) {
    return build(opts);
  }

  async send() {
    if (!liveUploadAllowed()) {
      const err = new Error('Live upload blocked');
      err.code = 'LIVE_UPLOAD_BLOCKED';
      err.flags = {
        ENABLE_LIVE_FACE_UPLOAD: process.env.ENABLE_LIVE_FACE_UPLOAD === 'true',
        UPLOAD_SCHEMA_VERIFIED: process.env.UPLOAD_SCHEMA_VERIFIED === 'true',
      };
      throw err;
    }
    const err = new Error('Live upload not implemented — capture schema first');
    err.code = 'NOT_IMPLEMENTED';
    throw err;
  }
}

module.exports = {
  FilePickerUploadRequestBuilder,
  build,
};
