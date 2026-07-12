'use strict';

/**
 * Dry-run FilePicker token request builder.
 * Does NOT send network. Live send blocked until dual flags true.
 */

const { REGIONS } = require('../../config/regions');
const { redactToken } = require('./filePickerCaptureParser');

const FACE_TAG = '_face_123_face_';

function liveUploadAllowed() {
  return (
    process.env.ENABLE_LIVE_FACE_UPLOAD === 'true' &&
    process.env.UPLOAD_SCHEMA_VERIFIED === 'true'
  );
}

/**
 * Build token RPC request description from known statics + optional capture overrides.
 *
 * CERTAIN from dump:
 *   rpc_gen_filepicker_token(params, usage, url)
 *   usage = TOKEN_FOR_UPLOAD (1) for uploads
 *   params include device_name, review; review_id field name mangled
 *
 * UNKNOWN without capture:
 *   exact review / review_id (12 vs 129)
 *   exact url string passed to RPC
 */
function buildTokenRequest({
  region = 'CN',
  usage = 1, // TOKEN_FOR_UPLOAD
  review = null,
  reviewId = null,
  deviceName = 'dry-run-device',
  url = null,
  tokenParam = null,
} = {}) {
  const reg = String(region).toUpperCase() === 'GLOBAL' || String(region).toUpperCase() === 'SEA'
    ? REGIONS.SEA
    : REGIONS.CN;

  const uploadUrl = url || reg.faceFilePickerUploadUrl;

  const params = {
    device_name: deviceName,
    review: review != null ? review : '<UNKNOWN:from_fp_review_config_or_REVIEW_VERIFYING>',
  };
  // review_id key name unproven — expose both candidates as documentation only
  if (reviewId != null) {
    params.review_id = reviewId;
    params._note_review_id_key = 'key name unproven in decompile; may differ';
  } else {
    params._note_review_candidates = {
      PIC_REVIEW_FACE_SHARE: 12,
      REVIEW_ID_FACE_SHARE: 129,
      which_used: 'UNKNOWN — FaceShare dump omits hex_fp_review_id arg',
    };
  }
  if (tokenParam && typeof tokenParam === 'object') {
    Object.assign(params, tokenParam);
  }

  return {
    rpc: 'rpc_gen_filepicker_token',
    params,
    usage,
    url: uploadUrl,
    region: reg.id === 'SEA' ? 'GLOBAL' : 'CN',
    dry_run: true,
    live_allowed: liveUploadAllowed(),
    blocked_reason: liveUploadAllowed()
      ? null
      : !process.env.ENABLE_LIVE_FACE_UPLOAD || process.env.ENABLE_LIVE_FACE_UPLOAD !== 'true'
        ? 'ENABLE_LIVE_FACE_UPLOAD!=true'
        : 'UPLOAD_SCHEMA_VERIFIED!=true',
  };
}

function parseTokenResponse(serverToken, { usage = null, url = null, review = null } = {}) {
  const red = redactToken(serverToken);
  return {
    ...red,
    usage,
    url,
    review,
    stripped_for_upload: red.tagged
      ? { note: 'client strips FACE_TAG prefix before storing _server_token', length_after_strip: Math.max(0, (serverToken?.length || 0) - FACE_TAG.length) }
      : null,
  };
}

class FilePickerTokenProvider {
  buildTokenRequest(opts) {
    return buildTokenRequest(opts);
  }

  parseTokenResponse(serverToken, meta) {
    return parseTokenResponse(serverToken, meta);
  }

  /**
   * Live token fetch — intentionally unimplemented until schema verified.
   */
  async requestToken() {
    if (!liveUploadAllowed()) {
      const err = new Error('Live token request blocked');
      err.code = 'LIVE_UPLOAD_BLOCKED';
      err.flags = {
        ENABLE_LIVE_FACE_UPLOAD: process.env.ENABLE_LIVE_FACE_UPLOAD === 'true',
        UPLOAD_SCHEMA_VERIFIED: process.env.UPLOAD_SCHEMA_VERIFIED === 'true',
      };
      throw err;
    }
    const err = new Error('Live token RPC not implemented — schema capture required');
    err.code = 'NOT_IMPLEMENTED';
    throw err;
  }
}

module.exports = {
  FilePickerTokenProvider,
  buildTokenRequest,
  parseTokenResponse,
  liveUploadAllowed,
  FACE_TAG,
};
