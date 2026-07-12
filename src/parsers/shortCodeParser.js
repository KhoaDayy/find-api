'use strict';

const { FP_OBJECT_KEY_RE, SHORT_CODE_RE } = require('../config/regions');

function isFilePickerObjectKey(key) {
  if (typeof key !== 'string') return false;
  return FP_OBJECT_KEY_RE.test(key);
}

function regionFromPrefix(prefix) {
  const p = String(prefix).toLowerCase();
  if (p === 'yysls') return 'china';
  if (p === 'wwm') return 'global';
  return null;
}

function regionFromObjectKeySuffix(key) {
  if (!isFilePickerObjectKey(key)) return 'unknown';
  const suf = key.slice(-2);
  if (suf === '07') return 'china';
  if (suf === '03') return 'global';
  return 'unknown';
}

/**
 * Parse FilePicker short code only.
 * Does NOT accept community plan_id.
 */
function parseShortCode(code) {
  if (typeof code !== 'string') {
    return { ok: false, error: 'not_a_string' };
  }
  const raw = code.trim();
  const m = raw.match(SHORT_CODE_RE);
  if (!m) {
    return { ok: false, error: 'malformed_short_code', raw };
  }
  const prefix = m[1].toLowerCase();
  const revision = Number(m[2]);
  const objectKey = m[3];
  if (!isFilePickerObjectKey(objectKey)) {
    return { ok: false, error: 'invalid_object_key', raw, objectKey };
  }
  return {
    ok: true,
    type: regionFromPrefix(prefix), // 'china' | 'global'
    prefix,
    revision,
    objectKey,
    regionFromSuffix: regionFromObjectKeySuffix(objectKey),
    raw,
  };
}

/**
 * Community ART code or raw plan_id.
 * plan_id is NOT a FilePicker object key.
 */
function parseArtOrPlanId(input) {
  if (typeof input !== 'string') return { ok: false, error: 'not_a_string' };
  const raw = input.trim();
  if (!raw) return { ok: false, error: 'empty' };

  if (/^(yysls|wwm)_facedata_/i.test(raw)) {
    return { ok: false, error: 'is_filepicker_short_code', raw };
  }
  if (/^[RD]67/i.test(raw)) {
    return { ok: false, error: 'is_long_face_data', raw };
  }

  if (raw.startsWith('ART') || raw.startsWith('art')) {
    const planId = raw.slice(3);
    if (!planId) return { ok: false, error: 'empty_plan_id', raw };
    // Community plan_ids are short base64-ish (~16), may contain / +
    if (isFilePickerObjectKey(planId)) {
      // Extremely unlikely; still flag
      return {
        ok: true,
        type: 'art',
        planId,
        artCode: `ART${planId}`,
        raw,
        warning: 'plan_id_matches_fp_key_morphology',
      };
    }
    return { ok: true, type: 'art', planId, artCode: `ART${planId}`, raw };
  }

  // raw plan_id heuristic: not FP key, not long face, short-ish token
  if (isFilePickerObjectKey(raw)) {
    return { ok: false, error: 'looks_like_fp_object_key_not_plan_id', raw };
  }
  if (raw.length < 6 || raw.length > 64) {
    return { ok: false, error: 'invalid_plan_id_length', raw };
  }
  if (/\s/.test(raw)) return { ok: false, error: 'invalid_plan_id_whitespace', raw };

  return {
    ok: true,
    type: 'plan_id',
    planId: raw,
    artCode: `ART${raw}`,
    raw,
  };
}

/**
 * Unified input classifier for convert/inspect.
 */
function parseInput(input) {
  if (typeof input !== 'string') return { ok: false, error: 'not_a_string' };
  const raw = input.trim();
  if (!raw) return { ok: false, error: 'empty' };

  if (/^[RD]67/i.test(raw) || raw.includes('|*|')) {
    return {
      ok: true,
      type: 'long_face',
      raw,
    };
  }

  if (/^(yysls|wwm)_facedata_/i.test(raw)) {
    const sc = parseShortCode(raw);
    if (!sc.ok) return sc;
    return { ...sc, inputType: sc.type === 'china' ? 'china_short' : 'global_short' };
  }

  const art = parseArtOrPlanId(raw);
  if (art.ok) return { ...art, inputType: art.type };
  return art;
}

function buildShortCode(region, revision, objectKey) {
  if (!isFilePickerObjectKey(objectKey)) {
    throw new Error('invalid_object_key');
  }
  const rev = revision == null ? 37 : Number(revision);
  const prefix = region === 'china' || region === 'CN' ? 'yysls' : 'wwm';
  return `${prefix}_facedata_R${rev}_${objectKey}`;
}

module.exports = {
  isFilePickerObjectKey,
  parseShortCode,
  parseArtOrPlanId,
  parseInput,
  buildShortCode,
  regionFromPrefix,
  regionFromObjectKeySuffix,
};
