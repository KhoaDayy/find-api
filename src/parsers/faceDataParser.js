'use strict';

const { normalizeFaceData, hashFaceData } = require('../utils/hash');

/**
 * Long face payload starts with R67 (new) or D67 (old/NPC) and usually contains |*| segments.
 */
function isLongFaceData(data) {
  if (typeof data !== 'string') return false;
  const s = normalizeFaceData(data);
  return /^[RD]67/i.test(s);
}

function parseLongFaceData(data) {
  if (typeof data !== 'string') {
    return { ok: false, error: 'not_a_string' };
  }
  const normalized = normalizeFaceData(data);
  if (!normalized) return { ok: false, error: 'empty' };
  if (!/^[RD]67/i.test(normalized)) {
    return { ok: false, error: 'missing_version_prefix', head: normalized.slice(0, 8) };
  }
  const version = normalized.slice(0, 3).toUpperCase();
  const parts = normalized.split('|*|');
  return {
    ok: true,
    type: 'long_face',
    version,
    partCount: parts.length,
    length: normalized.length,
    faceHash: hashFaceData(normalized),
    normalized,
    // keep raw parts for debug; do not mutate
    parts,
  };
}

/**
 * Extract face_data string from community view_data (string JSON or object).
 */
function extractFaceDataFromViewData(viewData) {
  if (viewData == null) return null;
  let obj = viewData;
  if (typeof viewData === 'string') {
    try {
      obj = JSON.parse(viewData);
    } catch {
      // maybe already a long face string
      if (isLongFaceData(viewData)) return normalizeFaceData(viewData);
      return null;
    }
  }
  if (obj && typeof obj === 'object' && typeof obj.face_data === 'string') {
    return normalizeFaceData(obj.face_data);
  }
  return null;
}

module.exports = {
  isLongFaceData,
  parseLongFaceData,
  extractFaceDataFromViewData,
};
