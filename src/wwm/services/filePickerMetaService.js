'use strict';

const { isLongFaceData, extractFaceDataFromViewData } = require('../../parsers/faceDataParser');
const { normalizeFaceData, hashFaceData } = require('../../utils/hash');
const { redact } = require('../../utils/redact');

const INTERESTING_KEYS = new Set([
  'plan_id',
  'pid',
  'puid',
  'uid',
  'number_id',
  'account',
  'hostnum',
  'name',
  'nickname',
  'author',
  'author_uid',
  'designer_id',
  'uploader',
  'owner',
  'original_author',
  'original_pid',
  'source_pid',
  'source_plan_id',
  'inherit_plan_id',
  'copy_from',
  'region',
  'server',
  'tags',
  'plan_type',
  'body_type',
  'picture_url',
  'view_data',
  'face_data',
  'create_time',
  'upload_ts',
]);

/**
 * Replace long face payloads with length/hash placeholders. Deep.
 * Also redacts secret-looking keys.
 */
function sanitizeFaceDataDeep(value, faceHashHint) {
  if (value == null) return value;
  if (typeof value === 'string') {
    if (isLongFaceData(value) || (value.length > 80 && /^[RD]67/i.test(value))) {
      const norm = normalizeFaceData(value);
      return {
        __face_data__: true,
        length: norm.length,
        sha256: hashFaceData(norm),
      };
    }
    // view_data often is a JSON string containing face_data
    if (value.trim().startsWith('{') && value.includes('face_data')) {
      try {
        const inner = JSON.parse(value);
        return JSON.stringify(sanitizeFaceDataDeep(inner, faceHashHint));
      } catch {
        return value;
      }
    }
    return value;
  }
  if (Array.isArray(value)) return value.map((v) => sanitizeFaceDataDeep(v, faceHashHint));
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (/^(session|token|server_token|cookie|authorization|auth|password|secret)$/i.test(k)) {
        out[k] = '***';
        continue;
      }
      out[k] = sanitizeFaceDataDeep(v, faceHashHint);
    }
    return out;
  }
  return value;
}

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (v && typeof v === 'object' && v.__face_data__) return 'face_data_placeholder';
  return typeof v;
}

/** Collect recursive field paths with types. */
function collectFieldPaths(obj, prefix = '$', out = [], depth = 0, maxDepth = 8) {
  if (depth > maxDepth || obj == null) return out;
  if (Array.isArray(obj)) {
    out.push({ path: prefix, type: 'array', length: obj.length });
    if (obj.length) collectFieldPaths(obj[0], `${prefix}[]`, out, depth + 1, maxDepth);
    return out;
  }
  if (typeof obj !== 'object') {
    out.push({ path: prefix, type: typeOf(obj) });
    return out;
  }
  if (obj.__face_data__) {
    out.push({ path: prefix, type: 'face_data_placeholder', length: obj.length, sha256: obj.sha256 });
    return out;
  }
  for (const [k, v] of Object.entries(obj)) {
    const p = `${prefix}.${k}`;
    out.push({ path: p, type: typeOf(v), interesting: INTERESTING_KEYS.has(k) });
    if (v && typeof v === 'object') collectFieldPaths(v, p, out, depth + 1, maxDepth);
  }
  return out;
}

/**
 * Find first path whose value is long face data (before sanitize).
 */
function findFaceDataFieldPath(obj, prefix = '$', depth = 0) {
  if (obj == null || depth > 8) return null;
  if (typeof obj === 'string') {
    if (isLongFaceData(obj)) return prefix;
    if (obj.trim().startsWith('{') && obj.includes('face_data')) {
      try {
        return findFaceDataFieldPath(JSON.parse(obj), prefix, depth + 1);
      } catch {
        return null;
      }
    }
    return null;
  }
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      const p = findFaceDataFieldPath(obj[i], `${prefix}[${i}]`, depth + 1);
      if (p) return p;
    }
    return null;
  }
  if (typeof obj === 'object') {
    // prefer explicit face_data keys
    if (typeof obj.face_data === 'string' && isLongFaceData(obj.face_data)) {
      return `${prefix}.face_data`;
    }
    if (obj.view_data != null) {
      const extracted = extractFaceDataFromViewData(obj.view_data);
      if (extracted) {
        if (typeof obj.view_data === 'string') return `${prefix}.view_data.face_data`;
        return `${prefix}.view_data.face_data`;
      }
    }
    for (const [k, v] of Object.entries(obj)) {
      const p = findFaceDataFieldPath(v, `${prefix}.${k}`, depth + 1);
      if (p) return p;
    }
  }
  return null;
}

function getByPath(obj, path) {
  // path like $.a.b or $.view_data.face_data — view_data may be JSON string
  if (!path || path === '$') return obj;
  const parts = path.replace(/^\$\.?/, '').split('.');
  let cur = obj;
  for (const part of parts) {
    if (cur == null) return undefined;
    if (typeof cur === 'string' && cur.trim().startsWith('{')) {
      try {
        cur = JSON.parse(cur);
      } catch {
        return undefined;
      }
    }
    const m = part.match(/^(\w+)\[(\d+)\]$/);
    if (m) {
      cur = cur[m[1]];
      if (!Array.isArray(cur)) return undefined;
      cur = cur[Number(m[2])];
    } else {
      cur = cur[part];
    }
  }
  return cur;
}

/**
 * Flatten primitive-ish leaf values for metadata diff (no face payloads).
 */
function flattenLeaves(obj, prefix = '$', out = {}, depth = 0) {
  if (obj == null || depth > 8) return out;
  if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
    out[prefix] = obj;
    return out;
  }
  if (obj && typeof obj === 'object' && obj.__face_data__) {
    out[prefix] = `face_data:sha256:${obj.sha256}:len:${obj.length}`;
    return out;
  }
  if (Array.isArray(obj)) {
    out[prefix] = `array(len=${obj.length})`;
    // include short arrays of primitives
    if (obj.every((x) => typeof x !== 'object' || x == null)) {
      out[prefix] = obj;
    }
    return out;
  }
  if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      flattenLeaves(v, `${prefix}.${k}`, out, depth + 1);
    }
  }
  return out;
}

function diffSanitizedWrappers(globalSan, chinaSan) {
  const g = flattenLeaves(globalSan);
  const c = flattenLeaves(chinaSan);
  const gKeys = new Set(Object.keys(g));
  const cKeys = new Set(Object.keys(c));
  const fieldsOnlyInGlobal = [...gKeys].filter((k) => !cKeys.has(k)).sort();
  const fieldsOnlyInChina = [...cKeys].filter((k) => !gKeys.has(k)).sort();
  const fieldsWithDifferentValues = [];
  for (const k of gKeys) {
    if (!cKeys.has(k)) continue;
    const gv = JSON.stringify(g[k]);
    const cv = JSON.stringify(c[k]);
    if (gv !== cv) {
      fieldsWithDifferentValues.push({ path: k, global: g[k], china: c[k] });
    }
  }
  const shapeEqual =
    fieldsOnlyInGlobal.length === 0 &&
    fieldsOnlyInChina.length === 0;
  const sameMetadata = shapeEqual && fieldsWithDifferentValues.length === 0;
  return {
    sameWrapperShape: shapeEqual,
    sameMetadata,
    fieldsOnlyInGlobal,
    fieldsOnlyInChina,
    fieldsWithDifferentValues,
  };
}

/**
 * Pull common metadata fields from raw (unsanitized) wrapper JSON.
 */
function extractWrapperIdentity(rawJson) {
  if (!rawJson || typeof rawJson !== 'object') {
    return {
      plan_id: null,
      pid: null,
      hostnum: null,
      account: null,
      name: null,
      tags: null,
      plan_type: null,
      body_type: null,
      picture_url: null,
    };
  }
  const pick = (...keys) => {
    for (const k of keys) {
      if (rawJson[k] != null && rawJson[k] !== '') return rawJson[k];
    }
    return null;
  };
  // nested result/data
  const nested = rawJson.result || rawJson.data || rawJson.plan_info || {};
  return {
    plan_id: pick('plan_id') || nested.plan_id || null,
    pid: pick('pid', 'puid', 'uid') || nested.pid || null,
    hostnum: pick('hostnum') ?? nested.hostnum ?? null,
    account: pick('account') || nested.account || null,
    name: pick('name', 'nickname') || nested.name || null,
    tags: pick('tags') || nested.tags || null,
    plan_type: pick('plan_type') ?? nested.plan_type ?? null,
    body_type: pick('body_type') ?? nested.body_type ?? null,
    picture_url: pick('picture_url') || nested.picture_url || null,
  };
}

function looksLikeCommunityPlanId(planId) {
  if (typeof planId !== 'string') return false;
  if (planId.length < 6 || planId.length > 64) return false;
  // community plan IDs are base64-ish, may contain / + ; NOT FP object keys
  if (/^[0-9a-f]{24}[A-Za-z0-9]{8}[0-9]{2}$/.test(planId)) return false;
  return true;
}

function redactForResponse(meta) {
  return redact(meta);
}

module.exports = {
  sanitizeFaceDataDeep,
  collectFieldPaths,
  findFaceDataFieldPath,
  getByPath,
  flattenLeaves,
  diffSanitizedWrappers,
  extractWrapperIdentity,
  looksLikeCommunityPlanId,
  redactForResponse,
  INTERESTING_KEYS,
};
