'use strict';

const { msgpackRequest } = require('../client');
const { extractFaceDataFromViewData } = require('../../parsers/faceDataParser');
const { hashFaceData, normalizeFaceData } = require('../../utils/hash');
const { PLAN_TAG_FACE, PLAN_TAG_MAKEUP } = require('../../config/regions');
const logger = require('../../utils/logger');

async function getDesignerData(host, pid, hostnum) {
  if (!pid || hostnum == null) return null;
  const data = await msgpackRequest(host, '/face_community/get_designer_data', {
    target_pid: String(pid),
    force_refresh: true,
    target_hostnum: Number(hostnum),
  });
  if (!data || typeof data !== 'object') return null;
  return data.result || data;
}

async function getFacePlanData(host, planId) {
  if (!planId) return null;
  const data = await msgpackRequest(host, '/flk/face_community/get_face_plan_data', {
    plan_id: String(planId),
  });
  if (!data || typeof data !== 'object') return null;
  return data;
}

/**
 * Batch fetch. Shape is unknown until diagnostic — return raw.
 * Tries a few common payload shapes without inventing success semantics.
 */
async function getFacePlanDataBatch(host, planIds) {
  const ids = [...new Set((planIds || []).filter(Boolean).map(String))];
  if (!ids.length) return { ok: false, error: 'empty_ids', raw: null };

  const attempts = [
    { plan_ids: ids },
    { plan_id_list: ids },
    { plan_id_dict: Object.fromEntries(ids.map((id) => [id, 0])) },
    { ids },
  ];

  for (const payload of attempts) {
    const data = await msgpackRequest(host, '/flk/face_community/get_face_plan_data_batch', payload);
    if (!data) continue;
    // Accept anything non-null for diagnostic; caller normalizes
    if (data.code === 0 || data.result || data.data || Array.isArray(data)) {
      return { ok: true, raw: data, payloadTried: payload };
    }
    // still return last raw if code present
    if (typeof data === 'object') {
      return { ok: true, raw: data, payloadTried: payload, note: 'nonzero_or_unknown_shape' };
    }
  }
  return { ok: false, error: 'batch_failed', raw: null };
}

/**
 * Normalize batch/single responses into Map(planId -> rawResultObject)
 */
function normalizePlanResults(batchOrSingle, fallbackIds = []) {
  const map = new Map();

  const push = (id, result, envelope) => {
    if (!id || !result) return;
    map.set(String(id), { planId: String(id), result, envelope });
  };

  const walk = (node, envelope) => {
    if (node == null) return;
    if (Array.isArray(node)) {
      for (const item of node) {
        if (item && typeof item === 'object') {
          const id = item.plan_id || item.planId || item.id;
          if (id && (item.view_data != null || item.face_data != null || item.tags)) {
            push(id, item, envelope);
          } else if (item.result) {
            walk(item.result, item);
          } else {
            walk(item, envelope);
          }
        }
      }
      return;
    }
    if (typeof node !== 'object') return;

    // map keyed by plan_id
    const keys = Object.keys(node);
    const looksLikePlanMap =
      keys.length > 0 &&
      keys.every((k) => typeof node[k] === 'object' && node[k] != null) &&
      keys.some((k) => node[k].view_data != null || node[k].plan_id != null);
    if (looksLikePlanMap && !node.view_data && !node.plan_id) {
      for (const k of keys) {
        const v = node[k];
        push(v.plan_id || k, v, envelope);
      }
      return;
    }

    if (node.view_data != null || node.plan_id) {
      push(node.plan_id || fallbackIds[0], node, envelope);
      return;
    }
    if (node.result) walk(node.result, node);
    if (node.data) walk(node.data, node);
  };

  walk(batchOrSingle, batchOrSingle);
  return map;
}

function summarizePlanResult(rawEnvelope) {
  // Accept: { result: planObj }, planObj directly, or batch-like only if single plan
  let result = null;
  if (!rawEnvelope || typeof rawEnvelope !== 'object') {
    return { ok: false, error: 'no_result' };
  }
  if (rawEnvelope.view_data != null || rawEnvelope.plan_id != null) {
    result = rawEnvelope;
  } else if (rawEnvelope.result && typeof rawEnvelope.result === 'object') {
    // single envelope { result: plan } OR batch { result: { id: plan } }
    if (rawEnvelope.result.view_data != null || rawEnvelope.result.plan_id != null) {
      result = rawEnvelope.result;
    } else {
      return { ok: false, error: 'batch_envelope_not_single_plan' };
    }
  } else {
    result = rawEnvelope;
  }

  if (!result || typeof result !== 'object') {
    return { ok: false, error: 'no_result' };
  }

  const longCode = extractFaceDataFromViewData(result.view_data);
  const tags = result.tags || [];
  return {
    ok: true,
    plan_id: result.plan_id || null,
    name: result.name || null,
    pid: result.pid || null, // author pid inside plan — not number_id
    account: result.account || null,
    hostnum: result.hostnum ?? null,
    tags,
    plan_type: result.plan_type ?? result.type ?? null,
    body_type: result.body_type ?? null,
    picture_url: result.picture_url || null,
    long_code: longCode,
    long_code_length: longCode ? longCode.length : 0,
    face_hash: longCode ? hashFaceData(longCode) : null,
    like_num: result.like_num,
    heat_val: result.heat_val,
    upload_ts: result.upload_ts,
    raw_result: result,
    raw_envelope: rawEnvelope,
  };
}

/**
 * Classify plan. Inventory buckets are only face|makeup|unknown.
 * Tags beat face_* source_list (makeup tag 1002 appears inside face_slots).
 */
function classifyPlanType({ sourceList, sourceLists, tags, planType }) {
  const lists = (sourceLists && sourceLists.length
    ? sourceLists
    : sourceList
      ? [sourceList]
      : []
  ).map((s) => String(s).toLowerCase());
  const tagArr = Array.isArray(tags) ? tags.map(Number) : [];
  const hasFaceTag = tagArr.includes(PLAN_TAG_FACE);
  const hasMakeupTag = tagArr.includes(PLAN_TAG_MAKEUP);

  if (hasMakeupTag && !hasFaceTag) {
    return { type: 'makeup', type_source: 'tag:1002', type_candidates: [] };
  }
  if (hasFaceTag && !hasMakeupTag) {
    return { type: 'face', type_source: 'tag:1001', type_candidates: [] };
  }
  if (hasFaceTag && hasMakeupTag) {
    return {
      type: 'unknown',
      type_source: 'conflicting_tags',
      type_candidates: ['face', 'makeup'],
    };
  }
  if (lists.some((s) => s.includes('makeup'))) {
    return { type: 'makeup', type_source: 'source_list', type_candidates: [] };
  }
  if (lists.some((s) => s.includes('face'))) {
    return { type: 'face', type_source: 'source_list', type_candidates: [] };
  }
  if (planType != null) {
    return {
      type: 'unknown',
      type_source: `plan_type:${planType}`,
      type_candidates: [],
    };
  }
  return { type: 'unknown', type_source: 'unknown', type_candidates: [] };
}

/** Backward-compatible string type (tests / inspect script). */
function classifyPlanTypeString(args) {
  return classifyPlanType(args).type;
}

/**
 * Deduplicate plan IDs while retaining all source_lists + indexes.
 */
function collectPlanIdsDeduped(designer) {
  const map = new Map();
  for (const item of collectPlanIdsFromDesigner(designer)) {
    const id = item.planId;
    if (!map.has(id)) {
      map.set(id, {
        plan_id: id,
        source_lists: [],
        source_indexes: [],
      });
    }
    const rec = map.get(id);
    if (!rec.source_lists.includes(item.source_list)) {
      rec.source_lists.push(item.source_list);
    }
    rec.source_indexes.push({
      source: item.source_list,
      index: item.slot_index,
    });
  }
  return [...map.values()];
}

function parsePreviewObjectKey(pictureUrl) {
  if (!pictureUrl || typeof pictureUrl !== 'string') return null;
  const m = pictureUrl.match(/\/file\/([0-9a-f]{24}[A-Za-z0-9]{8}[0-9]{2})/i);
  return m ? m[1] : null;
}

function longCodeVersion(longCode) {
  if (!longCode) return null;
  const m = String(longCode).match(/^([RD])(\d+)/i);
  return m ? Number(m[2]) : null;
}

/**
 * Collect plan IDs from designer with source_list preserved.
 * Only known field names — does not invent slots.
 */
const DESIGNER_PLAN_FIELDS = [
  'face_slots',
  'face_slot',
  'face_plans',
  'face_plans_public',
  'plans_public',
  'makeup_slots',
  'makeup_slot',
  'makeup_plans',
  'makeup_plans_public',
  'sex_face_slot',
  'sex_makeup_slot',
];

function collectPlanIdsFromDesigner(designer) {
  const items = [];
  if (!designer || typeof designer !== 'object') return items;

  for (const field of DESIGNER_PLAN_FIELDS) {
    if (!(field in designer)) continue;
    const val = designer[field];
    if (Array.isArray(val)) {
      val.forEach((id, idx) => {
        if (id) items.push({ planId: String(id), source_list: field, slot_index: idx });
      });
    } else if (typeof val === 'string' && val) {
      items.push({ planId: val, source_list: field, slot_index: 0 });
    } else if (val && typeof val === 'object') {
      // dict form
      Object.entries(val).forEach(([k, v], idx) => {
        const id = typeof v === 'string' ? v : v?.plan_id || k;
        if (id) items.push({ planId: String(id), source_list: field, slot_index: idx, key: k });
      });
    }
  }
  return items;
}

function findActiveIndices(designer) {
  if (!designer || typeof designer !== 'object') {
    return {
      face_slot_idx: null,
      makeup_slot_idx: null,
      sex_face_slot_idx: null,
      sex_makeup_slot_idx: null,
      active_source: 'unknown',
    };
  }
  const keys = [
    'face_slot_idx',
    'makeup_slot_idx',
    'sex_face_slot_idx',
    'sex_makeup_slot_idx',
  ];
  const found = {};
  let any = false;
  for (const k of keys) {
    if (designer[k] != null) {
      found[k] = designer[k];
      any = true;
    } else {
      found[k] = null;
    }
  }
  found.active_source = any ? 'designer_response' : 'unknown';
  return found;
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Fetch many plans: try batch, else single with concurrency 3 + delay.
 */
async function fetchPlansDetailed(host, planIds, { concurrency = 3, delayMs = 150 } = {}) {
  const ids = [...new Set(planIds.map(String))];
  const batch = await getFacePlanDataBatch(host, ids);
  let map = new Map();

  if (batch.ok && batch.raw) {
    map = normalizePlanResults(batch.raw, ids);
    logger.info(`batch returned ${map.size}/${ids.length} plans`, {
      payloadTried: batch.payloadTried,
    });
  }

  const missing = ids.filter((id) => !map.has(id));
  if (missing.length) {
    logger.info(`fallback single fetch for ${missing.length} plans`);
    for (let i = 0; i < missing.length; i += concurrency) {
      const chunk = missing.slice(i, i + concurrency);
      const results = await Promise.all(chunk.map((id) => getFacePlanData(host, id)));
      results.forEach((raw, j) => {
        const id = chunk[j];
        if (!raw) return;
        const n = normalizePlanResults(raw, [id]);
        for (const [k, v] of n) map.set(k, v);
        // if normalize missed, still store envelope
        if (!map.has(id) && raw.result) {
          map.set(id, { planId: id, result: raw.result, envelope: raw });
        }
      });
      if (i + concurrency < missing.length) await sleep(delayMs);
    }
  }

  return { map, batch };
}

module.exports = {
  getDesignerData,
  getFacePlanData,
  getFacePlanDataBatch,
  normalizePlanResults,
  summarizePlanResult,
  classifyPlanType,
  classifyPlanTypeString,
  collectPlanIdsFromDesigner,
  collectPlanIdsDeduped,
  findActiveIndices,
  fetchPlansDetailed,
  parsePreviewObjectKey,
  longCodeVersion,
  DESIGNER_PLAN_FIELDS,
  normalizeFaceData,
  PLAN_TAG_FACE,
  PLAN_TAG_MAKEUP,
};
