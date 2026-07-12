'use strict';

const { resolveRegion } = require('../session');
const playerService = require('./playerService');
const faceService = require('./faceService');
const { isLongFaceData } = require('../../parsers/faceDataParser');
const { hashFaceData, normalizeFaceData } = require('../../utils/hash');
const { redact } = require('../../utils/redact');
const logger = require('../../utils/logger');
const { isCacheEnabled } = require('../../storage/database');
const { ingestInventoryResponse } = require('./cacheIngestService');
const { UpstreamError } = require('../errors');

class InventoryError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function parseBool01(v, defaultValue) {
  if (v === undefined || v === null || v === '') return defaultValue;
  if (v === true || v === 1 || v === '1' || v === 'true') return true;
  if (v === false || v === 0 || v === '0' || v === 'false') return false;
  throw new InventoryError(400, 'invalid_flag', `Invalid boolean flag: ${v}`);
}

function validateInventoryQuery(q) {
  const hasId = q.id != null && String(q.id).trim() !== '';
  const hasName = q.name != null && String(q.name).trim() !== '';
  if (hasId === hasName) {
    // both or neither
    throw new InventoryError(
      400,
      'invalid_identity',
      hasId ? 'Provide only one of id or name' : "Missing 'id' or 'name'"
    );
  }
  if (!q.server) {
    throw new InventoryError(400, 'invalid_server', "Missing required 'server' (CN|SEA)");
  }
  const server = String(q.server).toUpperCase();
  if (server !== 'CN' && server !== 'SEA' && server !== 'GLOBAL') {
    throw new InventoryError(400, 'invalid_server', "server must be CN or SEA");
  }
  const type = String(q.type || 'all').toLowerCase();
  if (!['all', 'face', 'makeup', 'unknown'].includes(type)) {
    throw new InventoryError(400, 'invalid_type', 'type must be all|face|makeup|unknown');
  }
  let persist;
  if (q.persist === undefined || q.persist === null || q.persist === '') {
    persist = undefined; // default = ENABLE_FACE_CACHE
  } else {
    persist = parseBool01(q.persist, true);
  }
  return {
    id: hasId ? String(q.id).trim() : null,
    name: hasName ? String(q.name).trim() : null,
    server: server === 'GLOBAL' ? 'SEA' : server,
    type,
    includeLongCode: parseBool01(q.include_long_code, true),
    includeRaw: parseBool01(q.include_raw, false),
    includeEmptyPlans: parseBool01(q.include_empty_plans, false),
    persist,
  };
}

function buildItem({
  planMeta,
  planResult,
  classification,
  author,
  includeLongCode,
  includeRaw,
}) {
  const longCodeRaw =
    planResult && planResult.view_data != null
      ? faceService.summarizePlanResult({ result: planResult }).long_code
      : null;
  const longCode = longCodeRaw ? normalizeFaceData(longCodeRaw) : null;
  const hasFace = longCode && isLongFaceData(longCode);
  const faceHash = hasFace ? hashFaceData(longCode) : null;
  const version = hasFace ? faceService.longCodeVersion(longCode) : null;
  const previewKey = faceService.parsePreviewObjectKey(planResult?.picture_url || null);

  const item = {
    type: classification.type,
    type_source: classification.type_source,
    type_candidates: classification.type_candidates || [],
    plan_id: planMeta.plan_id,
    art_code: `ART${planMeta.plan_id}`,
    source_lists: planMeta.source_lists,
    source_indexes: planMeta.source_indexes,
    is_active: null,
    name: planResult?.name || null,
    body_type: planResult?.body_type ?? null,
    tags: planResult?.tags || [],
    plan_type: planResult?.plan_type ?? null,
    picture_url: planResult?.picture_url || null,
    preview_object_key: previewKey,
    preview_object_key_verified: !!previewKey,
    long_code: includeLongCode && hasFace ? longCode : null,
    long_code_version: version,
    face_data_length: hasFace ? longCode.length : 0,
    face_hash: faceHash ? `sha256:${faceHash}` : null,
    author: author || {
      pid: planResult?.pid || null,
      number_id: null,
      nickname: null,
      hostnum: planResult?.hostnum ?? null,
      account: planResult?.account || null,
      resolved: false,
      source: planResult?.pid ? 'face_plan_result' : 'none',
    },
    short_codes: { china: null, global: null },
    short_code_status: 'unavailable',
    short_code_source: null,
    metadata_source: 'face_plan_result',
    raw: null,
    _has_face_data: !!hasFace,
  };

  if (includeRaw && planResult) {
    item.raw = redact(planResult);
  }
  return item;
}

/**
 * Core inventory pipeline.
 */
async function inspectPlayerInventory({
  id,
  name,
  region,
  includeRaw = false,
  includeLongCode = true,
  includeEmptyPlans = false,
  type = 'all',
  persist = undefined,
}) {
  const stats = {
    upstreamRequests: 0,
    authorBatches: 0,
    startedAt: Date.now(),
  };

  const regionCfg = typeof region === 'string' ? resolveRegion(region) : region;
  const host = regionCfg.apiHost;
  const serverId = regionCfg.id === 'CN' ? 'CN' : 'SEA';

  // 1. find people — only 404 when upstream succeeds with empty result
  let rawPeople;
  try {
    if (id) {
      rawPeople = await playerService.findPeopleByNumberId(host, id);
    } else {
      rawPeople = await playerService.findPeopleByNickname(host, name);
    }
  } catch (e) {
    if (e instanceof UpstreamError) throw e;
    throw e;
  }
  stats.upstreamRequests += 1;

  const player = playerService.formatBasicPlayer(rawPeople);
  if (!player || !player.pid) {
    throw new InventoryError(404, 'PLAYER_NOT_FOUND', 'Player not found');
  }
  const hostnum = player.server_hostnum || player.hostnum;

  // 2. designer
  let designer = null;
  try {
    designer = await faceService.getDesignerData(host, player.pid, hostnum);
  } catch (e) {
    if (e instanceof UpstreamError) throw e;
    throw e;
  }
  stats.upstreamRequests += 1;

  const planMetas = designer ? faceService.collectPlanIdsDeduped(designer) : [];
  const planIds = planMetas.map((p) => p.plan_id);

  // 3. batch plans
  let planMap = new Map();
  let batchUsed = false;
  if (planIds.length) {
    const { map, batch } = await faceService.fetchPlansDetailed(host, planIds, {
      concurrency: 3,
      delayMs: 150,
    });
    planMap = map;
    batchUsed = !!(batch && batch.ok);
    stats.upstreamRequests += 1; // at least one batch; fallback singles not counted precisely
    if (batch && batch.ok === false) {
      // fallback happened inside fetchPlansDetailed — approximate
      stats.upstreamRequests += Math.ceil(planIds.length / 3);
    }
  }

  // 4. build items + collect authors
  const authorPairs = [];
  const itemsAll = [];

  for (const meta of planMetas) {
    const entry = planMap.get(meta.plan_id);
    const planResult = entry?.result || null;
    const summary = planResult
      ? faceService.summarizePlanResult({ result: planResult })
      : { ok: false, tags: [], plan_type: null, pid: null, hostnum: null, account: null };

    const classification = faceService.classifyPlanType({
      sourceLists: meta.source_lists,
      tags: summary.tags || planResult?.tags || [],
      planType: summary.plan_type ?? planResult?.plan_type,
    });

    if (summary.pid || planResult?.pid) {
      authorPairs.push({
        pid: summary.pid || planResult.pid,
        hostnum: summary.hostnum ?? planResult?.hostnum ?? hostnum,
        account: summary.account || planResult?.account || null,
      });
    }

    itemsAll.push({ meta, planResult, classification, summary });
  }

  // 5. batch authors
  const { authors, batchesUsed, uniqueCount } = await playerService.resolveAuthorsBatch(
    host,
    authorPairs,
    { chunkSize: 20, concurrency: 2 }
  );
  stats.authorBatches = batchesUsed;
  stats.upstreamRequests += batchesUsed;

  // 6. assemble
  const faces = [];
  const makeups = [];
  const unknown = [];
  const emptyPlans = [];
  const hashToPlans = new Map();
  let authorsResolved = 0;
  let authorsUnresolved = 0;
  let plansWithFaceData = 0;

  for (const row of itemsAll) {
    const pid = row.summary.pid || row.planResult?.pid || null;
    const ahn = row.summary.hostnum ?? row.planResult?.hostnum ?? hostnum;
    const akey = pid ? `${pid}@${ahn}` : null;
    let author = akey ? authors.get(akey) : null;
    if (!author && pid) {
      // try any hostnum match
      for (const [k, v] of authors) {
        if (k.startsWith(`${pid}@`)) {
          author = v;
          break;
        }
      }
    }
    if (author?.resolved) authorsResolved += 1;
    else if (pid) authorsUnresolved += 1;

    const item = buildItem({
      planMeta: row.meta,
      planResult: row.planResult,
      classification: row.classification,
      author: author
        ? {
            pid: author.pid,
            number_id: author.number_id,
            nickname: author.nickname,
            hostnum: author.hostnum,
            account: author.account,
            resolved: author.resolved,
            source: author.source,
          }
        : {
            pid,
            number_id: null,
            nickname: null,
            hostnum: ahn,
            account: row.planResult?.account || null,
            resolved: false,
            source: pid ? 'face_plan_result' : 'none',
          },
      includeLongCode,
      includeRaw,
    });

    if (item._has_face_data) {
      plansWithFaceData += 1;
      if (item.face_hash) {
        if (!hashToPlans.has(item.face_hash)) hashToPlans.set(item.face_hash, []);
        hashToPlans.get(item.face_hash).push(item.plan_id);
      }
      delete item._has_face_data;
      if (item.type === 'face') faces.push(item);
      else if (item.type === 'makeup') makeups.push(item);
      else unknown.push(item);
    } else {
      delete item._has_face_data;
      if (includeEmptyPlans) {
        emptyPlans.push({
          ...item,
          long_code: null,
          face_hash: null,
          face_data_length: 0,
        });
      }
    }
  }

  const filterType = type || 'all';
  const pick = (list, t) => (filterType === 'all' || filterType === t ? list : []);

  const duplicateFaceHashes = [...hashToPlans.entries()]
    .filter(([, ids]) => ids.length > 1)
    .map(([face_hash, plan_ids]) => ({ face_hash, plan_ids }));

  const elapsedMs = Date.now() - stats.startedAt;
  logger.info('face_inventory done', {
    player_pid: player.pid,
    discoveredPlans: planMetas.length,
    plansWithFaceData,
    faceCount: faces.length,
    makeupCount: makeups.length,
    unknownCount: unknown.length,
    authorBatches: stats.authorBatches,
    elapsedMs,
  });

  const payload = {
    success: true,
    player: {
      server: serverId,
      nickname: player.nickname,
      number_id: player.number_id,
      pid: player.pid,
      hostnum,
    },
    current: {
      face: null,
      makeup: null,
      active_source: 'unknown',
    },
    inventory: {
      faces: pick(faces, 'face'),
      makeups: pick(makeups, 'makeup'),
      unknown: pick(unknown, 'unknown'),
      empty_plans: includeEmptyPlans ? emptyPlans : [],
    },
    diagnostics: {
      discoveredPlans: planMetas.length,
      uniquePlans: planMetas.length,
      plansWithFaceData,
      plansWithoutFaceData: planMetas.length - plansWithFaceData,
      faceCount: faces.length,
      makeupCount: makeups.length,
      unknownCount: unknown.length,
      authorsRequested: uniqueCount,
      authorsResolved,
      authorsUnresolved,
      batchPlanFetchUsed: batchUsed,
      activeSlotKnown: false,
      shortCodesAvailable: 0,
      authorLookupBatches: stats.authorBatches,
      upstreamRequestsApprox: stats.upstreamRequests,
      elapsedMs,
      duplicateFaceHashes,
    },
  };

  // Optional cache persist (default on when ENABLE_FACE_CACHE=true)
  const shouldPersist =
    persist === undefined ? isCacheEnabled() : !!persist;
  if (shouldPersist) {
    // Ingest needs long_code — if includeLongCode was false, rebuild from internal lists
    // faces/makeups/unknown already computed with long_code based on includeLongCode flag.
    // Re-run build with long codes for cache if needed.
    let ingestPayload = payload;
    if (!includeLongCode) {
      // re-fetch items with long codes for storage only (from already-fetched planMap)
      // Simpler: call ingest on a synthetic payload built from faces/makeups before long_code stripped.
      // Those arrays already lost long_code — re-build quickly from planMap.
      ingestPayload = rebuildPayloadForIngest({
        player: payload.player,
        planMetas,
        planMap,
        faces,
        makeups,
        unknown,
      });
    }
    payload.cache = ingestInventoryResponse(ingestPayload, { includeRaw });
  } else {
    payload.cache = {
      enabled: isCacheEnabled(),
      persisted: false,
      facesInserted: 0,
      facesUpdated: 0,
      sourcesInserted: 0,
      sourcesUpdated: 0,
      aliasesInserted: 0,
      error: isCacheEnabled() ? 'persist_disabled' : 'cache_disabled',
    };
  }

  return payload;
}

/**
 * When API omitted long_code, rebuild minimal inventory items with long_code for DB ingest.
 */
function rebuildPayloadForIngest({ player, planMetas, planMap, faces, makeups, unknown }) {
  const byPlan = new Map();
  for (const item of [...faces, ...makeups, ...unknown]) {
    byPlan.set(item.plan_id, item);
  }
  const restored = [];
  for (const meta of planMetas) {
    const base = byPlan.get(meta.plan_id);
    if (!base || !base.face_hash) continue;
    const entry = planMap.get(meta.plan_id);
    const planResult = entry?.result;
    let longCode = null;
    if (planResult?.view_data) {
      const summary = faceService.summarizePlanResult({ result: planResult });
      longCode = summary.long_code;
    }
    restored.push({ ...base, long_code: longCode });
  }
  return {
    player,
    inventory: {
      faces: restored.filter((i) => i.type === 'face'),
      makeups: restored.filter((i) => i.type === 'makeup'),
      unknown: restored.filter((i) => i.type === 'unknown'),
    },
  };
}

module.exports = {
  inspectPlayerInventory,
  validateInventoryQuery,
  InventoryError,
  parseBool01,
  buildItem,
};
