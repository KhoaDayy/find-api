'use strict';

const { parseShortCode } = require('../../parsers/shortCodeParser');
const { isLongFaceData, extractFaceDataFromViewData } = require('../../parsers/faceDataParser');
const { normalizeFaceData, hashFaceData } = require('../../utils/hash');
const filePickerDownload = require('./filePickerDownloadService');
const filePickerMeta = require('./filePickerMetaService');
const faceService = require('./faceService');
const playerService = require('./playerService');
const { regionIdFromShortPrefix, REGIONS } = require('../../config/regions');
const { UpstreamError } = require('../errors');
const { getDb, isCacheEnabled, storeLongCode, nowSec } = require('../../storage/database');
const faceRepo = require('../../storage/repositories/faceRepository');
const sourceRepo = require('../../storage/repositories/sourceRepository');
const codeRepo = require('../../storage/repositories/codeRepository');
const aliasRepo = require('../../storage/repositories/aliasRepository');
const { stripHashPrefix } = require('../../storage/repositories/faceRepository');
const { redact } = require('../../utils/redact');
const logger = require('../../utils/logger');

/**
 * Extract Face Data from CDN body (plain or JSON wrappers).
 */
function extractFaceFromBody(buf, contentType) {
  const ct = String(contentType || '').toLowerCase();
  if (ct.includes('html') || ct.includes('xml') || ct.includes('image/') || ct.includes('video/')) {
    throw new UpstreamError('FILEPICKER_INVALID_BODY', `Unsupported content-type: ${ct}`, {
      retryable: false,
    });
  }

  // Reject obvious binary (high NUL ratio / non-text)
  const sample = buf.slice(0, Math.min(buf.length, 64));
  let nul = 0;
  for (const b of sample) if (b === 0) nul += 1;
  if (nul > 2) {
    throw new UpstreamError('FILEPICKER_INVALID_BODY', 'Binary content rejected', {
      retryable: false,
    });
  }

  let text;
  try {
    text = buf.toString('utf8');
  } catch {
    throw new UpstreamError('FILEPICKER_INVALID_BODY', 'Not UTF-8 text', { retryable: false });
  }

  const trimmed = text.trim();
  if (!trimmed) {
    throw new UpstreamError('FILEPICKER_INVALID_BODY', 'Empty body', { retryable: false });
  }
  if (trimmed.startsWith('<!DOCTYPE') || trimmed.startsWith('<html') || trimmed.startsWith('<?xml')) {
    throw new UpstreamError('FILEPICKER_INVALID_BODY', 'HTML/XML body rejected', {
      retryable: false,
    });
  }

  // JSON first when body looks like an object/array (face_data may contain |*| inside strings)
  let json = null;
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      json = JSON.parse(trimmed);
    } catch {
      throw new UpstreamError('FILEPICKER_INVALID_BODY', 'Invalid JSON body', {
        retryable: false,
      });
    }
  }

  // Plain face data (must start with version prefix — do not use bare |*| match)
  if (!json && /^[RD]67/i.test(trimmed)) {
    if (!isLongFaceData(trimmed)) {
      throw new UpstreamError('FACE_DATA_INVALID', 'Plain body is not valid long face data', {
        retryable: false,
      });
    }
    return {
      longCode: normalizeFaceData(trimmed),
      contentKind: 'plain_face_data',
      wrapper: null,
    };
  }

  if (!json) {
    throw new UpstreamError('FILEPICKER_INVALID_BODY', 'Body is neither face data nor JSON', {
      retryable: false,
    });
  }

  const candidates = [];
  const push = (v, path) => {
    if (typeof v === 'string' && v) candidates.push({ v, path });
  };

  if (json && typeof json === 'object') {
    push(json.face_data, 'face_data');
    if (json.view_data) {
      const extracted = extractFaceDataFromViewData(json.view_data);
      if (extracted) candidates.push({ v: extracted, path: 'view_data.face_data' });
      else push(typeof json.view_data === 'string' ? json.view_data : null, 'view_data');
    }
    if (json.data) {
      push(json.data.face_data, 'data.face_data');
      if (json.data.view_data) {
        const extracted = extractFaceDataFromViewData(json.data.view_data);
        if (extracted) candidates.push({ v: extracted, path: 'data.view_data.face_data' });
      }
    }
    if (json.plan_info) {
      if (json.plan_info.view_data) {
        const extracted = extractFaceDataFromViewData(json.plan_info.view_data);
        if (extracted) candidates.push({ v: extracted, path: 'plan_info.view_data.face_data' });
      }
      push(json.plan_info.face_data, 'plan_info.face_data');
    }
    if (json.result) {
      push(json.result.face_data, 'result.face_data');
      if (json.result.view_data) {
        const extracted = extractFaceDataFromViewData(json.result.view_data);
        if (extracted) candidates.push({ v: extracted, path: 'result.view_data.face_data' });
      }
    }
  }

  for (const c of candidates) {
    if (c.v && isLongFaceData(c.v)) {
      return {
        longCode: normalizeFaceData(c.v),
        contentKind: 'json_face_data',
        faceDataFieldPath: c.path.startsWith('$') ? c.path : `$.${c.path}`,
        wrapper: { path: c.path, keys: Object.keys(json) },
        rawJson: json,
      };
    }
  }

  throw new UpstreamError('FACE_DATA_INVALID', 'JSON wrapper has no valid face_data', {
    retryable: false,
  });
}

/**
 * Correlate wrapper identity with community plan + player profile (read-only).
 */
async function enrichWrapperMetadata({ region, faceHash, rawJson, faceDataFieldPath, contentKind }) {
  const identity = rawJson ? filePickerMeta.extractWrapperIdentity(rawJson) : {};
  const sanitized = rawJson
    ? filePickerMeta.sanitizeFaceDataDeep(rawJson)
    : null;

  const meta = {
    wrapper_type: contentKind,
    face_data_field_path: faceDataFieldPath || (rawJson ? filePickerMeta.findFaceDataFieldPath(rawJson) : null),
    related_plan_id: identity.plan_id || null,
    related_art_code: identity.plan_id ? `ART${identity.plan_id}` : null,
    related_plan_hash_match: null,
    owner: null,
    metadata_source: contentKind === 'json_face_data' ? 'filepicker_wrapper' : 'filepicker_plain',
    sanitized_metadata: sanitized,
    identity,
  };

  // Prefer game API region from hostnum (CN shard < 10400), not short-code CDN region.
  // Global FilePicker wrappers often embed CN pid/hostnum.
  const ownerHostnum = identity.hostnum != null ? Number(identity.hostnum) : null;
  const ownerIsCn = ownerHostnum != null ? ownerHostnum < 10400 : region === 'CN';
  const apiHost = ownerIsCn ? REGIONS.CN.apiHost : REGIONS.SEA.apiHost;
  const planApiHost = region === 'CN' ? REGIONS.CN.apiHost : apiHost;

  // Community plan correlation — only alias if hash matches
  if (identity.plan_id && filePickerMeta.looksLikeCommunityPlanId(identity.plan_id)) {
    try {
      const env = await faceService.getFacePlanData(planApiHost, identity.plan_id);
      const summary = faceService.summarizePlanResult(env);
      if (summary.ok && summary.face_hash) {
        meta.related_plan_hash_match = summary.face_hash === faceHash;
        if (meta.related_plan_hash_match) {
          meta.metadata_source =
            region === 'GLOBAL'
              ? 'global_filepicker_wrapper.community_plan_match'
              : 'filepicker_wrapper.community_plan_match';
          // Prefer community owner fields when hash matches
          if (summary.pid) identity.pid = identity.pid || summary.pid;
          if (summary.hostnum != null) identity.hostnum = identity.hostnum ?? summary.hostnum;
          if (summary.name) identity.name = identity.name || summary.name;
        }
      } else {
        meta.related_plan_hash_match = false;
      }
    } catch (e) {
      logger.warn('plan correlate failed', { code: e.code || e.message });
      meta.related_plan_hash_match = null;
    }
  }

  // Resolve pid → number_id (role is metadata owner, NOT original_author)
  if (identity.pid && identity.hostnum != null) {
    try {
      const prof = await playerService.resolveAuthorProfile(
        apiHost,
        identity.pid,
        Number(identity.hostnum)
      );
      meta.owner = {
        pid: prof.pid,
        number_id: prof.number_id,
        nickname: prof.nickname,
        hostnum: prof.hostnum,
        account: identity.account || null,
        role: 'filepicker_metadata_owner',
        resolved: !!prof.resolved,
      };
      if (region === 'GLOBAL' && (ownerIsCn || meta.owner.resolved)) {
        // Global short-code object embeds CN player identity
        meta.metadata_source = 'global_filepicker_wrapper.cn_source_metadata';
      } else if (region === 'CN' && meta.owner.resolved) {
        meta.metadata_source = 'filepicker_wrapper.owner_pid';
      }
    } catch (e) {
      logger.warn('owner resolve failed', { code: e.code || e.message });
      meta.owner = {
        pid: identity.pid,
        number_id: null,
        nickname: null,
        hostnum: identity.hostnum,
        account: identity.account || null,
        role: 'filepicker_metadata_owner',
        resolved: false,
      };
      if (region === 'GLOBAL' && ownerIsCn) {
        meta.metadata_source = 'global_filepicker_wrapper.cn_source_metadata';
      }
    }
  }

  return meta;
}

function persistResolved({
  faceHash,
  longCode,
  region,
  shortCode,
  revision,
  objectKey,
  enrichment,
}) {
  const stats = {
    persisted: false,
    face_inserted: false,
    source_inserted: false,
    code_inserted: false,
    alias_inserted: false,
    plan_alias_inserted: false,
    error: null,
  };
  if (!isCacheEnabled()) {
    stats.error = 'cache_disabled';
    return stats;
  }
  let db;
  try {
    db = getDb();
    if (!db) {
      stats.error = 'db_unavailable';
      return stats;
    }
  } catch (e) {
    stats.error = 'db_open_failed';
    return stats;
  }

  const hash = stripHashPrefix(faceHash);
  const identity = enrichment?.identity || {};
  try {
    db.exec('BEGIN IMMEDIATE');
    const up = faceRepo.upsertFace(db, {
      faceData: longCode,
      faceHash: hash,
      storeData: storeLongCode(),
    });
    stats.face_inserted = up.inserted;
    const faceId = up.id;

    const src = sourceRepo.upsertSource(db, faceId, {
      source_type: 'short_code',
      region,
      plan_id: enrichment?.related_plan_hash_match ? identity.plan_id || null : null,
      inventory_player_pid: null,
      plan_owner_pid: enrichment?.owner?.pid || identity.pid || null,
      plan_owner_number_id: enrichment?.owner?.number_id || null,
      plan_owner_nickname: enrichment?.owner?.nickname || identity.name || null,
      plan_owner_hostnum: enrichment?.owner?.hostnum ?? identity.hostnum ?? null,
      plan_owner_account: identity.account || null,
      plan_type: identity.plan_type,
      body_type: identity.body_type,
      tags: identity.tags,
      picture_url: identity.picture_url,
      metadata_source: enrichment?.metadata_source || 'filepicker_resolve',
      short_code: shortCode,
      object_key: objectKey,
      wrapper_type: enrichment?.wrapper_type || null,
      wrapper_schema_version: 1,
      face_data_field_path: enrichment?.face_data_field_path || null,
      related_plan_id: identity.plan_id || null,
      related_pid: identity.pid || null,
      related_hostnum: identity.hostnum ?? null,
      related_plan_hash_match: enrichment?.related_plan_hash_match,
      sanitized_metadata: enrichment?.sanitized_metadata || null,
      // never store full long face inside raw metadata
      raw_metadata: enrichment?.sanitized_metadata
        ? { wrapper_type: enrichment.wrapper_type, face_data_field_path: enrichment.face_data_field_path }
        : null,
    });
    stats.source_inserted = src.inserted;

    const aliasType = region === 'CN' ? 'china_short' : 'global_short';
    const ar = aliasRepo.upsertAlias(db, {
      faceId,
      aliasType,
      aliasValue: shortCode,
      region,
      sourceId: src.id,
    });
    stats.alias_inserted = ar.inserted;

    aliasRepo.upsertAlias(db, { faceId, aliasType: 'face_hash', aliasValue: hash });
    aliasRepo.upsertAlias(db, {
      faceId,
      aliasType: 'face_hash',
      aliasValue: `sha256:${hash}`,
    });

    // Only alias plan_id/ART when community hash matches
    if (enrichment?.related_plan_hash_match && identity.plan_id) {
      const p = aliasRepo.upsertAlias(db, {
        faceId,
        aliasType: 'plan_id',
        aliasValue: identity.plan_id,
        region,
        sourceId: src.id,
      });
      const a = aliasRepo.upsertAlias(db, {
        faceId,
        aliasType: 'art_code',
        aliasValue: `ART${identity.plan_id}`,
        region,
        sourceId: src.id,
      });
      stats.plan_alias_inserted = p.inserted || a.inserted;
    }

    const cr = codeRepo.upsertRegionalCode(db, {
      faceId,
      faceHash: hash,
      region,
      shortCode,
      revision,
      objectKey,
      status: 'verified',
      sourceType: 'resolved_input',
      verificationHash: hash,
    });
    stats.code_inserted = cr.inserted;

    db.exec('COMMIT');
    stats.persisted = true;
  } catch (e) {
    try {
      db.exec('ROLLBACK');
    } catch {
      /* ignore */
    }
    if (e.code === 'short_code_face_conflict' || e.name === 'CodeConflictError' || e.code === 'alias_face_conflict') {
      stats.error = 'CACHE_CONFLICT';
      const err = new UpstreamError('CACHE_CONFLICT', e.message || 'Cache conflict', {
        retryable: false,
      });
      err.cacheStats = stats;
      throw err;
    }
    if (e.code === 'hash_mismatch' || e.code === 'inconsistent_payload') {
      stats.error = e.code;
      const err = new UpstreamError('CACHE_CONFLICT', e.message, { retryable: false });
      err.cacheStats = stats;
      throw err;
    }
    stats.error = 'CACHE_WRITE_FAILED';
    logger.error('short-code persist failed', { err: e.message });
  }
  return stats;
}

/**
 * Resolve FilePicker short code → long face (read-only download + optional cache).
 */
async function resolveShortCode({ input, includeLongCode = true, persist = true }) {
  const parsed = parseShortCode(input);
  if (!parsed.ok) {
    throw new UpstreamError('INVALID_SHORT_CODE', parsed.error || 'Invalid short code', {
      retryable: false,
    });
  }

  const region = regionIdFromShortPrefix(parsed.prefix);
  if (!region) {
    throw new UpstreamError('UNSUPPORTED_REGION', 'Unknown short-code prefix', {
      retryable: false,
    });
  }

  const dl = await filePickerDownload.downloadFaceObject({
    prefix: parsed.prefix,
    objectKey: parsed.objectKey,
  });

  const extracted = extractFaceFromBody(dl.body, dl.contentType);
  const longCode = extracted.longCode;
  const faceHash = hashFaceData(longCode);
  const versionMatch = longCode.match(/^[RD](\d+)/i);
  const faceDataVersion = versionMatch ? Number(versionMatch[1]) : null;

  const enrichment = await enrichWrapperMetadata({
    region,
    faceHash,
    rawJson: extracted.rawJson || null,
    faceDataFieldPath: extracted.faceDataFieldPath || extracted.wrapper?.path || null,
    contentKind: extracted.contentKind,
  });

  let cache = {
    persisted: false,
    face_inserted: false,
    source_inserted: false,
    code_inserted: false,
    alias_inserted: false,
    error: persist ? null : 'persist_disabled',
  };

  if (persist) {
    try {
      cache = persistResolved({
        faceHash,
        longCode,
        region,
        shortCode: parsed.raw,
        revision: parsed.revision,
        objectKey: parsed.objectKey,
        enrichment,
      });
    } catch (e) {
      if (e instanceof UpstreamError && e.code === 'CACHE_CONFLICT') {
        throw e;
      }
      cache = e.cacheStats || {
        persisted: false,
        error: 'CACHE_WRITE_FAILED',
      };
    }
  }

  let preferred_source = null;
  let preferred_source_reason = enrichment.metadata_source || 'short_code_resolve';
  let regional_codes = {
    CN:
      region === 'CN'
        ? { short_code: parsed.raw, status: 'verified', verified_at: nowSec() }
        : null,
    GLOBAL:
      region === 'GLOBAL'
        ? { short_code: parsed.raw, status: 'verified', verified_at: nowSec() }
        : null,
  };

  if (isCacheEnabled()) {
    try {
      const db = getDb();
      if (db) {
        const face = faceRepo.getFaceByHash(db, faceHash);
        if (face) {
          const sources = sourceRepo.listSourcesByFaceId(db, face.id);
          const pref = sourceRepo.selectPreferredSource(sources);
          if (pref.source) {
            preferred_source = {
              id: pref.source.id,
              source_type: pref.source.source_type,
              region: pref.source.region,
              plan_id: pref.source.plan_id || pref.source.related_plan_id,
              plan_owner_pid: pref.source.plan_owner_pid || pref.source.related_pid,
              plan_owner_number_id: pref.source.plan_owner_number_id,
              plan_owner_nickname: pref.source.plan_owner_nickname,
              metadata_source: pref.source.metadata_source,
              short_code: pref.source.short_code || null,
            };
            preferred_source_reason = pref.preferred_source_reason;
          }
          regional_codes = codeRepo.codesByRegion(db, face.id);
        }
      }
    } catch {
      /* ignore */
    }
  }

  logger.info('short_code_resolved', {
    region,
    face_data_length: longCode.length,
    face_hash: faceHash.slice(0, 12),
    host: dl.host,
    contentKind: extracted.contentKind,
    metadata_source: enrichment.metadata_source,
  });

  return {
    success: true,
    input: {
      type: parsed.type === 'china' ? 'china_short' : 'global_short',
      region,
      revision: parsed.revision,
      object_key: parsed.objectKey,
    },
    face: {
      face_hash: `sha256:${faceHash}`,
      face_data_version: faceDataVersion,
      face_data_length: longCode.length,
      long_code: includeLongCode ? longCode : null,
    },
    regional_codes,
    metadata: {
      wrapper_type: enrichment.wrapper_type,
      face_data_field_path: enrichment.face_data_field_path,
      related_plan_id: enrichment.related_plan_id,
      related_art_code: enrichment.related_art_code,
      related_plan_hash_match: enrichment.related_plan_hash_match,
      owner: enrichment.owner,
      preferred_source,
      preferred_source_reason,
      metadata_source: enrichment.metadata_source,
      // never original_author without explicit evidence
      original_author: null,
    },
    cache,
    download: {
      host_used: dl.host,
      content_type: extracted.contentKind,
      fallback_count: dl.fallbackCount || 0,
    },
  };
}

module.exports = {
  resolveShortCode,
  extractFaceFromBody,
  enrichWrapperMetadata,
  sanitizeFaceDataDeep: filePickerMeta.sanitizeFaceDataDeep,
};
