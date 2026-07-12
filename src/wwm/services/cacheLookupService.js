'use strict';

const { getDb, isCacheEnabled, storeLongCode } = require('../../storage/database');
const faceRepo = require('../../storage/repositories/faceRepository');
const sourceRepo = require('../../storage/repositories/sourceRepository');
const codeRepo = require('../../storage/repositories/codeRepository');
const aliasRepo = require('../../storage/repositories/aliasRepository');
const { parseInput, parseShortCode } = require('../../parsers/shortCodeParser');
const { stripHashPrefix } = require('../../storage/repositories/faceRepository');
const { redact } = require('../../utils/redact');

function formatFaceRecord(db, face, { includeLongCode = true, includeRaw = false } = {}) {
  if (!face) return null;
  const sources = sourceRepo.listSourcesByFaceId(db, face.id).map((s) => {
    const out = { ...s };
    if (!includeRaw) delete out.raw_metadata_json;
    else if (out.raw_metadata_json) {
      try {
        out.raw_metadata = redact(JSON.parse(out.raw_metadata_json));
      } catch {
        out.raw_metadata = null;
      }
      delete out.raw_metadata_json;
    }
    return out;
  });
  const preferred = sourceRepo.selectPreferredSource(sources);
  const aliases = aliasRepo.listAliasesByFaceId(db, face.id);
  const regional = codeRepo.codesByRegion(db, face.id);

  let faceData = null;
  if (includeLongCode && storeLongCode() && face.face_data && face.face_data !== '[omitted]') {
    faceData = face.face_data;
  }

  return {
    face_hash: `sha256:${face.face_hash}`,
    face_data_length: face.face_data_length,
    face_data_version: face.face_data_version,
    face_data: faceData,
    regional_codes: regional,
    sources,
    aliases,
    preferred_source: preferred.source
      ? {
          id: preferred.source.id,
          source_type: preferred.source.source_type,
          region: preferred.source.region,
          plan_id: preferred.source.plan_id,
          plan_owner_pid: preferred.source.plan_owner_pid,
          plan_owner_number_id: preferred.source.plan_owner_number_id,
          plan_owner_nickname: preferred.source.plan_owner_nickname,
          metadata_source: preferred.source.metadata_source,
        }
      : null,
    preferred_source_reason: preferred.preferred_source_reason,
    // explicit: never original_author without proof
    original_author: null,
  };
}

function getByFaceHash(faceHash, opts = {}) {
  if (!isCacheEnabled()) return { ok: false, error: 'cache_disabled' };
  const db = getDb();
  if (!db) return { ok: false, error: 'db_unavailable' };
  const face = faceRepo.getFaceByHash(db, faceHash);
  if (!face) return { ok: false, error: 'not_found' };
  return { ok: true, data: formatFaceRecord(db, face, opts) };
}

/**
 * Local-only alias lookup (no network).
 */
function lookupByAlias(alias, opts = {}) {
  if (!isCacheEnabled()) return { ok: false, error: 'cache_disabled' };
  const db = getDb();
  if (!db) return { ok: false, error: 'db_unavailable' };

  const raw = String(alias || '').trim();
  if (!raw) return { ok: false, error: 'empty_alias' };

  // hash forms
  if (/^(sha256:)?[a-f0-9]{64}$/i.test(raw)) {
    return getByFaceHash(stripHashPrefix(raw), opts);
  }

  // short codes
  if (/^(yysls|wwm)_facedata_/i.test(raw)) {
    const sc = parseShortCode(raw);
    if (sc.ok) {
      const row = aliasRepo.findByAlias(
        db,
        sc.type === 'china' ? 'china_short' : 'global_short',
        sc.raw
      );
      if (row) {
        const face = faceRepo.getFaceById(db, row.face_id);
        return { ok: true, data: formatFaceRecord(db, face, opts) };
      }
      // also try by short_code table
      const codeRow = db.prepare('SELECT * FROM regional_codes WHERE short_code = ?').get(sc.raw);
      if (codeRow) {
        const face = faceRepo.getFaceById(db, codeRow.face_id);
        return { ok: true, data: formatFaceRecord(db, face, opts) };
      }
      return { ok: false, error: 'not_found' };
    }
  }

  const parsed = parseInput(raw);

  // ART...
  if (parsed.ok && (parsed.type === 'art' || parsed.inputType === 'art')) {
    const row = aliasRepo.findByAlias(db, 'art_code', parsed.artCode || raw);
    if (row) {
      const face = faceRepo.getFaceById(db, row.face_id);
      return { ok: true, data: formatFaceRecord(db, face, opts) };
    }
  }

  // Direct table lookups (do not depend on plan_id length heuristics)
  const candidates = [];
  if (parsed.ok && parsed.planId) candidates.push(parsed.planId);
  candidates.push(raw);
  if (raw.startsWith('ART') || raw.startsWith('art')) candidates.push(raw.slice(3));

  for (const planId of [...new Set(candidates.filter(Boolean))]) {
    const row = aliasRepo.findByAlias(db, 'plan_id', planId);
    if (row) {
      const face = faceRepo.getFaceById(db, row.face_id);
      return { ok: true, data: formatFaceRecord(db, face, opts) };
    }
    const art = aliasRepo.findByAlias(db, 'art_code', `ART${planId}`);
    if (art) {
      const face = faceRepo.getFaceById(db, art.face_id);
      return { ok: true, data: formatFaceRecord(db, face, opts) };
    }
  }

  const artExact = aliasRepo.findByAlias(db, 'art_code', raw);
  if (artExact) {
    const face = faceRepo.getFaceById(db, artExact.face_id);
    return { ok: true, data: formatFaceRecord(db, face, opts) };
  }

  return { ok: false, error: 'not_found' };
}

module.exports = {
  getByFaceHash,
  lookupByAlias,
  formatFaceRecord,
};
