'use strict';

const { nowSec } = require('../database');
const { parseShortCode, isFilePickerObjectKey } = require('../../parsers/shortCodeParser');
const { stripHashPrefix } = require('./faceRepository');

class CodeConflictError extends Error {
  constructor(code, message, details) {
    super(message);
    this.code = code;
    this.details = details;
    this.name = 'CodeConflictError';
  }
}

function regionLabel(r) {
  const x = String(r || '').toUpperCase();
  if (x === 'CHINA' || x === 'CN') return 'CN';
  if (x === 'GLOBAL' || x === 'SEA' || x === 'GL') return 'GLOBAL';
  return x;
}

/**
 * Upsert regional short code with strict validation.
 * Does NOT create codes from plan_id / preview keys — caller must pass real short code.
 */
function upsertRegionalCode(db, {
  faceId,
  faceHash,
  region,
  shortCode,
  revision,
  objectKey,
  status,
  sourceType,
  verificationHash,
}) {
  const parsed = parseShortCode(shortCode);
  if (!parsed.ok) {
    throw new CodeConflictError('invalid_short_code', 'Malformed short code', { shortCode });
  }

  const reg = regionLabel(region);
  const expectedType = reg === 'CN' ? 'china' : reg === 'GLOBAL' ? 'global' : null;
  if (expectedType && parsed.type !== expectedType) {
    throw new CodeConflictError('region_prefix_mismatch', 'Short code prefix does not match region', {
      region: reg,
      parsedType: parsed.type,
    });
  }

  const key = objectKey || parsed.objectKey;
  if (!isFilePickerObjectKey(key)) {
    throw new CodeConflictError('invalid_object_key', 'Object key failed morphology check', { key });
  }

  const st = status || 'candidate';
  if (st === 'verified') {
    const vh = stripHashPrefix(verificationHash);
    const fh = stripHashPrefix(faceHash);
    if (!vh || !fh || vh !== fh) {
      throw new CodeConflictError(
        'verification_hash_mismatch',
        'Verified regional code requires verificationHash === faceHash'
      );
    }
  }

  // Conflict: short_code already mapped to another face
  const byCode = db.prepare('SELECT * FROM regional_codes WHERE short_code = ?').get(shortCode);
  if (byCode && byCode.face_id !== faceId) {
    throw new CodeConflictError('short_code_face_conflict', 'Short code already mapped to another face', {
      shortCode,
      existingFaceId: byCode.face_id,
      newFaceId: faceId,
    });
  }

  // Conflict: object_key+region mapped to another face
  const byKey = db
    .prepare('SELECT * FROM regional_codes WHERE object_key = ? AND region = ?')
    .get(key, reg);
  if (byKey && byKey.face_id !== faceId) {
    throw new CodeConflictError('object_key_face_conflict', 'Object key already mapped to another face', {
      objectKey: key,
      region: reg,
    });
  }

  const t = nowSec();
  const existing = db
    .prepare('SELECT * FROM regional_codes WHERE face_id = ? AND region = ? AND short_code = ?')
    .get(faceId, reg, shortCode);

  if (existing) {
    // No downgrade verified → candidate
    if (existing.status === 'verified' && st !== 'verified') {
      db.prepare(
        `UPDATE regional_codes SET last_checked_at = ?, updated_at = ? WHERE id = ?`
      ).run(t, t, existing.id);
      return { id: existing.id, inserted: false, status: existing.status, skippedDowngrade: true };
    }
    db.prepare(
      `UPDATE regional_codes SET
        revision = COALESCE(?, revision),
        object_key = ?,
        status = ?,
        source_type = COALESCE(?, source_type),
        verification_hash = COALESCE(?, verification_hash),
        verified_at = CASE WHEN ? = 'verified' THEN COALESCE(verified_at, ?) ELSE verified_at END,
        last_checked_at = ?,
        updated_at = ?
       WHERE id = ?`
    ).run(
      revision ?? parsed.revision,
      key,
      st,
      sourceType || null,
      verificationHash ? stripHashPrefix(verificationHash) : null,
      st,
      t,
      t,
      t,
      existing.id
    );
    return { id: existing.id, inserted: false, status: st };
  }

  // Another verified code for same face+region: keep both rows if different short codes
  const info = db
    .prepare(
      `INSERT INTO regional_codes (
        face_id, region, short_code, revision, object_key, status, source_type,
        verification_hash, verified_at, last_checked_at, created_at, updated_at
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
    )
    .run(
      faceId,
      reg,
      shortCode,
      revision ?? parsed.revision,
      key,
      st,
      sourceType || null,
      verificationHash ? stripHashPrefix(verificationHash) : null,
      st === 'verified' ? t : null,
      t,
      t,
      t
    );

  return { id: Number(info.lastInsertRowid), inserted: true, status: st };
}

function listCodesByFaceId(db, faceId) {
  return db.prepare('SELECT * FROM regional_codes WHERE face_id = ?').all(faceId);
}

function codesByRegion(db, faceId) {
  const rows = listCodesByFaceId(db, faceId);
  const out = { CN: null, GLOBAL: null };
  for (const r of rows) {
    const entry = {
      short_code: r.short_code,
      object_key: r.object_key,
      revision: r.revision,
      status: r.status,
      source_type: r.source_type,
      verified_at: r.verified_at,
    };
    // prefer verified over candidate
    if (!out[r.region] || (r.status === 'verified' && out[r.region].status !== 'verified')) {
      out[r.region] = entry;
    }
  }
  return out;
}

module.exports = {
  upsertRegionalCode,
  listCodesByFaceId,
  codesByRegion,
  CodeConflictError,
  regionLabel,
};
