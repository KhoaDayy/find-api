'use strict';

const { nowSec } = require('../database');

function upsertAlias(db, { faceId, aliasType, aliasValue, region = null, sourceId = null }) {
  if (!aliasValue) return { id: null, inserted: false };
  const t = nowSec();
  const existing = db
    .prepare(
      `SELECT * FROM aliases
       WHERE alias_type = ? AND alias_value = ? AND IFNULL(region, '') = IFNULL(?, '')`
    )
    .get(aliasType, String(aliasValue), region);

  if (existing) {
    if (existing.face_id !== faceId) {
      // conflict — do not rebind silently
      const err = new Error('alias_face_conflict');
      err.code = 'alias_face_conflict';
      err.details = { aliasType, aliasValue, existingFaceId: existing.face_id, faceId };
      throw err;
    }
    db.prepare(`UPDATE aliases SET last_seen_at = ?, source_id = COALESCE(?, source_id) WHERE id = ?`).run(
      t,
      sourceId,
      existing.id
    );
    return { id: existing.id, inserted: false };
  }

  const info = db
    .prepare(
      `INSERT INTO aliases (face_id, alias_type, alias_value, region, source_id, created_at, last_seen_at)
       VALUES (?,?,?,?,?,?,?)`
    )
    .run(faceId, aliasType, String(aliasValue), region, sourceId, t, t);

  return { id: Number(info.lastInsertRowid), inserted: true };
}

function findByAlias(db, aliasType, aliasValue, region = null) {
  if (region != null) {
    return (
      db
        .prepare(
          `SELECT a.*, f.face_hash, f.face_data_length, f.face_data_version, f.face_data
           FROM aliases a JOIN faces f ON f.id = a.face_id
           WHERE a.alias_type = ? AND a.alias_value = ? AND IFNULL(a.region, '') = IFNULL(?, '')`
        )
        .get(aliasType, String(aliasValue), region) || null
    );
  }
  return (
    db
      .prepare(
        `SELECT a.*, f.face_hash, f.face_data_length, f.face_data_version, f.face_data
         FROM aliases a JOIN faces f ON f.id = a.face_id
         WHERE a.alias_type = ? AND a.alias_value = ?
         ORDER BY a.last_seen_at DESC LIMIT 1`
      )
      .get(aliasType, String(aliasValue)) || null
  );
}

function listAliasesByFaceId(db, faceId) {
  return db.prepare('SELECT * FROM aliases WHERE face_id = ?').all(faceId);
}

module.exports = {
  upsertAlias,
  findByAlias,
  listAliasesByFaceId,
};
