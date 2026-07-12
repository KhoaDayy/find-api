'use strict';

const crypto = require('crypto');
const { nowSec } = require('../database');
const { normalizeFaceData, hashFaceData } = require('../../utils/hash');

class IntegrityError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
    this.name = 'IntegrityError';
  }
}

function stripHashPrefix(h) {
  if (!h) return h;
  return String(h).replace(/^sha256:/i, '').toLowerCase();
}

function upsertFace(db, { faceData, faceHash, storeData = true }) {
  const normalized = normalizeFaceData(faceData);
  const computed = hashFaceData(normalized);
  const hash = stripHashPrefix(faceHash || computed);
  if (hash !== computed) {
    throw new IntegrityError(
      'hash_mismatch',
      'Provided faceHash does not match normalized Face Data'
    );
  }

  const existing = db.prepare('SELECT * FROM faces WHERE face_hash = ?').get(hash);
  const t = nowSec();
  const versionMatch = normalized.match(/^[RD](\d+)/i);
  const version = versionMatch ? Number(versionMatch[1]) : null;
  const length = normalized.length;

  if (existing) {
    // Integrity: stored data must still hash to same value
    const storedNorm = normalizeFaceData(existing.face_data);
    const storedHash = hashFaceData(storedNorm);
    if (storedHash !== hash && existing.face_data !== '' && existing.face_data !== '[omitted]') {
      throw new IntegrityError(
        'inconsistent_payload',
        'Existing face_data does not match face_hash'
      );
    }
    // If we now have real data and stored was omitted, fill it
    if (storeData && (existing.face_data === '[omitted]' || existing.face_data === '')) {
      db.prepare(
        `UPDATE faces SET face_data = ?, face_data_version = ?, face_data_length = ?,
         last_seen_at = ?, updated_at = ? WHERE id = ?`
      ).run(normalized, version, length, t, t, existing.id);
    } else {
      db.prepare(
        `UPDATE faces SET last_seen_at = ?, updated_at = ? WHERE id = ?`
      ).run(t, t, existing.id);
    }
    return { id: existing.id, face_hash: hash, inserted: false };
  }

  const dataToStore = storeData ? normalized : '[omitted]';
  const info = db
    .prepare(
      `INSERT INTO faces
       (face_hash, face_data, face_data_version, face_data_length, first_seen_at, last_seen_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(hash, dataToStore, version, length, t, t, t, t);

  return { id: Number(info.lastInsertRowid), face_hash: hash, inserted: true };
}

function getFaceByHash(db, faceHash) {
  const hash = stripHashPrefix(faceHash);
  return db.prepare('SELECT * FROM faces WHERE face_hash = ?').get(hash) || null;
}

function getFaceById(db, id) {
  return db.prepare('SELECT * FROM faces WHERE id = ?').get(id) || null;
}

module.exports = {
  upsertFace,
  getFaceByHash,
  getFaceById,
  stripHashPrefix,
  IntegrityError,
};
