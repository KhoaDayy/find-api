'use strict';

const { nowSec } = require('../database');

const ACTIVE = new Set(['pending', 'running']);

/**
 * Ensure at most one active (pending|running) job per face_id + region.
 */
function createOrGetActiveJob(db, { faceId, region }) {
  const existing = db
    .prepare(
      `SELECT * FROM upload_jobs
       WHERE face_id = ? AND region = ? AND status IN ('pending', 'running')
       LIMIT 1`
    )
    .get(faceId, region);

  if (existing) return { job: existing, inserted: false };

  const t = nowSec();
  try {
    const info = db
      .prepare(
        `INSERT INTO upload_jobs
         (face_id, region, status, attempt_count, created_at, updated_at)
         VALUES (?, ?, 'pending', 0, ?, ?)`
      )
      .run(faceId, region, t, t);
    const job = db.prepare('SELECT * FROM upload_jobs WHERE id = ?').get(Number(info.lastInsertRowid));
    return { job, inserted: true };
  } catch (e) {
    // unique partial index race
    const again = db
      .prepare(
        `SELECT * FROM upload_jobs
         WHERE face_id = ? AND region = ? AND status IN ('pending', 'running') LIMIT 1`
      )
      .get(faceId, region);
    if (again) return { job: again, inserted: false };
    throw e;
  }
}

function lockJob(db, jobId) {
  const t = nowSec();
  const r = db
    .prepare(
      `UPDATE upload_jobs SET status = 'running', locked_at = ?, updated_at = ?,
       attempt_count = attempt_count + 1
       WHERE id = ? AND status = 'pending'`
    )
    .run(t, t, jobId);
  return r.changes > 0;
}

function finishJob(db, jobId, { status, lastError = null, retryAfter = null }) {
  const t = nowSec();
  db.prepare(
    `UPDATE upload_jobs SET status = ?, last_error = ?, retry_after = ?, locked_at = NULL, updated_at = ?
     WHERE id = ?`
  ).run(status, lastError, retryAfter, t, jobId);
}

function getActiveJob(db, faceId, region) {
  return (
    db
      .prepare(
        `SELECT * FROM upload_jobs
         WHERE face_id = ? AND region = ? AND status IN ('pending', 'running') LIMIT 1`
      )
      .get(faceId, region) || null
  );
}

module.exports = {
  createOrGetActiveJob,
  lockJob,
  finishJob,
  getActiveJob,
  ACTIVE,
};
