'use strict';

const { getDb, isCacheEnabled, storeLongCode, nowSec } = require('../../storage/database');
const faceRepo = require('../../storage/repositories/faceRepository');
const sourceRepo = require('../../storage/repositories/sourceRepository');
const aliasRepo = require('../../storage/repositories/aliasRepository');
const { stripHashPrefix, IntegrityError } = require('../../storage/repositories/faceRepository');
const logger = require('../../utils/logger');

function collectItems(inventoryResponse) {
  const inv = inventoryResponse?.inventory || {};
  return [
    ...(inv.faces || []),
    ...(inv.makeups || []),
    ...(inv.unknown || []),
  ];
}

/**
 * Persist /face_inventory response into SQLite cache.
 * Never creates short codes from plan_id / preview_object_key.
 */
function ingestInventoryResponse(response, options = {}) {
  const stats = {
    enabled: isCacheEnabled(),
    persisted: false,
    facesInserted: 0,
    facesUpdated: 0,
    sourcesInserted: 0,
    sourcesUpdated: 0,
    aliasesInserted: 0,
    aliasesUpdated: 0,
    error: null,
  };

  if (!stats.enabled) {
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
    logger.error('cache open failed', { err: e.message });
    stats.error = 'db_open_failed';
    return stats;
  }

  const items = collectItems(response).filter((i) => i.face_hash && i.face_data_length > 0);
  // long_code may be omitted (include_long_code=0) — then we can only update sources if face exists
  const player = response.player || {};
  const region = player.server === 'CN' ? 'CN' : player.server === 'SEA' ? 'GLOBAL' : 'UNKNOWN';
  const storeData = storeLongCode();

  try {
    db.exec('BEGIN IMMEDIATE');

    for (const item of items) {
      const hash = stripHashPrefix(item.face_hash);
      let faceRow = faceRepo.getFaceByHash(db, hash);

      if (!faceRow) {
        if (!item.long_code) {
          // cannot create face without payload when long code omitted
          continue;
        }
        const up = faceRepo.upsertFace(db, {
          faceData: item.long_code,
          faceHash: hash,
          storeData,
        });
        if (up.inserted) stats.facesInserted += 1;
        else stats.facesUpdated += 1;
        faceRow = faceRepo.getFaceById(db, up.id);
      } else {
        if (item.long_code) {
          const up = faceRepo.upsertFace(db, {
            faceData: item.long_code,
            faceHash: hash,
            storeData,
          });
          if (up.inserted) stats.facesInserted += 1;
          else stats.facesUpdated += 1;
        } else {
          // touch last_seen only
          const t = nowSec();
          db.prepare('UPDATE faces SET last_seen_at = ?, updated_at = ? WHERE id = ?').run(
            t,
            t,
            faceRow.id
          );
          stats.facesUpdated += 1;
        }
        faceRow = faceRepo.getFaceByHash(db, hash);
      }

      const src = sourceRepo.upsertSource(db, faceRow.id, {
        source_type: 'player_inventory',
        region,
        plan_id: item.plan_id,
        art_code: item.art_code || (item.plan_id ? `ART${item.plan_id}` : null),
        inventory_player_pid: player.pid || null,
        inventory_player_number_id: player.number_id || null,
        inventory_player_nickname: player.nickname || null,
        inventory_player_hostnum: player.hostnum ?? null,
        plan_owner_pid: item.author?.pid || null,
        plan_owner_number_id: item.author?.number_id || null,
        plan_owner_nickname: item.author?.nickname || null,
        plan_owner_hostnum: item.author?.hostnum ?? null,
        plan_owner_account: item.author?.account || null,
        plan_type: item.plan_type,
        body_type: item.body_type,
        tags: item.tags,
        source_lists: item.source_lists,
        picture_url: item.picture_url,
        preview_object_key: item.preview_object_key,
        metadata_source: item.metadata_source || 'face_plan_result.pid',
        raw_metadata: options.includeRaw ? item.raw : null,
      });
      if (src.inserted) stats.sourcesInserted += 1;
      else stats.sourcesUpdated += 1;

      // aliases — never short codes from plan/preview
      const aliasOps = [
        { aliasType: 'face_hash', aliasValue: hash, region: null },
        { aliasType: 'face_hash', aliasValue: `sha256:${hash}`, region: null },
      ];
      if (item.plan_id) {
        aliasOps.push({ aliasType: 'plan_id', aliasValue: item.plan_id, region });
        aliasOps.push({
          aliasType: 'art_code',
          aliasValue: item.art_code || `ART${item.plan_id}`,
          region,
        });
      }

      for (const a of aliasOps) {
        try {
          const ar = aliasRepo.upsertAlias(db, {
            faceId: faceRow.id,
            aliasType: a.aliasType,
            aliasValue: a.aliasValue,
            region: a.region,
            sourceId: src.id,
          });
          if (ar.inserted) stats.aliasesInserted += 1;
          else stats.aliasesUpdated += 1;
        } catch (e) {
          if (e.code === 'alias_face_conflict') {
            logger.warn('alias conflict skipped', {
              aliasType: a.aliasType,
              // do not log full values that might be huge
            });
          } else {
            throw e;
          }
        }
      }
    }

    db.exec('COMMIT');
    stats.persisted = true;
  } catch (e) {
    try {
      db.exec('ROLLBACK');
    } catch {
      /* ignore */
    }
    if (e instanceof IntegrityError) {
      stats.error = e.code;
      logger.error('cache ingest integrity', { code: e.code });
    } else {
      stats.error = 'ingest_failed';
      logger.error('cache ingest failed', { err: e.message });
    }
    stats.persisted = false;
  }

  return stats;
}

module.exports = {
  ingestInventoryResponse,
  collectItems,
};
