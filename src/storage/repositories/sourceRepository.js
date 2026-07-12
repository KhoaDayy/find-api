'use strict';

const { nowSec } = require('../database');
const { redact } = require('../../utils/redact');

function upsertSource(db, faceId, source) {
  const t = nowSec();
  const sourceType = source.source_type || 'community_plan';
  const region = source.region || 'UNKNOWN';
  const planId = source.plan_id || null;
  const invPid = source.inventory_player_pid || null;
  const shortCode = source.short_code || null;

  // Identity: short_code sources key by short_code; others by plan/inventory
  let existing = null;
  if (sourceType === 'short_code' && shortCode) {
    existing = db
      .prepare(
        `SELECT * FROM face_sources
         WHERE source_type = 'short_code'
           AND short_code = ?
           AND IFNULL(region, '') = IFNULL(?, '')`
      )
      .get(shortCode, region);
  } else {
    existing = db
      .prepare(
        `SELECT * FROM face_sources
         WHERE source_type = ?
           AND IFNULL(region, '') = IFNULL(?, '')
           AND IFNULL(plan_id, '') = IFNULL(?, '')
           AND IFNULL(inventory_player_pid, '') = IFNULL(?, '')`
      )
      .get(sourceType, region, planId, invPid);
  }

  const tagsJson = source.tags ? JSON.stringify(source.tags) : null;
  const listsJson = source.source_lists ? JSON.stringify(source.source_lists) : null;
  let rawJson = null;
  if (source.raw_metadata) {
    rawJson = JSON.stringify(redact(source.raw_metadata));
  }
  let sanitizedJson = null;
  if (source.sanitized_metadata) {
    sanitizedJson = JSON.stringify(redact(source.sanitized_metadata));
  }

  const commonUpdate = `
        art_code = COALESCE(?, art_code),
        inventory_player_number_id = COALESCE(?, inventory_player_number_id),
        inventory_player_nickname = COALESCE(?, inventory_player_nickname),
        inventory_player_hostnum = COALESCE(?, inventory_player_hostnum),
        plan_owner_pid = COALESCE(?, plan_owner_pid),
        plan_owner_number_id = COALESCE(?, plan_owner_number_id),
        plan_owner_nickname = COALESCE(?, plan_owner_nickname),
        plan_owner_hostnum = COALESCE(?, plan_owner_hostnum),
        plan_owner_account = COALESCE(?, plan_owner_account),
        plan_type = COALESCE(?, plan_type),
        body_type = COALESCE(?, body_type),
        tags_json = COALESCE(?, tags_json),
        source_lists_json = COALESCE(?, source_lists_json),
        picture_url = COALESCE(?, picture_url),
        preview_object_key = COALESCE(?, preview_object_key),
        metadata_source = ?,
        raw_metadata_json = COALESCE(?, raw_metadata_json),
        short_code = COALESCE(?, short_code),
        object_key = COALESCE(?, object_key),
        wrapper_type = COALESCE(?, wrapper_type),
        wrapper_schema_version = COALESCE(?, wrapper_schema_version),
        face_data_field_path = COALESCE(?, face_data_field_path),
        related_plan_id = COALESCE(?, related_plan_id),
        related_pid = COALESCE(?, related_pid),
        related_hostnum = COALESCE(?, related_hostnum),
        related_plan_hash_match = COALESCE(?, related_plan_hash_match),
        sanitized_metadata_json = COALESCE(?, sanitized_metadata_json),
        last_seen_at = ?,
        updated_at = ?
  `;

  const updateParams = [
    source.art_code || null,
    source.inventory_player_number_id || null,
    source.inventory_player_nickname || null,
    source.inventory_player_hostnum ?? null,
    source.plan_owner_pid || null,
    source.plan_owner_number_id || null,
    source.plan_owner_nickname || null,
    source.plan_owner_hostnum ?? null,
    source.plan_owner_account || null,
    source.plan_type != null ? String(source.plan_type) : null,
    source.body_type ?? null,
    tagsJson,
    listsJson,
    source.picture_url || null,
    source.preview_object_key || null,
    source.metadata_source || 'face_plan_result.pid',
    rawJson,
    shortCode,
    source.object_key || null,
    source.wrapper_type || null,
    source.wrapper_schema_version ?? null,
    source.face_data_field_path || null,
    source.related_plan_id || null,
    source.related_pid || null,
    source.related_hostnum ?? null,
    source.related_plan_hash_match == null ? null : source.related_plan_hash_match ? 1 : 0,
    sanitizedJson,
    t,
    t,
  ];

  if (existing) {
    db.prepare(`UPDATE face_sources SET ${commonUpdate} WHERE id = ?`).run(...updateParams, existing.id);
    return { id: existing.id, inserted: false };
  }

  const info = db
    .prepare(
      `INSERT INTO face_sources (
        face_id, source_type, region, plan_id, art_code,
        inventory_player_pid, inventory_player_number_id, inventory_player_nickname, inventory_player_hostnum,
        plan_owner_pid, plan_owner_number_id, plan_owner_nickname, plan_owner_hostnum, plan_owner_account,
        plan_type, body_type, tags_json, source_lists_json, picture_url, preview_object_key,
        metadata_source, raw_metadata_json,
        short_code, object_key, wrapper_type, wrapper_schema_version, face_data_field_path,
        related_plan_id, related_pid, related_hostnum, related_plan_hash_match, sanitized_metadata_json,
        first_seen_at, last_seen_at, created_at, updated_at
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    )
    .run(
      faceId,
      sourceType,
      region,
      planId,
      source.art_code || (planId ? `ART${planId}` : null),
      invPid,
      source.inventory_player_number_id || null,
      source.inventory_player_nickname || null,
      source.inventory_player_hostnum ?? null,
      source.plan_owner_pid || null,
      source.plan_owner_number_id || null,
      source.plan_owner_nickname || null,
      source.plan_owner_hostnum ?? null,
      source.plan_owner_account || null,
      source.plan_type != null ? String(source.plan_type) : null,
      source.body_type ?? null,
      tagsJson,
      listsJson,
      source.picture_url || null,
      source.preview_object_key || null,
      source.metadata_source || 'face_plan_result.pid',
      rawJson,
      shortCode,
      source.object_key || null,
      source.wrapper_type || null,
      source.wrapper_schema_version ?? null,
      source.face_data_field_path || null,
      source.related_plan_id || null,
      source.related_pid || null,
      source.related_hostnum ?? null,
      source.related_plan_hash_match == null ? null : source.related_plan_hash_match ? 1 : 0,
      sanitizedJson,
      t,
      t,
      t,
      t
    );

  return { id: Number(info.lastInsertRowid), inserted: true };
}

function listSourcesByFaceId(db, faceId) {
  return db
    .prepare('SELECT * FROM face_sources WHERE face_id = ? ORDER BY last_seen_at DESC')
    .all(faceId);
}

/**
 * Preferred source for display only — never mutates records.
 * Priority:
 * 1 verified community plan with hash match / owner
 * 2 FilePicker wrapper with resolvable pid/plan_id
 * 3 canonical CN community
 * 4 plain short_code
 * 5 manual/unknown
 */
function selectPreferredSource(sources) {
  if (!sources || !sources.length) {
    return { source: null, preferred_source_reason: 'none' };
  }

  const score = (s) => {
    let n = 0;
    if (s.source_type === 'community_plan' && s.related_plan_hash_match === 1) n += 200;
    if (s.source_type === 'community_plan' && s.plan_owner_pid) n += 120;
    if (s.source_type === 'community_plan' && s.plan_owner_number_id) n += 50;
    if (s.source_type === 'player_inventory' && s.plan_owner_number_id) n += 90;
    if (s.source_type === 'player_inventory') n += 60;
    if (s.source_type === 'short_code' && (s.related_pid || s.related_plan_id)) n += 100;
    if (s.source_type === 'short_code' && s.related_plan_hash_match === 1) n += 40;
    if (s.source_type === 'short_code') n += 30;
    if (s.metadata_source === 'global_filepicker_wrapper.cn_source_metadata') n += 35;
    if (s.region === 'CN') n += 8;
    if (s.plan_owner_number_id || s.inventory_player_number_id) n += 15;
    if (s.source_type === 'manual') n += 5;
    return n;
  };

  const sorted = [...sources].sort((a, b) => score(b) - score(a));
  const best = sorted[0];
  let reason = 'highest_metadata_score';

  if (best.source_type === 'community_plan' && best.related_plan_hash_match === 1) {
    reason = 'verified_community_plan_hash_match';
  } else if (best.source_type === 'community_plan' && best.plan_owner_number_id) {
    reason = 'community_plan_with_resolved_owner';
  } else if (
    best.source_type === 'short_code' &&
    best.metadata_source === 'global_filepicker_wrapper.cn_source_metadata'
  ) {
    reason = 'global_filepicker_wrapper.cn_source_metadata';
  } else if (best.source_type === 'short_code' && (best.related_pid || best.related_plan_id)) {
    reason = 'filepicker_wrapper_with_identity';
  } else if (best.region === 'CN' && best.source_type === 'community_plan') {
    reason = 'cn_community_metadata_priority';
  } else if (best.region === 'CN' && best.source_type === 'player_inventory') {
    reason = 'canonical_cn_record';
  } else if (best.source_type === 'player_inventory') {
    reason = 'player_inventory_metadata';
  } else if (best.source_type === 'short_code') {
    reason = 'short_code_source';
  }

  return { source: best, preferred_source_reason: reason };
}

module.exports = {
  upsertSource,
  listSourcesByFaceId,
  selectPreferredSource,
};
