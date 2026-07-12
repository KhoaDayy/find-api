'use strict';

/**
 * Raw diagnostic for player face inventory schema.
 * Does NOT invent short codes from plan_id.
 * Does NOT mark slot 0 as active.
 *
 * Usage:
 *   node scripts/inspect_player_face.js --server CN --id 0111452488
 *   node scripts/inspect_player_face.js --server SEA --name "Example"
 *   node scripts/inspect_player_face.js --server CN --id 0111452488 --debug
 */

const fs = require('fs');
const path = require('path');
try {
  require('dotenv').config();
} catch {
  /* optional */
}
const { resolveRegion } = require('../src/wwm/session');
const playerService = require('../src/wwm/services/playerService');
const faceService = require('../src/wwm/services/faceService');
const { isFilePickerObjectKey } = require('../src/parsers/shortCodeParser');
const { redact } = require('../src/utils/redact');
const logger = require('../src/utils/logger');

const FP_URL_HINTS = [
  'face_url',
  'face_url_id',
  'share_url',
  'share_id',
  'file_url',
  'file_id',
  'object_key',
  'resource_url',
  'download_url',
  'data_url',
  'pict_url',
  'picture_url',
  'view_url',
  'origin_url',
];

function parseArgs(argv) {
  const out = { server: 'SEA', id: null, name: null, debug: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--server') out.server = argv[++i];
    else if (a === '--id') out.id = argv[++i];
    else if (a === '--name') out.name = argv[++i];
    else if (a === '--debug') out.debug = true;
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function writeJson(file, data) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

/** Collect recursive key paths (max depth) */
function collectKeyPaths(obj, prefix = '$', depth = 0, maxDepth = 6, out = []) {
  if (obj == null || depth > maxDepth) return out;
  if (Array.isArray(obj)) {
    if (obj.length === 0) out.push(`${prefix}[]`);
    else collectKeyPaths(obj[0], `${prefix}[]`, depth + 1, maxDepth, out);
    return out;
  }
  if (typeof obj !== 'object') return out;
  for (const k of Object.keys(obj)) {
    const p = `${prefix}.${k}`;
    out.push(p);
    collectKeyPaths(obj[k], p, depth + 1, maxDepth, out);
  }
  return out;
}

function regionFromObjectKey(key) {
  if (!isFilePickerObjectKey(key)) return 'UNKNOWN';
  const s = key.slice(-2);
  if (s === '07') return 'CN';
  if (s === '03') return 'GLOBAL';
  return 'UNKNOWN';
}

/**
 * Walk object for URL/id fields that may hold FilePicker object keys.
 */
function findObjectKeyCandidates(obj, basePath = '$', out = [], depth = 0) {
  if (obj == null || depth > 8) return out;
  if (typeof obj === 'string') {
    const s = obj.trim();
    // full short code
    const shortM = s.match(/(?:yysls|wwm)_facedata_R\d+_([0-9a-f]{24}[A-Za-z0-9]{8}[0-9]{2})/i);
    if (shortM) {
      out.push({
        objectKeyCandidate: shortM[1],
        fieldPath: basePath,
        regionCandidate: regionFromObjectKey(shortM[1]),
        verified: false,
        via: 'short_code_in_string',
      });
    }
    // /file/{key}
    const fileM = s.match(/\/file\/([0-9a-f]{24}[A-Za-z0-9]{8}[0-9]{2})/i);
    if (fileM) {
      out.push({
        objectKeyCandidate: fileM[1],
        fieldPath: basePath,
        regionCandidate: regionFromObjectKey(fileM[1]),
        verified: false,
        via: 'file_url',
      });
    }
    if (isFilePickerObjectKey(s)) {
      out.push({
        objectKeyCandidate: s,
        fieldPath: basePath,
        regionCandidate: regionFromObjectKey(s),
        verified: false,
        via: 'raw_key',
      });
    }
    return out;
  }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => findObjectKeyCandidates(v, `${basePath}[${i}]`, out, depth + 1));
    return out;
  }
  if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      const p = `${basePath}.${k}`;
      const kLower = k.toLowerCase();
      const hint = FP_URL_HINTS.some((h) => kLower.includes(h.replace(/_/g, '')) || kLower.includes(h));
      // always recurse; prioritize hint fields in report order later
      findObjectKeyCandidates(v, p, out, depth + 1);
      if (hint && typeof v === 'string' && !isFilePickerObjectKey(v) && !/\/file\//.test(v)) {
        // still record path for manual review
        out.push({
          objectKeyCandidate: null,
          fieldPath: p,
          regionCandidate: 'UNKNOWN',
          verified: false,
          via: 'hint_field_no_fp_key',
          valuePreview: v.slice(0, 120),
        });
      }
    }
  }
  return out;
}

function uniqCandidates(list) {
  const seen = new Set();
  const out = [];
  for (const c of list) {
    const key = `${c.fieldPath}|${c.objectKeyCandidate}|${c.via}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }
  return out;
}

function deepFindKeys(obj, names, prefix = '$', depth = 0, out = []) {
  if (obj == null || depth > 6) return out;
  if (Array.isArray(obj)) {
    obj.slice(0, 3).forEach((v, i) => deepFindKeys(v, names, `${prefix}[${i}]`, depth + 1, out));
    return out;
  }
  if (typeof obj !== 'object') return out;
  for (const [k, v] of Object.entries(obj)) {
    const p = `${prefix}.${k}`;
    if (names.includes(k)) out.push({ path: p, value: v });
    deepFindKeys(v, names, p, depth + 1, out);
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help || (!args.id && !args.name)) {
    console.log(`Usage:
  node scripts/inspect_player_face.js --server CN --id <number_id>
  node scripts/inspect_player_face.js --server SEA --name <nickname>
  node scripts/inspect_player_face.js --server CN --id <number_id> --debug`);
    process.exit(args.help ? 0 : 1);
  }

  const region = resolveRegion(args.server);
  const host = region.apiHost;
  const debugDir = path.join(process.cwd(), 'debug');
  ensureDir(debugDir);

  console.log('=== inspect_player_face ===');
  console.log('server:', region.id, 'host:', host);
  console.log('TLS verify: ON');

  // 1. Lookup player
  let rawPeople;
  if (args.id) {
    rawPeople = await playerService.findPeopleByNumberId(host, args.id);
  } else {
    rawPeople = await playerService.findPeopleByNickname(host, args.name);
  }
  const player = playerService.formatBasicPlayer(rawPeople);
  if (!player) {
    console.error('Player not found. Raw:', JSON.stringify(redact(rawPeople), null, 2));
    process.exit(2);
  }
  const hostnum = player.server_hostnum || player.hostnum;
  console.log('\n[player]');
  console.log(
    JSON.stringify(
      {
        nickname: player.nickname,
        number_id: player.number_id,
        pid: player.pid,
        hostnum,
      },
      null,
      2
    )
  );

  // redis_player for active-slot hunting + player profile
  const redisPlayer = await playerService.getPlayersInfo(host, player.pid, hostnum, [
    'base',
    'head',
    'name_card',
    'settings',
    'title_prop',
    'school',
  ]);
  writeJson(path.join(debugDir, `redis-player-${player.pid.replace(/[^\w.-]+/g, '_')}.json`), redisPlayer);

  const activeFromRedis = deepFindKeys(redisPlayer, [
    'face_slot_idx',
    'makeup_slot_idx',
    'sex_face_slot_idx',
    'sex_makeup_slot_idx',
    'face_plan',
    'guise',
    'appearance',
    'makeup',
    'face_slot',
    'makeup_slot',
  ]);
  console.log('\n[redis_player active-related hits]', activeFromRedis.length);
  for (const h of activeFromRedis.slice(0, 40)) {
    const preview =
      typeof h.value === 'object' ? JSON.stringify(h.value).slice(0, 160) : String(h.value).slice(0, 160);
    console.log(`  ${h.path}: ${preview}`);
  }

  // optional hget
  let hget = null;
  try {
    hget = await playerService.hgetPlayerData(host, player.pid, hostnum);
    writeJson(path.join(debugDir, `hget-${player.pid.replace(/[^\w.-]+/g, '_')}.json`), hget);
    const hgetHits = deepFindKeys(hget, [
      'face_slot_idx',
      'makeup_slot_idx',
      'face_plan',
      'makeup',
      'guise',
    ]);
    console.log('\n[hget_data hits]', hgetHits.length);
    for (const h of hgetHits.slice(0, 20)) {
      console.log(`  ${h.path}`);
    }
  } catch (e) {
    console.log('\n[hget_data] error', e.message);
  }

  // 2. designer
  const designer = await faceService.getDesignerData(host, player.pid, hostnum);
  const designerPath = path.join(debugDir, `designer-${String(player.pid).replace(/[^\w.-]+/g, '_')}.json`);
  writeJson(designerPath, designer);
  console.log('\n[designer] saved', designerPath);
  if (!designer) {
    console.error('get_designer_data returned null');
    process.exit(3);
  }

  const topKeys = Object.keys(designer);
  console.log('\n[designer top-level keys]', topKeys.join(', '));
  const designerPaths = collectKeyPaths(designer);
  console.log('[designer key paths] count=', designerPaths.length);
  if (args.debug) {
    console.log(designerPaths.join('\n'));
  } else {
    console.log(designerPaths.slice(0, 80).join('\n'));
    if (designerPaths.length > 80) console.log(`... +${designerPaths.length - 80} more (use --debug)`);
  }

  const activeFromDesigner = faceService.findActiveIndices(designer);
  console.log('\n[active indices from designer]', activeFromDesigner);

  // 3. collect plan ids
  const planItems = faceService.collectPlanIdsFromDesigner(designer);
  console.log('\n[plan ids collected]', planItems.length);
  const bySource = {};
  for (const it of planItems) {
    bySource[it.source_list] = (bySource[it.source_list] || 0) + 1;
  }
  console.log('[by source_list]', bySource);

  // 4. batch + fallback
  const planIds = planItems.map((p) => p.planId);
  const { map: planMap, batch } = await faceService.fetchPlansDetailed(host, planIds, {
    concurrency: 3,
    delayMs: 150,
  });
  writeJson(path.join(debugDir, `batch-raw-${String(player.pid).replace(/[^\w.-]+/g, '_')}.json`), batch);

  console.log('\n[batch]', {
    ok: batch.ok,
    payloadTried: batch.payloadTried,
    mapSize: planMap.size,
    requested: planIds.length,
  });
  if (batch.raw) {
    const batchPaths = collectKeyPaths(batch.raw);
    console.log('[batch key paths sample]', batchPaths.slice(0, 40).join('\n'));
  }

  // 5. per-plan summary
  const inventory = [];
  const allKeyCandidates = [];

  for (const item of planItems) {
    const entry = planMap.get(item.planId);
    // entry: { planId, result, envelope } — summarize the per-plan result only
    const planResult = entry?.result || null;
    const summary = faceService.summarizePlanResult(
      planResult ? { result: planResult } : null
    );

    // raw save
    if (args.debug && planResult) {
      writeJson(
        path.join(
          debugDir,
          `plan-${String(item.planId).replace(/[^\w.-]+/g, '_')}.json`
        ),
        planResult
      );
    }

    const resultObj = summary.ok ? summary.raw_result : planResult;
    const planPaths = resultObj ? collectKeyPaths(resultObj) : [];
    let viewKeys = [];
    if (resultObj?.view_data) {
      try {
        const vd =
          typeof resultObj.view_data === 'string'
            ? JSON.parse(resultObj.view_data)
            : resultObj.view_data;
        viewKeys = vd && typeof vd === 'object' ? Object.keys(vd) : [];
      } catch {
        viewKeys = ['<parse_error>'];
      }
    }

    const candidates = resultObj ? uniqCandidates(findObjectKeyCandidates(resultObj)) : [];
    allKeyCandidates.push(...candidates);

    // author resolve — plan.pid is author_pid, NOT number_id
    let author = {
      pid: summary.pid || null,
      hostnum: summary.hostnum ?? null,
      nickname: null,
      number_id: null,
      metadata_source: summary.pid ? 'face_plan_result.pid' : 'none',
    };
    if (summary.pid) {
      const ap = await playerService.resolveAuthorProfile(
        host,
        summary.pid,
        summary.hostnum ?? hostnum
      );
      author = {
        pid: ap.pid,
        hostnum: ap.hostnum,
        nickname: ap.nickname,
        number_id: ap.number_id,
        metadata_source: ap.number_id
          ? 'face_plan_result.pid+redis_player'
          : 'face_plan_result.pid',
      };
      // small delay to avoid spam when many plans
      await new Promise((r) => setTimeout(r, 50));
    }

    const type = faceService.classifyPlanTypeString({
      sourceList: item.source_list,
      tags: summary.tags,
      planType: summary.plan_type,
    });

    // is_active: only if we have index from designer and source is face_slots/makeup_slots
    let is_active = null;
    let active_source = 'unknown';
    if (
      item.source_list === 'face_slots' &&
      activeFromDesigner.face_slot_idx != null &&
      Number(activeFromDesigner.face_slot_idx) === Number(item.slot_index)
    ) {
      is_active = true;
      active_source = 'designer.face_slot_idx';
    } else if (
      item.source_list === 'makeup_slots' &&
      activeFromDesigner.makeup_slot_idx != null &&
      Number(activeFromDesigner.makeup_slot_idx) === Number(item.slot_index)
    ) {
      is_active = true;
      active_source = 'designer.makeup_slot_idx';
    }

    const row = {
      type,
      slot_index: item.slot_index,
      is_active,
      active_source,
      source_list: item.source_list,
      plan_id: item.planId,
      art_code: `ART${item.planId}`,
      long_code_length: summary.long_code_length || 0,
      face_hash: summary.face_hash,
      tags: summary.tags || [],
      plan_type: summary.plan_type,
      picture_url: summary.picture_url,
      author,
      // NEVER set short from plan_id
      short_code_candidate: null,
      short_code_verified: false,
      object_key_candidates: candidates.filter((c) => c.objectKeyCandidate),
      view_data_keys: viewKeys,
      plan_key_path_count: planPaths.length,
    };

    if (args.debug) {
      row.plan_key_paths = planPaths;
      row.long_code_head = summary.long_code ? summary.long_code.slice(0, 48) : null;
    }

    inventory.push(row);
  }

  // picture_url object keys are preview images — report but not verified face short codes
  const fpCandidates = uniqCandidates(allKeyCandidates).filter((c) => c.objectKeyCandidate);
  console.log('\n[FilePicker objectKey candidates across plans]', fpCandidates.length);
  for (const c of fpCandidates.slice(0, 30)) {
    console.log(
      JSON.stringify({
        objectKeyCandidate: c.objectKeyCandidate,
        fieldPath: c.fieldPath,
        regionCandidate: c.regionCandidate,
        verified: false,
        via: c.via,
      })
    );
  }

  // makeup location report
  const makeupItems = inventory.filter((i) => i.type === 'makeup');
  const faceItems = inventory.filter((i) => i.type === 'face');
  const unknownItems = inventory.filter((i) => i.type === 'unknown' || i.type.startsWith('plan_type_'));

  const report = {
    player: {
      nickname: player.nickname,
      number_id: player.number_id,
      pid: player.pid,
      hostnum,
      server: region.id,
    },
    designer_top_level_keys: topKeys,
    designer_active_indices: activeFromDesigner,
    redis_active_hits: activeFromRedis.map((h) => h.path),
    plan_counts_by_source: bySource,
    batch: {
      ok: batch.ok,
      payloadTried: batch.payloadTried,
      resolved: planMap.size,
      requested: planIds.length,
    },
    inventory_counts: {
      total: inventory.length,
      face: faceItems.length,
      makeup: makeupItems.length,
      other: unknownItems.length,
    },
    // sample rows without huge raw
    inventory: inventory.map((r) => ({
      ...r,
      // strip nothing else
    })),
    object_key_candidates: fpCandidates,
    notes: [
      'plan_id is NOT FilePicker object key — short_code_candidate left null unless FP key found',
      'is_active is null unless designer face_slot_idx/makeup_slot_idx present and matches',
      'author.number_id resolved via redis_player from plan.pid; null if resolve failed',
      'picture_url object keys are usually preview images, not face short codes — verified=false',
    ],
    unverified: [
      'exact batch request schema (tried multiple payloads)',
      'whether makeup_slots field exists on this designer payload',
      'active slot outside designer indices',
      'FilePicker short code linkage from community plan fields',
    ],
  };

  const reportPath = path.join(
    debugDir,
    `report-${String(player.pid).replace(/[^\w.-]+/g, '_')}.json`
  );
  writeJson(reportPath, report);

  console.log('\n=== SUMMARY REPORT ===');
  console.log(
    JSON.stringify(
      {
        player: report.player,
        designer_top_level_keys: report.designer_top_level_keys,
        designer_active_indices: report.designer_active_indices,
        plan_counts_by_source: report.plan_counts_by_source,
        batch: report.batch,
        inventory_counts: report.inventory_counts,
        object_key_candidate_count: fpCandidates.length,
        author_resolved_count: inventory.filter((i) => i.author?.number_id).length,
        report_path: reportPath,
        notes: report.notes,
        unverified: report.unverified,
      },
      null,
      2
    )
  );

  console.log('\nDone. Full inventory in', reportPath);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
