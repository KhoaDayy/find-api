'use strict';

/**
 * Inspect FilePicker short-code CDN object metadata (sanitized).
 *
 *   node scripts/inspect_filepicker_object.js --code "wwm_facedata_R37_..."
 *   node scripts/inspect_filepicker_object.js --code "yysls_facedata_R37_..." --debug
 *   node scripts/inspect_filepicker_object.js --compare
 */

try {
  require('dotenv').config();
} catch {
  /* optional */
}

const fs = require('fs');
const path = require('path');
const { parseShortCode } = require('../src/parsers/shortCodeParser');
const { regionIdFromShortPrefix } = require('../src/config/regions');
const filePickerDownload = require('../src/wwm/services/filePickerDownloadService');
const { extractFaceFromBody } = require('../src/wwm/services/shortCodeResolveService');
const meta = require('../src/wwm/services/filePickerMetaService');
const { hashFaceData } = require('../src/utils/hash');
const faceService = require('../src/wwm/services/faceService');
const playerService = require('../src/wwm/services/playerService');
const { REGIONS } = require('../src/config/regions');

function parseArgs(argv) {
  const out = { codes: [], debug: false, compare: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--code') out.codes.push(argv[++i]);
    else if (a === '--debug') out.debug = true;
    else if (a === '--compare') out.compare = true;
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

async function inspectOne(code, { debug }) {
  const parsed = parseShortCode(code);
  if (!parsed.ok) {
    console.error('Invalid short code:', parsed.error);
    return null;
  }
  const region = regionIdFromShortPrefix(parsed.prefix);
  console.log('\n===', region, parsed.raw, '===');

  const dl = await filePickerDownload.downloadFaceObject({
    prefix: parsed.prefix,
    objectKey: parsed.objectKey,
  });
  console.log('host:', dl.host, 'content-type header:', dl.contentType, 'bytes:', dl.body.length);

  const extracted = extractFaceFromBody(dl.body, dl.contentType);
  const faceHash = hashFaceData(extracted.longCode);
  console.log('contentKind:', extracted.contentKind);
  console.log('face_hash:', faceHash);
  console.log('face_data_length:', extracted.longCode.length);

  let rawJson = null;
  const text = dl.body.toString('utf8').trim();
  if (text.startsWith('{') || text.startsWith('[')) {
    rawJson = JSON.parse(text);
  }

  const facePath = rawJson ? meta.findFaceDataFieldPath(rawJson) : null;
  console.log('face_data_field_path:', facePath);

  const identity = rawJson ? meta.extractWrapperIdentity(rawJson) : {};
  console.log('identity:', JSON.stringify(identity));

  const sanitized = rawJson
    ? meta.sanitizeFaceDataDeep(rawJson)
    : { __plain__: true, face: { __face_data__: true, length: extracted.longCode.length, sha256: faceHash } };

  const paths = meta.collectFieldPaths(sanitized);
  console.log('field paths:', paths.length);
  const interesting = paths.filter((p) => p.interesting || /plan_id|pid|hostnum|account|name|tag|picture|face_data|upload/i.test(p.path));
  for (const p of interesting.slice(0, debug ? 500 : 80)) {
    console.log(`  ${p.path}  (${p.type}${p.length != null ? ' len=' + p.length : ''})`);
  }

  const debugDir = path.join(process.cwd(), 'debug');
  ensureDir(debugDir);
  const outFile = path.join(debugDir, `filepicker-${region}-${parsed.objectKey}.json`);
  fs.writeFileSync(
    outFile,
    JSON.stringify(
      {
        short_code: parsed.raw,
        region,
        object_key: parsed.objectKey,
        host: dl.host,
        contentKind: extracted.contentKind,
        face_hash: faceHash,
        face_data_length: extracted.longCode.length,
        face_data_field_path: facePath,
        identity,
        sanitized,
        field_paths: paths,
      },
      null,
      2
    ),
    'utf8'
  );
  console.log('saved', outFile);

  // Optional community plan correlation
  let planCorrelation = null;
  if (identity.plan_id && meta.looksLikeCommunityPlanId(identity.plan_id)) {
    const apiHost = region === 'CN' ? REGIONS.CN.apiHost : REGIONS.SEA.apiHost;
    try {
      const env = await faceService.getFacePlanData(apiHost, identity.plan_id);
      const summary = faceService.summarizePlanResult(env);
      const match = summary.face_hash === faceHash;
      planCorrelation = {
        plan_id: identity.plan_id,
        art_code: `ART${identity.plan_id}`,
        community_face_hash: summary.face_hash,
        hash_match: match,
        community_pid: summary.pid,
        community_name: summary.name,
      };
      console.log('plan correlation:', planCorrelation);
    } catch (e) {
      console.log('plan correlation failed:', e.code || e.message);
      planCorrelation = { plan_id: identity.plan_id, error: e.code || e.message };
    }
  }

  // Optional pid resolve — use hostnum region (CN if <10400), not short-code CDN region
  let owner = null;
  if (identity.pid && identity.hostnum != null) {
    const hn = Number(identity.hostnum);
    const apiHost = hn < 10400 ? REGIONS.CN.apiHost : REGIONS.SEA.apiHost;
    try {
      const prof = await playerService.resolveAuthorProfile(apiHost, identity.pid, hn);
      owner = {
        pid: prof.pid,
        number_id: prof.number_id,
        nickname: prof.nickname,
        hostnum: prof.hostnum,
        role: 'filepicker_metadata_owner',
        resolved: prof.resolved,
      };
      console.log('owner resolve:', owner);
    } catch (e) {
      console.log('owner resolve failed:', e.code || e.message);
    }
  }

  return {
    region,
    parsed,
    faceHash,
    face_data_length: extracted.longCode.length,
    contentKind: extracted.contentKind,
    face_data_field_path: facePath,
    identity,
    sanitized,
    host: dl.host,
    planCorrelation,
    owner,
  };
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    console.log(`Usage:
  node scripts/inspect_filepicker_object.js --code "wwm_facedata_R37_..."
  node scripts/inspect_filepicker_object.js --code "yysls_..." --code "wwm_..." --compare
`);
    process.exit(0);
  }

  let codes = args.codes;
  if (args.compare && codes.length === 0) {
    codes = [
      'wwm_facedata_R37_6a47e2900f5db520d85f5f3ahqdzOR1h03',
      'yysls_facedata_R37_6a527f86e0d2f8e5305227f82gvxhbPw07',
    ];
  }
  if (!codes.length) {
    console.error('Provide --code or --compare');
    process.exit(1);
  }

  const results = [];
  for (const code of codes) {
    results.push(await inspectOne(code, { debug: args.debug }));
  }

  if (results.length >= 2) {
    const g = results.find((r) => r && r.region === 'GLOBAL');
    const c = results.find((r) => r && r.region === 'CN');
    if (g && c) {
      const diff = meta.diffSanitizedWrappers(g.sanitized, c.sanitized);
      const report = {
        sameFaceHash: g.faceHash === c.faceHash,
        faceHashes: { GLOBAL: g.faceHash, CN: c.faceHash },
        face_data_field_path: {
          GLOBAL: g.face_data_field_path,
          CN: c.face_data_field_path,
        },
        contentKind: { GLOBAL: g.contentKind, CN: c.contentKind },
        hosts: { GLOBAL: g.host, CN: c.host },
        identity: { GLOBAL: g.identity, CN: c.identity },
        planCorrelation: { GLOBAL: g.planCorrelation, CN: c.planCorrelation },
        owners: { GLOBAL: g.owner, CN: c.owner },
        ...diff,
        conclusion: null,
      };

      if (report.sameFaceHash) {
        const gPid = g.identity?.pid;
        const cPid = c.identity?.pid;
        const gPlan = g.identity?.plan_id;
        const cPlan = c.identity?.plan_id;
        if (gPid && cPid && gPid === cPid) {
          report.conclusion = 'Global mirror preserves CN source metadata (same pid in wrappers)';
          report.metadata_source_hint = 'global_filepicker_wrapper.cn_source_metadata';
        } else if (!gPid && cPid) {
          report.conclusion = 'Global wrapper lacks author; join via face_hash to CN canonical record';
          report.metadata_source_hint = 'canonical_cn_record';
        } else if (gPlan && cPlan && gPlan === cPlan) {
          report.conclusion = 'Same plan_id in both wrappers';
          report.metadata_source_hint = 'filepicker_wrapper_plan_id';
        } else if (!gPid && !cPid) {
          report.conclusion = 'No author metadata in either wrapper';
          report.metadata_source_hint = 'none';
        } else {
          report.conclusion = 'Wrappers differ in identity fields; see fieldsWithDifferentValues';
          report.metadata_source_hint = 'mixed';
        }
      }

      const reportPath = path.join(process.cwd(), 'debug', 'filepicker-compare-report.json');
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');
      console.log('\n=== COMPARE REPORT ===');
      console.log(JSON.stringify(report, null, 2));
      console.log('saved', reportPath);
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
