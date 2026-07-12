'use strict';

const msgpack = require('msgpack-lite');
const { msgpackRequest } = require('../client');
const { getSessionKey } = require('../session');

async function findPeopleByNumberId(host, numberId) {
  return msgpackRequest(host, '/flk/find_people/by_number_id', {
    number_id: String(numberId),
    force_search: false,
  });
}

async function findPeopleByNickname(host, nickname) {
  return msgpackRequest(host, '/flk/find_people/by_nickname', {
    nickname: String(nickname),
  });
}

function formatBasicPlayer(raw) {
  if (!raw || !raw.result || Object.keys(raw.result).length === 0) return null;
  const r = raw.result;
  const base = r.base || {};
  return {
    pid: r.id || null,
    hostnum: r.hostnum || base.server_hostnum || null,
    server_hostnum: base.server_hostnum || r.hostnum || null,
    nickname: base.nickname || null,
    number_id: base.number_id || null,
    level: base.level || null,
    school: base.school || null,
    body_type: base.body_type ?? null,
  };
}

/**
 * redis_player/get_players_info — custom msgpack map for hostnum2pids
 * (ported from Hasukatsu-API; needed for author number_id resolution)
 */
const AUTHOR_FIELDS = ['base', 'head', 'name_card', 'settings'];

/**
 * Encode hostnum2pids msgpack map for one hostnum → many pids.
 * Map size 1: { hostnum: [pid, ...] }
 */
function encodeHostnum2Pids(hostnum, pids) {
  const pidsBuf = msgpack.encode(pids.map(String));
  const fieldsBuf = msgpack.encode(AUTHOR_FIELDS);
  const numBuf = Buffer.alloc(3);
  numBuf[0] = 0xcd;
  numBuf.writeUInt16BE(Number(hostnum), 1);
  const mapBuf = Buffer.concat([Buffer.from([0x81]), numBuf, pidsBuf]);
  return Buffer.concat([
    Buffer.from([0x82]),
    msgpack.encode('hostnum2pids'),
    mapBuf,
    msgpack.encode('fields'),
    fieldsBuf,
  ]);
}

async function getPlayersInfo(host, pid, hostnum, fields) {
  if (!pid || hostnum == null) return null;
  const map = await getPlayersInfoBatch(host, [pid], hostnum, fields);
  return map.get(String(pid)) || null;
}

/**
 * Batch redis_player lookup for many pids on one hostnum.
 * Returns Map(pid -> playerData).
 */
async function getPlayersInfoBatch(host, pids, hostnum, fields) {
  const out = new Map();
  const list = [...new Set((pids || []).filter(Boolean).map(String))];
  if (!list.length || hostnum == null) return out;

  const requestedFields = fields || AUTHOR_FIELDS;
  try {
    // If custom fields, rebuild buffer (encodeHostnum2Pids uses AUTHOR_FIELDS)
    let customBuffer;
    if (fields && fields !== AUTHOR_FIELDS) {
      const pidsBuf = msgpack.encode(list);
      const fieldsBuf = msgpack.encode(requestedFields);
      const numBuf = Buffer.alloc(3);
      numBuf[0] = 0xcd;
      numBuf.writeUInt16BE(Number(hostnum), 1);
      const mapBuf = Buffer.concat([Buffer.from([0x81]), numBuf, pidsBuf]);
      customBuffer = Buffer.concat([
        Buffer.from([0x82]),
        msgpack.encode('hostnum2pids'),
        mapBuf,
        msgpack.encode('fields'),
        fieldsBuf,
      ]);
    } else {
      customBuffer = encodeHostnum2Pids(hostnum, list);
    }

    const data = await msgpackRequest(host, '/flk/redis_player/get_players_info', null, customBuffer);
    if (!data || typeof data !== 'object') return out;
    const resultDict = data.result || data;
    for (const pid of list) {
      if (resultDict[pid]) out.set(pid, resultDict[pid]);
    }
  } catch {
    /* leave empty */
  }
  return out;
}

async function resolveAuthorProfile(host, authorPid, authorHostnum) {
  if (!authorPid) {
    return {
      pid: null,
      hostnum: authorHostnum || null,
      nickname: null,
      number_id: null,
      account: null,
      resolved: false,
      source: 'none',
    };
  }
  const info = await getPlayersInfo(host, authorPid, authorHostnum, AUTHOR_FIELDS);
  const base = info?.base || {};
  const resolved = !!(base.nickname || base.number_id);
  return {
    pid: authorPid,
    hostnum: authorHostnum ?? base.server_hostnum ?? null,
    nickname: base.nickname || null,
    number_id: base.number_id || null,
    account: null,
    resolved,
    source: resolved ? 'redis_player' : 'face_plan_result',
    raw: info || null,
  };
}

/**
 * Batch-resolve authors: unique pid+hostnum, group by hostnum, chunk 20, concurrency 2.
 * pairs: [{ pid, hostnum, account? }]
 * Returns Map(`${pid}@${hostnum}` -> author object)
 */
async function resolveAuthorsBatch(host, pairs, { chunkSize = 20, concurrency = 2 } = {}) {
  const unique = new Map();
  for (const p of pairs || []) {
    if (!p?.pid) continue;
    const hn = p.hostnum ?? null;
    const key = `${p.pid}@${hn}`;
    if (!unique.has(key)) unique.set(key, { pid: String(p.pid), hostnum: hn, account: p.account || null });
  }

  const result = new Map();
  // group by hostnum
  const byHost = new Map();
  for (const [key, v] of unique) {
    const hnKey = String(v.hostnum);
    if (!byHost.has(hnKey)) byHost.set(hnKey, []);
    byHost.get(hnKey).push({ ...v, mapKey: key });
  }

  const jobs = [];
  for (const [hnKey, list] of byHost) {
    const hostnum = hnKey === 'null' ? null : Number(hnKey);
    for (let i = 0; i < list.length; i += chunkSize) {
      jobs.push({ hostnum, chunk: list.slice(i, i + chunkSize) });
    }
  }

  let batchesUsed = 0;
  for (let i = 0; i < jobs.length; i += concurrency) {
    const slice = jobs.slice(i, i + concurrency);
    await Promise.all(
      slice.map(async (job) => {
        batchesUsed += 1;
        if (job.hostnum == null) {
          for (const item of job.chunk) {
            result.set(item.mapKey, {
              pid: item.pid,
              hostnum: null,
              nickname: null,
              number_id: null,
              account: item.account,
              resolved: false,
              source: 'face_plan_result',
            });
          }
          return;
        }
        const map = await getPlayersInfoBatch(
          host,
          job.chunk.map((c) => c.pid),
          job.hostnum,
          AUTHOR_FIELDS
        );
        for (const item of job.chunk) {
          const info = map.get(item.pid);
          const base = info?.base || {};
          const resolved = !!(base.nickname || base.number_id);
          result.set(item.mapKey, {
            pid: item.pid,
            hostnum: item.hostnum ?? base.server_hostnum ?? null,
            nickname: base.nickname || null,
            number_id: base.number_id || null,
            account: item.account,
            resolved,
            source: resolved ? 'redis_player' : 'face_plan_result',
          });
        }
      })
    );
  }

  // fill any missing as unresolved
  for (const [key, v] of unique) {
    if (!result.has(key)) {
      result.set(key, {
        pid: v.pid,
        hostnum: v.hostnum,
        nickname: null,
        number_id: null,
        account: v.account,
        resolved: false,
        source: 'face_plan_result',
      });
    }
  }

  return { authors: result, batchesUsed, uniqueCount: unique.size };
}

async function hgetPlayerData(host, puid, hostnum, keys = ['player_local_data_npc_stuff']) {
  return msgpackRequest(host, '/player_service/hget_data', {
    uid: getSessionKey(host),
    puid,
    hostnum: Number(hostnum),
    keys,
    tag: 'player',
  });
}

module.exports = {
  findPeopleByNumberId,
  findPeopleByNickname,
  formatBasicPlayer,
  getPlayersInfo,
  getPlayersInfoBatch,
  resolveAuthorProfile,
  resolveAuthorsBatch,
  hgetPlayerData,
  AUTHOR_FIELDS,
};
