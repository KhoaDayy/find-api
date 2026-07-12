'use strict';

const fs = require('fs');
const path = require('path');
try {
  require('dotenv').config();
} catch {
  /* optional */
}
const { REGIONS } = require('../config/regions');

/**
 * Dual session: CN vs Global/SEA.
 * Sources (first hit wins per region):
 *   env WWM_SESSION_KEY_CN / WWM_SESSION_KEY_GLOBAL
 *   env GAME_SESSION (fallback both)
 *   session.cn.txt / session.global.txt / session.txt
 */
function readFileIfExists(p) {
  try {
    if (fs.existsSync(p)) {
      const v = fs.readFileSync(p, 'utf8').trim();
      if (v.length > 5) return v;
    }
  } catch {
    /* ignore */
  }
  return null;
}

function projectRoot() {
  return path.resolve(__dirname, '..', '..');
}

function getSessionKey(regionOrHost) {
  const root = projectRoot();
  const isCN =
    regionOrHost === 'CN' ||
    regionOrHost === REGIONS.CN.apiHost ||
    regionOrHost === REGIONS.CN ||
    (typeof regionOrHost === 'number' && regionOrHost < 10400);

  if (isCN) {
    return (
      process.env.WWM_SESSION_KEY_CN ||
      process.env.CN_SESSION ||
      process.env.GAME_SESSION ||
      readFileIfExists(path.join(root, 'session.cn.txt')) ||
      readFileIfExists(path.join(root, 'session.txt')) ||
      ''
    );
  }

  return (
    process.env.WWM_SESSION_KEY_GLOBAL ||
    process.env.GLOBAL_SESSION ||
    process.env.GAME_SESSION ||
    readFileIfExists(path.join(root, 'session.global.txt')) ||
    readFileIfExists(path.join(root, 'session.txt')) ||
    ''
  );
}

function resolveRegion(server) {
  const s = String(server || 'SEA').toUpperCase();
  if (s === 'CN' || s === 'CHINA') return REGIONS.CN;
  return REGIONS.SEA;
}

function hasSession(regionOrHost) {
  return !!getSessionKey(regionOrHost);
}

function sessionReadiness() {
  return {
    CN: hasSession('CN'),
    GLOBAL: hasSession('SEA'),
  };
}

module.exports = {
  getSessionKey,
  resolveRegion,
  hasSession,
  sessionReadiness,
};
