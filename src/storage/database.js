'use strict';

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { migrate } = require('./migrations');
const logger = require('../utils/logger');

let _db = null;
let _dbPath = null;

function isCacheEnabled() {
  const v = process.env.ENABLE_FACE_CACHE;
  if (v === undefined || v === '') return true;
  return v === '1' || v === 'true' || v === 'TRUE';
}

function storeLongCode() {
  const v = process.env.CACHE_STORE_LONG_CODE;
  if (v === undefined || v === '') return true;
  return v === '1' || v === 'true' || v === 'TRUE';
}

function resolveDbPath(override) {
  if (override) return path.resolve(override);
  if (process.env.DATABASE_PATH) return path.resolve(process.env.DATABASE_PATH);
  return path.resolve(process.cwd(), 'data', 'faces.db');
}

function openDatabase(options = {}) {
  if (_db && !options.forceNew) return _db;
  if (!isCacheEnabled() && !options.force) {
    return null;
  }

  const dbPath = resolveDbPath(options.path);
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });

  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA busy_timeout = 5000');
  migrate(db);

  if (!options.forceNew) {
    _db = db;
    _dbPath = dbPath;
  }
  return db;
}

function getDb() {
  if (!isCacheEnabled()) return null;
  if (!_db) return openDatabase();
  return _db;
}

function closeDatabase() {
  if (_db) {
    try {
      _db.close();
    } catch {
      /* ignore */
    }
    _db = null;
    _dbPath = null;
  }
}

function integrityCheck(db = getDb()) {
  if (!db) return { ok: false, error: 'no_db' };
  const row = db.prepare('PRAGMA integrity_check').get();
  const val = row?.integrity_check || Object.values(row || {})[0];
  return { ok: val === 'ok', result: val };
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

// graceful close
process.on('exit', () => {
  try {
    closeDatabase();
  } catch {
    /* ignore */
  }
});

module.exports = {
  openDatabase,
  getDb,
  closeDatabase,
  isCacheEnabled,
  storeLongCode,
  resolveDbPath,
  integrityCheck,
  nowSec,
  getDbPath: () => _dbPath,
};
