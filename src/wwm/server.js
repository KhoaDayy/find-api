'use strict';

const app = require('./app');
const { closeDatabase, getDb, openDatabase, isCacheEnabled } = require('../storage/database');
const logger = require('../utils/logger');

const PORT = Number(process.env.PORT || process.env.WWM_PORT || 3005);

let server = null;
let shuttingDown = false;

function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info(`shutdown ${signal}`);

  const done = () => {
    try {
      if (isCacheEnabled()) {
        const db = getDb() || openDatabase();
        if (db) {
          try {
            db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
          } catch {
            /* ignore */
          }
        }
      }
      closeDatabase();
    } catch {
      /* ignore */
    }
    process.exit(0);
  };

  if (server) {
    server.close(() => done());
    setTimeout(done, 5000).unref();
  } else {
    done();
  }
}

if (require.main === module) {
  // warm DB
  try {
    if (isCacheEnabled()) openDatabase();
  } catch (e) {
    logger.warn('db warm failed', { err: e.message });
  }

  server = app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`[READY] WWM API on http://localhost:${PORT}`);
    // eslint-disable-next-line no-console
    console.log('  GET  /health  /ready');
    // eslint-disable-next-line no-console
    console.log('  GET  /face_inventory?id=...&server=CN');
    // eslint-disable-next-line no-console
    console.log('  POST /face_resolve  { "input": "wwm_facedata_R37_..." }');
  });

  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
}

module.exports = app;
