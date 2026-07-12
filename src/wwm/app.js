'use strict';

/**
 * Express app for WWM face inventory + cache + resolve routes.
 */
try {
  require('dotenv').config();
} catch {
  /* optional */
}

const express = require('express');
const cors = require('cors');
const faceInventoryRoute = require('./routes/faceInventoryRoute');
const faceCacheRoute = require('./routes/faceCacheRoute');
const faceResolveRoute = require('./routes/faceResolveRoute');
const { isCacheEnabled, openDatabase, integrityCheck, getDb } = require('../storage/database');
const { sessionReadiness } = require('./session');

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'find-api-wwm' });
});

app.get('/ready', (_req, res) => {
  const sessions = sessionReadiness();
  let database = { ready: false, integrity: 'unknown' };
  if (isCacheEnabled()) {
    try {
      openDatabase();
      const db = getDb();
      const ic = integrityCheck(db);
      database = { ready: !!db && ic.ok, integrity: ic.result || (ic.ok ? 'ok' : 'fail') };
    } catch {
      database = { ready: false, integrity: 'error' };
    }
  } else {
    database = { ready: true, integrity: 'cache_disabled' };
  }

  const ready = database.ready && (sessions.CN || sessions.GLOBAL);
  res.status(ready ? 200 : 503).json({
    ready,
    database,
    sessions,
  });
});

app.use(faceInventoryRoute);
app.use(faceCacheRoute);
app.use(faceResolveRoute);

app.use('/api', faceInventoryRoute);
app.use('/api', faceCacheRoute);
app.use('/api', faceResolveRoute);

module.exports = app;
