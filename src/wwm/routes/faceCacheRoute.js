'use strict';

const express = require('express');
const { getByFaceHash, lookupByAlias } = require('../services/cacheLookupService');
const { isCacheEnabled } = require('../../storage/database');

const router = express.Router();

function parseFlag(v, def = false) {
  if (v === undefined || v === null || v === '') return def;
  return v === '1' || v === 'true' || v === true;
}

router.get('/face_cache/lookup', (req, res) => {
  if (!isCacheEnabled()) {
    return res.status(503).json({ success: false, error: 'cache_disabled' });
  }
  const alias = req.query.alias;
  if (!alias) {
    return res.status(400).json({ success: false, error: 'missing_alias' });
  }
  const result = lookupByAlias(alias, {
    includeLongCode: parseFlag(req.query.include_long_code, true),
    includeRaw: parseFlag(req.query.include_raw, false),
  });
  if (!result.ok) {
    const status = result.error === 'not_found' ? 404 : 400;
    return res.status(status).json({ success: false, error: result.error });
  }
  return res.json({ success: true, ...result.data });
});

router.get('/face_cache/:faceHash', (req, res) => {
  if (!isCacheEnabled()) {
    return res.status(503).json({ success: false, error: 'cache_disabled' });
  }
  const result = getByFaceHash(req.params.faceHash, {
    includeLongCode: parseFlag(req.query.include_long_code, true),
    includeRaw: parseFlag(req.query.include_raw, false),
  });
  if (!result.ok) {
    const status = result.error === 'not_found' ? 404 : 400;
    return res.status(status).json({ success: false, error: result.error });
  }
  return res.json({ success: true, ...result.data });
});

module.exports = router;
