'use strict';

const express = require('express');
const { resolveShortCode } = require('../services/shortCodeResolveService');
const { UpstreamError, toApiError } = require('../errors');
const logger = require('../../utils/logger');

const router = express.Router();

function parseFlag(v, def) {
  if (v === undefined || v === null || v === '') return def;
  if (v === true || v === 1 || v === '1' || v === 'true') return true;
  if (v === false || v === 0 || v === '0' || v === 'false') return false;
  return def;
}

async function handleResolve(input, opts, res) {
  if (!input || !String(input).trim()) {
    return res.status(400).json({
      success: false,
      error: 'INVALID_SHORT_CODE',
      message: 'Missing input short code',
    });
  }
  try {
    const result = await resolveShortCode({
      input: String(input).trim(),
      includeLongCode: opts.includeLongCode,
      persist: opts.persist,
    });
    return res.json(result);
  } catch (e) {
    if (e instanceof UpstreamError) {
      const mapped = toApiError(e);
      logger.error('face_resolve failed', { code: e.code });
      return res.status(mapped.status).json(mapped.body);
    }
    logger.error('face_resolve internal', { err: e.message });
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal error',
    });
  }
}

/**
 * POST /face_resolve
 * Body: { input, include_long_code?, persist? }
 */
router.post('/face_resolve', async (req, res) => {
  const body = req.body || {};
  return handleResolve(body.input || body.code, {
    includeLongCode: parseFlag(body.include_long_code, true),
    persist: parseFlag(body.persist, true),
  }, res);
});

/**
 * GET /face_resolve?code=...
 */
router.get('/face_resolve', async (req, res) => {
  return handleResolve(req.query.code || req.query.input, {
    includeLongCode: parseFlag(req.query.include_long_code, true),
    persist: parseFlag(req.query.persist, true),
  }, res);
});

module.exports = router;
