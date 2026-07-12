'use strict';

const express = require('express');
const {
  inspectPlayerInventory,
  validateInventoryQuery,
  InventoryError,
} = require('../services/inventoryService');
const { UpstreamError, toApiError } = require('../errors');
const logger = require('../../utils/logger');

const router = express.Router();

/**
 * GET /face_inventory
 * Community inventory → long Face Data (read-only).
 * Does NOT return FilePicker face short codes.
 */
router.get('/face_inventory', async (req, res) => {
  try {
    const q = validateInventoryQuery(req.query);
    const result = await inspectPlayerInventory({
      id: q.id,
      name: q.name,
      region: q.server,
      includeRaw: q.includeRaw,
      includeLongCode: q.includeLongCode,
      includeEmptyPlans: q.includeEmptyPlans,
      type: q.type,
      persist: q.persist,
    });
    return res.json(result);
  } catch (e) {
    if (e instanceof InventoryError) {
      return res.status(e.status).json({
        success: false,
        error: e.code,
        message: e.message,
      });
    }
    if (e instanceof UpstreamError) {
      const mapped = toApiError(e);
      logger.error('face_inventory upstream', { code: e.code, endpoint: e.endpoint });
      return res.status(mapped.status).json(mapped.body);
    }
    logger.error('face_inventory failed', { err: e.message });
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal error',
    });
  }
});

module.exports = router;
