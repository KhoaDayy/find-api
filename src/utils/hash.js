'use strict';

const crypto = require('crypto');

/**
 * Normalize face long-code for hashing.
 * - trim ends
 * - strip CR/LF and other whitespace introduced by Discord/paste
 * - do NOT alter internal payload characters (base64-ish, |*|, etc.)
 */
function normalizeFaceData(faceData) {
  if (faceData == null) return '';
  return String(faceData)
    .replace(/[\r\n\t\v\f]+/g, '')
    .replace(/ +/g, '') // Discord often injects spaces on wrap; face payload has no spaces
    .trim();
}

function hashFaceData(faceData) {
  const normalized = normalizeFaceData(faceData);
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

module.exports = {
  normalizeFaceData,
  hashFaceData,
};
