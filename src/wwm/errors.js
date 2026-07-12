'use strict';

/**
 * Structured upstream / domain errors — never embed session values.
 */
class UpstreamError extends Error {
  constructor(code, message, { statusCode = null, endpoint = null, region = null, retryable = false } = {}) {
    super(message || code);
    this.name = 'UpstreamError';
    this.code = code;
    this.statusCode = statusCode;
    this.endpoint = endpoint;
    this.region = region;
    this.retryable = !!retryable;
  }
}

const HTTP_STATUS = {
  PLAYER_NOT_FOUND: 404,
  INVALID_SHORT_CODE: 400,
  UNSUPPORTED_REGION: 400,
  FILEPICKER_NOT_FOUND: 404,
  FILEPICKER_TIMEOUT: 502,
  FILEPICKER_INVALID_BODY: 422,
  FACE_DATA_INVALID: 422,
  CACHE_CONFLICT: 409,
  SESSION_NOT_CONFIGURED: 503,
  UPSTREAM_TIMEOUT: 502,
  UPSTREAM_DNS_ERROR: 502,
  UPSTREAM_TLS_ERROR: 502,
  UPSTREAM_HTTP_ERROR: 502,
  UPSTREAM_AUTH_FAILED: 503,
  DECODE_FAILED: 502,
  INTERNAL_ERROR: 500,
};

function httpStatusForCode(code) {
  return HTTP_STATUS[code] || 500;
}

function toApiError(err) {
  if (err instanceof UpstreamError) {
    return {
      status: httpStatusForCode(err.code),
      body: {
        success: false,
        error: err.code,
        message: err.message,
        retryable: err.retryable,
        endpoint: err.endpoint || undefined,
      },
    };
  }
  if (err && err.status && err.code) {
    return {
      status: err.status,
      body: { success: false, error: err.code, message: err.message },
    };
  }
  return {
    status: 500,
    body: { success: false, error: 'INTERNAL_ERROR', message: 'Internal error' },
  };
}

module.exports = {
  UpstreamError,
  HTTP_STATUS,
  httpStatusForCode,
  toApiError,
};
