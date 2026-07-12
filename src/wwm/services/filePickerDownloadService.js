'use strict';

const https = require('https');
const { URL } = require('url');
const {
  allCdnHosts,
  cdnHostsForShortPrefix,
  FP_OBJECT_KEY_RE,
} = require('../../config/regions');
const { UpstreamError } = require('../errors');
const logger = require('../../utils/logger');

const MAX_BYTES = Number(process.env.FILEPICKER_MAX_BYTES || 1024 * 1024); // 1MB
const TIMEOUT_MS = Number(process.env.FILEPICKER_TIMEOUT_MS || 12000);

const ALLOWLIST = new Set(allCdnHosts());

function assertSafeObjectKey(objectKey) {
  if (typeof objectKey !== 'string' || !FP_OBJECT_KEY_RE.test(objectKey)) {
    throw new UpstreamError('INVALID_SHORT_CODE', 'Invalid object key morphology', {
      retryable: false,
    });
  }
  if (objectKey.includes('..') || objectKey.includes('/') || objectKey.includes('\\')) {
    throw new UpstreamError('INVALID_SHORT_CODE', 'Object key path traversal rejected', {
      retryable: false,
    });
  }
}

function assertAllowlistedHost(hostname) {
  if (!ALLOWLIST.has(hostname)) {
    throw new UpstreamError('UNSUPPORTED_REGION', `Host not allowlisted: ${hostname}`, {
      retryable: false,
    });
  }
}

/**
 * GET https://{host}/file/{objectKey}
 * TLS verify ON. No game session. Size-capped.
 */
function downloadOnce(host, objectKey) {
  assertAllowlistedHost(host);
  assertSafeObjectKey(objectKey);

  const path = `/file/${objectKey}`;
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: host,
        path,
        method: 'GET',
        headers: {
          'User-Agent': 'FilePickerClient/1.1.0',
          Accept: '*/*',
          Host: host,
        },
        servername: host,
        timeout: TIMEOUT_MS,
        // rejectUnauthorized default true
      },
      (res) => {
        const status = res.statusCode || 0;
        // only allow same-host redirects if any
        if (status >= 300 && status < 400 && res.headers.location) {
          try {
            const loc = new URL(res.headers.location, `https://${host}`);
            if (loc.hostname !== host || !ALLOWLIST.has(loc.hostname)) {
              res.resume();
              return reject(
                new UpstreamError('FILEPICKER_INVALID_BODY', 'Redirect to non-allowlisted host', {
                  statusCode: status,
                  endpoint: host,
                  retryable: false,
                })
              );
            }
          } catch {
            res.resume();
            return reject(
              new UpstreamError('FILEPICKER_INVALID_BODY', 'Invalid redirect', {
                statusCode: status,
                endpoint: host,
                retryable: false,
              })
            );
          }
        }

        if (status === 404) {
          res.resume();
          return reject(
            new UpstreamError('FILEPICKER_NOT_FOUND', 'File not found on CDN', {
              statusCode: 404,
              endpoint: host,
              retryable: false,
            })
          );
        }
        if (status !== 200) {
          res.resume();
          return reject(
            new UpstreamError('UPSTREAM_HTTP_ERROR', `CDN HTTP ${status}`, {
              statusCode: status,
              endpoint: host,
              retryable: status >= 500,
            })
          );
        }

        const chunks = [];
        let total = 0;
        let aborted = false;
        res.on('data', (c) => {
          total += c.length;
          if (total > MAX_BYTES) {
            aborted = true;
            req.destroy();
            return reject(
              new UpstreamError('FILEPICKER_INVALID_BODY', 'Response exceeds size limit', {
                endpoint: host,
                retryable: false,
              })
            );
          }
          chunks.push(c);
        });
        res.on('end', () => {
          if (aborted) return;
          const buf = Buffer.concat(chunks);
          resolve({
            host,
            status,
            contentType: res.headers['content-type'] || '',
            body: buf,
          });
        });
      }
    );
    req.on('timeout', () => {
      req.destroy();
      reject(
        new UpstreamError('FILEPICKER_TIMEOUT', 'CDN timeout', {
          endpoint: host,
          retryable: true,
        })
      );
    });
    req.on('error', (e) => {
      const code = e.code || '';
      if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
        return reject(
          new UpstreamError('UPSTREAM_DNS_ERROR', 'CDN DNS error', {
            endpoint: host,
            retryable: true,
          })
        );
      }
      if (/timeout/i.test(e.message || '')) {
        return reject(
          new UpstreamError('FILEPICKER_TIMEOUT', 'CDN timeout', {
            endpoint: host,
            retryable: true,
          })
        );
      }
      reject(
        new UpstreamError('UPSTREAM_HTTP_ERROR', e.message || 'CDN network error', {
          endpoint: host,
          retryable: true,
        })
      );
    });
    req.end();
  });
}

/**
 * Try hosts in order for a short-code prefix region.
 */
async function downloadFaceObject({ prefix, objectKey }) {
  const hosts = cdnHostsForShortPrefix(prefix);
  if (!hosts.length) {
    throw new UpstreamError('UNSUPPORTED_REGION', 'No CDN hosts for prefix', { retryable: false });
  }

  let lastErr = null;
  let fallbackCount = 0;
  for (let i = 0; i < hosts.length; i++) {
    const host = hosts[i];
    try {
      const result = await downloadOnce(host, objectKey);
      return { ...result, fallbackCount };
    } catch (e) {
      lastErr = e;
      // try next host on not found / timeout / 5xx
      const retryNext =
        e instanceof UpstreamError &&
        (e.code === 'FILEPICKER_NOT_FOUND' ||
          e.code === 'FILEPICKER_TIMEOUT' ||
          e.code === 'UPSTREAM_DNS_ERROR' ||
          (e.code === 'UPSTREAM_HTTP_ERROR' && e.retryable));
      if (retryNext && i < hosts.length - 1) {
        fallbackCount += 1;
        logger.warn(`CDN fallback from ${host}`, { code: e.code });
        continue;
      }
      throw e;
    }
  }
  throw lastErr || new UpstreamError('FILEPICKER_NOT_FOUND', 'All CDN hosts failed');
}

module.exports = {
  downloadFaceObject,
  downloadOnce,
  assertSafeObjectKey,
  assertAllowlistedHost,
  ALLOWLIST,
  MAX_BYTES,
};
