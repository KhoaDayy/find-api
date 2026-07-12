'use strict';

const https = require('https');
const dns = require('dns');
const zlib = require('zlib');
const msgpack = require('msgpack-lite');
const { getSessionKey } = require('./session');
const { UpstreamError } = require('./errors');
const logger = require('../utils/logger');

const dnsCache = new Map();
const googleDns = new dns.Resolver();
googleDns.setServers(['8.8.8.8', '8.8.4.4']);

const httpsAgent = new https.Agent({ keepAlive: true });

async function resolveHost(hostname) {
  const hit = dnsCache.get(hostname);
  if (hit && Date.now() - hit.ts < 300000) return hit.ip;
  try {
    const addrs = await new Promise((resolve, reject) => {
      googleDns.resolve4(hostname, (err, a) => (err ? reject(err) : resolve(a)));
    });
    const ip = addrs[0];
    dnsCache.set(hostname, { ip, ts: Date.now() });
    logger.debug(`DNS ${hostname} -> ${ip}`);
    return ip;
  } catch (e) {
    throw new UpstreamError('UPSTREAM_DNS_ERROR', `DNS resolve failed for ${hostname}`, {
      endpoint: hostname,
      retryable: true,
    });
  }
}

function convertBytesToStr(obj) {
  if (Buffer.isBuffer(obj)) {
    try {
      return obj.toString('utf8');
    } catch {
      return obj.toString('hex');
    }
  }
  if (Array.isArray(obj)) return obj.map(convertBytesToStr);
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const k of Object.keys(obj)) out[k] = convertBytesToStr(obj[k]);
    return out;
  }
  return obj;
}

function classifyNetError(err, endpoint) {
  const msg = err?.message || String(err);
  const code = err?.code || '';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || /getaddrinfo/i.test(msg)) {
    return new UpstreamError('UPSTREAM_DNS_ERROR', 'DNS error', { endpoint, retryable: true });
  }
  if (
    code === 'CERT_HAS_EXPIRED' ||
    code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
    code === 'ERR_TLS_CERT_ALTNAME_INVALID' ||
    /certificate|SSL|TLS/i.test(msg)
  ) {
    return new UpstreamError('UPSTREAM_TLS_ERROR', 'TLS error', { endpoint, retryable: false });
  }
  if (code === 'ETIMEDOUT' || code === 'ESOCKETTIMEDOUT' || /timeout/i.test(msg)) {
    return new UpstreamError('UPSTREAM_TIMEOUT', 'Upstream timeout', { endpoint, retryable: true });
  }
  return new UpstreamError('UPSTREAM_HTTP_ERROR', msg || 'Network error', {
    endpoint,
    retryable: true,
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Single attempt msgpack POST. Throws UpstreamError — never returns null on failure.
 */
async function msgpackRequestOnce(host, endpoint, payload = null, customBuffer = null) {
  const session = getSessionKey(host);
  if (!session) {
    throw new UpstreamError('SESSION_NOT_CONFIGURED', 'Session not configured for host', {
      endpoint,
      retryable: false,
    });
  }

  const body = customBuffer || (payload ? msgpack.encode(payload) : Buffer.alloc(0));
  let realIp;
  try {
    realIp = await resolveHost(host);
  } catch (e) {
    if (e instanceof UpstreamError) throw e;
    throw classifyNetError(e, endpoint);
  }

  const path = `${endpoint}?session=${encodeURIComponent(session)}`;

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: realIp,
        path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/msgpack',
          'Content-Length': body.length,
          'h72-ms-uid': session,
          Host: host,
        },
        servername: host,
        agent: httpsAgent,
        timeout: 12000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let buf = Buffer.concat(chunks);
          const status = res.statusCode || 0;

          if (status === 401 || status === 403) {
            return reject(
              new UpstreamError('UPSTREAM_AUTH_FAILED', `Auth failed HTTP ${status}`, {
                statusCode: status,
                endpoint,
                retryable: false,
              })
            );
          }
          if (status >= 500) {
            return reject(
              new UpstreamError('UPSTREAM_HTTP_ERROR', `Upstream HTTP ${status}`, {
                statusCode: status,
                endpoint,
                retryable: true,
              })
            );
          }
          if (status !== 200) {
            return reject(
              new UpstreamError('UPSTREAM_HTTP_ERROR', `Upstream HTTP ${status}`, {
                statusCode: status,
                endpoint,
                retryable: false,
              })
            );
          }

          try {
            if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) buf = zlib.gunzipSync(buf);
            else if (buf.length >= 1 && buf[0] === 0x78) buf = zlib.inflateSync(buf);
          } catch {
            /* not compressed */
          }

          try {
            return resolve(convertBytesToStr(msgpack.decode(buf)));
          } catch {
            try {
              return resolve(JSON.parse(buf.toString('utf8')));
            } catch {
              return reject(
                new UpstreamError('DECODE_FAILED', 'Failed to decode upstream response', {
                  endpoint,
                  retryable: false,
                })
              );
            }
          }
        });
      }
    );

    req.on('error', (e) => reject(classifyNetError(e, endpoint)));
    req.on('timeout', () => {
      req.destroy();
      reject(
        new UpstreamError('UPSTREAM_TIMEOUT', 'Upstream timeout', {
          endpoint,
          retryable: true,
        })
      );
    });
    req.write(body);
    req.end();
  });
}

/**
 * Msgpack request with at most 1 retry for retryable errors.
 * Jitter 150–300ms. No retry on auth / player_not_found / decode.
 */
async function msgpackRequest(host, endpoint, payload = null, customBuffer = null) {
  try {
    return await msgpackRequestOnce(host, endpoint, payload, customBuffer);
  } catch (e) {
    if (!(e instanceof UpstreamError) || !e.retryable) throw e;
    const jitter = 150 + Math.floor(Math.random() * 151);
    logger.warn(`retry ${endpoint} after ${jitter}ms`, { code: e.code });
    await sleep(jitter);
    return msgpackRequestOnce(host, endpoint, payload, customBuffer);
  }
}

module.exports = {
  msgpackRequest,
  msgpackRequestOnce,
  resolveHost,
  UpstreamError,
};
