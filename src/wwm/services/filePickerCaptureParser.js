'use strict';

/**
 * Parse user-supplied FilePicker capture (HAR / JSON / log text).
 * Never stores raw tokens — only redacted metadata + schema.
 */

const { redact } = require('../../utils/redact');
const { isLongFaceData } = require('../../parsers/faceDataParser');
const { normalizeFaceData, hashFaceData } = require('../../utils/hash');
const { isFilePickerObjectKey } = require('../../parsers/shortCodeParser');
const { REGIONS, allCdnHosts } = require('../../config/regions');

const FACE_TAG = '_face_123_face_';
const SECRET_HEADER = /^(authorization|cookie|set-cookie|x-auth|token|server.?token|h72-ms-uid)$/i;

const UPLOAD_HOSTS = new Set([
  'fp.ps.netease.com',
  'fp.ps.easebar.com',
  tryHost(REGIONS.CN.faceFilePickerUploadUrl),
  tryHost(REGIONS.SEA.faceFilePickerUploadUrl),
].filter(Boolean));

const DOWNLOAD_HOSTS = new Set(allCdnHosts());

function tryHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function redactHeaders(headers) {
  if (!headers || typeof headers !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (SECRET_HEADER.test(k)) out[k] = '***';
    else if (typeof v === 'string' && v.includes(FACE_TAG)) out[k] = FACE_TAG + '***';
    else out[k] = typeof v === 'string' && v.length > 80 ? `${v.slice(0, 12)}…(len=${v.length})` : v;
  }
  return out;
}

function redactToken(token) {
  if (!token || typeof token !== 'string') return { token_redacted: null, token_length: 0, tagged: false };
  const tagged = token.startsWith(FACE_TAG);
  return {
    tagged,
    tag_prefix: tagged ? FACE_TAG : null,
    token_length: token.length,
    token_redacted: tagged ? `${FACE_TAG}***` : '***',
  };
}

function classifyBody(body, contentType) {
  const ct = String(contentType || '').toLowerCase();
  let text = null;
  if (Buffer.isBuffer(body)) text = body.toString('utf8');
  else if (typeof body === 'string') text = body;
  else if (body && typeof body === 'object') {
    return {
      body_type: 'json_object',
      body_length: JSON.stringify(body).length,
      body_schema: schemaOf(body),
      face_hash: extractFaceHashFromValue(body),
      parsed: body,
    };
  }

  if (text == null) {
    return { body_type: 'unknown', body_length: 0, body_schema: [], face_hash: null, parsed: null };
  }

  const trimmed = text.trim();
  const body_length = Buffer.byteLength(text, 'utf8');

  if (ct.includes('multipart') || trimmed.startsWith('--')) {
    return {
      body_type: 'multipart',
      body_length,
      body_schema: ['<multipart — fields not guessed>'],
      face_hash: null,
      parsed: null,
    };
  }

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const json = JSON.parse(trimmed);
      return {
        body_type: 'json',
        body_length,
        body_schema: schemaOf(json),
        face_hash: extractFaceHashFromValue(json),
        parsed: json,
      };
    } catch {
      return { body_type: 'text_invalid_json', body_length, body_schema: [], face_hash: null, parsed: null };
    }
  }

  if (/^[RD]67/i.test(trimmed) || isLongFaceData(trimmed)) {
    const norm = normalizeFaceData(trimmed);
    return {
      body_type: 'raw_face_data',
      body_length,
      body_schema: ['raw_face_data'],
      face_hash: hashFaceData(norm),
      parsed: { __raw_face__: true, length: norm.length, sha256: hashFaceData(norm) },
    };
  }

  if (ct.includes('x-www-form-urlencoded') || trimmed.includes('=') && trimmed.includes('&')) {
    return {
      body_type: 'form',
      body_length,
      body_schema: ['<form — fields not guessed>'],
      face_hash: null,
      parsed: null,
    };
  }

  return { body_type: 'raw', body_length, body_schema: ['raw'], face_hash: null, parsed: null };
}

function schemaOf(obj, prefix = '', depth = 0, out = []) {
  if (depth > 4 || obj == null) return out;
  if (Array.isArray(obj)) {
    out.push(prefix ? `${prefix}[]` : '[]');
    if (obj[0] && typeof obj[0] === 'object') schemaOf(obj[0], `${prefix}[]`, depth + 1, out);
    return out;
  }
  if (typeof obj !== 'object') {
    out.push(prefix || typeof obj);
    return out;
  }
  for (const k of Object.keys(obj)) {
    const p = prefix ? `${prefix}.${k}` : k;
    const v = obj[k];
    if (typeof v === 'string' && isLongFaceData(v)) out.push(`${p}:face_data`);
    else if (v && typeof v === 'object' && !Array.isArray(v)) {
      out.push(`${p}:object`);
      schemaOf(v, p, depth + 1, out);
    } else out.push(`${p}:${Array.isArray(v) ? 'array' : typeof v}`);
  }
  return out;
}

function extractFaceHashFromValue(obj) {
  if (!obj) return null;
  if (typeof obj === 'string' && isLongFaceData(obj)) return hashFaceData(obj);
  if (typeof obj === 'object') {
    if (typeof obj.face_data === 'string' && isLongFaceData(obj.face_data)) {
      return hashFaceData(obj.face_data);
    }
    if (obj.view_data) {
      try {
        const vd = typeof obj.view_data === 'string' ? JSON.parse(obj.view_data) : obj.view_data;
        if (vd && typeof vd.face_data === 'string') return hashFaceData(vd.face_data);
      } catch {
        /* ignore */
      }
    }
  }
  return null;
}

function parseObjectKeyFromUrl(url) {
  if (!url || typeof url !== 'string') return null;
  const m = url.match(/\/file\/([0-9a-f]{24}[A-Za-z0-9]{8}[0-9]{2})/i);
  if (m && isFilePickerObjectKey(m[1])) return m[1];
  return null;
}

function isUploadUrl(url) {
  try {
    const u = new URL(url);
    return UPLOAD_HOSTS.has(u.hostname) && /\/file\/new\/?$/i.test(u.pathname);
  } catch {
    return false;
  }
}

function isDownloadUrl(url) {
  try {
    const u = new URL(url);
    return DOWNLOAD_HOSTS.has(u.hostname) && /\/file\//i.test(u.pathname);
  } catch {
    return false;
  }
}

/**
 * Normalize one HTTP request-like object.
 */
function normalizeHttpEntry(entry) {
  const req = entry.request || entry.req || entry;
  const res = entry.response || entry.res || {};
  const url = req.url || req.uri || entry.url || '';
  const method = (req.method || entry.method || 'GET').toUpperCase();
  let headers = req.headers || entry.headers || {};
  if (Array.isArray(headers)) {
    const h = {};
    for (const x of headers) h[x.name || x.key] = x.value;
    headers = h;
  }
  let body = req.body || req.postData?.text || req.data || entry.body || null;
  const contentType =
    headers['Content-Type'] ||
    headers['content-type'] ||
    req.postData?.mimeType ||
    entry.content_type ||
    '';

  // response may be nested under entry.response or top-level fields on plain objects
  let resBody =
    res.content?.text ||
    res.body ||
    entry.response_body ||
    (entry.response && typeof entry.response === 'object' && !entry.response.content
      ? entry.response.body
      : null);
  // support test shape: response: { status, body }
  if (entry.response && entry.response.body != null && resBody == null) {
    resBody = entry.response.body;
  }
  let resStatus = res.status || res.statusCode || entry.status || entry.response?.status || null;

  return { method, url, headers, body, contentType, resBody, resStatus };
}

function extractTokenFromHeaders(headers) {
  for (const [k, v] of Object.entries(headers || {})) {
    if (typeof v === 'string' && (SECRET_HEADER.test(k) || v.includes(FACE_TAG) || /token/i.test(k))) {
      return { header: k, ...redactToken(v) };
    }
  }
  return null;
}

/**
 * Parse HAR JSON.
 */
function parseHar(har) {
  const entries = har?.log?.entries || har?.entries || [];
  const http = entries.map((e) => {
    const n = normalizeHttpEntry({
      request: e.request,
      response: e.response,
    });
    return n;
  });
  return parseHttpList(http);
}

/**
 * Parse array of HTTP-like objects or a single capture bundle.
 */
function parseJsonlCapture(text) {
  const lines = String(text).split(/\r?\n/).filter((l) => l.trim());
  const events = [];
  for (const line of lines) {
    try {
      events.push(JSON.parse(line));
    } catch {
      /* skip bad line */
    }
  }

  const out = {
    token_request: null,
    token_response: null,
    upload_request: null,
    upload_response: null,
    notes: ['parsed_from_jsonl', `events:${events.length}`],
    events,
  };

  for (const ev of events) {
    const e = (ev && ev.event) || '';
    const d = (ev && ev.data) || {};
    if (e === 'token_rpc_request' || e === 'rpc_gen_filepicker_token') {
      out.token_request = {
        params: d.params || null,
        usage: d.usage ?? null,
        url: d.url ?? null,
        review: d.review ?? d.hex_fp_review_id ?? null,
        via: d.via || e,
        share_id: ev.share_id || null,
      };
    }
    if (e === 'token_rpc_response' || e === 'rpc_server_filepicker_token') {
      out.token_response = {
        tagged: !!d.token_tagged,
        tag_prefix: d.token_prefix || (d.token_tagged ? '_face_123_face_' : null),
        token_length: d.token_length || 0,
        token_redacted: d.token || '***',
        usage: d.usage ?? null,
        url: d.url ?? null,
        review: d.review ?? null,
        share_id: ev.share_id || null,
      };
    }
    if (e === 'upload_plain_text' || e === 'real_upload') {
      const content = d.content || d.request_body || {};
      out.upload_request = {
        method: 'POST',
        url: d.fp_post_url || d.url || null,
        headers: {},
        content_type: null,
        body_type: content.content_kind || d.body_kind || 'unknown',
        body_length: content.content_length || d.body_length || 0,
        body_schema: content.content_keys || [],
        face_hash: content.face_data?.sha256 || content.face_data?.hash_djb2 || null,
        body_identity: {
          pid: content.pid ?? d.pid ?? null,
          hostnum: content.hostnum ?? d.hostnum ?? null,
          face_share_type: content.face_share_type ?? d.face_share_type ?? null,
          has_dressing: content.has_dressing ?? d.has_dressing ?? null,
        },
        share_id: ev.share_id || null,
        source: ev.source || 'lua',
      };
    }
    if (e === 'http_exchange') {
      const reqBody = d.request_body || {};
      const isPost = (d.method || '').toUpperCase() === 'POST';
      if (isPost || (d.path && /file\/new/i.test(d.path))) {
        out.upload_request = {
          method: d.method || 'POST',
          url: d.host && d.path ? `https://${d.host}${d.path}` : d.path || null,
          headers: d.headers || {},
          content_type: null,
          body_type: reqBody.body_kind || 'unknown',
          body_length: reqBody.body_length || 0,
          body_schema: reqBody.top_level_keys || [],
          face_hash: reqBody.face_data?.sha256 || reqBody.body_sha256 || null,
          body_identity: {
            pid: reqBody.pid ?? null,
            hostnum: reqBody.hostnum ?? null,
            face_share_type: reqBody.face_share_type ?? null,
            has_dressing: reqBody.has_dressing ?? null,
          },
          share_id: ev.share_id || null,
          source: 'winhttp',
        };
        out.upload_response = {
          status: d.response_status ?? null,
          pict_url: d.pict_url || null,
          object_key: d.object_key || parseObjectKeyFromUrl(d.pict_url || ''),
          body_keys: [],
        };
      }
    }
    if (e === 'filepicker_callback') {
      out.upload_response = {
        status: d.success ? 200 : null,
        pict_url: d.pict_url || null,
        object_key: d.object_key || parseObjectKeyFromUrl(d.pict_url || ''),
        body_keys: d.detail_keys || [],
        share_id: ev.share_id || null,
      };
    }
  }
  return out;
}

function parseCapture(input) {
  if (typeof input === 'string') {
    const trimmed = input.trim();
    // JSONL: multiple lines of JSON objects
    if (trimmed.includes('\n') && trimmed.split(/\r?\n/).filter(Boolean).length > 1) {
      const first = trimmed.split(/\r?\n/).find((l) => l.trim());
      try {
        const o = JSON.parse(first);
        if (o && (o.schema_version || o.event)) return parseJsonlCapture(trimmed);
      } catch {
        /* fall through */
      }
    }
    // single-line JSONL / JSON
    try {
      const o = JSON.parse(trimmed);
      if (o && o.schema_version && o.event) return parseJsonlCapture(trimmed);
      return parseCapture(o);
    } catch {
      return parseLogText(trimmed);
    }
  }

  // HAR: has log.entries (Chrome) or top-level entries with nested request objects
  if (input?.log?.entries) return parseHar(input);
  if (Array.isArray(input?.entries) && input.entries[0]?.request) return parseHar(input);

  // Bundle: { entries: [ { method, url, headers, body, response } ] }
  if (Array.isArray(input?.entries)) {
    return parseHttpList(input.entries.map(normalizeHttpEntry));
  }

  // Plain array of HTTP-like objects (not HAR)
  if (Array.isArray(input)) return parseHttpList(input.map(normalizeHttpEntry));

  // bundle shape
  if (input.token_request || input.upload_request || input.http) {
    return finalizeBundle(input);
  }

  // single http entry
  if (input.url || input.request || input.method) {
    return parseHttpList([normalizeHttpEntry(input)]);
  }

  return finalizeBundle({});
}

function parseHttpList(list) {
  const out = {
    token_request: null,
    token_response: null,
    upload_request: null,
    upload_response: null,
    notes: [],
  };

  for (const e of list) {
    const url = e.url || '';
    // token RPC is game API — look for gen_filepicker in path/body
    if (/filepicker_token|gen_filepicker|rpc_gen_filepicker/i.test(url + JSON.stringify(e.body || ''))) {
      out.token_request = {
        params: redact(typeof e.body === 'object' ? e.body : { raw_type: typeof e.body }),
        usage: e.body?.usage ?? null,
        url: e.body?.url ?? null,
        review: e.body?.review ?? e.body?.review_id ?? null,
        method: e.method,
        request_url: url,
      };
      if (e.resBody) {
        let tr = e.resBody;
        try {
          tr = typeof tr === 'string' ? JSON.parse(tr) : tr;
        } catch {
          /* keep */
        }
        const tok =
          tr?.server_token || tr?.token || (typeof tr === 'string' ? tr : null);
        out.token_response = {
          ...redactToken(typeof tok === 'string' ? tok : ''),
          raw_keys: tr && typeof tr === 'object' ? Object.keys(tr) : [],
        };
      }
    }

    const looksLikeUpload =
      isUploadUrl(url) ||
      (e.method === 'POST' &&
        /\/file\/new\/?/i.test(url) &&
        /fp\.ps\.(netease|easebar)\.com/i.test(url));
    if (looksLikeUpload) {
      const classified = classifyBody(e.body, e.contentType);
      const tokHdr = extractTokenFromHeaders(e.headers);
      out.upload_request = {
        method: e.method,
        url,
        headers: redactHeaders(e.headers),
        content_type: e.contentType || null,
        body_type: classified.body_type,
        body_length: classified.body_length,
        body_schema: classified.body_schema,
        face_hash: classified.face_hash,
        token_in_headers: tokHdr,
        // preserve identity fields if JSON
        body_identity: extractIdentity(classified.parsed),
      };

      let pict = null;
      let object_key = null;
      if (e.resBody) {
        let rb = e.resBody;
        try {
          rb = typeof rb === 'string' ? JSON.parse(rb) : rb;
        } catch {
          /* text */
        }
        pict =
          rb?.detail?.pict_url ||
          rb?.pict_url ||
          rb?.url ||
          (typeof rb === 'string' && rb.includes('/file/') ? rb : null);
        object_key = parseObjectKeyFromUrl(pict || '') || rb?.object_key || null;
        out.upload_response = {
          status: e.resStatus,
          pict_url: pict,
          object_key,
          body_keys: rb && typeof rb === 'object' ? Object.keys(rb) : [],
        };
      } else {
        out.upload_response = { status: e.resStatus, pict_url: null, object_key: null };
      }
    }
  }

  return finalizeBundle(out);
}

function extractIdentity(parsed) {
  if (!parsed || typeof parsed !== 'object' || parsed.__raw_face__) return null;
  return {
    pid: parsed.pid ?? null,
    hostnum: parsed.hostnum ?? null,
    face_share_type: parsed.face_share_type ?? null,
    has_dressing: !!parsed.dressing,
    has_face_data: typeof parsed.face_data === 'string' || !!parsed.face_data?.__face_data__,
    keys: Object.keys(parsed),
  };
}

function parseLogText(text) {
  const out = {
    token_request: null,
    token_response: null,
    upload_request: null,
    upload_response: null,
    notes: ['parsed_from_log_text'],
  };

  // token tag
  const tagM = text.match(/(_face_123_face_)[A-Za-z0-9+/=_-]{8,}/);
  if (tagM) {
    out.token_response = redactToken(tagM[0]);
  }

  // pict_url
  const pictM = text.match(/https?:\/\/[^\s"'\\]+\/file\/[0-9a-f]{24}[A-Za-z0-9]{8}[0-9]{2}/i);
  if (pictM) {
    out.upload_response = {
      status: null,
      pict_url: pictM[0],
      object_key: parseObjectKeyFromUrl(pictM[0]),
    };
  }

  // upload URL
  const upM = text.match(/https?:\/\/fp\.ps\.(netease|easebar)\.com\/h72face[a-z]*\/file\/new\/?/i);
  if (upM) {
    out.upload_request = {
      method: 'POST',
      url: upM[0],
      headers: {},
      content_type: null,
      body_type: 'unknown',
      body_length: 0,
      body_schema: [],
      face_hash: null,
      token_in_headers: null,
      body_identity: null,
    };
  }

  // review ids mentioned
  const reviews = [];
  if (/\b129\b/.test(text)) reviews.push(129);
  if (/\b12\b/.test(text) && /review/i.test(text)) reviews.push(12);
  if (reviews.length) out.notes.push(`review_ids_seen:${reviews.join(',')}`);

  return finalizeBundle(out);
}

function finalizeBundle(partial) {
  return {
    token_request: partial.token_request || null,
    token_response: partial.token_response || null,
    upload_request: partial.upload_request || null,
    upload_response: partial.upload_response || null,
    notes: partial.notes || [],
  };
}

/**
 * Diff upload body identity vs downloaded wrapper (sanitized-friendly).
 */
function correlateUploadWithDownload(uploadParsed, downloadWrapper) {
  if (!uploadParsed && !downloadWrapper) {
    return { case: 'D', reason: 'no_data' };
  }

  const upType = uploadParsed?.body_type;
  if (upType === 'raw_face_data') {
    const upHash = uploadParsed.face_hash;
    let dlHash = null;
    if (downloadWrapper?.face_data) {
      const fd =
        typeof downloadWrapper.face_data === 'string'
          ? downloadWrapper.face_data
          : null;
      if (fd) dlHash = hashFaceData(fd);
      else if (downloadWrapper.face_data?.sha256) dlHash = downloadWrapper.face_data.sha256;
    }
    return {
      case: 'B',
      reason: 'upload_raw_face_data',
      same_face_hash: upHash && dlHash ? upHash === dlHash : null,
      upload_face_hash: upHash,
      download_face_hash: dlHash,
    };
  }

  if (upType === 'multipart') {
    return { case: 'C', reason: 'upload_multipart_not_field_guessed' };
  }

  if (upType === 'json' || upType === 'json_object') {
    const id = uploadParsed.body_identity || extractIdentity(uploadParsed.parsed);
    const dl = downloadWrapper || {};
    const fields = ['pid', 'hostnum', 'face_share_type'];
    const field_compare = {};
    for (const f of fields) {
      field_compare[f] = {
        upload: id?.[f] ?? uploadParsed.parsed?.[f] ?? null,
        download: dl[f] ?? null,
        same:
          (id?.[f] ?? uploadParsed.parsed?.[f] ?? null) === (dl[f] ?? null) ||
          String(id?.[f] ?? uploadParsed.parsed?.[f] ?? '') === String(dl[f] ?? ''),
      };
    }
    const upHash = uploadParsed.face_hash;
    let dlHash = null;
    if (typeof dl.face_data === 'string') dlHash = hashFaceData(dl.face_data);
    else if (dl.face_data?.sha256) dlHash = dl.face_data.sha256;

    const dressing_same =
      id?.has_dressing != null
        ? id.has_dressing === !!dl.dressing
        : !!uploadParsed.parsed?.dressing === !!dl.dressing;

    return {
      case: 'A',
      reason: 'upload_json_wrapper',
      field_compare,
      dressing_present_both: dressing_same,
      same_face_hash: upHash && dlHash ? upHash === dlHash : null,
      upload_keys: id?.keys || (uploadParsed.parsed ? Object.keys(uploadParsed.parsed) : []),
      download_keys: Object.keys(dl),
    };
  }

  return { case: 'D', reason: `upload_body_type_${upType || 'unknown'}` };
}

function assertUploadHostAllowed(url) {
  try {
    const u = new URL(url);
    if (!UPLOAD_HOSTS.has(u.hostname)) {
      return { ok: false, error: 'upload_host_not_allowlisted', host: u.hostname };
    }
    if (DOWNLOAD_HOSTS.has(u.hostname) && !/\/file\/new/i.test(u.pathname)) {
      return { ok: false, error: 'download_cdn_is_not_upload_url', host: u.hostname };
    }
    return { ok: true, host: u.hostname };
  } catch {
    return { ok: false, error: 'invalid_url' };
  }
}

module.exports = {
  parseCapture,
  parseHar,
  parseLogText,
  classifyBody,
  correlateUploadWithDownload,
  redactToken,
  redactHeaders,
  parseObjectKeyFromUrl,
  isUploadUrl,
  isDownloadUrl,
  assertUploadHostAllowed,
  FACE_TAG,
  UPLOAD_HOSTS,
  DOWNLOAD_HOSTS,
};
