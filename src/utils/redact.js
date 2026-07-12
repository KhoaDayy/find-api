'use strict';

const SECRET_KEY_RE =
  /^(session|token|server_token|cookie|authorization|auth|password|secret|access_key|secret_key|h72-ms-uid)$/i;

const SECRET_VALUE_RE =
  /(session=)[^&\s]+|(_face_123_face_)[A-Za-z0-9+/=_-]+|(Bearer\s+)[A-Za-z0-9._\-]+/gi;

function redactString(s) {
  if (typeof s !== 'string') return s;
  if (s.length > 12 && /^[A-Za-z0-9+/=_-]{16,}$/.test(s) && !s.startsWith('R67') && !s.startsWith('D67')) {
    // likely opaque id/token — partial redact when used as secret context by callers
  }
  return s.replace(SECRET_VALUE_RE, (m, p1, p2, p3) => {
    if (p1) return `${p1}***`;
    if (p2) return `${p2}***`;
    if (p3) return `${p3}***`;
    return '***';
  });
}

function redactValue(value, key) {
  if (key && SECRET_KEY_RE.test(String(key))) {
    if (value == null) return value;
    const s = String(value);
    if (s.length <= 4) return '***';
    return `${s.slice(0, 4)}***`;
  }
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map((v) => redactValue(v));
  if (value && typeof value === 'object') return redactObject(value);
  return value;
}

function redactObject(obj) {
  if (obj == null || typeof obj !== 'object') return redactValue(obj);
  if (Array.isArray(obj)) return obj.map((v) => redactValue(v));
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = redactValue(v, k);
  }
  return out;
}

function redact(input) {
  if (typeof input === 'string') return redactString(input);
  return redactObject(input);
}

module.exports = {
  redact,
  redactString,
  redactObject,
  SECRET_KEY_RE,
};
