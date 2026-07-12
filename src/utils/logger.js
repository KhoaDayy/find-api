'use strict';

const { redact } = require('./redact');

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const current = LEVELS[(process.env.LOG_LEVEL || 'info').toLowerCase()] ?? 2;

function log(level, msg, meta) {
  if ((LEVELS[level] ?? 2) > current) return;
  const line = meta !== undefined ? `${msg} ${JSON.stringify(redact(meta))}` : msg;
  // eslint-disable-next-line no-console
  console[level === 'debug' ? 'log' : level](`[${level}] ${line}`);
}

module.exports = {
  error: (m, meta) => log('error', m, meta),
  warn: (m, meta) => log('warn', m, meta),
  info: (m, meta) => log('info', m, meta),
  debug: (m, meta) => log('debug', m, meta),
};
