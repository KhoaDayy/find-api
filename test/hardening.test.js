'use strict';

const assert = require('assert');
const { UpstreamError, toApiError, httpStatusForCode } = require('../src/wwm/errors');
const { sessionReadiness } = require('../src/wwm/session');

function test(name, fn) {
  try {
    fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    console.error(`  FAIL ${name}`);
    console.error(e);
    process.exitCode = 1;
  }
}

console.log('hardening');

test('timeout maps 502 not 404', () => {
  const e = new UpstreamError('UPSTREAM_TIMEOUT', 'timeout', { retryable: true });
  const m = toApiError(e);
  assert.strictEqual(m.status, 502);
  assert.notStrictEqual(m.status, 404);
});

test('player_not_found is 404 only as domain code', () => {
  assert.strictEqual(httpStatusForCode('PLAYER_NOT_FOUND'), 404);
});

test('session missing maps 503', () => {
  const e = new UpstreamError('SESSION_NOT_CONFIGURED', 'no session');
  assert.strictEqual(toApiError(e).status, 503);
});

test('auth failed not retryable and 503', () => {
  const e = new UpstreamError('UPSTREAM_AUTH_FAILED', 'auth', {
    statusCode: 401,
    retryable: false,
  });
  assert.strictEqual(e.retryable, false);
  assert.strictEqual(toApiError(e).status, 503);
});

test('error body does not contain session-like fields', () => {
  const e = new UpstreamError('UPSTREAM_TIMEOUT', 'x', { endpoint: '/flk/x' });
  const body = JSON.stringify(toApiError(e).body);
  assert.ok(!/session=/.test(body));
  assert.ok(!/h72-ms-uid/.test(body));
});

test('sessionReadiness returns booleans only', () => {
  const s = sessionReadiness();
  assert.strictEqual(typeof s.CN, 'boolean');
  assert.strictEqual(typeof s.GLOBAL, 'boolean');
  assert.ok(!JSON.stringify(s).includes('aZ'));
});

if (process.exitCode) {
  console.error('\nSome hardening tests failed');
  process.exit(1);
}
console.log('\nAll hardening tests passed');
