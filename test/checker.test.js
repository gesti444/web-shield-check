import test from 'node:test';
import assert from 'node:assert/strict';
import { checkSite, validateTarget } from '../src/checker.js';

const publicLookup = async () => [{ address: '93.184.216.34', family: 4 }];

test('adds HTTPS when the protocol is omitted', async () => {
  assert.equal((await validateTarget('example.com', publicLookup)).href, 'https://example.com/');
});

test('blocks private destinations', async () => {
  await assert.rejects(() => validateTarget('http://localhost', async () => [{ address: '127.0.0.1', family: 4 }]), /Private/);
});

test('scores HTTPS and present security headers', async () => {
  const fakeFetch = async () => ({ url: 'https://example.com/', status: 200, headers: new Headers({
    'strict-transport-security': 'max-age=31536000', 'x-content-type-options': 'nosniff'
  }) });
  const result = await checkSite('example.com', { lookup: publicLookup, fetch: fakeFetch });
  assert.equal(result.score, 43);
  assert.equal(result.checks[0].passed, true);
});

test('validates every redirect destination', async () => {
  const redirectFetch = async () => ({
    url: 'https://example.com/', status: 302, headers: new Headers({ location: 'http://127.0.0.1/' })
  });
  const lookup = async host => [{ address: host === '127.0.0.1' ? '127.0.0.1' : '93.184.216.34', family: 4 }];
  await assert.rejects(() => checkSite('example.com', { lookup, fetch: redirectFetch }), /Private/);
});
