import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeDomain, issueChallenge, matchTxt, verifyChallenge } from '../pilot/domain-verification.mjs';

test('normalizes a domain and IDN to ASCII', () => {
  assert.equal(normalizeDomain('EXAMPLE.COM.'), 'example.com');
  assert.equal(normalizeDomain('bücher.example'), 'xn--bcher-kva.example');
});
test('rejects URLs, credentials, wildcards and local names', () => {
  for (const input of ['https://example.com', 'user@example.com', '*.example.com', 'localhost', '127.0.0.1', 'a..example.com', 'bad_label.example.com']) assert.throws(() => normalizeDomain(input), input);
});
test('issues unique, cryptographically random DNS challenges', () => {
  const a = issueChallenge('Example.com'), b = issueChallenge('example.com');
  assert.equal(a.record, '_nexus-verify.example.com');
  assert.match(a.token, /^nexus-verification=[0-9a-f]{48}$/);
  assert.notEqual(a.token, b.token);
});
test('accepts split TXT chunks and rejects unrelated records', () => {
  const token = issueChallenge('example.com').token;
  assert.equal(matchTxt([[token.slice(0,20), token.slice(20)]], token), true);
  assert.equal(matchTxt([['unrelated'],['nexus-verification=bad']], token), false);
});
test('verifies DNS TXT ownership with injected resolver', async () => {
  const challenge = issueChallenge('example.com');
  const result = await verifyChallenge(challenge, { resolver: async name => { assert.equal(name, challenge.record); return [[challenge.token]]; } });
  assert.equal(result.verified, true);
});
test('missing TXT record does not verify ownership', async () => {
  const challenge = issueChallenge('example.com');
  const result = await verifyChallenge(challenge, { resolver: async () => { const e = new Error('missing'); e.code='ENODATA'; throw e; } });
  assert.equal(result.verified, false);
});
test('resolver failure is not silently treated as non-ownership', async () => {
  const challenge = issueChallenge('example.com');
  await assert.rejects(verifyChallenge(challenge, { resolver: async () => { const e = new Error('timeout'); e.code='ETIMEOUT'; throw e; } }), /timeout/);
});
test('rejects tampered DNS record name', async () => {
  const challenge = issueChallenge('example.com');
  await assert.rejects(verifyChallenge({ ...challenge, record: '_nexus-verify.attacker.com' }), /Invalid challenge/);
});
