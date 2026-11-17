// Pilot-domain ownership verification: DNS TXT only, no active scanning.
// Server-side module. Persist token hashes and verification events in an authenticated tenant store before production use.
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { resolveTxt } from 'node:dns/promises';
import { domainToASCII } from 'node:url';

export function normalizeDomain(input) {
  if (typeof input !== 'string' || input.length > 253) throw new Error('Invalid domain');
  const value = input.trim().replace(/\.$/, '').toLowerCase();
  if (!value || /[\\/:@?#\s]/.test(value) || value.includes('*')) throw new Error('Invalid domain');
  const domain = domainToASCII(value);
  if (!domain || domain.length > 253 || !domain.includes('.')) throw new Error('Invalid domain');
  const labels = domain.split('.');
  if (labels.some(x => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))) throw new Error('Invalid domain');
  if (labels.at(-1).length < 2 || /^\d+$/.test(labels.at(-1))) throw new Error('Invalid domain');
  return domain;
}

export function issueChallenge(domain) {
  const normalized = normalizeDomain(domain);
  return { domain: normalized, record: '_nexus-verify.' + normalized, token: 'nexus-verification=' + randomBytes(24).toString('hex') };
}

export function matchTxt(records, expected) {
  if (!Array.isArray(records) || typeof expected !== 'string' || !/^nexus-verification=[0-9a-f]{48}$/.test(expected)) return false;
  const target = Buffer.from(expected);
  return records.some(chunks => {
    if (!Array.isArray(chunks)) return false;
    const value = Buffer.from(chunks.join(''));
    return value.length === target.length && timingSafeEqual(value, target);
  });
}

export async function verifyChallenge(challenge, { resolver = resolveTxt } = {}) {
  if (!challenge || typeof challenge !== 'object') throw new Error('Missing challenge');
  const domain = normalizeDomain(challenge.domain);
  if (challenge.record !== '_nexus-verify.' + domain) throw new Error('Invalid challenge record');
  try {
    const records = await resolver(challenge.record);
    return { domain, verified: matchTxt(records, challenge.token), method: 'dns-txt' };
  } catch (error) {
    if (['ENODATA', 'ENOTFOUND', 'NXDOMAIN'].includes(error?.code)) return { domain, verified: false, method: 'dns-txt' };
    throw error; // DNS timeouts and resolver failures are not ownership denials
  }
}
