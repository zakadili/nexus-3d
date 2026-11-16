import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeDomain,hostInScope,buildDomainReport} from '../exposure-core.mjs';
test('domain normalization rejects URLs, IPs and malformed input',()=>{
 assert.equal(normalizeDomain(' Example.COM. '),'example.com');
 for(const v of ['https://example.com','127.0.0.1','localhost','bad..com','evil.com/path','-bad.com'])assert.equal(normalizeDomain(v),null);
});
test('subdomain matching is boundary aware',()=>{
 assert.equal(hostInScope('a.example.com','example.com'),true);
 assert.equal(hostInScope('example.com.evil.net','example.com'),false);
 assert.equal(hostInScope('notexample.com','example.com'),false);
});
test('only attributable evidence is included',()=>{
 const report=buildDomainReport('example.com',[
  {hostname:'api.example.com',source:'test-feed',observed_at:'2026-11-16',evidence_url:'https://example.org/evidence'},
  {hostname:'example.com.evil.net',source:'test-feed',observed_at:'2026-11-16',evidence_url:'https://example.org/evidence'},
  {hostname:'example.com',source:'test-feed',observed_at:'2026-11-16',evidence_url:'javascript:alert(1)'}
 ],[{name:'test-feed',status:'ok',retrieved_at:'2026-11-16'}]);
 assert.equal(report.findings.length,1);
 assert.equal(report.status,'evidence-found');
});
test('unavailable sources never imply safety',()=>{
 const report=buildDomainReport('example.com',[],[{name:'test-feed',status:'unavailable'}]);
 assert.equal(report.status,'coverage-unavailable');
 assert.match(report.disclaimer,/does not mean secure/);
});
test('empty successful coverage means no matching evidence, not secure',()=>{
 const report=buildDomainReport('example.com',[],[{name:'test-feed',status:'ok'}]);
 assert.equal(report.status,'no-matching-evidence');
});
