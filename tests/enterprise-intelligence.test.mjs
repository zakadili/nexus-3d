import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeOverview,formatCount,formatEpss,filterKev} from '../enterprise-v2-intelligence.mjs';

const fixture = () => ({
  schema: 2,
  generated_at: '2026-11-17T07:55:26.956611+00:00',
  data_lag: 'Feeds update on different schedules; not live packet streaming.',
  indicators: {
    unique_indicators: 35233,
    countries: [{code:'US',indicators:13086},{code:'MA',indicators:104},{code:'?',indicators:23}],
    source_health: [{id:'blocklistde',name:'blocklist.de',status:'ok',records:23550},
      {id:'feodo',name:'Feodo Tracker',status:'ok',records:1}]
  },
  cves: {status:'ok',source:'https://example.test/kev.json',total_kev:1781,date_released:'2026-11-13T20:24:18.3008Z',
    top:[{id:'CVE-2026-12345',vendor:'Example',product:'App',date_added:'2026-11-16',epss:0.76,ransomware_observed:true},
         {id:'CVE-2026-98765',vendor:'Example',product:'Library',date_added:'2026-11-14',epss:4,ransomware_observed:false},
         {id:'NOT-A-CVE',vendor:'Unknown',epss:0.5}]},
  failures:[],
  extra_health: [{id:'threatfox',status:'unavailable',records:null,reason:'no key configured'}],
  history:[{generated_at:'2026-11-16T00:00:00Z',unique_indicators:4},
           {generated_at:'2026-11-15T00:00:00Z',unique_indicators:3}]
});

test('published overview is normalized with source-aware semantics',()=>{
  const d=normalizeOverview(fixture(),Date.parse('2026-11-17T10:00:00Z'));
  assert.equal(d.listedIps,35233);
  assert.equal(d.kevCount,1781);
  assert.equal(d.countries.length,2);
  assert.equal(d.countries[0].code,'US');
  assert.equal(d.stale,false);
  assert.equal(d.sourceSummary,1);
  assert.equal(d.sourceRows.find(x=>x.id==='feodo').status,'retired');
  assert.equal(d.sourceRows.find(x=>x.id==='threatfox').count,null);
  assert.equal(d.kev.length,2);
  assert.equal(d.kev[1].epss,null);
  assert.deepEqual(d.history.map(x=>x.count),[3,4]);
});

test('stale snapshots are flagged and never passed off as live',()=>{
  const d=normalizeOverview(fixture(),Date.parse('2026-11-19T10:00:00Z'));
  assert.equal(d.stale,true);
  assert.ok(d.ageHours>18);
});

test('missing or invalid published data fails closed',()=>{
  assert.throws(()=>normalizeOverview(null),/invalid published snapshot/);
  assert.throws(()=>normalizeOverview({schema:2,generated_at:'invalid',indicators:{unique_indicators:2}}),/invalid published snapshot/);
  const bad=fixture();delete bad.indicators.unique_indicators;
  assert.throws(()=>normalizeOverview(bad),/indicator count/);
});

test('KEV or EPSS is not fabricated when source is unavailable',()=>{
  const f=fixture();f.cves={status:'unavailable',top:[{id:'CVE-2026-12345'}]};
  const d=normalizeOverview(f);
  assert.equal(d.kevCount,null);
  assert.deepEqual(d.kev,[]);
  assert.equal(formatCount(null),'Unavailable');
  assert.equal(formatEpss(null),'Not available');
  assert.equal(formatEpss(0.123), '12.3%');
});

test('candidate filters only match observed fields',()=>{
  const rows=normalizeOverview(fixture()).kev;
  assert.equal(filterKev(rows,'cve-2026-12345').length,1);
  assert.equal(filterKev(rows,'example').length,2);
  assert.equal(filterKev(rows,'','ransomware').length,1);
  assert.equal(filterKev(rows,'','epss').length,1);
  assert.equal(filterKev(rows,'missing','all').length,0);
});
