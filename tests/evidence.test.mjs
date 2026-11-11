import test from 'node:test';
import assert from 'node:assert/strict';
import {probability,rankCatalog,snapshotStatus} from '../evidence-utils.mjs';
import {shortestPath} from '../graph-core.mjs';
import {processBatch,rowsCsv,downloadableIps} from '../lookup-core.mjs';
import {readFileSync} from 'node:fs';

test('near-one probabilities never imply certainty; unknown stays unknown',()=>{
 assert.equal(probability(.99998),'>99.9%');assert.equal(probability(.99999,2),'>99.99%');
 assert.equal(probability(null),'Unavailable');assert.equal(probability(''),'Unavailable');assert.equal(probability(1.2),'Unavailable');
 assert.equal(probability(.00001),'<0.1%');assert.equal(probability(0),'0.0%');assert.equal(probability(.125),'12.5%');
});
test('an exact CVE match precedes a description that mentions it',()=>{
 const rows=[{cveID:'CVE-2021-45046',shortDescription:'An incomplete fix of CVE-2021-44228'},{cveID:'CVE-2021-44228'}];
 assert.equal(rankCatalog(rows,'cve-2021-44228')[0].cveID,'CVE-2021-44228');assert.equal(rankCatalog(rows,'no-such-product').length,0);
});
test('coverage, stale publication and failed retrieval are independent signals',()=>{
 const now=Date.parse('2026-11-11T12:00:00Z'),health=[{status:'ok'},{status:'unavailable'}];
 assert.equal(snapshotStatus('2026-11-11T10:00:00Z',health,now).label,'Partial coverage');
 assert.equal(snapshotStatus('2026-11-11T02:00:00Z',health,now).label,'Snapshot delayed');
 assert.equal(snapshotStatus('invalid',health,now).stale,true);
 assert.equal(snapshotStatus('2026-11-11T10:00:00Z',health,now,true).label,'Cached snapshot');
});
test('synthetic graph traces the modeled path and a control really interrupts it',()=>{
 const g=JSON.parse(readFileSync(new URL('../sentinel/lab.json',import.meta.url)));
 assert.deepEqual(shortestPath(g,'internet','dc'),['internet','web','ws','alice','admins','dc']);
 assert.deepEqual(shortestPath(g,'internet','dc',['web->ws']),[]);
 assert.deepEqual(shortestPath(g,'internet','dc',['api->db']),['internet','web','ws','alice','admins','dc']);
 assert.throws(()=>shortestPath(g,'unknown','dc'));
});
test('lookup preserves unsupported-type boundaries and safe exported addresses',()=>{
 const ctx={ips:[{type:'ipv4',value:'8.8.8.8',sources:['feodo']}],kev:{records:[{id:'CVE-2021-44228'}]}};
 const rows=processBatch(['8.8.8.8','8.8.8.0/24','CVE-2021-44228','example.com','9.9.9.9'],ctx);
 assert.deepEqual(rows.map(r=>r.status),['listed','listed','cve','unsupported','notfound']);
 assert.deepEqual(downloadableIps(rows),['8.8.8.8']);
 assert.match(rowsCsv([{query:'=HYPERLINK("bad")'}],['query']),/'=HYPERLINK/);
});
