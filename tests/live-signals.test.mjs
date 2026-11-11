import test from 'node:test';
import assert from 'node:assert/strict';
import {validateObservation,freshForPulse,shouldConnect,LiveLedger} from '../live-signals-core.mjs';
const origin='https://signals.example',now=Date.parse('2026-11-12T01:00:00Z');
const event={id:'fixture-1',source:'ris_live',type:'bgp_announcement',ts_observed:new Date(now).toISOString(),ts_received:new Date(now).toISOString(),label:'BGP prefix announcements',attribution:'RIPE NCC RIS Live',confidence:'derived',country:'FR',value:1,evidence_url:origin+'/api/live/evidence/fixture-1'};
const opts={origin,now,countries:new Set(['FR'])};
test('untrusted observations require a valid source, time and local evidence URL',()=>{
 assert.ok(validateObservation(event,opts));
 for(const patch of [{evidence_url:'javascript:alert(1)'},{evidence_url:'https://evil.example/api/live/evidence/fixture-1'},{country:'XX'},{value:Infinity},{source:'unknown'},{ts_observed:'yesterday'}])assert.equal(validateObservation({...event,...patch},opts),null);
 assert.equal(validateObservation({...event,type:'bgp_withdrawal'},opts),null);
});
test('hidden, paused, closed and license-blocked sources do not connect',()=>{
 const base={open:true,hidden:false,paused:false,selected:new Set(['ris_live']),sources:{ris_live:{status:'connected'}}};
 assert.equal(shouldConnect(base),true);
 for(const patch of [{open:false},{hidden:true},{paused:true},{sources:{ris_live:{status:'license_blocked'}}}])assert.equal(shouldConnect({...base,...patch}),false);
});
test('old replay never pulses and bounded queues cannot grow indefinitely',()=>{
 assert.equal(freshForPulse(event,now,true),false);assert.equal(freshForPulse(event,now+60000),false);
 const ledger=new LiveLedger();assert.ok(ledger.add(event,{now}));assert.equal(ledger.add(event,{now}),false);
 assert.equal(ledger.count('ris_live',now),1);
 for(let i=0;i<3000;i++){ledger.add({...event,id:'e'+i},{now,replay:true});ledger.enqueue(event)}
 assert.equal(ledger.seen.size,2000);assert.equal(ledger.rows.length,40);assert.equal(ledger.pending.length,100);
 assert.equal(ledger.count('ris_live',now+61000),0);
});

