import test from 'node:test';
import assert from 'node:assert/strict';
import {nextScheduledCollection,remainingToCollection,timeSinceSnapshot} from '../collection-clock.mjs';
function at(s){return Date.parse(s);}
test('next scheduled collection is 00:17 / 06:17 / 12:17 / 18:17 UTC',()=>{
 assert.equal(nextScheduledCollection(at('2026-11-10T05:59:59Z')),at('2026-11-10T06:17:00Z'));
 assert.equal(nextScheduledCollection(at('2026-11-10T12:17:00Z')),at('2026-11-10T18:17:00Z'));
 assert.equal(nextScheduledCollection(at('2026-11-10T23:59:59Z')),at('2026-11-11T00:17:00Z'));
});
test('countdown returns HH:MM:SS and the UTC next slot',()=>{
 const result=remainingToCollection(at('2026-11-10T06:16:00Z'));
 assert.equal(result.label,'00:01:00');
 assert.equal(result.nextUTC,'2026-11-10T06:17:00.000Z');
});

test('elapsed published-snapshot age is exact and uses real timestamps',()=>{
 const result=timeSinceSnapshot('2026-11-10T10:00:00Z',at('2026-11-10T11:02:05Z'));
 assert.equal(result.label,'01:02:05');
 assert.equal(result.hours,1);
 assert.equal(result.minutes,2);
 assert.equal(result.seconds,5);
});
test('missing timestamps are not converted into fictitious elapsed time',()=>{
 assert.equal(timeSinceSnapshot(''),null);
 assert.equal(timeSinceSnapshot(undefined),null);
});
