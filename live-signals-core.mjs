// Pure input boundary and bounded browser accounting for NEXUS LIVE.
export const SOURCE_NAMES=Object.freeze({ris_live:'RIPE RIS Live',ioda:'Georgia Tech IODA',certstream:'Certificate Transparency'});
const TYPES={ris_live:new Set(['bgp_announcement','bgp_withdrawal','routing_anomaly_candidate']),ioda:new Set(['outage','outage_event']),certstream:new Set(['ct_observation','certificate_aggregate','lookalike_candidate'])};
const ID=/^[A-Za-z0-9_-]{1,128}$/;
const UTC=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/;
const plain=(v,n)=>typeof v==='string'&&v.length>0&&v.length<=n&&!/[\u0000-\u001f\u007f]/.test(v);
export function utcMillis(v){return typeof v==='string'&&UTC.test(v)&&Number.isFinite(Date.parse(v))?Date.parse(v):null}
export function apiOrigin(value){try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password&&u.pathname==='/'&&!u.search&&!u.hash?u.origin:null}catch{return null}}
export function evidenceURL(value,id,origin){
 if(!ID.test(id)||typeof value!=='string'||value.length>512||!origin)return null;
 try{const u=new URL(value);return u.origin===origin&&!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/api/live/evidence/'+id?u.href:null}catch{return null}
}
export function validateObservation(item,{origin,countries,now=Date.now()}={}){
 if(!item||Array.isArray(item)||typeof item!=='object'||JSON.stringify(item).length>2048)return null;
 if(!ID.test(item.id)||!Object.hasOwn(TYPES,item.source)||!TYPES[item.source].has(item.type))return null;
 const observed=utcMillis(item.ts_observed),received=utcMillis(item.ts_received);
 if(observed===null||received===null||observed>now+60000||received>now+60000||observed>received+60000)return null;
 if(!plain(item.label,300)||!plain(item.attribution,300)||!['observed','derived','candidate'].includes(item.confidence))return null;
 if(item.country!==undefined&&(!countries?.has(item.country)||item.source==='certstream'||item.type==='bgp_withdrawal'))return null;
 if(item.asn!==undefined&&(!Number.isInteger(item.asn)||item.asn<1||item.asn>4294967295))return null;
 if(item.value!==undefined&&(typeof item.value!=='number'||!Number.isFinite(item.value)||item.value<0))return null;
 const url=evidenceURL(item.evidence_url,item.id,origin);if(!url)return null;
 // Construct only the approved fields; ignore unknown properties instead of exposing them.
 return {id:item.id,source:item.source,type:item.type,ts_observed:item.ts_observed,ts_received:item.ts_received,label:item.label,attribution:item.attribution,confidence:item.confidence,evidence_url:url,...(item.country===undefined?{}:{country:item.country}),...(item.asn===undefined?{}:{asn:item.asn}),...(item.value===undefined?{}:{value:item.value})};
}
export function freshForPulse(item,now=Date.now(),replay=false){return !replay&&now-Date.parse(item.ts_received)<=15000&&now-Date.parse(item.ts_observed)<=30000&&now>=Date.parse(item.ts_received)-1000}
export function eligible(status){return ['connected','quiet','healthy','degraded','stale','unavailable','connecting'].includes(status)}
export function shouldConnect({open,hidden,paused,selected,sources}){return open&&!hidden&&!paused&&Object.keys(SOURCE_NAMES).some(s=>selected.has(s)&&eligible(sources[s]?.status))}
export class LiveLedger{
 constructor(){this.seen=new Map();this.rows=[];this.buckets=new Map();this.pending=[];this.visualOmissions=0;this.rejected=0}
 add(item,{now=Date.now(),replay=false}={}){
  if(this.seen.has(item.id))return false;
  this.seen.set(item.id,now);while(this.seen.size>2000)this.seen.delete(this.seen.keys().next().value);
  this.rows.unshift({item,replay});if(this.rows.length>40)this.rows.pop();
  if(!replay){const second=Math.floor(now/1000),key=item.source+':'+second;this.buckets.set(key,(this.buckets.get(key)||0)+1)}
  this.prune(now);return true;
 }
 prune(now){const cutoff=Math.floor(now/1000)-59;for(const key of this.buckets.keys())if(Number(key.slice(key.lastIndexOf(':')+1))<cutoff)this.buckets.delete(key)}
 count(source,now=Date.now()){this.prune(now);let n=0;for(const [key,v] of this.buckets)if(key.startsWith(source+':'))n+=v;return n}
 enqueue(item){if(this.pending.length>=100){this.visualOmissions++;return false}this.pending.push(item);return true}
 drain(){const result=this.pending;this.pending=[];return result}
 clearVisuals(){this.pending=[]}
}

