/* NEXUS live adapter. No demo events. Absence of a backend is explicitly reported. */
import { STREAM_API } from './stream-config.js?v=20261111-deploy';
const root=document.createElement('section');
root.className='nexus-stream';
root.id='live-intelligence';
root.setAttribute('aria-label','Event-driven feed status');
root.innerHTML='<div class="ns-head"><div><span class="ns-kicker">◈ EVENT-DRIVEN INTELLIGENCE</span><h2>OBSERVATIONS, NOT SIMULATED ATTACKS</h2></div><strong id="ns-status">BACKEND NOT CONFIGURED</strong></div><p class="ns-disclaimer">Feed entries describe reported indicators and connectivity alerts. They are not attacks observed by NEXUS. Map country is infrastructure enrichment, not attacker attribution. Scheduled snapshot data elsewhere on this page remains separate.</p><div class="ns-windows"><div>5 MINUTE ARRIVALS <strong id="ns-5">—</strong></div><div>15 MINUTE ARRIVALS <strong id="ns-15">—</strong></div><div>60 MINUTE ARRIVALS <strong id="ns-60">—</strong></div></div><div class="ns-cols"><section><h3>CURRENT PUBLISHED INDICATORS · SNAPSHOTS</h3><div id="ns-snapshots">Loading current source lists…</div><h3>RECENT LIST CHANGES · DETECTION TIME</h3><ol id="ns-events"><li>No recent public list changes retained. Current lists are shown above.</li></ol></section><section><h3>FEED HEALTH AND PROVENANCE</h3><div id="ns-feeds">No streaming server configured. Data is unavailable, not zero activity.</div><details><summary>Data provenance and limits</summary><div id="ns-limits">Live feed access, replay coverage and redistribution rights must be confirmed before displaying upstream events. The static snapshot dashboard uses a different collection cadence.</div></details></section></div>';
const target=document.querySelector('main .disclosure')||document.querySelector('main');
if(target?.parentNode)target.parentNode.insertBefore(root,target);else document.body.append(root);
const $=id=>root.querySelector('#'+id);
const api=String(STREAM_API||'').replace(/\/+$/,'');
let ws=null,retry=1000,timer=null,replaying=false,pending=[],coverageGap=false;
const cursorKey='nexus-stream-seq:'+api;
let last=Number(sessionStorage.getItem(cursorKey)||0);
if(!Number.isSafeInteger(last)||last<0)last=0;
const seen=new Set();
function report(state){$('ns-status').textContent=state}
function time(v){if(!v)return 'never';const d=new Date(v);return Number.isNaN(d.valueOf())?'unknown':d.toLocaleString()}
function eventLine(item){
 if(!item||!Number.isSafeInteger(item.seq)||seen.has(item.event_id))return;
 seen.add(item.event_id);if(seen.size>2000)seen.clear();
 last=Math.max(last,item.seq);sessionStorage.setItem(cursorKey,String(last));
 const li=document.createElement('li');const label=document.createElement('b');
 label.textContent=String(item.feed_source||'feed')+' · '+(item.kind==='snapshot'?'SNAPSHOT SAMPLE':String(item.action||'update'));
 const more=document.createElement('span');
 more.textContent=' — '+time(item.received_at)+' · '+String(item.indicator||'non-IP observation');
 li.append(label,more);if(String(item.action).toLowerCase().includes('remov'))li.className='ns-removal';
 const list=$('ns-events');if(list.firstElementChild?.textContent==='No recent public list changes retained. Current lists are shown above.')list.replaceChildren();
 list.prepend(li);while(list.children.length>45)list.lastElementChild.remove();
 // Never plot an unlocated indicator. The existing globe is a separate
 // historical snapshot visualization, not an attack flight animator.
 if(item.kind==='enriched' && Number.isFinite(item.latitude) && Number.isFinite(item.longitude)
    && item.enrichment_source){
   document.dispatchEvent(new CustomEvent('nexus:geolocated-event',{detail:item}));
 }
}
function health(data){
 const publishable=new Map((data.publishable_sources||[]).map(s=>[s.id,s]));
 const list=$('ns-feeds');list.replaceChildren();
 const feeds=data.feeds||[];
 if(!feeds.length)list.textContent='No feed health records available. Coverage unknown.';
 for(const f of feeds){
  const p=document.createElement('p');p.className='ns-feed '+(f.state==='connected'||f.state==='reference_current'?'ns-connected':'ns-degraded');
  const reference=['cisa_kev','first_epss'].includes(f.feed);
  const stamp=reference?f.last_success_at:f.last_received_at;
  const age=stamp?Math.max(0,Math.round((Date.now()-new Date(stamp).valueOf())/1000))+'s ago':'never';
  p.textContent=String(f.feed)+' · '+String(f.state||'unknown')+' · '+(reference?'reference fetched ':'last arrival ')+age+
    ' · source latency '+(f.source_to_ingest_latency_s==null?'unknown':f.source_to_ingest_latency_s+'s')+
    ' · gaps '+Number(f.gap_count||0)+(f.degraded_reason?' · '+String(f.degraded_reason).slice(0,170):'');
  list.append(p);
  const sources={urlhaus:'https://urlhaus.abuse.ch/',threatfox:'https://threatfox.abuse.ch/',Feodotracker:'https://feodotracker.abuse.ch/',ioda:'https://ioda.inetintel.cc.gatech.edu/',cisa_kev:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',first_epss:'https://www.first.org/epss/'};
  if(sources[f.feed]){const a=document.createElement('a');a.href=sources[f.feed];a.textContent=' · SOURCE ↗';a.target='_blank';a.rel='noopener noreferrer';p.append(a)}
  if(publishable.has(f.feed)){const s=publishable.get(f.feed); const a=document.createElement('a');a.href=s.license_url;a.textContent=' · '+s.license+' LICENSE ↗';a.target='_blank';a.rel='noopener noreferrer';p.append(document.createTextNode(' · '+s.cadence),a);}
 }
 $('ns-limits').textContent='Per-feed status is reported by the backend; silent feed periods are not zero activity. '+
 (data.public_feed_rebroadcast?'Public feed redistribution enabled by operator.':'Raw abuse.ch redistribution disabled pending licensing.')+
 ' CISA KEV is a daily reference catalog. IODA reports Internet disruptions, not necessarily attacks. '+
 'Upstream Spamhaus resume is limited by provider retention. Browser replay uses a different durable sequence. '+
 'Local observations retain at most 48 hours / approximately 20,000 sequence positions, with periodic cleanup. '+
 'EPSS covers the 100 most recently added KEVs; references and assessments are not live observations. No geographic enrichment is currently performed. '+
 'Publishable feeds are checked every five minutes. Initial snapshot samples do not count as new arrivals; later additions/removals are detected list changes, not newly observed attacks. Provider publication cadence can be slower than polling. PhishDestroy primary data is MIT licensed; Copyright (c) 2019 PhishDestroy. abuse.ch SSLBL data is CC0 under its published exceptions.';
 const degraded=feeds.some(f=>!['connected','reference_current'].includes(f.state)||f.last_success_age_s>900&&f.feed==='ioda');
 report(coverageGap?'CONNECTED · REPLAY GAP':degraded?'CONNECTED · FEEDS DEGRADED':'CONNECTED · FEEDS CURRENT');
}
async function windows(){
 try{
  const r=await fetch(api+'/api/windows',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);
  const data=await r.json();
  for(const k of [5,15,60])$('ns-'+k).textContent=(data.windows||[]).reduce((a,v)=>a+Number(v['last_'+k+'m']||0),0).toLocaleString();
 }catch{for(const k of [5,15,60])$('ns-'+k).textContent='UNAVAILABLE'}
}
async function snapshots(){
 try{
  const r=await fetch(api+'/api/public-snapshots',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);
  const data=await r.json(),container=$('ns-snapshots');container.replaceChildren();
  for(const source of data.snapshots||[]){
   const section=document.createElement('section'),heading=document.createElement('p');
   const link=document.createElement('a');link.href=source.url;link.textContent=source.name;link.target='_blank';link.rel='noopener noreferrer';
   heading.append(link,document.createTextNode(' · '+Number(source.record_count||0).toLocaleString()+' published indicators · '+source.license));
   const stamp=document.createElement('p');stamp.textContent='SNAPSHOT · Last checked '+time(source.fetched_at)+' · Checked every 5 minutes';
   const list=document.createElement('ul');
   for(const value of source.sample||[]){const li=document.createElement('li');li.textContent=String(value);list.append(li)}
   section.append(heading,stamp,list);container.append(section);
  }
  if(!container.children.length)container.textContent='No current source snapshot available. See feed health for collection status.';
 }catch{$('ns-snapshots').textContent='Current source lists unavailable. Retrying automatically.'}
}
async function start(){
 // Load existing records on every visit, even when this tab has a saved replay cursor.
 // Do not advance that cursor here: reconnect must still replay missed observations.
 const saved=last;
 try{
  const r=await fetch(api+'/api/events?recent=true&limit=45',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);
  const data=await r.json();for(const event of data.events||[])eventLine(event);
 }catch{$('ns-events').textContent='Recent history unavailable; waiting for stream reconnection.'}
 finally{last=saved;sessionStorage.setItem(cursorKey,String(saved));connect()}
}
function connect(){
 report('CONNECTING');
 try{ws=new WebSocket(api.replace(/^http/,'ws')+'/ws/live')}catch{report('INVALID ENDPOINT');return}
 ws.onopen=()=>{retry=1000;replaying=true;pending=[];report('STREAM CONNECTED');ws.send(JSON.stringify({type:'resume',after_seq:last}))};
 ws.onmessage=({data})=>{
  let m;try{m=JSON.parse(data)}catch{return}
  if(m.feeds)health(m);
  if(m.replay_gap){coverageGap=true;report('CONNECTED · REPLAY GAP');$('ns-limits').textContent+=' Replay gap: '+String(m.gap_reason||'history expired')+'.';}
  if(m.type==='events'&&replaying){pending.push(...(m.events||[]));if(pending.length>2000){ws.close();}return}
  if(['events','replay'].includes(m.type)){
   for(const event of m.events||[])eventLine(event);
   if(m.has_more&&Number.isSafeInteger(m.next_after_seq)&&m.next_after_seq>=0)
     ws.send(JSON.stringify({type:'resume',after_seq:m.next_after_seq}));
   else if(m.type==='replay'){replaying=false;for(const event of pending.sort((a,b)=>a.seq-b.seq))eventLine(event);pending=[];}
  }
 };
 ws.onerror=()=>ws.close();
 ws.onclose=()=>{report('STREAM UNAVAILABLE');for(const k of [5,15,60])$('ns-'+k).textContent='UNAVAILABLE';
  $('ns-feeds').textContent='Connection lost. Coverage unknown, not zero. Waiting for reconnect.';
  clearTimeout(timer);timer=setTimeout(connect,retry+Math.random()*1000);retry=Math.min(30000,retry*2)};
}
if(/^https:\/\//.test(api) && !api.includes('stream.example.com')){
 start();snapshots();windows();setInterval(windows,15000);setInterval(snapshots,60000);
}else{
 report('BACKEND NOT CONFIGURED');
 $('ns-feeds').textContent='Real-time backend not deployed. The radar above displays scheduled snapshots only.';
}
