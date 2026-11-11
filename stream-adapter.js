/* NEXUS live adapter. No demo events. Absence of a backend is explicitly reported. */
import { STREAM_API } from './stream-config.js';
const root=document.createElement('section');
root.className='nexus-stream';
root.setAttribute('aria-label','Event-driven feed status');
root.innerHTML='<div class="ns-head"><div><span class="ns-kicker">◈ EVENT-DRIVEN INTELLIGENCE</span><h2>OBSERVATIONS, NOT SIMULATED ATTACKS</h2></div><strong id="ns-status">BACKEND NOT CONFIGURED</strong></div><p class="ns-disclaimer">Feed entries describe reported indicators and connectivity alerts. They are not attacks observed by NEXUS. Map country is infrastructure enrichment, not attacker attribution. Scheduled snapshot data elsewhere on this page remains separate.</p><div class="ns-windows"><div>5 MINUTE ARRIVALS <strong id="ns-5">—</strong></div><div>15 MINUTE ARRIVALS <strong id="ns-15">—</strong></div><div>60 MINUTE ARRIVALS <strong id="ns-60">—</strong></div></div><div class="ns-cols"><section><h3>OBSERVED ARRIVALS</h3><ol id="ns-events"><li>Awaiting verified upstream observations.</li></ol></section><section><h3>FEED HEALTH AND PROVENANCE</h3><div id="ns-feeds">No streaming server configured. Data is unavailable, not zero activity.</div><details><summary>Data provenance and limits</summary><div id="ns-limits">Live feed access, replay coverage and redistribution rights must be confirmed before displaying upstream events. The static snapshot dashboard uses a different collection cadence.</div></details></section></div>';
const target=document.querySelector('main .disclosure')||document.querySelector('main');
if(target?.parentNode)target.parentNode.insertBefore(root,target);else document.body.append(root);
const $=id=>root.querySelector('#'+id);
const api=String(STREAM_API||'').replace(/\/+$/,'');
let ws=null,retry=1000,timer=null;
let last=Number(sessionStorage.getItem('nexus-stream-seq')||0);
if(!Number.isSafeInteger(last)||last<0)last=0;
const seen=new Set();
function report(state){$('ns-status').textContent=state}
function time(v){if(!v)return 'never';const d=new Date(v);return Number.isNaN(d.valueOf())?'unknown':d.toLocaleString()}
function eventLine(item){
 if(!item||!Number.isSafeInteger(item.seq)||seen.has(item.event_id))return;
 seen.add(item.event_id);if(seen.size>2000)seen.clear();
 last=Math.max(last,item.seq);sessionStorage.setItem('nexus-stream-seq',String(last));
 const li=document.createElement('li');const label=document.createElement('b');
 label.textContent=String(item.feed_source||'feed')+' · '+String(item.action||'update');
 const more=document.createElement('span');
 more.textContent=' — '+time(item.received_at)+' · '+String(item.indicator||'non-IP observation');
 li.append(label,more);if(String(item.action).toLowerCase().includes('remov'))li.className='ns-removal';
 const list=$('ns-events');if(list.firstElementChild?.textContent==='Awaiting verified upstream observations.')list.replaceChildren();
 list.prepend(li);while(list.children.length>45)list.lastElementChild.remove();
 // Never plot an unlocated indicator. The existing globe is a separate
 // historical snapshot visualization, not an attack flight animator.
 if(item.kind==='enriched' && Number.isFinite(item.latitude) && Number.isFinite(item.longitude)
    && item.enrichment_source){
   document.dispatchEvent(new CustomEvent('nexus:geolocated-event',{detail:item}));
 }
}
function health(data){
 const list=$('ns-feeds');list.replaceChildren();
 const feeds=data.feeds||[];
 if(!feeds.length)list.textContent='No feed health records available. Coverage unknown.';
 for(const f of feeds){
  const p=document.createElement('p');p.className='ns-feed '+(f.state==='connected'||f.state==='reference_current'?'ns-connected':'ns-degraded');
  const age=f.last_received_at?Math.max(0,Math.round((Date.now()-new Date(f.last_received_at).valueOf())/1000))+'s ago':'never';
  p.textContent=String(f.feed)+' · '+String(f.state||'unknown')+' · last arrival '+age+
    ' · gaps '+Number(f.gap_count||0)+(f.degraded_reason?' · '+String(f.degraded_reason).slice(0,170):'');
  list.append(p);
 }
 $('ns-limits').textContent='Per-feed status is reported by the backend; silent feed periods are not zero activity. '+
 (data.public_feed_rebroadcast?'Public feed redistribution enabled by operator.':'Raw abuse.ch redistribution disabled pending licensing.')+
 ' CISA KEV is a daily reference catalog. IODA reports Internet disruptions, not necessarily attacks. '+
 'Upstream Spamhaus resume is limited by provider retention. Browser replay uses a different durable sequence.';
}
async function windows(){
 try{
  const r=await fetch(api+'/api/windows',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);
  const data=await r.json();
  for(const k of [5,15,60])$('ns-'+k).textContent=(data.windows||[]).reduce((a,v)=>a+Number(v['last_'+k+'m']||0),0).toLocaleString();
 }catch{for(const k of [5,15,60])$('ns-'+k).textContent='UNAVAILABLE'}
}
function connect(){
 report('CONNECTING');
 try{ws=new WebSocket(api.replace(/^http/,'ws')+'/ws/live')}catch{report('INVALID ENDPOINT');return}
 ws.onopen=()=>{retry=1000;report('STREAM CONNECTED');ws.send(JSON.stringify({type:'resume',after_seq:last}))};
 ws.onmessage=({data})=>{
  let m;try{m=JSON.parse(data)}catch{return}
  if(m.feeds)health(m);
  if(['events','replay'].includes(m.type)){
   for(const event of m.events||[])eventLine(event);
   if(m.has_more&&Number.isSafeInteger(m.next_after_seq)&&m.next_after_seq>=0)
     ws.send(JSON.stringify({type:'resume',after_seq:m.next_after_seq}));
  }
 };
 ws.onerror=()=>ws.close();
 ws.onclose=()=>{report('STREAM UNAVAILABLE');for(const k of [5,15,60])$('ns-'+k).textContent='UNAVAILABLE';
  $('ns-feeds').textContent='Connection lost. Coverage unknown, not zero. Waiting for reconnect.';
  clearTimeout(timer);timer=setTimeout(connect,retry+Math.random()*1000);retry=Math.min(30000,retry*2)};
}
if(/^https:\/\//.test(api) && !api.includes('stream.example.com')){
 connect();windows();setInterval(windows,15000);
}else{
 report('BACKEND NOT CONFIGURED');
 $('ns-feeds').textContent='Real-time backend not deployed. The radar above displays scheduled snapshots only.';
}
