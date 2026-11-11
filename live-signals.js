/* Real server observations only. No demonstration events or direct source connections. */
import {STREAM_API} from './stream-config.js';
import {SOURCE_NAMES,apiOrigin,validateObservation,utcMillis,freshForPulse,shouldConnect,eligible,LiveLedger} from './live-signals-core.mjs';
const container=document.getElementById('live-signals-content'),disclosure=document.getElementById('live-intelligence');
const origin=apiOrigin(STREAM_API),ledger=new LiveLedger(),selected=new Set(['ris_live']);
const sources=Object.fromEntries(Object.keys(SOURCE_NAMES).map(s=>[s,{status:'unknown',reason:'Source status not checked.'}]));
const countries=new Set();let paused=false,stream=null,healthAbort=null,evidenceAbort=null,retryTimer=null,tick=null,lastControl=0,connected=false,nextConnect=0,retry=15000,frameSecond=0,frameCount=0,dirty=true,selectedItem=null;
const el=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e};
const stamp=value=>utcMillis(value)===null?'none received':new Date(value).toLocaleString();
const active=()=>disclosure.open&&!document.hidden&&!paused;
const event=(name,detail)=>document.dispatchEvent(new CustomEvent(name,{detail}));
const root=el('section','live-signals');root.setAttribute('aria-label','Live Internet signals');
const header=el('div','ls-header'),title=el('div');title.append(el('p','ls-kicker','LIVE SIGNALS · SEPARATE FROM SNAPSHOTS'),el('h2','','Real observations. Visible limits.'));
const pause=el('button','ls-pause','Pause live signals');pause.type='button';pause.setAttribute('aria-pressed','false');
header.append(title,pause);const status=el('p','ls-status','Checking the live service…');status.setAttribute('role','status');
const disclaimer=el('p','ls-note','No public source gives a per-attack feed of the whole Internet. NEXUS shows independent Internet signals. Hosting country, ASN registration country and routing activity are not attacker attribution.');
const cards=el('div','ls-sources'),views={};
const legends={ris_live:'Cyan rings: announcements grouped by origin ASN registration country. Filtered routing observations, not attacks or physical locations. Withdrawals without a known origin remain unlocated. Anomaly candidates are not confirmed hijacks.',ioda:'Amber rings: reported outage geography. Outages have many causes and are not necessarily cyber activity. Attribution: Georgia Tech IODA.',certstream:'Ticker only: CT log observations, not unique worldwide certificates. Certificates have no geographic location. Keyword matches are candidates, not confirmed phishing.'};
for(const [source,name] of Object.entries(SOURCE_NAMES)){
 const card=el('section','ls-source'),label=el('label','ls-toggle'),input=el('input');input.type='checkbox';input.checked=selected.has(source);input.disabled=true;input.id='ls-toggle-'+source;
 label.append(input,document.createTextNode(name));const state=el('p','ls-source-state','Checking availability…'),time=el('p','ls-source-time','Last event: none received'),meter=el('p','ls-meter','Received events / last 60 s: —'),scope=el('p','ls-scope');
 card.append(label,state,time,meter,el('p','ls-legend',legends[source]),scope);cards.append(card);views[source]={input,state,time,meter,scope};
 input.addEventListener('change',()=>{input.checked?selected.add(source):selected.delete(source);event('nexus:live-clear',{source});ledger.clearVisuals();dirty=true;reconcile()});
}
const summary=el('p','ls-note','Counters measure normalized events received in this tab over 60 seconds, not attacks or worldwide totals. Replay is excluded. Paused, disconnected and unchecked sources have incomplete coverage.');
const gaps=el('p','ls-gap');gaps.setAttribute('role','status');const sampling=el('p','ls-note');
const grid=el('div','ls-grid'),recent=el('section'),listTitle=el('h3','','Recent live signals'),list=el('ol','ls-events');list.setAttribute('aria-label','Recent signals, newest first');list.append(el('li','','No source event received. No map pulse is generated.'));
recent.append(listTitle,list);const details=el('section','ls-detail');details.id='ls-detail';details.tabIndex=-1;details.setAttribute('aria-label','Selected signal evidence');details.append(el('h3','','Signal details'),el('p','','Select a ring or a recent signal to inspect its source and evidence.'));
const ticker=el('p','ls-certificate','Certificate stream: unavailable until source rights and capacity are verified.');
const methods=el('a','','Sources, definitions and limitations ↗');methods.href='./radar-methodology.html#live-signals-methods';
grid.append(recent,details);root.append(header,status,disclaimer,cards,summary,ticker,gaps,sampling,grid,methods);container.replaceChildren(root);
function sourceStatus(){
 for(const [key,view] of Object.entries(views)){
  const data=sources[key],available=eligible(data.status);view.input.disabled=!available;
  view.state.textContent=data.status.replaceAll('_',' ').toUpperCase()+(data.reason?' · '+data.reason:'');
  view.time.textContent='Last event: '+stamp(data.last_event)+' · Received: '+stamp(data.last_received);
  view.meter.textContent='Received events / last 60 s: '+(connected&&active()&&selected.has(key)&&available?ledger.count(key):'— (coverage incomplete)');
  view.scope.textContent=key==='ris_live'&&data.scope?'Scope: '+data.scope:'';
 }
}
function setStatus(value){if(status.textContent!==value)status.textContent=value}
function clearVisuals(){ledger.clearVisuals();event('nexus:live-clear',{})}
function closeStream(){const prior=stream;stream=null;if(prior){prior.close();connected=false}clearVisuals()}
function healthPayload(data){
 if(!data||data.schema!=='nexus.live.health.v1'||utcMillis(data.server_time)===null||!data.sources)return false;
 const validStates=new Set(['connected','quiet','healthy','degraded','stale','unavailable','connecting','disabled','license_blocked','unknown']);
 for(const key of Object.keys(SOURCE_NAMES)){
  const s=data.sources[key];if(!s||!validStates.has(s.status))continue;
  const scope=typeof s.scope==='string'?s.scope: s.scope&&typeof s.scope==='object'?JSON.stringify(s.scope):'';
  sources[key]={status:s.status,reason:typeof s.reason==='string'?s.reason.slice(0,300):'',last_event:utcMillis(s.last_event)!==null?s.last_event:null,last_received:utcMillis(s.last_received)!==null?s.last_received:null,scope:scope.slice(0,600)};
 }
 lastControl=Date.now();dirty=true;sourceStatus();return true;
}
async function boundedJSON(response,maxBytes=16384){
 if(!response.body)throw Error('Missing body');const reader=response.body.getReader(),chunks=[];let size=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>maxBytes)throw Error('Response too large');chunks.push(value)}}finally{await reader.cancel().catch(()=>{})}
 const data=new Uint8Array(size);let offset=0;for(const chunk of chunks){data.set(chunk,offset);offset+=chunk.length}return JSON.parse(new TextDecoder().decode(data));
}
async function checkHealth(){
 if(!active()||!origin||healthAbort)return;
 const controller=new AbortController();healthAbort=controller;const timeout=setTimeout(()=>controller.abort(),8000);
 try{const response=await fetch(origin+'/api/health',{cache:'no-store',credentials:'omit',signal:controller.signal});if(!response.ok)throw Error('Unavailable');const body=await boundedJSON(response,65536);
  if(!healthPayload(body.live_signals)){for(const s of Object.values(sources)){s.status='unavailable';s.reason='Live signal API is not configured.'}closeStream();sourceStatus();setStatus('LIVE SIGNALS NOT CONFIGURED · snapshot data remains separate');return}
  reconcile();
 }catch{if(active()){for(const s of Object.values(sources)){s.status='unavailable';s.reason='Service health unavailable; coverage unknown.'}closeStream();setStatus('SERVICE UNAVAILABLE · no filler events');sourceStatus()}}
 finally{clearTimeout(timeout);if(healthAbort===controller)healthAbort=null}
}
function parseFrame(message){
 const second=Math.floor(Date.now()/1000);if(second!==frameSecond){frameSecond=second;frameCount=0}
 if(++frameCount>128||typeof message.data!=='string'||message.data.length>16384){ledger.rejected++;failStream('Stream exceeded browser safety limits.');return null}
 try{return JSON.parse(message.data)}catch{ledger.rejected++;return null}
}
function failStream(reason){closeStream();nextConnect=Date.now()+retry+Math.random()*3000;retry=Math.min(60000,retry*2);setStatus('LIVE SERVICE UNAVAILABLE · reconnecting with backoff');gaps.textContent=reason+' Coverage is incomplete, not zero.';dirty=true;scheduleReconnect()}
function scheduleReconnect(){clearTimeout(retryTimer);if(active())retryTimer=setTimeout(()=>{retryTimer=null;checkHealth()},Math.max(1000,nextConnect-Date.now()))}
function receive(message,replay){
 if(!active())return;const data=parseFrame(message);if(!data)return;
 const item=validateObservation(data,{origin,countries});if(!item){ledger.rejected++;dirty=true;return}
 if(!selected.has(item.source))return;
 if(!ledger.add(item,{replay}))return;
 if(!replay&&freshForPulse(item)&&item.country)ledger.enqueue(item);
 if(item.source==='certstream')ticker.textContent='Certificate stream · '+item.label+' · '+(item.value??'unreported')+' · '+stamp(item.ts_observed)+(replay?' · retained replay':'');
 dirty=true;
}
function reconcile(){
 if(!active()){closeStream();setStatus(paused?'PAUSED · no live connection':document.hidden?'PAUSED · tab hidden':'PAUSED · Live signals closed');return}
 if(!origin){setStatus('LIVE SERVICE NOT CONFIGURED');return}
 if(!shouldConnect({open:disclosure.open,hidden:document.hidden,paused,selected,sources})){closeStream();setStatus('NO ELIGIBLE SIGNAL SELECTED · see source status');sourceStatus();return}
 if(stream||Date.now()<nextConnect||!countries.size)return;
 setStatus('CONNECTING TO LIVE SIGNALS');const connection=new EventSource(origin+'/api/live/events');stream=connection;
 connection.onopen=()=>{if(stream!==connection)return;connected=true;lastControl=Date.now();retry=15000;setStatus('CONNECTED · waiting for attributable observations');sourceStatus()};
 connection.addEventListener('health',m=>{if(stream!==connection)return;const payload=parseFrame(m);if(payload&&healthPayload(payload)){setStatus('CONNECTED · source coverage shown below');reconcile()}});
 connection.addEventListener('observation',m=>{if(stream===connection)receive(m,false)});
 connection.addEventListener('replay',m=>{if(stream===connection)receive(m,true)});
 connection.addEventListener('gap',m=>{if(stream!==connection)return;const p=parseFrame(m);if(p?.schema==='nexus.live.gap.v1'){gaps.textContent='Coverage gap: '+String(p.reason||'Retained history unavailable').slice(0,300)+'. Old observations are never animated as new.';clearVisuals()}});
 connection.onerror=()=>{if(stream===connection)failStream('Connection lost; this browser does not backfill missed observations.')};
}
function renderRows(){
 const entries=ledger.rows.filter(({item})=>selected.has(item.source));
 if(!entries.length){list.replaceChildren(el('li','','No source event received for selected signals. No map pulse is generated.'));return}
 // Retain focused controls instead of rebuilding the list underneath keyboard users.
 const focused=list.contains(document.activeElement)?document.activeElement.dataset.event:null;
 list.replaceChildren();for(const {item,replay} of entries){const li=el('li'),button=el('button','ls-event');button.type='button';button.dataset.event=item.id;
  button.append(el('strong','',SOURCE_NAMES[item.source]+' · '+(item.country||'unlocated')),el('span','',item.label),el('small','',stamp(item.ts_observed)+' · '+item.confidence+(replay?' · retained replay':'')));
  button.addEventListener('click',()=>showDetails(item));li.append(button);list.append(li);
 }
 if(focused){const button=[...list.querySelectorAll('button')].find(b=>b.dataset.event===focused);button?.focus({preventScroll:true})}
}
async function showDetails(item){
 selectedItem=item.id;evidenceAbort?.abort();const controller=new AbortController();evidenceAbort=controller;
 const title=el('h3','','Signal evidence'),facts=el('dl');
 const pair=(term,value)=>facts.append(el('dt','',term),el('dd','',value));
 pair('Source',SOURCE_NAMES[item.source]);pair('Observed',stamp(item.ts_observed));pair('Received by service',stamp(item.ts_received));pair('Observation',item.label);pair('Evidence class',item.confidence);
 if(item.value!==undefined)pair('Reported value',String(item.value)+' · units stated in observation / evidence');
 pair('Geography',item.country?(item.source==='ris_live'?'ASN registration country: ':'Reported affected country: ')+item.country:'Unlocated; no position inferred');
 if(item.asn)pair('Origin ASN',String(item.asn));pair('Attribution',item.attribution);
 const evidence=el('a','','Open retained evidence ↗');evidence.href=item.evidence_url;evidence.target='_blank';evidence.rel='noopener noreferrer';
 const expiry=el('p','ls-note','Checking evidence expiry…');details.replaceChildren(title,facts,evidence,expiry,el('p','ls-note','Aggregate evidence documents NEXUS processing. It is short-lived, may expire early under load, and is not permanent forensic replay.'));
 details.focus({preventScroll:true});const timeout=setTimeout(()=>controller.abort(),8000);
 try{const response=await fetch(item.evidence_url,{credentials:'omit',cache:'no-store',signal:controller.signal});if(selectedItem!==item.id)return;
  if(response.status===410){expiry.textContent='Evidence expired. This historical item cannot be independently replayed here.';evidence.remove();return}
  if(!response.ok)throw Error('Evidence unavailable');const data=await boundedJSON(response);if(selectedItem!==item.id)return;
  expiry.textContent=utcMillis(data.expires_at)!==null?'Evidence expires no later than '+stamp(data.expires_at)+'. Capacity limits can evict it sooner.':'Evidence is retained only briefly; an exact expiry was not supplied.';
 }catch{if(selectedItem===item.id&&!controller.signal.aborted)expiry.textContent='Evidence unavailable. Do not treat this item as independently verified.';else if(selectedItem===item.id)expiry.textContent='Evidence check interrupted or timed out.'}
 finally{clearTimeout(timeout);if(evidenceAbort===controller)evidenceAbort=null}
}
document.addEventListener('nexus:live-select',e=>{const row=ledger.rows.find(({item})=>item.id===e.detail?.id);if(row)showDetails(row.item)});
document.addEventListener('nexus:live-omitted',()=>{ledger.visualOmissions++;dirty=true});
function update(){
 if(!active())return;
 if(stream&&Date.now()-lastControl>45000){failStream('Source health heartbeat expired.');return}
 for(const item of ledger.drain())event('nexus:live-observation',item);
 sourceStatus();if(dirty){renderRows();sampling.textContent='Display limit: 30 simultaneous rings. Omitted visuals: '+ledger.visualOmissions+'. Rejected messages: '+ledger.rejected+'. These are display diagnostics, separate from source coverage.';dirty=false}
}
let lastHealth=0;
function visibility(){
 clearInterval(tick);tick=null;clearTimeout(retryTimer);retryTimer=null;
 if(!active()){healthAbort?.abort();evidenceAbort?.abort();closeStream();reconcile();return}
 checkHealth();lastHealth=Date.now();tick=setInterval(()=>{update();if(Date.now()-lastHealth>=30000){lastHealth=Date.now();checkHealth()}},250);reconcile();
}
pause.addEventListener('click',()=>{paused=!paused;pause.textContent=paused?'Resume live signals':'Pause live signals';pause.setAttribute('aria-pressed',String(paused));visibility()});
document.addEventListener('visibilitychange',visibility);disclosure.addEventListener('toggle',visibility);
window.addEventListener('pagehide',()=>{clearInterval(tick);clearTimeout(retryTimer);healthAbort?.abort();evidenceAbort?.abort();closeStream()});
// Country codes are local static metadata, never inferred from arbitrary source strings.
try{const response=await fetch('./assets/country-codes.json');if(!response.ok)throw Error('Country metadata missing');const data=await boundedJSON(response,32768);for(const row of data)if(/^[A-Z]{2}$/.test(row['alpha-2']))countries.add(row['alpha-2']);visibility()}
catch{setStatus('LIVE SIGNALS UNAVAILABLE · local country metadata could not load')}

