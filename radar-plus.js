import {buildExtrasUI} from './radar-extras.js';
// NEXUS V2: country-level IP indicator observatory + CISA KEV priority + ENISA sectors.
// Data comes only from the scheduled snapshot; no demonstration data is invented.
const $=s=>document.querySelector(s);
const txt=(s,v)=>{$(s).textContent=String(v)};
const fmt=n=>Number(n||0).toLocaleString('en-US');
const DOM={svg:$('#globe'),map:$('#world-layer'),markers:$('#points-layer')};
const state={data:null,world:null,d3:null,projection:null,path:null,iso:null,byCode:new Map(),layer:'all',selected:null,spin:true,draggedAt:0,extra:null,extraError:null,pinned:null,tab:'overview',focusFrame:0,hovered:null,searchIndex:0,pending:new URLSearchParams(location.search).get('country')?.toUpperCase()||null};
const SOURCES={blocklistde:'blocklist.de / 48h',ipsum:'IPsum / 3+ source lists',dshield:'DShield / sensor source IPs',feodo:'Feodo / botnet C2'};
function create(tag,cls,value){const el=document.createElement(tag);if(cls)el.className=cls;if(value!==undefined)el.textContent=String(value);return el;}
function link(label,url){const a=create('a','',label);a.href=url;a.target='_blank';a.rel='noopener noreferrer';return a;}
const extraUI=buildExtrasUI(state,{create,note,fmt,name,link,select});
function setHealth(msg,ok){txt('#status',msg);$('#connection-dot').className='beacon '+(ok===true?'live':ok===false?'error':'');}
function allCountries(){
 const base=state.data?.indicators?.countries||[];
 const additional=new Set();
 for(const id of ['urlhaus','threatfox'])
  for(const code of Object.keys(state.extra?.feeds?.[id]?.countries||{}))additional.add(code);
 const known=new Set(base.map(x=>x.code));
 return [...base,...[...additional].filter(code=>!known.has(code)&&/^[A-Z]{2}$/.test(code))
 .map(code=>({code,indicators:0,by_source:{},examples:[],samples_by_source:{}}))];
}
function score(row){
 if(state.layer==='all')return Number(row.indicators||0);
 if(['urlhaus','threatfox'].includes(state.layer))
   return Number(state.extra?.feeds?.[state.layer]?.countries?.[row.code]||0);
 return Number(row.by_source?.[state.layer]||0);
}
function layerUnits(){return state.layer==='urlhaus'?'LISTED URLs ON IPv4 HOSTS':state.layer==='threatfox'?'LISTED IPv4 IOCs':'LISTED IPv4 IPs';}
function countries(){return allCountries().filter(c=>score(c)>0).sort((a,b)=>score(b)-score(a));}
function name(code){if(state.iso?.byCode?.has(code))return state.iso.byCode.get(code).name;
 try{return new Intl.DisplayNames(['en'],{type:'region'}).of(code)||code;}catch(e){return code;}}
function getISO(f){const n=String(f.id||'').padStart(3,'0');return state.iso?.byNumeric?.get(n)||null;}
function showTip(event,code){const row=allCountries().find(v=>v.code===code);const tip=$('#map-tooltip'),bounds=$('#globe-container').getBoundingClientRect();
 tip.replaceChildren();tip.append(create('strong','',name(code)),create('div','',row?code+' / '+fmt(score(row))+' '+layerUnits():code+' / NO LISTED INDICATORS'),create('small','',row?fmt(row.indicators)+' across all available feeds':'No coverage in this current feed sample.'));
 tip.hidden=false;let x=event.clientX-bounds.left+14,y=event.clientY-bounds.top+16;
 tip.style.left=Math.max(8,Math.min(bounds.width-250,x))+'px';tip.style.top=Math.max(8,Math.min(bounds.height-105,y))+'px';
}
function hideTip(){const tip=$('#map-tooltip');if(tip)tip.hidden=true;}
function draw(){if(!state.d3||!state.world)return;const d3=state.d3,p=state.projection,path=state.path;
 const earth=d3.select(DOM.map);earth.selectAll('*').remove();const top=d3.select(DOM.markers);top.selectAll('*').remove();
 earth.append('circle').attr('cx',450).attr('cy',260).attr('r',Math.max(253,p.scale()+16)).attr('fill','url(#glow)').attr('opacity',.72).attr('filter','url(#softglow)');
 earth.append('path').datum({type:'Sphere'}).attr('d',path).attr('fill','url(#planet-fill)').attr('stroke','#b54057').attr('stroke-width',1.4);
 earth.append('path').datum(d3.geoGraticule10()).attr('d',path).attr('fill','none').attr('stroke','#502838').attr('opacity',.48).attr('stroke-width',.55);
 const rows=new Map(countries().map(c=>[c.code,c]));const values=[...rows.values()].map(score);const max=Math.max(1,...values);
 earth.selectAll('path.country-shape').data(state.world).join('path').attr('class','country-shape').attr('d',path)
  .attr('fill',f=>{const code=getISO(f),val=rows.get(code)?score(rows.get(code)):0;if(val===0)return '#1b1d29';if(code===state.selected)return '#ff6079';return d3.interpolateRgb('#491c2e','#f54a63')(Math.max(.08,Math.log1p(val)/Math.log1p(max)));})
  .attr('stroke',f=>getISO(f)===state.selected?'#ffb1bf':rows.has(getISO(f))?'#e35770':'#572d3b')
  .attr('stroke-width',f=>getISO(f)===state.selected?1.7:rows.has(getISO(f))?.8:.45)
  .on('click',(event,f)=>{const code=getISO(f);if(code)select(code);})
  .on('mousemove',(event,f)=>{const code=getISO(f);if(code)showTip(event,code);else hideTip();})
  .on('mouseleave',hideTip)
  .append('title').text(f=>{const code=getISO(f);return code?name(code)+' / '+fmt(rows.get(code)?score(rows.get(code)):0)+' listed IPs':'Unmapped territory'});
 const center=p.rotate().map(v=>-v);
 for(const row of countries()){
  const feature=state.byCode.get(row.code);if(!feature)continue;const lonlat=d3.geoCentroid(feature);
  if(!lonlat||d3.geoDistance(lonlat,center)>=Math.PI/2-.05)continue;
  const xy=p(lonlat);if(!xy||xy.some(x=>!Number.isFinite(x)))continue;
  const count=score(row);const r=Math.min(11,2.5+Math.log10(1+count)*1.7);
  const marker=top.append('g').attr('transform',`translate(${xy[0]},${xy[1]})`).attr('style','cursor:pointer');
  marker.append('circle').attr('r',r+7).attr('fill','none').attr('stroke','#ff3c59').attr('opacity',.16);
  marker.append('circle').attr('r',r).attr('fill',row.code===state.selected?'#fff':'#fa435f').attr('fill-opacity',.76).attr('stroke','#fd8da2');
  marker.append('title').text(name(row.code)+' — '+fmt(count)+' listed IPs from selected feed(s)');
  marker.on('click',event=>{event.stopPropagation();select(row.code)})
        .on('mousemove',event=>showTip(event,row.code)).on('mouseleave',hideTip);
 }
}
function rankings(){const pane=$('#rankings');pane.replaceChildren();const all=countries();
 if(!all.length){pane.append(create('div','empty-state','No countries are present in this source layer.'));return;}
 all.forEach((row,i)=>{const b=create('button','rank'+(row.code===state.selected?' selected':'')),left=create('span','',String(i+1).padStart(2,'0')+'  '+name(row.code));
 left.append(create('small','',row.code+' · '+fmt(score(row))+' '+layerUnits()));
 b.append(left,create('b','',fmt(score(row))));b.addEventListener('click',()=>select(row.code));pane.append(b);});
 const active=pane.querySelector('.rank.selected');if(active){
  // Only scroll inside the country ranking panel. scrollIntoView() also scrolls
  // the whole page, which caused the screen to drift downward on repeated clicks.
  const top=active.offsetTop-pane.offsetTop;
  if(top<pane.scrollTop)pane.scrollTop=top;
  else if(top+active.offsetHeight>pane.scrollTop+pane.clientHeight)pane.scrollTop=top+active.offsetHeight-pane.clientHeight;
 }
}
function flag(code){return /^[A-Z]{2}$/.test(code)?String.fromCodePoint(...[...code].map(c=>127397+c.charCodeAt(0))):'◎';}
function kpi(value,label){const e=create('div','dossier-kpi');e.append(create('strong','',value),create('small','',label));return e;}
function note(text){return create('p','dossier-note',text);}
function select(code,{zoom=true,updateUrl=true,autoTour=false}={}){
 if(tourActive&&!autoTour)stopTour();
 // Repeated clicks on the currently selected country preserve camera framing
 // and scroll position instead of repeatedly triggering focus animations.
 if(state.selected===code && !autoTour){state.draggedAt=Date.now();state.tab='overview';renderDossier();triggerCountryPulse();return;}
 const row=allCountries().find(r=>r.code===code);
 state.selected=code;state.tab='overview';hideTip();rankings();triggerCountryPulse();
 if(row)renderDossier();else renderUnavailableCountry(code);
 txt('#map-mode','◉ COUNTRY INVESTIGATION / '+code);txt('#focused-title',name(code).toUpperCase());
 $('#map-focus-controls').hidden=false;setFocusSummary();
 if(zoom)flyToCountry(code);
 if(updateUrl)syncAddress();
}
function renderUnavailableCountry(code){
 const panel=$('#country-detail');panel.className='dossier';panel.replaceChildren();
 const header=create('div','dossier-heading');header.append(create('div','dossier-eyebrow','◎ COUNTRY VIEW / NO OBSERVED COVERAGE'),create('div','dossier-country',flag(code)+' '+name(code)));
 panel.append(header);
 const body=create('div','dossier-section');
 body.append(create('h3','','NO LISTED IPs IN THE CURRENT SNAPSHOT'));
 body.append(note('NEXUS has no geolocated IP indicators assigned to this country in the available feeds. This does not mean the country is free from cyber activity, attacks, compromised systems, or vulnerabilities.'));
 body.append(note('Data depends on provider coverage, IP allocation and list inclusion. Country-level vulnerability exposure is not measured by this module.'));
 panel.append(body);txt('#dossier-mode','COVERAGE NOT OBSERVED / '+code);
}
function triggerCountryPulse(){
 const container=$('#globe-container');if(!container)return;
 container.classList.remove('country-focus-activated');void container.offsetWidth;
 container.classList.add('country-focus-activated');
 const existing=container.querySelector('.country-focus-flash');if(existing)existing.remove();
 const flash=create('div','country-focus-flash');
 flash.append(create('small','','◈ TARGET LOCK / GEO INTELLIGENCE'),create('strong','',name(state.selected).toUpperCase()),create('span','','PASSIVE THREAT OBSERVATION'));
 container.append(flash);
 flash.addEventListener('animationend',()=>flash.remove(),{once:true});
}
function renderCountryOverview(row){
 const box=create('div','country-overview'),signals=state.data?.country_cve_signals;
 const country=signals?.countries?.[row.code];
 box.append(create('h3','','COUNTRY THREAT INTELLIGENCE / '+row.code));
 const cards=create('div','overview-cards');
 for(const [label,value] of [
  ['LISTED IP INDICATORS',fmt(row.indicators)],
  ['C2 SOURCE LIST',fmt(row.by_source?.feodo||0)],
  ['SENSOR SOURCE LIST',fmt(row.by_source?.dshield||0)],
  ['CROSS-LISTED IPs',Number.isInteger(row.multi_source_count)?fmt(row.multi_source_count):'N/A']]){
   const card=create('div','overview-card');card.append(create('small','',label),create('strong','',value));cards.append(card);
 }
 box.append(cards);
 const executive=create('div','overview-executive');
 executive.append(create('div','overview-eyebrow','◈ INTELLIGENCE SNAPSHOT · '+name(row.code).toUpperCase()));
 executive.append(create('div','overview-executive-title',fmt(row.indicators)+' LISTED NETWORK INDICATORS'));
 executive.append(note('Country of public IP infrastructure, not attacker nationality. Data is refreshed every six hours.'));
 box.prepend(executive);
 box.append(create('h3','','PRIORITY VULNERABILITY SIGNALS · SAMPLED IPs'));
 if(country?.responded>0){
  box.append(note('Shodan InternetDB passive enrichment: '+country.responded+' of '+country.requested+' sampled IPs returned data; '+country.with_cves+' had possible CVE matches. NOT national CVE prevalence.'));
  const cves=Array.isArray(country.cves)?country.cves.slice(0,6):[];
  if(cves.length){
   for(const item of cves){
    if(!/^CVE-\d{4}-\d{4,}$/.test(item.id))continue;
    const line=create('div','overview-finding');
    line.append(link(item.id+' ↗','https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(item.id)),create('span','',fmt(item.sample_ips)+' sampled IPs'));
    box.append(line);
   }
  }else box.append(note('No possible CVEs reported for these sampled IPs; this does not establish national safety.'));
  const ports=Array.isArray(country.ports)?country.ports.slice(0,5):[];
  box.append(create('h3','','EXPOSED PORTS · COUNTRY IP SAMPLE'));
  if(ports.length)for(const item of ports){const line=create('div','overview-finding');line.append(create('span','',':'+item.port),create('strong','',fmt(item.sample_ips)+' sampled IPs'));box.append(line);}
  else box.append(note('No exposed ports returned in the sampled metadata.'));
 }else{
  box.append(note('Country-specific CVE sample data is not available in this snapshot. No CVE ranking can be inferred from global KEV data.'));
 }
 box.append(create('h3','','ACTIVITY SIGNALS · PUBLIC SOURCE LISTS'));
 const labels=[['FEODO / BOTNET C2',row.by_source?.feodo||0],['DSHIELD / SENSOR SOURCES',row.by_source?.dshield||0],['BLOCKLIST.DE / REPORTED ABUSE',row.by_source?.blocklistde||0],['IPSUM / AGGREGATED LISTS',row.by_source?.ipsum||0]];
 for(const [label,value] of labels){const line=create('div','overview-finding');line.append(create('span','',label),create('strong','',fmt(value)+' IPs'));box.append(line);}
 box.append(note('These categories describe public IP list membership, not confirmed attacks originating in this country.'));
 box.append(create('h3','','MOST IMPACTED SECTORS · GLOBAL CONTEXT'));
 const sector=state.data?.sectors;
 if(Array.isArray(sector?.rows)&&sector.rows.length){
  for(const item of sector.rows.slice(0,4)){const line=create('div','overview-finding');line.append(create('span','',item.name),create('strong','',Number(item.percent).toFixed(1)+'%'));box.append(line);}
  box.append(note('GLOBAL sector distribution from '+(sector.source||'the source report')+'. This is NOT a country-specific sector breakdown.'));
 }else box.append(note('No sector statistics available in this snapshot.'));
 box.append(countryTrend(row.code));
 box.append(extraUI.countrySection(row.code));
 const action=create('button','primary research-action','◈ EXPLORE COUNTRY CVE EVIDENCE');
 action.addEventListener('click',()=>{state.tab='cves';renderDossier();});box.append(action);
 return box;
}
function renderDossier(){
 const row=allCountries().find(r=>r.code===state.selected),panel=$('#country-detail');if(!row)return;
 panel.className='dossier';panel.replaceChildren();
 const rank=countries().findIndex(x=>x.code===row.code)+1;const globalRank=allCountries().findIndex(x=>x.code===row.code)+1;
 txt('#dossier-mode','COUNTRY INTELLIGENCE / '+row.code);
 const heading=create('div','dossier-heading');heading.append(create('div','dossier-eyebrow','◉ INVESTIGATION DOSSIER // '+row.code));
 const title=create('div','dossier-country');title.append(create('span','flag',flag(row.code)),create('span','',name(row.code)));heading.append(title,create('div','dossier-sub',row.code==='MA'?'FULL GEOGRAPHIC VIEW INCLUDING WESTERN SAHARA · STATUS DISPUTED · IP COUNTS: MA ONLY':'COUNTRY-LEVEL IP ALLOCATION · NOT ACTOR ATTRIBUTION'));panel.append(heading);
 const metrics=create('div','dossier-summary');
 metrics.append(kpi(fmt(score(row)),'IN SELECTED LAYER'),kpi(fmt(row.indicators),'ALL FEEDS / UNIQUE'),
   kpi(rank?'#'+rank:'—','RANK IN THIS LAYER'),kpi(Number.isInteger(row.multi_source_count)?fmt(row.multi_source_count):'—','IN 2+ SOURCE LISTS'));
 panel.append(metrics);
 const tabs=create('div','dossier-tabs');for(const [key,label] of [['overview','INTELLIGENCE'],['cves','CVE RESEARCH'],['evidence','EVIDENCE'],['context','CONTEXT'],['sources','SOURCES']]){
  const b=create('button',key===state.tab?'active':'',label);b.addEventListener('click',()=>{state.tab=key;renderDossier();});tabs.append(b);
 }panel.append(tabs);
 const body=create('div','dossier-section');
 if(state.tab==='overview'){
  body.append(renderCountryOverview(row));
 }else if(state.tab==='sources'){
  body.append(create('h3','',fmt(row.indicators)+' DISTINCT SOURCE IP ADDRESSES'));
  const max=Math.max(1,...Object.keys(SOURCES).map(k=>Number(row.by_source?.[k]||0)));
  for(const [key,label] of Object.entries(SOURCES)){
   const n=Number(row.by_source?.[key]||0),r=create('div','dossier-source'),top=create('div','dossier-source-top');
   top.append(create('span','',label),create('strong','',fmt(n)));r.append(top);
   const meter=create('div','dossier-meter'),bar=create('span');bar.style.width=(100*n/max)+'%';meter.append(bar);r.append(meter);body.append(r);
  }
  body.append(note('Counts from individual feeds overlap. All-feeds totals are deduplicated across providers.'));
  const summary=create('div','dossier-signal-summary');
  summary.append(create('h3','','HIGH-VALUE SECURITY SIGNALS'));
  summary.append(vendorRow('C2 INDICATORS / FEODO',fmt(row.by_source?.feodo||0)));
  summary.append(vendorRow('SENSOR-OBSERVED IPs / DSHIELD',fmt(row.by_source?.dshield||0)));
  summary.append(vendorRow('MULTI-FEED IP OVERLAP',Number.isInteger(row.multi_source_count)?fmt(row.multi_source_count):'Not collected'));
  summary.append(note('These are different signal categories, not verified attack totals. A zero count only means no address was listed in that input dataset.'));
  const cveJump=create('button','primary research-action','◈ INVESTIGATE COUNTRY CVE SIGNALS');
  cveJump.addEventListener('click',()=>{state.tab='cves';renderDossier();});
  summary.append(cveJump);body.append(summary);
  body.append(countryTrend(row.code));
 }else if(state.tab==='cves'){
  body.append(renderCVESignals(row));
 }else if(state.tab==='evidence'){
  body.append(create('h3','','SOURCE-ATTRIBUTED IP EVIDENCE / SAMPLE'));
  const samples=row.samples_by_source||{};let shown=0;
  for(const [key,label] of Object.entries(SOURCES)){
   const entries=samples[key]||[];
   if(!entries.length)continue;
   body.append(create('h3','',label+' · '+entries.length+' representative records'));
   for(const sample of entries){
    const e=create('div','dossier-evidence'),left=create('div');left.append(create('code','',sample.ip),create('small','',Array.isArray(sample.sources)?sample.sources.join(' / '):key));
    const actions=create('div','evidence-actions');const inspect=create('button','','INSPECT');inspect.addEventListener('click',()=>inspectIp(sample.ip));actions.append(inspect,link('SANS ↗','https://isc.sans.edu/ipinfo/'+encodeURIComponent(sample.ip)));e.append(left,actions);body.append(e);shown++;
   }
  }
  if(!shown){const old=row.examples||[];for(const sample of old){const el=create('div','dossier-evidence');el.append(create('code','',sample.ip),create('small','',(sample.sources||[]).join(' + ')));body.append(el);}
   if(!old.length)body.append(note('Per-provider evidence samples will appear after the new collection workflow completes. Existing country totals remain valid.'));}
  body.append(note('Evidence IPs are examples from public indicator lists, not a list of all addresses, validated compromise, or an endorsement to scan them.'));const ctx=create('div','ip-context');ctx.id='ip-context';body.append(ctx);
 }else{
  const date=state.data.generated_at||'unknown';
  const rows=[['POSITION','Country #'+globalRank+' by unique listed IPs (all sources)'],
   ['SAMPLE SHARE',((100*row.indicators)/Math.max(1,state.data.indicators.resolved_indicators)).toFixed(2)+'% of country-resolved indicators in this snapshot'],
   ['COLLECTED',new Date(date).toLocaleString()],['LOCATION',row.code==='MA'?'Geographic outline includes Western Sahara; international status disputed. Source-IP statistics use MA allocation only.':'DB-IP Lite country-level allocation'],
   ['CVE CORRELATION','No per-country vulnerable-device or CVE evidence in this source collection'],
   ['PROVENANCE','blocklist.de · IPsum · SANS DShield · abuse.ch Feodo']];
  for(const [label,value] of rows){const e=create('div','dossier-source');e.append(create('div','dossier-eyebrow',label),note(value));body.append(e);}
  body.append(countryTrend(row.code));body.append(link('METHODS & LIMITATIONS ↗','./radar-methodology.html'));
 }
 panel.append(body);
 const actions=create('div','dossier-actions');
 const pin=create('button','primary',state.pinned===row.code?'UNPIN COUNTRY':'⚖ PIN / COMPARE');
 pin.addEventListener('click',()=>pinCountry(row.code));actions.append(pin);
 const copy=create('button','','↗ SHARE LINK');copy.addEventListener('click',shareCountry);actions.append(copy);
 const brief=create('button','','↓ EXPORT BRIEF');brief.addEventListener('click',downloadBrief);actions.append(brief);
 panel.append(actions);
}
const internetDbCache=new Map();
const sampleResearchCache=new Map();
function sampledIPs(row,limit=10){
 const bySource=row.samples_by_source||{};
 // Prefer IPs across providers, not just the dominant list. These are small
 // deterministic samples, not representative or exhaustive.
 const groups=Object.keys(SOURCES).map(k=>(bySource[k]||[]).map(x=>x.ip));
 const seen=new Set(),result=[];
 for(let depth=0;depth<6 && result.length<limit;depth++){
  for(const group of groups){const ip=group[depth];if(!ip||seen.has(ip))continue;seen.add(ip);result.push(ip);if(result.length===limit)break;}
 }
 return result;
}
function vendorRow(label,value){const row=create('div','research-stat');row.append(create('span','',label),create('strong','',String(value)));return row;}
function sourceResearchLinks(code){
 const links=create('div','research-links');
 const attackUrl='https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/monitoring/?category=monitoring&geo='+encodeURIComponent(code)+'&limit=100&statistic=unique_ips';
 const exposureUrl='https://dashboard.shadowserver.org/statistics/combined/visualisation/?date_range=1&group_by=tag&source=http_vulnerable&geo='+encodeURIComponent(code)+'&style=table';
 const shadowA=link('SHADOWSERVER / EXPLOIT ATTEMPTS ↗',attackUrl);
 const shadowB=link('SHADOWSERVER / EXPOSED WEB CVEs ↗',exposureUrl);
 links.append(shadowA,shadowB);
 return links;
}
function renderCVESignals(row){
 const wrap=create('div','cve-signals');
 wrap.append(create('h3','','COUNTRY-SCOPED VULNERABILITY RESEARCH / '+row.code));
 const callout=create('div','research-callout');
 callout.append(create('strong','','DATASET 01 · SHADOWSERVER COUNTRY STATISTICS'),
  note('Review Shadowserver’s country-filtered honeypot exploitation observations or its exposed vulnerable web services. These external reports can distinguish traffic originating from a country from vulnerable devices within it.'));
 callout.append(sourceResearchLinks(row.code));
 callout.append(note('Shadowserver publishes country-level figures on its own site. NEXUS does not scrape, reproduce, or invent these restricted datasets.'));
 wrap.append(callout);
 const ips=sampledIPs(row),samplePanel=create('div','research-callout');
 samplePanel.append(create('strong','','DATASET 02 · SHODAN INTERNETDB / PASSIVE IP ENRICHMENT'));
 samplePanel.append(note('Inspect '+ips.length+' selected IP indicators from '+name(row.code)+'. Identify possible CVEs and exposed ports observed by Shodan. These are not the country’s most common vulnerabilities or confirmed exploits; results can be stale or unverified.'));
 if(row.code==='MA')samplePanel.append(note('Only IP addresses geolocated as MA are included. The contiguous geographic outline does not change country-of-IP reporting.'));
 const action=create('button','primary research-action','⌁ ANALYZE '+ips.length+' SAMPLE IPs');
 action.disabled=!ips.length;
 const results=create('div','research-results');
 action.addEventListener('click',()=>{action.disabled=true;action.textContent='ANALYZING PUBLIC DATA…';runCountryPassiveResearch(row,results).finally(()=>{action.disabled=false;action.textContent='↻ REFRESH SAMPLE RESEARCH';});});
 samplePanel.append(action,results);
 if(sampleResearchCache.has(row.code))populatePassiveResearch(results,sampleResearchCache.get(row.code),row);
 if(!ips.length)samplePanel.append(note('No attributed sample addresses are available yet. Wait for the next data-collection snapshot.'));
 wrap.append(samplePanel);
 return wrap;
}
async function lookupInternetDB(ip){
 if(internetDbCache.has(ip))return internetDbCache.get(ip);
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),8500);
 try{
  const response=await fetch('https://internetdb.shodan.io/'+encodeURIComponent(ip),{signal:controller.signal});
  if(response.status===404){const empty={ip,ports:[],vulns:[],tags:[],cpes:[],unindexed:true};internetDbCache.set(ip,empty);return empty;}
  if(!response.ok)throw Error('Shodan '+response.status);
  const raw=await response.json(),data={ip,ports:Array.isArray(raw.ports)?raw.ports.slice(0,100):[],
   vulns:Array.isArray(raw.vulns)?raw.vulns.filter(x=>/^CVE-\d{4}-\d{4,}$/.test(x)).slice(0,150):[],
   tags:Array.isArray(raw.tags)?raw.tags.slice(0,20):[],cpes:Array.isArray(raw.cpes)?raw.cpes.slice(0,40):[]};
  internetDbCache.set(ip,data);return data;
 }finally{clearTimeout(timer);}
}
async function runCountryPassiveResearch(row,box){
 box.replaceChildren();box.append(note('Consulting Shodan InternetDB for a small set of public addresses. No direct network probes are sent to those IPs.'));
 const ips=sampledIPs(row);let cursor=0;const records=[],errors=[];
 await Promise.all(Array.from({length:Math.min(3,ips.length)},async()=>{
  while(cursor<ips.length){const ip=ips[cursor++];
   try{records.push(await lookupInternetDB(ip));}
   catch(e){errors.push(ip+': '+e.message);}
  }
 }));
 const result={records,errors,checked_at:new Date().toISOString(),requested:ips.length};
 sampleResearchCache.set(row.code,result);
 if(state.selected===row.code&&state.tab==='cves'&&box.isConnected)populatePassiveResearch(box,result,row);
}
function populatePassiveResearch(box,result,row){
 box.replaceChildren();const records=result.records||[];
 box.append(create('h3','','SAMPLED-IP FINDINGS / '+row.code));
 box.append(vendorRow('PUBLIC IPs QUERIED',result.requested));
 box.append(vendorRow('RESPONSES RETURNED',records.length));
 const indexed=records.filter(x=>!x.unindexed),cveIPs=new Map(),portIPs=new Map();
 for(const r of records){
  for(const cve of new Set(r.vulns||[])){if(!cveIPs.has(cve))cveIPs.set(cve,new Set());cveIPs.get(cve).add(r.ip);}
  for(const port of new Set(r.ports||[])){if(!portIPs.has(port))portIPs.set(port,new Set());portIPs.get(port).add(r.ip);}
 }
 box.append(vendorRow('SAMPLED IPs WITH ANY CVE',records.filter(r=>r.vulns?.length>0).length));
 box.append(create('h3','','CVE MENTIONS IN RETURNED IP RECORDS'));
 const most=[...cveIPs.entries()].sort((a,b)=>b[1].size-a[1].size||a[0].localeCompare(b[0])).slice(0,12);
 if(!most.length)box.append(note('No CVEs were returned for these sampled IPs. This does not prove the selected country or these hosts are free of vulnerabilities.'));
 for(const [cve,ips] of most){const e=create('div','research-cve');
  e.append(link(cve+' ↗','https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(cve)),create('span','',ips.size+' sampled IP'+(ips.size===1?'':'s')));
  const detail=create('small','',Array.from(ips).slice(0,3).join(', '));e.append(detail);box.append(e);}
 box.append(create('h3','','COMMON OBSERVED PORTS / SAMPLED IPs'));
 const ports=[...portIPs.entries()].sort((a,b)=>b[1].size-a[1].size||a[0]-b[0]).slice(0,10);
 for(const [port,ips] of ports){const e=create('div','research-stat');e.append(create('span','',':'+port),create('strong','',ips.size+' sampled IPs'));box.append(e);}
 if(!ports.length)box.append(note('No service information returned.'));
 box.append(note('Shodan InternetDB updates periodically. Its vulns include both verified and unverified identifications. Country totals here are a tiny, biased sample of listed source IP infrastructure, not country-wide exposure estimates.'));
 if(result.errors?.length)box.append(note(result.errors.length+' lookups failed (possibly browser CORS or provider rate limits). No failed query is treated as a negative vulnerability result.'));
 box.append(create('div','research-foot','READ-ONLY ENRICHMENT · NO DIRECT SCANNING · '+new Date(result.checked_at).toLocaleString()));
}
function pinCountry(code){
 if(state.pinned===code){state.pinned=null;$('#compare-panel').hidden=true;showToast('Comparison pin removed.');renderDossier();return;}
 if(!state.pinned){state.pinned=code;showToast('Pinned '+name(code)+'. Select another country, then click PIN / COMPARE.');renderDossier();return;}
 if(state.pinned!==code){renderComparison(state.pinned,code);showToast('Comparing '+name(state.pinned)+' and '+name(code));}
}
function renderComparison(a,b){const left=allCountries().find(x=>x.code===a),right=allCountries().find(x=>x.code===b);if(!left||!right)return;
 const panel=$('#compare-panel'),box=$('#compare-content');panel.hidden=false;box.replaceChildren();box.className='compare-content';
 box.append(create('div','compare-title',name(a)+'  ⚖  '+name(b)));
 const add=(label,x,y)=>{box.append(create('p','dossier-eyebrow',label));const grid=create('div','compare-grid');
 grid.append(create('b','',fmt(x)),create('span','','VS'),create('b','',fmt(y)));box.append(grid);
 const track=create('div','compare-mini'),sum=Math.max(1,x+y);const l=create('div');l.style.width=100*x/sum+'%';const r=create('div','right');r.style.width=100*y/sum+'%';track.append(l,r);box.append(track);};
 add('DISTINCT IPs / ALL FEEDS',left.indicators,right.indicators);
 for(const key of Object.keys(SOURCES))add(SOURCES[key].toUpperCase(),Number(left.by_source?.[key]||0),Number(right.by_source?.[key]||0));
 box.append(note('Different list coverage does not imply that one country has greater cybercrime or security risk.'));
}
function renderCVEs(){const box=$('#cve-board');box.replaceChildren();const data=state.data.cves;
 if(data.status!=='ok'){box.append(create('div','empty-state','CISA/EPSS enrichment unavailable: '+(data.error||'no data')));return;}
 txt('#kev-method',fmt(data.total_kev)+' CISA KEVs · '+fmt(data.scored_candidates)+' ranked candidates');
 for(const row of data.top||[]){const card=create('button','cve-row');const id=create('strong','',row.id);
 const desc=create('span','cve-description',row.vendor+' / '+row.product);desc.append(create('small','',row.name||''));
 const epss=create('span','score',row.epss==null?'—':(row.epss*100).toFixed(1)+'%');
 epss.append(create('small','',row.epss==null?'EPSS N/A':'EPSS / 30D'));
 const ransomware=create('span','ransom'+(row.ransomware_observed?'':' blank'),row.ransomware_observed?'RANSOMWARE':'KEV');
 card.append(id,desc,epss,ransomware);card.addEventListener('click',()=>showCVE(row));box.append(card);}
}
function showCVE(row){
 const prior=$('#cve-detail');if(prior)prior.remove();const panel=create('div','','');panel.id='cve-detail';
 panel.append(create('h3','',row.id+' / '+(row.name||'')),create('p','',row.description||'No description'));
 panel.append(create('p','',row.epss==null?'No EPSS score returned':'EPSS '+(row.epss*100).toFixed(2)+'% estimated exploitation probability over the next 30 days; not proof of exploitability on a target'));
 if(row.cvss?.score!==undefined)panel.append(create('p','', 'NVD CVSS '+row.cvss.score+' ('+(row.cvss.severity||'unclassified')+')'));
 panel.append(create('p','', 'CISA added '+row.date_added+' · Ransomware campaign use '+(row.ransomware_observed?'KNOWN':'not marked known')));
 panel.append(link('Open NVD vulnerability record ↗','https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(row.id)));
 $('#cve-board').after(panel);panel.scrollIntoView({block:'nearest',behavior:'smooth'});
}
function renderSectors(){const box=$('#sector-board');box.replaceChildren();const sector=state.data.sectors;
 if(!sector){box.append(create('div','empty-state','Sector report unavailable'));return;}
 for(const s of sector.rows){const row=create('div','sector-row');const title=create('div','name');title.append(create('span','',s.name),create('strong','',s.percent.toFixed(1)+'%'));
 const bar=create('div','track'),inner=create('span');inner.style.width=Math.min(100,s.percent/40*100)+'%';bar.append(inner);row.append(title,bar);box.append(row);}
}
function renderSources(){const box=$('#feed-health');box.replaceChildren();for(const row of [...(state.data.indicators.source_health||[]),...(state.extra?.source_health||state.data.extra_health||[])]){
  const e=create('div','feed');const description=create('div');description.append(create('strong','',row.name),create('small','',row.meaning||''));
  const count=create('span','count',row.status==='ok'?fmt(row.records):'UNAVAILABLE');count.append(create('small','',row.status==='ok'?'INGESTED':'FAILED'));e.append(description,count);box.append(e);}
}
function renderTable(){const box=$('#observations');box.replaceChildren();for(const row of countries().slice(0,100)){const tr=create('tr');for(const val of [name(row.code)+' ('+row.code+')',fmt(row.indicators),fmt(row.by_source?.blocklistde),fmt(row.by_source?.ipsum),fmt((row.by_source?.dshield||0)+(row.by_source?.feodo||0))])tr.append(create('td','',val));box.append(tr);}}
function renderSummary(){const d=state.data,box=$('#collection-info');box.replaceChildren();const lines=[
 ['COLLECTION TIME',new Date(d.generated_at).toLocaleString()],['SOURCE COUNTRIES',fmt(d.indicators.countries.length)],
 ['LOCATION DATABASE',d.indicators.geo_method||'IP geolocation'],
 ['UNRESOLVED IPs',fmt(d.indicators.unresolved_indicators)],
 ['CISA RELEASE',d.cves.date_released||'unavailable'],['SECTOR REPORT',d.sectors.source+' / '+d.sectors.period],
 ['DATA WINDOW',d.data_lag||'Different sources update on different schedules']];
 for(const [name,value] of lines){const p=create('p');p.append(create('strong','',name+': '),create('span','',value));box.append(p);}
 box.append(link('Read complete methodology ↗','./radar-methodology.html'));}
function render(){const d=state.data;if(!d)return;
 txt('#sources',fmt(d.indicators.unique_indicators));txt('#reports',fmt(d.indicators.resolved_indicators));txt('#countries',fmt(d.indicators.countries.length));txt('#hot-port',fmt(d.cves.total_kev||0));txt('#port-caption','CISA Known Exploited Vulnerabilities');
 const healthy=(d.indicators.source_health||[]).filter(r=>r.status==='ok').length;txt('#mode',healthy+' / '+(d.indicators.source_health||[]).length);
 txt('#freshness','IP feeds · CISA · FIRST · ENISA');updateTimestamp();txt('#observation-window','SOURCE COUNTS / OBSERVATION LISTS');
 const layer=state.layer;const active=countries();if(layer!=='all'){
 txt('#countries',fmt(active.length));txt('#sources',fmt(active.reduce((n,c)=>n+score(c),0)));
 txt('#reports','—');txt('#freshness','FILTERED LAYER / '+layerUnits()+' ONLY');
 const label=document.querySelector('.metric label');if(label)label.textContent=layerUnits();
}else{
 const label=document.querySelector('.metric label');if(label)label.textContent='UNIQUE LISTED IPs';
 txt('#freshness','Deduplicated by IP / all sources');
}
 renderCVEs();renderSectors();renderSources();renderTable();renderSummary();extraUI.renderGlobal();extraUI.renderHealthTimeline(d.history||[],d.indicators.source_health||[]);rankings();renderCountryChanges();draw();if(state.selected){if(allCountries().some(r=>r.code===state.selected))renderDossier();else renderUnavailableCountry(state.selected);setFocusSummary();}txt('#map-total',fmt(d.indicators.countries.length)+' COUNTRIES · '+fmt(d.indicators.unique_indicators)+' INDICATORS');
 $('#map-loading').style.display=state.world?'none':'block';txt('#notice','IP-list entries are not confirmed attacks. Country is IP-location only. Sources have different measurement windows; never add their counts as incidents.');
}
function comparableSnapshots(){
 const all=Array.isArray(state.data?.history)?state.data.history.slice(-28):[];
 const latest=all.at(-1);if(!latest||!Array.isArray(latest.available_sources))return [];
 const key=latest.available_sources.slice().sort().join('|');
 return all.filter(x=>Array.isArray(x.available_sources)&&x.available_sources.slice().sort().join('|')===key&&x.country_counts&&typeof x.country_counts==='object');
}
function renderCountryChanges(){
 const panel=$('#country-changes');if(!panel)return;panel.replaceChildren();
 const snaps=comparableSnapshots();
 if(snaps.length<2){panel.append(create('div','empty-state','Waiting for at least two comparable collections with the same successful feed set.'));return;}
 const a=snaps[0].country_counts,b=snaps.at(-1).country_counts;
 const codes=new Set([...Object.keys(a),...Object.keys(b)]);
 const changes=[...codes].filter(code=>Number.isFinite(a[code]??0)&&Number.isFinite(b[code]??0))
 .map(code=>({code,delta:(b[code]||0)-(a[code]||0),start:a[code]||0,end:b[code]||0}))
 .filter(x=>x.delta!==0);
 const groups=[['TOP RISERS',changes.filter(x=>x.delta>0).sort((x,y)=>y.delta-x.delta).slice(0,5)],
 ['TOP FALLERS',changes.filter(x=>x.delta<0).sort((x,y)=>x.delta-y.delta).slice(0,5)]];
 for(const [label,rows] of groups){
  panel.append(create('h3','trend-subhead',label));
  if(!rows.length){panel.append(note('No changes in the available comparable snapshots.'));continue;}
  for(const r of rows){const btn=create('button','trend-item');
   btn.append(create('span','',name(r.code)),create('b',r.delta>0?'rise':'fall',(r.delta>0?'+':'')+fmt(r.delta)));
   btn.addEventListener('click',()=>select(r.code));panel.append(btn);}
 }
 panel.append(note(snaps.length+' comparable snapshots · '+new Date(snaps[0].generated_at).toLocaleString()+' to '+new Date(snaps.at(-1).generated_at).toLocaleString()));
}
function countryTrend(code){
 const section=create('div','dossier-trend');
 section.append(create('h3','','RECENT SNAPSHOT CHANGE / INDICATOR LISTINGS'));
 const valid=comparableSnapshots().filter(entry=>Number.isFinite(entry.country_counts?.[code]));
 if(valid.length<2){section.append(note('A comparable trend will appear after at least two successful snapshots using the same set of providers. This is not a live attack counter.'));return section;}
 const points=valid.slice(-20),vals=points.map(p=>p.country_counts[code]),min=Math.min(...vals),max=Math.max(...vals),span=Math.max(1,max-min);
 const width=285,height=80,pts=vals.map((v,i)=>[8+i*(width-16)/Math.max(1,vals.length-1),height-10-(v-min)/span*58]);
 const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
 svg.setAttribute('viewBox','0 0 '+width+' '+height);svg.setAttribute('width','100%');svg.setAttribute('height','84');svg.setAttribute('role','img');svg.setAttribute('aria-label','Trend in listed IP indicators across '+pts.length+' comparable snapshots');
 const path=document.createElementNS('http://www.w3.org/2000/svg','polyline');
 path.setAttribute('points',pts.map(p=>p.join(',')).join(' '));path.setAttribute('fill','none');path.setAttribute('stroke','#ff5770');path.setAttribute('stroke-width','2.5');svg.append(path);
 for(const [x,y] of [pts[0],pts.at(-1)]){const c=document.createElementNS('http://www.w3.org/2000/svg','circle');c.setAttribute('cx',x);c.setAttribute('cy',y);c.setAttribute('r','3.5');c.setAttribute('fill','#fff');svg.append(c);}
 section.append(svg);
 const change=vals.at(-1)-vals[0],label=(change>0?'+':'')+fmt(change)+' listed IPs vs first comparable snapshot';
 section.append(create('p','dossier-note',label+' · '+points.length+' snapshots · '+new Date(points[0].generated_at).toLocaleDateString()+' → '+new Date(points.at(-1).generated_at).toLocaleDateString()));
 section.append(note('Changes reflect list membership and feed behavior, not incident counts or new attacks.'));
 return section;
}
const ipContextCache=new Map();
async function inspectIp(ip){
 const box=$('#ip-context');if(!box)return;box.replaceChildren();
 box.append(create('h3','','IP NETWORK CONTEXT / '+ip));
 box.append(note('Fetching public network/geolocation metadata. This does not verify malicious activity.'));
 let data=ipContextCache.get(ip);
 if(!data){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),9000);
  try{
   const response=await fetch('https://ipwho.is/'+encodeURIComponent(ip),{signal:controller.signal});
   if(!response.ok)throw Error('Geolocation provider HTTP '+response.status);
   data=await response.json();if(data.success===false)throw Error(data.message||'No network record available');
   ipContextCache.set(ip,data);
  }catch(error){if($('#ip-context')===box)box.append(note('Network detail unavailable: '+error.message+'. Use the outbound SANS link instead.'));return;}
  finally{clearTimeout(timer);}
 }
 if($('#ip-context')!==box)return;
 box.replaceChildren();box.append(create('h3','','NETWORK METADATA / '+ip));
 const attrs=[['COUNTRY',data.country],['REGION',data.region],['CITY',data.city],['ASN',data.connection?.asn],['ISP',data.connection?.isp],['ORGANIZATION',data.connection?.org],['NETWORK DOMAIN',data.connection?.domain]];
 for(const [label,value] of attrs){if(value===undefined||value===null||value==='')continue;const line=create('div','detail-line');line.append(create('span','',label),create('b','',String(value)));box.append(line);}
 box.append(note('ipwho.is approximate network geolocation; a hosting/network organization is not necessarily the operator behind a listed activity.'));
 box.append(link('OPEN SANS IP INFORMATION ↗','https://isc.sans.edu/ipinfo/'+encodeURIComponent(ip)));
}
let tourTimer=0,tourActive=false,tourSequence=[],tourStep=0;
function stopTour({exit=false}={}){
 clearTimeout(tourTimer);tourTimer=0;tourActive=false;$('#stop-tour').hidden=true;
 txt('#tour','▶ CINEMATIC TOUR');
 if(exit)toggleImmersive(false);
}
function beginTour(){
 if(!state.data||!state.projection){showToast('Country telemetry and the globe must finish loading first.');return;}
 if(tourActive){stopTour();showToast('Tour paused.');return;}
 tourSequence=countries().slice(0,6).map(r=>r.code);
 if(!tourSequence.length){showToast('No countries available to explore.');return;}
 tourActive=true;tourStep=0;toggleImmersive(true);$('#stop-tour').hidden=false;txt('#tour','■ STOP TOUR');
 const advance=()=>{
  if(!tourActive)return;
  if(tourStep>=tourSequence.length){stopTour();showToast('Cinematic tour complete — all values are from the real snapshot.');return;}
  const code=tourSequence[tourStep++];select(code,{autoTour:true});
  tourTimer=setTimeout(advance,5300);
 };
 advance();
}
function setFocusSummary(){
 const row=allCountries().find(r=>r.code===state.selected),el=$('#map-floating-summary');
 if(!state.selected){el.hidden=true;return;}el.hidden=false;el.replaceChildren();
 el.append(create('small','','◎ COUNTRY FOCUS / '+state.selected),
   create('strong','',name(state.selected)),
   create('span','',row?fmt(score(row))+' listed IPs in selected layer':'No listed indicators in current source coverage'),
   create('span','',row?fmt(row.indicators)+' unique IP indicators across all feeds':'No observed coverage does not imply absence of risk'),
   create('small','','IP INFRASTRUCTURE GEOLOCATION · NOT ACTOR ATTRIBUTION'));
}
function updateSpin(on){state.spin=on;$('#spin').setAttribute('aria-pressed',String(on));txt('#spin',on?'◉ AUTO ROTATE':'○ ROTATION PAUSED');}
function ease(t){return 1-Math.pow(1-t,3);}
function flyTo(rotation,scale,duration=1050,done=()=>{}){
 if(!state.projection)return;
 cancelAnimationFrame(state.focusFrame);state.draggedAt=Date.now();
 const start=state.projection.rotate(),startScale=state.projection.scale();
 const normalized=rotation.map((v,i)=>i===0?start[0]+(((v-start[0]+540)%360)-180):v);
 const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;
 if(reduced){state.projection.rotate(normalized).scale(scale);draw();done();return;}
 let t0=0,lastDraw=0;
 const frame=time=>{
  if(!t0)t0=time;const progress=Math.min(1,(time-t0)/duration),v=ease(progress);
  if(time-lastDraw>=30||progress>=1){lastDraw=time;
   state.projection.rotate(start.map((x,i)=>x+(normalized[i]-x)*v)).scale(startScale+(scale-startScale)*v);draw();}
  if(progress<1)state.focusFrame=requestAnimationFrame(frame);else done();
 };state.focusFrame=requestAnimationFrame(frame);
}
function flyToCountry(code){const feature=state.byCode.get(code);if(!feature||!state.d3)return;
 // For the unified Moroccan geographical display, use a center that includes
 // the southern area. For other countries choose a stable geographical centroid.
 const center=code==='MA'?[-8.5,28.5]:state.d3.geoCentroid(feature);
 const area=Math.max(.000005,state.d3.geoArea(feature));
 const angle=2*Math.sqrt(area/Math.PI);
 // Keep the orthographic globe within a useful viewport when focused.
 // Excessive 650+ zoom was clipping the globe into apparently empty space.
 const zoom=code==='MA'?415:Math.min(460,Math.max(280,175/Math.max(.31,Math.sin(angle))));
 updateSpin(false);flyTo([-center[0],-center[1],0],zoom);
}
function backToWorld({exitImmersive=false}={}){
 state.selected=null;state.pinned=null;state.tab='overview';$('#country-detail').className='empty-state';
 txt('#country-detail','Select any mapped country or search all source countries to begin an investigation.');
 txt('#dossier-mode','SELECT COUNTRY');txt('#map-mode','◎ GLOBAL OBSERVATION MODE');$('#map-floating-summary').hidden=true;
 $('#map-focus-controls').hidden=true;$('#compare-panel').hidden=true;hideTip();
 if(exitImmersive)toggleImmersive(false);
 syncAddress();rankings();
 updateSpin(false);
 flyTo([-10,-12,0],235,900,()=>{if(!state.selected)updateSpin(true);});
}
function syncAddress(){
 try{const url=new URL(location.href);
  if(state.selected)url.searchParams.set('country',state.selected);else url.searchParams.delete('country');
  if(state.layer!=='all')url.searchParams.set('layer',state.layer);else url.searchParams.delete('layer');
  history.replaceState(null,'',url.pathname+url.search+url.hash);
 }catch(e){}
}
let toastTimer=0;
function showToast(message){const el=$('#toast');txt('#toast',message);el.hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>{el.hidden=true;},3800);}
function countryBrief(row){
 const rank=allCountries().findIndex(r=>r.code===row.code)+1;
 const lines=[
 'NEXUS SENTINEL // COUNTRY INTELLIGENCE BRIEF',
 'Country: '+name(row.code)+' ('+row.code+')',
 'Snapshot collected: '+state.data.generated_at,
 'Rank in available geolocated IP indicator sample: #'+rank+' of '+allCountries().length,
 'Current layer: '+state.layer,
 'Listed IPv4 indicators in selected layer: '+fmt(score(row)),
 'Unique IPv4 indicators across all sources: '+fmt(row.indicators),
 'Cross-listed in 2+ feeds: '+(Number.isInteger(row.multi_source_count)?fmt(row.multi_source_count):'Not available'),
 '',
 'PROVIDER COUNTS (overlapping; DO NOT add):'
 ];
 for(const [key,label] of Object.entries(SOURCES))lines.push('  '+label+': '+fmt(row.by_source?.[key]));
 lines.push('','EVIDENCE SAMPLE (not exhaustive):');
 for(const [provider,samples] of Object.entries(row.samples_by_source||{})){
  for(const entry of samples)lines.push('  '+entry.ip+' / '+provider+' / '+(entry.sources||[]).join(','));
 }
 lines.push('','LIMITATIONS: Country reflects public IP allocation, NOT individual attacker attribution. Listings vary in reliability and may contain benign scanners or false positives. No country-specific CVE exposure has been established.','Data sources: blocklist.de, IPsum, SANS/DShield, abuse.ch Feodo, DB-IP Lite.','NEXUS: '+location.origin+location.pathname);
 return lines.join('\n');
}
async function copyString(value){if(navigator.clipboard?.writeText)await navigator.clipboard.writeText(value);else{const e=create('textarea');e.value=value;e.style.position='fixed';e.style.opacity='0';document.body.append(e);e.select();if(!document.execCommand('copy'))throw Error('Copy unsupported');e.remove();}}
async function shareCountry(){try{syncAddress();await copyString(location.href);showToast('Country investigation link copied.');}catch(e){showToast('Could not copy automatically — copy the current page URL.');}}
function downloadBrief(){const row=allCountries().find(r=>r.code===state.selected);if(!row)return;
 const blob=new Blob([countryBrief(row)],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),a=create('a');
 a.href=url;a.download='NEXUS-'+row.code+'-country-brief.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 showToast('Evidence-labeled country brief exported.');
}
async function captureMap(){
 if(!state.world||!state.data){showToast('Globe or data is not loaded yet.');return;}
 try{
  const svg=$('#globe').cloneNode(true);svg.setAttribute('xmlns','http://www.w3.org/2000/svg');
  const xml=new XMLSerializer().serializeToString(svg);
  const sourceUrl=URL.createObjectURL(new Blob([xml],{type:'image/svg+xml;charset=utf-8'}));
  const image=new Image();
  image.onload=()=>{
   const canvas=create('canvas');canvas.width=1800;canvas.height=1170;const ctx=canvas.getContext('2d');
   ctx.fillStyle='#070910';ctx.fillRect(0,0,canvas.width,canvas.height);
   ctx.drawImage(image,0,40,1800,1060);
   ctx.fillStyle='#f3546e';ctx.font='bold 32px monospace';ctx.fillText('◈ NEXUS SENTINEL / GLOBAL INTELLIGENCE',65,54);
   ctx.fillStyle='#c7c3d1';ctx.font='18px monospace';
   const title=state.selected?name(state.selected)+' / '+fmt(score(allCountries().find(r=>r.code===state.selected)))+' listed source IPs':'COUNTRY-LEVEL CYBER INTELLIGENCE';
   ctx.fillText(title,65,1124);ctx.fillText('SNAPSHOT: '+state.data.generated_at.slice(0,19)+' UTC',65,1153);
   ctx.fillText('IP allocation ≠ attacker attribution',1170,1153);
   canvas.toBlob(blob=>{if(!blob){showToast('PNG export failed.');return;}
    const url=URL.createObjectURL(blob),a=create('a');a.href=url;a.download='NEXUS-'+(state.selected||'GLOBAL')+'-RADAR.png';a.click();setTimeout(()=>URL.revokeObjectURL(url),2000);showToast('Map snapshot saved — ready to share.');},'image/png');
   URL.revokeObjectURL(sourceUrl);
  };
  image.onerror=()=>{URL.revokeObjectURL(sourceUrl);showToast('Could not capture globe image.');};
  image.src=sourceUrl;
 }catch(e){showToast('Screenshot error: '+e.message);}
}
function toggleImmersive(force){const enabled=force===undefined?!document.body.classList.contains('immersive'):force;
 document.body.classList.toggle('immersive',enabled);$('#focus-mode').setAttribute('aria-pressed',String(enabled));
 txt('#focus-mode',enabled?'⛶ EXIT FOCUS':'⛶ IMMERSIVE');$('#exit-immersive').hidden=!enabled;
 $('#map-focus-controls').hidden=!(enabled||state.selected);
 if(!state.selected)txt('#focused-title',enabled?'IMMERSIVE GLOBAL RADAR':'');
 if(!state.selected)txt('#back-world',enabled?'← WORLD OVERVIEW':'← BACK TO PLANET');
}
let searchItems=[],searchCursor=0;
function openSearch(){if(!state.data){showToast('Load the intelligence snapshot first.');return;}
 $('#search-overlay').hidden=false;$('#country-search').value='';refreshSearch();$('#country-search').focus();}
function closeSearch(){$('#search-overlay').hidden=true;$('#open-search').focus();}
function refreshSearch(){
 const query=$('#country-search').value.trim().toLowerCase();
 searchItems=allCountries().filter(r=>name(r.code).toLowerCase().includes(query)||r.code.toLowerCase().includes(query)).sort((a,b)=>b.indicators-a.indicators).slice(0,30);
 searchCursor=Math.min(searchCursor,Math.max(0,searchItems.length-1));const box=$('#search-results');box.replaceChildren();
 if(!searchItems.length){box.append(create('div','empty-state','No country matching this search exists in the current dataset.'));return;}
 searchItems.forEach((row,i)=>{const e=create('button','search-result'+(i===searchCursor?' active':''));e.append(create('span','',flag(row.code)+' '+name(row.code)+'  /  '+row.code),create('small','',fmt(row.indicators)+' listed IPs'));e.addEventListener('click',()=>{closeSearch();select(row.code);});box.append(e);});
}
function keyboard(event){
 if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){event.preventDefault();$('#search-overlay').hidden?openSearch():closeSearch();return;}
 if(event.key==='Escape'){
  if(tourActive)stopTour();
  if(!$('#search-overlay').hidden){closeSearch();return;}
  if(document.body.classList.contains('immersive')){toggleImmersive(false);return;}
  if(state.selected){backToWorld();return;}
 }
 if($('#search-overlay').hidden)return;
 if(event.key==='ArrowDown'||event.key==='ArrowUp'){event.preventDefault();searchCursor=Math.max(0,Math.min(searchItems.length-1,searchCursor+(event.key==='ArrowDown'?1:-1)));refreshSearchHighlights();}
 if(event.key==='Enter'&&searchItems[searchCursor]){event.preventDefault();const code=searchItems[searchCursor].code;closeSearch();select(code);}
}
function refreshSearchHighlights(){$('#search-results').querySelectorAll('.search-result').forEach((el,i)=>el.classList.toggle('active',i===searchCursor));const el=$('#search-results').querySelector('.active');if(el)el.scrollIntoView({block:'nearest'});}

async function prepareMap(){
 try{const [d3,topo]=await Promise.all([import('https://cdn.jsdelivr.net/npm/d3@7/+esm'),import('https://cdn.jsdelivr.net/npm/topojson-client@3/+esm')]);
  const [world,iso]=await Promise.all([fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-50m.json').then(r=>r.json()),
    fetch('https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json').then(r=>r.json())]);
  const byNumeric=new Map(),byCode=new Map();
  for(const c of iso){const code=c['alpha-2'],numeric=c['country-code'];if(code&&numeric){const rec={code,name:c.name};byNumeric.set(String(numeric).padStart(3,'0'),code);byCode.set(code,rec);}}
  state.iso={byNumeric,byCode};state.d3=d3;
  const rawFeatures=topo.feature(world,world.objects.countries).features;
  // The upstream Natural Earth/World Atlas geography splits Western Sahara
  // into ISO 732. Offer a contiguous Morocco-focused visualization by combining
  // Morocco (504) with the adjacent territory (732) for DISPLAY ONLY.
  // Political status remains disputed and is explicitly acknowledged in UI.
  const morocco=rawFeatures.find(f=>String(f.id).padStart(3,'0')==='504');
  const southern=rawFeatures.find(f=>String(f.id).padStart(3,'0')==='732');
  if(morocco&&southern){
   const pieces=world.objects.countries.geometries.filter(g=>['504','732'].includes(String(g.id).padStart(3,'0')));
   if(pieces.length===2){
    const combined=topo.merge(world,pieces);
    const whole={type:'Feature',id:504,properties:{...morocco.properties,displayNote:'Includes Western Sahara geography; political status disputed'},geometry:combined};
    state.world=rawFeatures.filter(f=>!['504','732'].includes(String(f.id).padStart(3,'0'))).concat([whole]);
   }else state.world=rawFeatures;
  }else state.world=rawFeatures;
  state.byCode=new Map(state.world.map(f=>[getISO(f),f]).filter(([a,b])=>a));
  state.projection=d3.geoOrthographic().scale(235).translate([450,260]).clipAngle(90).precision(.5).rotate([-10,-12]);
  state.path=d3.geoPath(state.projection);draw();if(state.data)$('#map-loading').style.display='none';
  if(state.selected)flyToCountry(state.selected);
  else if(state.pending && state.data){const code=state.pending;state.pending=null;select(code,{updateUrl:false});}
  let start=null,rot=null;d3.select('#globe').call(d3.drag().on('start',e=>{cancelAnimationFrame(state.focusFrame);start=[e.x,e.y];rot=state.projection.rotate();state.draggedAt=Date.now();})
   .on('drag',e=>{state.projection.rotate([rot[0]+(e.x-start[0])*.33,Math.max(-70,Math.min(70,rot[1]-(e.y-start[1])*.23))]);state.draggedAt=Date.now();draw();}));
  d3.select('#globe').on('wheel.manualZoom',event=>{event.preventDefault();cancelAnimationFrame(state.focusFrame);
   const next=Math.max(210,Math.min(720,state.projection.scale()*Math.exp(-event.deltaY*.001)));state.projection.scale(next);state.draggedAt=Date.now();draw();});
  const spin=()=>{if(state.spin && !state.selected && state.projection && Date.now()-state.draggedAt>4000 && !document.body.classList.contains('immersive')){const r=state.projection.rotate();state.projection.rotate([r[0]+.25,r[1]]);draw();}setTimeout(spin,160);};spin();
 }catch(e){txt('#map-loading','MAP ASSETS UNAVAILABLE');txt('#notice','Could not load external map assets: '+e.message+'. Source tables remain available.');}
}
function updateTimestamp(){
 const time=state.data?.generated_at;if(!time)return;
 const epoch=Date.parse(time);if(!Number.isFinite(epoch))return;
 const delta=Math.max(0,Math.floor((Date.now()-epoch)/60000));
 const relative=delta<1?'just now':delta<60?delta+'m ago':delta<1440?Math.floor(delta/60)+'h ago':Math.floor(delta/1440)+'d ago';
 txt('#updated','Last updated: '+new Date(epoch).toISOString().replace('.000Z','Z')+' ('+relative+')');
}
async function loadExtra(){
 try{
  const route=location.port==='8765'?'/api/extra':'./data/extra.json';
  const response=await fetch(route+'?v='+Date.now(),{cache:'no-store'});
  if(!response.ok)throw Error('Extra feed HTTP '+response.status);
  const data=await response.json();
  if(data.schema!==1||!data.feeds||!Array.isArray(data.source_health))throw Error('Invalid extra feed snapshot');
  state.extra=data;state.extraError=null;
 }catch(e){
  state.extraError=e.message;
  state.extra={schema:1,feeds:{},source_health:state.data?.extra_health||[]};
 }
 if(state.data)render();
}
setInterval(updateTimestamp,60000);
const isMac=/Mac|iPhone|iPad/.test(navigator.platform||'');
const shortcut=document.querySelector('#shortcut-label');
if(shortcut)shortcut.textContent=isMac?'⌘K':'Ctrl K';
async function load(){setHealth('COLLECTING');$('#refresh').disabled=true;
 try{const url=location.port==='8765'?'/api/overview':'./data/overview.json';
 const response=await fetch(url+'?v='+Date.now(),{cache:'no-store'});if(!response.ok)throw Error('Snapshot HTTP '+response.status);
 const d=await response.json();if(d.schema!==2 || !Array.isArray(d.indicators?.countries))throw Error('Unknown snapshot format');
 state.data=d;state.extra={schema:1,feeds:{},source_health:d.extra_health||[]};state.extraError=null;
 try{localStorage.setItem('nexus.last.good.overview',JSON.stringify(d));}catch(e){}
 render();setHealth('MULTI-SOURCE ONLINE',true);loadExtra();
 document.querySelectorAll('.skeleton').forEach(x=>x.classList.remove('skeleton','skeleton-metric','skeleton-panel'));
 if(state.pending){const code=state.pending;state.pending=null;const row=allCountries().find(r=>r.code===code);if(row)select(code,{zoom:!!state.projection,updateUrl:false});}
 else if(state.selected && state.projection)draw();
 }catch(e){
 setHealth('SNAPSHOT UNAVAILABLE',false);
 let cached=null;try{cached=JSON.parse(localStorage.getItem('nexus.last.good.overview')||'null');}catch(error){}
 if(cached?.schema===2&&Array.isArray(cached.indicators?.countries)){
  state.data=cached;state.extra={schema:1,feeds:{},source_health:cached.extra_health||[]};
  render();txt('#updated','Snapshot unavailable, last good snapshot: '+new Date(cached.generated_at).toISOString());
  txt('#notice','Showing cached, potentially stale observations. Latest snapshot failed: '+e.message);
  loadExtra();
 }else{
  txt('#updated','Snapshot unavailable, last good snapshot: none stored');
  txt('#notice','No real dataset loaded: '+e.message);
  txt('#map-loading','SNAPSHOT UNAVAILABLE');
 }
}
 finally{$('#refresh').disabled=false;}
}
$('#refresh').addEventListener('click',load);
$('#layer').addEventListener('change',e=>{state.layer=e.target.value;syncAddress();if(state.data)render();});
$('#spin').addEventListener('click',()=>updateSpin(!state.spin));
$('#reset-globe').addEventListener('click',()=>backToWorld());
$('#back-world').addEventListener('click',()=>backToWorld({exitImmersive:document.body.classList.contains('immersive')}));
$('#focus-mode').addEventListener('click',()=>{if(tourActive)stopTour();toggleImmersive();});
$('#exit-immersive').addEventListener('click',()=>{if(tourActive)stopTour();toggleImmersive(false);});
$('#tour').addEventListener('click',beginTour);
$('#stop-tour').addEventListener('click',()=>{stopTour();showToast('Cinematic tour stopped.');});
$('#capture').addEventListener('click',captureMap);
$('#open-search').addEventListener('click',openSearch);
$('#close-search').addEventListener('click',closeSearch);
$('#close-compare').addEventListener('click',()=>{state.pinned=null;$('#compare-panel').hidden=true;if(state.selected)renderDossier();});
$('#country-search').addEventListener('input',()=>{searchCursor=0;refreshSearch();});
$('#search-overlay').addEventListener('click',e=>{if(e.target===$('#search-overlay'))closeSearch();});
window.addEventListener('keydown',keyboard);
const initialLayer=new URLSearchParams(location.search).get('layer');
if(initialLayer&&['all',...Object.keys(SOURCES),'urlhaus','threatfox'].includes(initialLayer)){
 state.layer=initialLayer;$('#layer').value=initialLayer;
}
prepareMap();load();
