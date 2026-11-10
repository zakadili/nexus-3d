// NEXUS V2: country-level IP indicator observatory + CISA KEV priority + ENISA sectors.
// Data comes only from the scheduled snapshot; no demonstration data is invented.
const $=s=>document.querySelector(s);
const txt=(s,v)=>{$(s).textContent=String(v)};
const fmt=n=>Number(n||0).toLocaleString('en-US');
const DOM={svg:$('#globe'),map:$('#world-layer'),markers:$('#points-layer')};
const state={data:null,world:null,d3:null,projection:null,path:null,iso:null,byCode:new Map(),layer:'all',selected:null,spin:true,draggedAt:0,pinned:null,tab:'sources',focusFrame:0,hovered:null,searchIndex:0,pending:new URLSearchParams(location.search).get('country')?.toUpperCase()||null};
const SOURCES={blocklistde:'blocklist.de / 48h',ipsum:'IPsum / 3+ source lists',dshield:'DShield / sensor source IPs',feodo:'Feodo / botnet C2'};
function create(tag,cls,value){const el=document.createElement(tag);if(cls)el.className=cls;if(value!==undefined)el.textContent=String(value);return el;}
function link(label,url){const a=create('a','',label);a.href=url;a.target='_blank';a.rel='noopener noreferrer';return a;}
function setHealth(msg,ok){txt('#status',msg);$('#connection-dot').className='beacon '+(ok===true?'live':ok===false?'error':'');}
function allCountries(){return state.data?.indicators?.countries||[];}
function score(row){return state.layer==='all'?row.indicators:Number(row.by_source?.[state.layer]||0);}
function countries(){return allCountries().filter(c=>score(c)>0).sort((a,b)=>score(b)-score(a));}
function name(code){if(state.iso?.byCode?.has(code))return state.iso.byCode.get(code).name;
 try{return new Intl.DisplayNames(['en'],{type:'region'}).of(code)||code;}catch(e){return code;}}
function getISO(f){const n=String(f.id||'').padStart(3,'0');return state.iso?.byNumeric?.get(n)||null;}
function showTip(event,code){const row=allCountries().find(v=>v.code===code);const tip=$('#map-tooltip'),bounds=$('#globe-container').getBoundingClientRect();
 tip.replaceChildren();tip.append(create('strong','',name(code)),create('div','',row?code+' / '+fmt(score(row))+' listed IPs':code+' / NO LISTED INDICATORS'),create('small','',row?fmt(row.indicators)+' across all available feeds':'No coverage in this current feed sample.'));
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
 left.append(create('small','',row.code+' · '+fmt(score(row))+' listed IPv4 indicators'));
 b.append(left,create('b','',fmt(score(row))));b.addEventListener('click',()=>select(row.code));pane.append(b);});
 const active=pane.querySelector('.rank.selected');if(active)active.scrollIntoView({block:'nearest'});
}
function flag(code){return /^[A-Z]{2}$/.test(code)?String.fromCodePoint(...[...code].map(c=>127397+c.charCodeAt(0))):'◎';}
function kpi(value,label){const e=create('div','dossier-kpi');e.append(create('strong','',value),create('small','',label));return e;}
function note(text){return create('p','dossier-note',text);}
function select(code,{zoom=true,updateUrl=true}={}){
 const row=allCountries().find(r=>r.code===code);
 state.selected=code;state.tab='sources';hideTip();rankings();
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
function renderDossier(){
 const row=allCountries().find(r=>r.code===state.selected),panel=$('#country-detail');if(!row)return;
 panel.className='dossier';panel.replaceChildren();
 const rank=countries().findIndex(x=>x.code===row.code)+1;const globalRank=allCountries().findIndex(x=>x.code===row.code)+1;
 txt('#dossier-mode','COUNTRY INTELLIGENCE / '+row.code);
 const heading=create('div','dossier-heading');heading.append(create('div','dossier-eyebrow','◉ INVESTIGATION DOSSIER // '+row.code));
 const title=create('div','dossier-country');title.append(create('span','flag',flag(row.code)),create('span','',name(row.code)));heading.append(title,create('div','dossier-sub','COUNTRY-LEVEL IP ALLOCATION · NOT ACTOR ATTRIBUTION'));panel.append(heading);
 const metrics=create('div','dossier-summary');
 metrics.append(kpi(fmt(score(row)),'IN SELECTED LAYER'),kpi(fmt(row.indicators),'ALL FEEDS / UNIQUE'),
   kpi(rank?'#'+rank:'—','RANK IN THIS LAYER'),kpi(Number.isInteger(row.multi_source_count)?fmt(row.multi_source_count):'—','IN 2+ SOURCE LISTS'));
 panel.append(metrics);
 const tabs=create('div','dossier-tabs');for(const [key,label] of [['sources','SOURCES'],['evidence','EVIDENCE'],['context','CONTEXT']]){
  const b=create('button',key===state.tab?'active':'',label);b.addEventListener('click',()=>{state.tab=key;renderDossier();});tabs.append(b);
 }panel.append(tabs);
 const body=create('div','dossier-section');
 if(state.tab==='sources'){
  body.append(create('h3','',fmt(row.indicators)+' DISTINCT SOURCE IP ADDRESSES'));
  const max=Math.max(1,...Object.keys(SOURCES).map(k=>Number(row.by_source?.[k]||0)));
  for(const [key,label] of Object.entries(SOURCES)){
   const n=Number(row.by_source?.[key]||0),r=create('div','dossier-source'),top=create('div','dossier-source-top');
   top.append(create('span','',label),create('strong','',fmt(n)));r.append(top);
   const meter=create('div','dossier-meter'),bar=create('span');bar.style.width=(100*n/max)+'%';meter.append(bar);r.append(meter);body.append(r);
  }
  body.append(note('Counts from individual feeds overlap. All-feeds totals are deduplicated across providers.'));
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
   ['COLLECTED',new Date(date).toLocaleString()],['LOCATION','DB-IP Lite country-level allocation'],
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
function renderSources(){const box=$('#feed-health');box.replaceChildren();for(const row of state.data.indicators.source_health||[]){
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
 txt('#freshness','IP feeds · CISA · FIRST · ENISA');txt('#updated','Snapshot '+new Date(d.generated_at).toLocaleString());txt('#observation-window','SOURCE COUNTS / OBSERVATION LISTS');
 const layer=state.layer;const active=countries();if(layer!=='all'){txt('#countries',fmt(active.length));txt('#sources',fmt(active.reduce((n,c)=>n+score(c),0)));txt('#reports','—');txt('#freshness','FILTERED LAYER / IP count only');}else txt('#freshness','Deduplicated by IP / all sources');
 renderCVEs();renderSectors();renderSources();renderTable();renderSummary();rankings();draw();if(state.selected){if(allCountries().some(r=>r.code===state.selected))renderDossier();else renderUnavailableCountry(state.selected);setFocusSummary();}txt('#map-total',fmt(d.indicators.countries.length)+' COUNTRIES · '+fmt(d.indicators.unique_indicators)+' INDICATORS');
 $('#map-loading').style.display=state.world?'none':'block';txt('#notice','IP-list entries are not confirmed attacks. Country is IP-location only. Sources have different measurement windows; never add their counts as incidents.');
}
function countryTrend(code){
 const section=create('div','dossier-trend');
 section.append(create('h3','','RECENT SNAPSHOT CHANGE / INDICATOR LISTINGS'));
 const all=state.data?.history||[];
 const current=all.at(-1)?.available_sources||[];
 const valid=all.filter(entry=>Array.isArray(entry.available_sources)&&entry.available_sources.join('|')===current.join('|')&&Number.isFinite(entry.country_counts?.[code]));
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
 const center=state.d3.geoCentroid(feature);const area=state.d3.geoArea(feature);
 const angle=2*Math.sqrt(Math.max(area,.000005)/Math.PI);
 const zoom=Math.min(650,Math.max(295,195/Math.max(.29,Math.sin(angle))));
 updateSpin(false);flyTo([-center[0],-center[1],0],zoom);
}
function backToWorld({exitImmersive=false}={}){
 state.selected=null;state.pinned=null;state.tab='sources';$('#country-detail').className='empty-state';
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
  const [world,iso]=await Promise.all([fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json').then(r=>r.json()),
    fetch('https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json').then(r=>r.json())]);
  const byNumeric=new Map(),byCode=new Map();
  for(const c of iso){const code=c['alpha-2'],numeric=c['country-code'];if(code&&numeric){const rec={code,name:c.name};byNumeric.set(String(numeric).padStart(3,'0'),code);byCode.set(code,rec);}}
  state.iso={byNumeric,byCode};state.d3=d3;state.world=topo.feature(world,world.objects.countries).features;state.byCode=new Map(state.world.map(f=>[getISO(f),f]).filter(([a,b])=>a));
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
async function load(){setHealth('COLLECTING');$('#refresh').disabled=true;
 try{const url=location.port==='8765'?'/api/overview':'./data/overview.json';
 const response=await fetch(url+'?v='+Date.now(),{cache:'no-store'});if(!response.ok)throw Error('Snapshot HTTP '+response.status);
 const d=await response.json();if(d.schema!==2 || !Array.isArray(d.indicators?.countries))throw Error('Unknown snapshot format');
 state.data=d;render();setHealth('MULTI-SOURCE ONLINE',true);
 if(state.pending){const code=state.pending;state.pending=null;const row=allCountries().find(r=>r.code===code);if(row)select(code,{zoom:!!state.projection,updateUrl:false});}
 else if(state.selected && state.projection)draw();
 }catch(e){setHealth('DATA PIPELINE OFFLINE',false);txt('#notice','Intelligence snapshot has not been generated or is unreachable: '+e.message+'. GitHub Actions → Refresh global intelligence snapshot → Run workflow. No figures are invented.');txt('#map-loading','AWAITING AUTOMATED FEED SNAPSHOT');}
 finally{$('#refresh').disabled=false;}
}
$('#refresh').addEventListener('click',load);
$('#layer').addEventListener('change',e=>{state.layer=e.target.value;syncAddress();if(state.data)render();});
$('#spin').addEventListener('click',()=>updateSpin(!state.spin));
$('#reset-globe').addEventListener('click',()=>backToWorld());
$('#back-world').addEventListener('click',()=>backToWorld({exitImmersive:document.body.classList.contains('immersive')}));
$('#focus-mode').addEventListener('click',()=>toggleImmersive());
$('#exit-immersive').addEventListener('click',()=>toggleImmersive(false));
$('#capture').addEventListener('click',captureMap);
$('#open-search').addEventListener('click',openSearch);
$('#close-search').addEventListener('click',closeSearch);
$('#close-compare').addEventListener('click',()=>{state.pinned=null;$('#compare-panel').hidden=true;if(state.selected)renderDossier();});
$('#country-search').addEventListener('input',()=>{searchCursor=0;refreshSearch();});
$('#search-overlay').addEventListener('click',e=>{if(e.target===$('#search-overlay'))closeSearch();});
window.addEventListener('keydown',keyboard);
const initialLayer=new URLSearchParams(location.search).get('layer');
if(initialLayer&&['all',...Object.keys(SOURCES)].includes(initialLayer)){
 state.layer=initialLayer;$('#layer').value=initialLayer;
}
prepareMap();load();
