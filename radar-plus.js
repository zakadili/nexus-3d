// NEXUS V2: country-level IP indicator observatory + CISA KEV priority + ENISA sectors.
// Data comes only from the scheduled snapshot; no demonstration data is invented.
const $=s=>document.querySelector(s);
const txt=(s,v)=>{$(s).textContent=String(v)};
const fmt=n=>Number(n||0).toLocaleString('en-US');
const DOM={svg:$('#globe'),map:$('#world-layer'),markers:$('#points-layer')};
const state={data:null,world:null,d3:null,projection:null,path:null,iso:null,byCode:new Map(),layer:'all',selected:null,spin:true,draggedAt:0};
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
function draw(){if(!state.d3||!state.world)return;const d3=state.d3,p=state.projection,path=state.path;
 const earth=d3.select(DOM.map);earth.selectAll('*').remove();const top=d3.select(DOM.markers);top.selectAll('*').remove();
 earth.append('circle').attr('cx',450).attr('cy',260).attr('r',253).attr('fill','url(#glow)').attr('opacity',.78).attr('filter','url(#softglow)');
 earth.append('path').datum({type:'Sphere'}).attr('d',path).attr('fill','url(#planet-fill)').attr('stroke','#b54057').attr('stroke-width',1.6);
 earth.append('path').datum(d3.geoGraticule10()).attr('d',path).attr('fill','none').attr('stroke','#502838').attr('opacity',.55).attr('stroke-width',.55);
 const rows=new Map(countries().map(c=>[c.code,c]));const values=[...rows.values()].map(score);const max=Math.max(1,...values);
 earth.selectAll('path.country-shape').data(state.world).join('path').attr('class','country-shape').attr('d',path)
  .attr('fill',f=>{const code=getISO(f),val=rows.get(code)?score(rows.get(code)):0;if(val===0)return '#1b1d29';return d3.interpolateRgb('#491c2e','#f54a63')(Math.max(.08,Math.log1p(val)/Math.log1p(max)));})
  .attr('stroke',f=>rows.has(getISO(f))?'#e35770':'#572d3b').attr('stroke-width',f=>rows.has(getISO(f))?.85:.45)
  .on('click',(event,f)=>{const code=getISO(f);if(code&&rows.has(code))select(code);})
  .append('title').text(f=>{const code=getISO(f);return code?name(code)+' / '+fmt(rows.get(code)?score(rows.get(code)):0)+' listed IPs':'Unmapped territory'});
 const center=p.rotate().map(v=>-v);
 for(const row of countries()){
  const feature=state.byCode.get(row.code);if(!feature)continue;let lonlat=d3.geoCentroid(feature);
  if(!lonlat||d3.geoDistance(lonlat,center)>=Math.PI/2-.05)continue;
  const xy=p(lonlat);if(!xy||xy.some(x=>!Number.isFinite(x)))continue;
  const count=score(row);const r=Math.min(12,2.6+Math.log10(1+count)*1.8);
  const marker=top.append('g').attr('transform',`translate(${xy[0]},${xy[1]})`).attr('style','cursor:pointer');
  marker.append('circle').attr('r',r+7).attr('fill','none').attr('stroke','#ff3c59').attr('opacity',.2);
  marker.append('circle').attr('r',r).attr('fill',row.code===state.selected?'#fff':'#fa435f').attr('fill-opacity',.76).attr('stroke','#fd8da2');
  marker.append('title').text(name(row.code)+' — '+fmt(count)+' listed IPs from selected feed(s)');
  marker.on('click',event=>{event.stopPropagation();select(row.code)});
 }
}
function rankings(){const pane=$('#rankings');pane.replaceChildren();const all=countries();
 if(!all.length){pane.append(create('div','empty-state','No countries are present in this source layer.'));return;}
 all.slice(0,70).forEach((row,i)=>{const b=create('button','rank'+(row.code===state.selected?' selected':'')),left=create('span','',String(i+1).padStart(2,'0')+'  '+name(row.code));
 left.append(create('small','',row.code+' · '+fmt(score(row))+' listed IPv4 indicators'));
 b.append(left,create('b','',fmt(score(row))));b.addEventListener('click',()=>select(row.code));pane.append(b);});
}
function select(code){const row=allCountries().find(r=>r.code===code);if(!row)return;state.selected=code;rankings();
 const panel=$('#country-detail');panel.replaceChildren();panel.append(create('div','country-name',name(code)),create('div','country-code',code+' / LISTED IP INFRASTRUCTURE'));
 const metrics=create('div','country-metrics');const a=create('div');a.append(create('strong','',fmt(score(row))),create('small','','LISTED IPv4 IN THIS LAYER'));const b=create('div');b.append(create('strong','',fmt(row.indicators)),create('small','','ALL SOURCES DEDUPLICATED'));metrics.append(a,b);panel.append(metrics);
 const breakdown=create('div','country-breakdown');for(const [key,label] of Object.entries(SOURCES)){const line=create('div','detail-line');line.append(create('span','',label),create('b','',fmt(row.by_source?.[key]||0)));breakdown.append(line);}
 const foot=create('p','muted','Cross-source counts overlap: source subtotals must not be summed. IP geolocation does not attribute attackers.');breakdown.append(foot);
 for(const sample of row.examples||[]){const p=create('p','muted',sample.ip+' · '+sample.sources.join(', '));breakdown.append(p);}
 panel.append(breakdown);
 const feature=state.byCode.get(code);if(feature&&state.projection){const [lng,lat]=state.d3.geoCentroid(feature);state.projection.rotate([-lng,-lat]);state.draggedAt=Date.now();draw();}
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
 renderCVEs();renderSectors();renderSources();renderTable();renderSummary();rankings();draw();
 $('#map-loading').style.display='none';txt('#notice','IP-list entries are not confirmed attacks. Country is IP-location only. Sources have different measurement windows; never add their counts as incidents.');
}
async function prepareMap(){
 try{const [d3,topo]=await Promise.all([import('https://cdn.jsdelivr.net/npm/d3@7/+esm'),import('https://cdn.jsdelivr.net/npm/topojson-client@3/+esm')]);
  const [world,iso]=await Promise.all([fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json').then(r=>r.json()),
    fetch('https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json').then(r=>r.json())]);
  const byNumeric=new Map(),byCode=new Map();
  for(const c of iso){const code=c['alpha-2'],numeric=c['country-code'];if(code&&numeric){const rec={code,name:c.name};byNumeric.set(String(numeric).padStart(3,'0'),code);byCode.set(code,rec);}}
  state.iso={byNumeric,byCode};state.d3=d3;state.world=topo.feature(world,world.objects.countries).features;state.byCode=new Map(state.world.map(f=>[getISO(f),f]).filter(([a,b])=>a));
  state.projection=d3.geoOrthographic().scale(235).translate([450,260]).clipAngle(90).precision(.5).rotate([-10,-12]);
  state.path=d3.geoPath(state.projection);draw();
  let start=null,rot=null;d3.select('#globe').call(d3.drag().on('start',e=>{start=[e.x,e.y];rot=state.projection.rotate();state.draggedAt=Date.now();}).on('drag',e=>{state.projection.rotate([rot[0]+(e.x-start[0])*.33,Math.max(-70,Math.min(70,rot[1]-(e.y-start[1])*.23))]);state.draggedAt=Date.now();draw();}));
  const spin=()=>{if(state.spin && state.projection && Date.now()-state.draggedAt>4000){const r=state.projection.rotate();state.projection.rotate([r[0]+.25,r[1]]);draw();}setTimeout(spin,160);};spin();
 }catch(e){txt('#map-loading','MAP ASSETS UNAVAILABLE');txt('#notice','Could not load external map assets: '+e.message+'. Source tables remain available.');}
}
async function load(){setHealth('COLLECTING');$('#refresh').disabled=true;
 try{const url=location.port==='8765'?'/api/overview':'./data/overview.json';
 const response=await fetch(url+'?v='+Date.now(),{cache:'no-store'});if(!response.ok)throw Error('Snapshot HTTP '+response.status);
 const d=await response.json();if(d.schema!==2 || !Array.isArray(d.indicators?.countries))throw Error('Unknown snapshot format');
 state.data=d;render();setHealth('MULTI-SOURCE ONLINE',true);
 }catch(e){setHealth('DATA PIPELINE OFFLINE',false);txt('#notice','Intelligence snapshot has not been generated or is unreachable: '+e.message+'. GitHub Actions → Refresh global intelligence snapshot → Run workflow. No figures are invented.');txt('#map-loading','AWAITING AUTOMATED FEED SNAPSHOT');}
 finally{$('#refresh').disabled=false;}
}
$('#refresh').addEventListener('click',load);
$('#layer').addEventListener('change',e=>{state.layer=e.target.value;state.selected=null;if(state.data)render();});
$('#spin').addEventListener('click',()=>{state.spin=!state.spin;$('#spin').setAttribute('aria-pressed',String(state.spin));txt('#spin',state.spin?'◉ AUTO ROTATE':'○ ROTATION PAUSED');});
$('#reset-globe').addEventListener('click',()=>{if(state.projection){state.selected=null;state.projection.rotate([-10,-12]);draw();rankings();}});
prepareMap();load();
