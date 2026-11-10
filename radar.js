// NEXUS GLOBAL RADAR — live sources, never synthetic telemetry.
// DShield supplies source-IP and port observations; ipwho.is supplies approximate IP geolocation.
const $ = s => document.querySelector(s);
const fmt = n => Number(n||0).toLocaleString('en-US');
const CACHE_KEY='nexus_radar_v1';
const TTL=60*60*1000;
const MAX_BROWSER_IPS=24;
const STATE={data:null,selected:null,rotate:true,world:null,d3:null,projection:null,path:null,frame:null,lastInteraction:0};
function setText(id,val){$(id).textContent=String(val);}
function setState(label,style=''){$('#status').textContent=label;$('#connection-dot').className='beacon '+style;}
function notice(message){setText('#notice',message);}
function numericRows(value,field){
  if(Array.isArray(value))return value;
  if(!value || typeof value!=='object')return [];
  if(Array.isArray(value[field]))return value[field];
  const nested=value[field];
  if(nested && nested!==value){const r=numericRows(nested, field==='topips'?'ipaddress':field==='topports'?'port':'data');if(r.length)return r;}
  if(Array.isArray(value.data))return value.data;
  if(Array.isArray(value.ipaddress))return value.ipaddress;
  if(Array.isArray(value.port))return value.port;
  return Object.keys(value).filter(k=>/^\d+$/.test(k)).sort((a,b)=>Number(a)-Number(b)).map(k=>value[k]).filter(x=>x&&typeof x==='object');
}
function normalizedIp(value){
  const raw=String(value||'').trim();
  if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(raw))return null;
  const parts=raw.split('.').map(Number);
  return parts.every(x=>x>=0&&x<=255)?parts.join('.'):null;
}
function normalizeSource(row){const ip=normalizedIp(row.source||row.ip||row.number||row.ipaddress);if(!ip)return null;
  return {ip,reports:Math.max(0,Number(row.reports??row.count??row.records??0)||0),targets:Math.max(0,Number(row.targets??row.attacks??0)||0)};
}
function normalizePort(row){const port=Number(row.targetport??row.port??row.number);if(!Number.isInteger(port)||port<0||port>65535)return null;
  return {port,reports:Math.max(0,Number(row.records??row.reports??0)||0),sources:Math.max(0,Number(row.sources??0)||0)};
}
async function json(url,timeout=15000){const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeout);
  try{const r=await fetch(url,{signal:controller.signal});if(!r.ok)throw Error('HTTP '+r.status+' at '+new URL(url).hostname);return await r.json();}
  finally{clearTimeout(timer);}
}
async function parallelMap(items,limit,worker){let next=0;const out=new Array(items.length);
  await Promise.all(Array.from({length:Math.min(items.length,limit)},async()=>{while(next<items.length){const i=next++;try{out[i]=await worker(items[i],i)}catch(e){out[i]={...items[i],geo_error:e.message}}}}));return out;
}
async function browserFeed(){
  const [src,ports]=await Promise.allSettled([
    json('https://isc.sans.edu/api/topips/records/30?json'),
    json('https://isc.sans.edu/api/topports/records/12?json')
  ]);
  if(src.status!=='fulfilled')throw Error('SANS source feed unavailable: '+src.reason.message+'. Try the local collector if your browser blocks cross-origin requests.');
  const raw=numericRows(src.value,'topips');
  const seen=new Set();
  const sources=raw.map(normalizeSource).filter(Boolean).filter(s=>{if(seen.has(s.ip))return false;seen.add(s.ip);return true}).slice(0,MAX_BROWSER_IPS);
  if(!sources.length)throw Error('DShield returned no readable source IP rows.');
  const enriched=await parallelMap(sources,3,async s=>{
    const geo=await json('https://ipwho.is/'+encodeURIComponent(s.ip),10000);
    if(geo.success===false || !geo.country_code)return {...s,country:null,code:null,latitude:null,longitude:null};
    return {...s,country:String(geo.country||geo.country_code),code:String(geo.country_code).toUpperCase(),latitude:Number(geo.latitude),longitude:Number(geo.longitude)};
  });
  const portRows=ports.status==='fulfilled'?numericRows(ports.value,'topports').map(normalizePort).filter(Boolean):[];
  return {source:'SANS ISC / DShield',mode:'BROWSER FEED',sample_basis:'Top sources by reported packets (sample)',retrieved_at:new Date().toISOString(),
    source_date:String(src.value.date||src.value.topips?.date||'Recent source sample'),ports_date:ports.status==='fulfilled'?String(ports.value.date||'Recent port sample'):'Unavailable',
    sources:enriched,ports:portRows,notes:ports.status==='rejected'?'Port telemetry is unavailable.':null};
}
function cached(){try{const entry=JSON.parse(localStorage.getItem(CACHE_KEY)||'null');if(entry&&Date.now()-entry.at<TTL&&Array.isArray(entry.data.sources))return entry.data;}catch(e){}return null;}
function store(data){try{localStorage.setItem(CACHE_KEY,JSON.stringify({at:Date.now(),data}));}catch(e){}}
function validate(data){if(!data||!Array.isArray(data.sources)||!data.sources.length)throw Error('Source did not return usable telemetry.');
  if(!Array.isArray(data.ports))data.ports=[];return data;}
async function load(force=false){
  const cache=!force&&cached();
  if(cache){STATE.data=cache;render();setState('CACHED OBSERVATIONS','live');notice('Showing source observations cached less than one hour ago.');return;}
  $('#refresh').disabled=true;setState('FETCHING SENSOR DATA');notice('Fetching observed source-IP and port summaries. Geolocation may take several seconds.');
  try{let data;
    if(location.hostname==='127.0.0.1'||location.hostname==='localhost'){
      try{data=validate(await json('/api/radar',45000));}
      catch(e){data=validate(await browserFeed());}
    }else{data=validate(await browserFeed());}
    STATE.data=data;STATE.selected=null;store(data);render();setState('OBSERVATIONS LOADED','live');
    notice((data.notes||'')+' All values are from a sampled sensor feed, not worldwide totals. Approximate geolocation is not attacker attribution.');
  }catch(e){setState('FEED UNAVAILABLE','error');notice('Live telemetry unavailable: '+e.message+' No sample numbers have been fabricated.');$('#map-loading').textContent='FEED UNAVAILABLE';}
  finally{$('#refresh').disabled=false;}
}
function groupCountries(sources){
  const groups=new Map();
  for(const s of sources){if(!s.code||!Number.isFinite(s.latitude)||!Number.isFinite(s.longitude))continue;
    if(!groups.has(s.code))groups.set(s.code,{code:s.code,name:s.country||s.code,sources:[],reports:0,latitude:s.latitude,longitude:s.longitude});
    const g=groups.get(s.code);g.sources.push(s);g.reports+=s.reports;
  }
  return [...groups.values()].sort((a,b)=>b.sources.length-a.sources.length||b.reports-a.reports);
}
function element(tag,klass,txt){const n=document.createElement(tag);if(klass)n.className=klass;if(txt!==undefined)n.textContent=String(txt);return n;}
function showCountry(code){if(!STATE.data)return;const g=groupCountries(STATE.data.sources).find(v=>v.code===code);if(!g)return;
  STATE.selected=code;const detail=$('#country-detail');detail.replaceChildren();
  detail.append(element('div','country-name',g.name),element('div','country-code',g.code+' / APPROXIMATE SOURCE COUNTRY'));
  const m=element('div','country-metrics');
  const a=element('div');a.append(element('strong','',fmt(g.sources.length)),element('small','','SAMPLED SOURCE IPs'));
  const b=element('div');b.append(element('strong','',fmt(g.reports)),element('small','','REPORTS IN SAMPLE'));
  m.append(a,b);detail.append(m);
  const list=element('div','country-detail-bottom','Observed source addresses: '+g.sources.slice(0,6).map(v=>v.ip).join(', ')+(g.sources.length>6?' …':''));
  detail.append(list);renderRankings();
  if(STATE.projection){STATE.projection.rotate([-g.longitude,-g.latitude]);STATE.lastInteraction=Date.now();drawGlobe();}
}
function renderRankings(){const rankings=$('#rankings');rankings.replaceChildren();
  const groups=groupCountries(STATE.data.sources);if(!groups.length){rankings.append(element('div','empty-state','Geolocation unavailable for this sample.'));return;}
  groups.forEach((g,i)=>{const b=element('button','rank'+(STATE.selected===g.code?' selected':''));const left=element('span','',String(i+1).padStart(2,'0')+'  '+g.name);left.append(element('small','',g.code+' · '+fmt(g.reports)+' reports in sampled IPs'));b.append(left,element('b','',fmt(g.sources.length)));b.addEventListener('click',()=>showCountry(g.code));rankings.append(b);});
}
function renderTable(){const tbody=$('#observations');tbody.replaceChildren();
 for(const row of STATE.data.sources){const tr=element('tr');for(const value of [row.ip,row.country||'Not resolved',fmt(row.reports),fmt(row.targets)])tr.append(element('td','',value));
 const td=element('td');const a=element('a','','SANS ↗');a.href='https://isc.sans.edu/ipinfo/'+encodeURIComponent(row.ip);a.rel='noopener noreferrer';a.target='_blank';td.append(a);tr.append(td);tbody.append(tr);}
}
function renderPorts(){const container=$('#ports');container.replaceChildren();const arr=STATE.data.ports;if(!arr.length){container.append(element('div','empty-state','Port feed unavailable.'));return;}
 const high=Math.max(1,...arr.map(p=>p.reports));for(const p of arr){const row=element('div','port-row'),bar=element('div','bar'),fill=element('span');fill.style.width=(100*p.reports/high)+'%';bar.append(fill);row.append(element('strong','',':'+p.port),bar,element('small','',fmt(p.reports)));container.append(row);}
}
function render(){const data=STATE.data;const groups=groupCountries(data.sources);setText('#sources',fmt(data.sources.length));setText('#reports',fmt(data.sources.reduce((n,s)=>n+s.reports,0)));setText('#countries',fmt(groups.length));setText('#hot-port',data.ports[0]?':'+data.ports[0].port:'—');setText('#port-caption',data.ports[0]?fmt(data.ports[0].reports)+' reports in port summary':'No port data');
 setText('#mode',data.mode||'OBSERVED');setText('#freshness','Sample / recent observations');setText('#updated','Collected '+new Date(data.retrieved_at).toLocaleString());setText('#observation-window','SANS / DSHIELD · '+data.source_date);
 const missing=data.sources.filter(s=>!s.code).length;if(missing)notice(missing+' sampled IPs had no geolocation. Country counts cover resolved sources only.');
 renderRankings();renderTable();renderPorts();drawGlobe();$('#map-loading').style.display=groups.length?'none':'block';if(!groups.length)$('#map-loading').textContent='COUNTRY GEOLOCATION UNAVAILABLE';
}
async function initGlobe(){
  try{const [d3,topo]=await Promise.all([import('https://cdn.jsdelivr.net/npm/d3@7/+esm'),import('https://cdn.jsdelivr.net/npm/topojson-client@3/+esm')]);
    const world=await json('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json',18000);
    STATE.d3=d3;STATE.world=topo.feature(world,world.objects.countries).features;
    STATE.projection=d3.geoOrthographic().scale(235).translate([450,260]).clipAngle(90).precision(.5).rotate([-10,-12]);
    STATE.path=d3.geoPath(STATE.projection);drawGlobe();bindGlobe();animate();
  }catch(e){$('#map-loading').textContent='MAP LAYERS UNAVAILABLE';notice('Map assets could not load: '+e.message+'. Telemetry tables can still work.');}
}
function drawGlobe(){const d3=STATE.d3;if(!d3||!STATE.world)return;const world=d3.select('#world-layer'),points=d3.select('#points-layer'),path=STATE.path,p=STATE.projection;
  world.selectAll('*').remove();points.selectAll('*').remove();
  world.append('circle').attr('cx',450).attr('cy',260).attr('r',253).attr('fill','url(#glow)').attr('opacity',.8).attr('filter','url(#softglow)');
  world.append('path').datum({type:'Sphere'}).attr('d',path).attr('fill','url(#planet-fill)').attr('stroke','#ae445d').attr('stroke-width',1.5);
  world.append('path').datum(d3.geoGraticule10()).attr('d',path).attr('fill','none').attr('stroke','#4f2636').attr('stroke-width',.55).attr('opacity',.43);
  const groups=STATE.data?groupCountries(STATE.data.sources):[];
  const byName=new Map(groups.map(g=>[g.name.toLowerCase(),g]));
  world.selectAll('.country-shape').data(STATE.world).join('path').attr('class','country-shape').attr('d',path)
    .attr('fill',f=>byName.has(String(f.properties?.name||'').toLowerCase())?'#662235':'#1b1d29')
    .attr('stroke','#702d3b').attr('stroke-width',.45).attr('opacity',.93);
  const center=p.rotate().map(v=>-v);for(const g of groups){if(d3.geoDistance([g.longitude,g.latitude],[center[0],center[1]])>Math.PI/2-.02)continue;
    const xy=p([g.longitude,g.latitude]);if(!xy||xy.some(x=>!Number.isFinite(x)))continue;const r=Math.min(15,5+Math.sqrt(g.sources.length)*2.3);
    const marker=points.append('g').attr('class','marker').attr('style','cursor:pointer').attr('transform','translate('+xy[0]+','+xy[1]+')');
    marker.append('circle').attr('r',r+9).attr('fill','none').attr('stroke','#fa4862').attr('stroke-width',1).attr('opacity',.18);
    marker.append('circle').attr('r',r).attr('fill','#f33b57').attr('fill-opacity',STATE.selected===g.code?.85:.5).attr('stroke','#ff8899').attr('stroke-width',1);
    marker.append('circle').attr('r',2.5).attr('fill','#fff');
    marker.append('title').text(g.name+' — '+g.sources.length+' sampled source IPs / '+fmt(g.reports)+' reports');
    marker.on('click',e=>{e.stopPropagation();showCountry(g.code);});
  }
}
function bindGlobe(){const d3=STATE.d3;let startRotation=null,startPoint=null;
 d3.select('#globe').call(d3.drag().on('start',e=>{STATE.lastInteraction=Date.now();startPoint=[e.x,e.y];startRotation=STATE.projection.rotate();})
 .on('drag',e=>{if(!startPoint)return;const dx=e.x-startPoint[0],dy=e.y-startPoint[1];STATE.projection.rotate([startRotation[0]+dx*.32,Math.max(-70,Math.min(70,startRotation[1]-dy*.24))]);STATE.lastInteraction=Date.now();drawGlobe();}));
}
function animate(){if(STATE.rotate&&Date.now()-STATE.lastInteraction>5500&&STATE.projection){const r=STATE.projection.rotate();STATE.projection.rotate([r[0]+.13,r[1],r[2]]);drawGlobe();}STATE.frame=setTimeout(animate,95);}
$('#spin').addEventListener('click',()=>{STATE.rotate=!STATE.rotate;$('#spin').setAttribute('aria-pressed',String(STATE.rotate));$('#spin').textContent=STATE.rotate?'◉ AUTO ROTATE':'○ ROTATION PAUSED';});
$('#reset-globe').addEventListener('click',()=>{if(STATE.projection){STATE.projection.rotate([-10,-12]);STATE.selected=null;renderRankings();drawGlobe();}});
$('#refresh').addEventListener('click',()=>load(true));
initGlobe();load();
