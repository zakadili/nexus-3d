import {normalizeOverview, formatCount, formatEpss, filterKev, exportKevCsv} from './enterprise-v2-intelligence.mjs';
import {d3, topo} from './assets/map-vendor.js';

// An executive interface for actual public-source snapshots; customer examples
// are isolated in the explicitly simulated workspace.
const $ = id => document.getElementById(id);
const SVG_NS = 'http://www.w3.org/2000/svg';
const nav = [...document.querySelectorAll('.nav-item[data-view]')];
const viewButtons = [...document.querySelectorAll('button[data-view]')];
const filters = [...document.querySelectorAll('[data-filter]')];
const labels = {
  overview: ['Dashboard','Executive Intelligence Overview'],
  intelligence: ['CVE Intelligence','Source-backed vulnerability research'],
  sources: ['Threat Sources','Collection status and provenance'],
  workspace: ['Demo Workspace','Fictional customer · no scans'],
  roadmap: ['Build Roadmap','Product engineering milestones']
};
let snapshot = null;
let filterMode = 'all';
let currentView = 'overview';
let selectedAsset = 0;
let workflowPhase = 0;

function node(tag, className = '', content = null) {
  const el = document.createElement(tag);
  if(className) el.className = className;
  if(content !== null && content !== undefined) el.textContent = String(content);
  return el;
}
function svg(tag, attrs = {}) {
  const el = document.createElementNS(SVG_NS, tag);
  for(const [key,value] of Object.entries(attrs)) el.setAttribute(key,String(value));
  return el;
}
function replaceText(id, value) { $(id).textContent = value === null || value === undefined ? '—' : String(value); }
function utcDate(value) {
  if(!value || !Number.isFinite(Date.parse(value))) return 'Unavailable';
  return new Date(value).toISOString().replace('T',' ').slice(0,16)+' UTC';
}
function shortDate(value) {
  if(!value || !Number.isFinite(Date.parse(value))) return 'Unknown date';
  return new Date(value).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric',timeZone:'UTC'});
}
function markCveLink(id) {
  if(!/^CVE-\d{4}-\d{4,}$/.test(id)) return node('span','',id);
  const a = node('a','',id);
  a.href = 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(id);
  a.target = '_blank';a.rel = 'noopener noreferrer';
  return a;
}
function showView(view) {
  if(!labels[view]) return;
  currentView = view;
  for(const [key] of Object.entries(labels)) $(key).classList.toggle('active',key === view);
  for(const b of nav) {
    const selected = b.dataset.view === view;
    b.classList.toggle('selected',selected);
    if(selected) b.setAttribute('aria-current','page');
    else b.removeAttribute('aria-current');
  }
  $('page-title').textContent = labels[view][0];
  $('page-subtitle').textContent = labels[view][1];
  $('workspace-label').textContent = view === 'workspace' ? 'Aster Labs · Fictional' : 'NEXUS / Public Intelligence';
}
for(const b of viewButtons)b.addEventListener('click',()=>showView(b.dataset.view));

function renderHistoryMini(history) {
  const box=$('mini-history');
  box.replaceChildren();
  for(const item of history.slice(-12)) {
    const n=node('i');
    n.style.height = '8px';
    box.append(n);
  }
  if(history.length < 2)return;
  const items=history.slice(-12),values=items.map(i=>i.count);
  const min=Math.min(...values), max=Math.max(...values),span=Math.max(max-min,1);
  for(const [i,value] of values.entries())box.children[i].style.height=(5+20*(value-min)/span).toFixed(1)+'px';
}

function renderMetrics(data) {
  replaceText('metric-ips',formatCount(data.listedIps));
  replaceText('metric-kev',formatCount(data.kevCount));
  const eligible=data.sourceRows.filter(x=>x.status!=='retired');
  const ok=eligible.filter(x=>x.status==='ok').length;
  replaceText('metric-sources',eligible.length?ok+' / '+eligible.length:'—');
  replaceText('metric-age',data.ageHours<1?'Under 1h':Math.floor(data.ageHours)+'h');
  replaceText('metric-age-detail',data.stale?'Stale historical snapshot':'Published snapshot · not live');
  replaceText('metric-time',utcDate(data.generatedAt));
  renderHistoryMini(data.history);
}
function renderPriority(data) {
  const box=$('priority-list');box.replaceChildren();
  const items=data.kev.slice(0,4);
  if(!items.length){box.append(node('p','loading','CISA KEV candidate data unavailable.'));return}
  for(const record of items) {
    const row=node('div','priority-item');
    const label=node('span','tag '+(record.ransomwareObserved?'warn':'info'),record.ransomwareObserved?'RANSOM':'KEV');
    const body=node('div');const title=node('div','priority-title');
    title.append(markCveLink(record.id),node('span','', ' · '+(record.product||record.vendor||'Published record')));
    body.append(title,node('div','priority-desc',(record.vendor||'Unknown vendor')+' / '+(record.product||'Unknown product')+' · Source: CISA KEV'));
    const meta=node('div','priority-meta','EPSS '+formatEpss(record.epss));
    meta.append(node('small','',record.dateAdded||'Date unavailable'));
    row.append(label,body,meta);box.append(row);
  }
}
function renderGauge(data) {
  const eligible=data.sourceRows.filter(x=>x.status!=='retired');
  const count=eligible.length;
  const healthy=eligible.filter(x=>x.status==='ok').length;
  const unavailable=eligible.filter(x=>x.status!=='ok').length;
  const retired=data.sourceRows.filter(x=>x.status==='retired').length;
  const fraction=count?healthy/count:null;
  $('coverage-percent').textContent=fraction===null?'—':Math.round(fraction*100)+'%';
  $('source-gauge').setAttribute('aria-label',fraction===null?'No collector availability data':healthy+' of '+count+' non-retired sources reported OK at collection');
  replaceText('coverage-ok',count?healthy+' / '+count:'Unavailable');
  replaceText('coverage-unavailable',count?unavailable:'Unavailable');
  replaceText('coverage-retired',retired);
  const group=$('gauge-segments');group.replaceChildren();
  for(let i=0;i<21;i++) {
    const a=Math.PI+i*Math.PI/20,cx=170,cy=174;
    const r1=116,r2=139;
    const line=svg('line',{
      x1:(cx+r1*Math.cos(a)).toFixed(2),y1:(cy+r1*Math.sin(a)).toFixed(2),
      x2:(cx+r2*Math.cos(a)).toFixed(2),y2:(cy+r2*Math.sin(a)).toFixed(2)
    });
    const fill=fraction!==null && i < Math.round(21*fraction);
    line.setAttribute('class','segment'+(fill?(i>13?' warn':' active'):''));
    group.append(line);
  }
}
function drawHistory(data) {
  const grid=$('chart-grid'),points=$('chart-points');
  grid.replaceChildren();points.replaceChildren();
  $('trend-area').setAttribute('d','');$('trend-line').setAttribute('d','');
  const records=data.history.slice(-30);
  if(records.length < 2){
    $('history-chart').setAttribute('aria-label','Collection trend unavailable: insufficient historical observations');
    replaceText('trend-span','Insufficient history');replaceText('trend-range','No verified trend');
    return;
  }
  const w=680,h=260,left=58,right=655,top=27,bottom=221;
  const vals=records.map(r=>r.count),min=Math.min(...vals),max=Math.max(...vals);
  const padding=(max-min)*.12 || Math.max(1,max*.05);
  const low=Math.max(0,min-padding), high=max+padding;
  const x=i=>left+i*(right-left)/(records.length-1);
  const y=v=>bottom-(v-low)/(high-low)*(bottom-top);
  for(let i=0;i<5;i++) {
    const gy=top+i*(bottom-top)/4;
    grid.append(svg('line',{x1:left,x2:right,y1:gy,y2:gy,class:'grid-line'}));
    const t=svg('text',{x:7,y:gy+3,class:'chart-label'});
    t.textContent=formatCount(Math.round(high-i*(high-low)/4));grid.append(t);
  }
  const pts=records.map((r,i)=>[x(i),y(r.count)]);
  $('trend-line').setAttribute('d',pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(2)+' '+p[1].toFixed(2)).join(' '));
  $('trend-area').setAttribute('d',pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(2)+' '+p[1].toFixed(2)).join(' ')+' L'+right+' '+bottom+' L'+left+' '+bottom+' Z');
  for(const i of [0,Math.floor((records.length-1)/2),records.length-1]) {
    const t=svg('text',{x:x(i),y:252,'text-anchor':i===0?'start':i===records.length-1?'end':'middle',class:'chart-label'});
    t.textContent=shortDate(records[i].time);grid.append(t);
  }
  for(const i of [0,records.length-1]){
    const p=pts[i];const c=svg('circle',{cx:p[0],cy:p[1],r:4,class:'chart-point'});
    const title=svg('title');title.textContent=utcDate(records[i].time)+': '+formatCount(records[i].count)+' listed indicators';
    c.append(title);points.append(c);
  }
  const days=(Date.parse(records[records.length-1].time)-Date.parse(records[0].time))/86400000;
  replaceText('trend-span',records.length+' observed snapshots');
  replaceText('trend-range',formatCount(min)+'–'+formatCount(max)+' listed IPs');
  $('history-chart').setAttribute('aria-label',records.length+' measured collection snapshots spanning '+days.toFixed(1)+' days; minimum '+formatCount(min)+' listed IPs; maximum '+formatCount(max));
}
function renderCountryList(data) {
  const box=$('country-list');box.replaceChildren();
  if(!data.countries.length){box.append(node('p','loading','Country allocations unavailable.'));return}
  for(const c of data.countries.slice(0,6)){
    const row=node('div','country-row');
    row.append(node('i'),node('span','',c.code),node('strong','',formatCount(c.count)));
    const tooltip='Published listed IPs with '+c.code+' allocation; not attack origin';
    row.title=tooltip;box.append(row);
  }
}
async function drawWorld(data) {
  const land=$('world-land'),marks=$('world-points');land.replaceChildren();marks.replaceChildren();
  try{
    const [geoResp,codesResp]=await Promise.all([
      fetch('./assets/countries-110m.json',{cache:'force-cache'}),
      fetch('./assets/country-codes.json',{cache:'force-cache'})
    ]);
    if(!geoResp.ok||!codesResp.ok)throw Error('Geographic base layer unavailable');
    const [geometry,codes]=await Promise.all([geoResp.json(),codesResp.json()]);
    if(!geometry.objects?.countries || !Array.isArray(codes))throw Error('Unknown map schema');
    const features=topo.feature(geometry,geometry.objects.countries).features;
    const iso=new Map(codes.map(x=>[String(x['country-code']).padStart(3,'0'),x['alpha-2']]));
    const counts=new Map(data.countries.map(x=>[x.code,x.count]));
    const max=Math.max(1,...data.countries.map(x=>x.count));
    const projection=d3.geoOrthographic().scale(121).translate([244,135]).rotate([-18,-11]).clipAngle(90);
    const path=d3.geoPath(projection);
    for(const feature of features){
      const outline=path(feature);if(!outline)continue;
      const code=iso.get(String(feature.id).padStart(3,'0'))||null;
      const count=code?counts.get(code):null;
      const strength=count?count/max:0;
      const p=svg('path',{d:outline,class:'world-country'+(strength>.32?' hot':strength>.04?' medium':'')});
      const label=svg('title');
      label.textContent=code&&count!==undefined?code+': '+formatCount(count)+' published listed IPs (allocation only)':(feature.properties?.name||'Country')+' — not listed in geographic snapshot';
      p.append(label);land.append(p);
    }
    const topCodes=new Set(data.countries.slice(0,12).map(x=>x.code));
    for(const feature of features){
      const code=iso.get(String(feature.id).padStart(3,'0'));
      if(!topCodes.has(code))continue;
      const coords=d3.geoCentroid(feature);
      // Only show plotted points on the visible hemisphere; markers are approximate centroids.
      if(d3.geoDistance(coords,[18,11])>Math.PI/2-.07)continue;
      const xy=projection(coords);
      if(!xy||xy.some(x=>!Number.isFinite(x)))continue;
      const c=svg('circle',{cx:xy[0],cy:xy[1],r:3.1,class:'map-marker'});
      const t=svg('title');t.textContent=code+': '+formatCount(counts.get(code))+' listed indicator IPs (country allocation)';
      c.append(t);marks.append(c);
    }
  }catch(e){
    const t=svg('text',{x:244,y:130,'text-anchor':'middle',fill:'#9aa6c3','font-size':13});
    t.textContent='Geographic base map unavailable';land.append(t);
  }
}
const exportButtons = document.querySelectorAll('[data-export-kev]');
function matchingKevRows() {
  return filterKev(snapshot?.kev || [], $('search').value, filterMode);
}
for (const button of exportButtons) {
  button.addEventListener('click', () => {
    const rows = matchingKevRows();
    if (!snapshot || !rows.length) return;
    const csv = exportKevCsv(rows, snapshot.generatedAt);
    const url = URL.createObjectURL(new Blob(['\uFEFF', csv], {type:'text/csv;charset=utf-8'}));
    const link = node('a');
    link.href = url;
    link.download = 'nexus-kev-' + new Date(snapshot.generatedAt).toISOString().slice(0, 10) + '.csv';
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}

function renderCveTable() {
  const box=$('cve-table');box.replaceChildren();
  const rows = matchingKevRows();
  for (const button of exportButtons) button.disabled = rows.length === 0;
  if(!rows.length){
    const tr=node('tr'),td=node('td','',snapshot?'No matching published candidates.':'Published candidates unavailable.');
    td.colSpan=6;tr.append(td);box.append(tr);
  }
  for(const record of rows.slice(0,9)){
    const tr=node('tr');
    const id=node('td');id.append(markCveLink(record.id));
    const vendor=node('td','',(record.vendor||'Unknown vendor')+' / '+(record.product||'Unknown product'));
    const date=node('td','',record.dateAdded||'Unavailable');
    const epss=node('td','',formatEpss(record.epss));
    const ransom=node('td');ransom.append(node('span','tag '+(record.ransomwareObserved?'warn':'neutral'),record.ransomwareObserved?'REPORTED':'NOT REPORTED'));
    const src=node('td');const link=node('a','', 'NVD ↗');link.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(record.id);link.target='_blank';link.rel='noopener noreferrer';src.append(link);
    tr.append(id,vendor,date,epss,ransom,src);box.append(tr);
  }
  replaceText('table-count','Showing '+Math.min(rows.length,9)+' of '+rows.length+' published candidate records');
  renderResearchList(rows);
}
function renderResearchList(rows){
  const box=$('intelligence-list');box.replaceChildren();
  if(!rows.length){box.append(node('p','loading','No published candidates match your search or source is unavailable.'));return}
  for(const r of rows.slice(0,18)){
    const item=node('div','research-item');
    const cve=node('div');cve.append(markCveLink(r.id));
    const body=node('div');
    body.append(node('strong','',(r.vendor||'Unknown vendor')+' / '+(r.product||'Unknown product')));
    body.append(node('p','', 'Added '+(r.dateAdded||'unknown')+' · '+(r.ransomwareObserved?'Ransomware use reported':'Ransomware use not reported in feed')));
    item.append(cve,body,node('div','meta','EPSS '+formatEpss(r.epss)));box.append(item);
  }
}
function renderSources(data){
  const box=$('source-list');box.replaceChildren();
  if(!data.sourceRows.length){box.append(node('p','loading','No source health records available.'))}
  for(const s of data.sourceRows){
    const item=node('div','source-item'),head=node('div','source-row-head');
    head.append(node('h3','',s.name));
    const cls=s.status==='ok'?'ok':s.status==='retired'?'off':'warn';
    const label=s.status==='ok'?'REPORTED OK':s.status==='retired'?'RETIRED':'UNAVAILABLE';
    head.append(node('span','state-tag '+cls,label));item.append(head);
    const stat=s.count===null?'No record count reported':formatCount(s.count)+' records in source snapshot';
    item.append(node('p','source-count',stat));
    if(s.reason)item.append(node('p','',s.reason));
    if(s.meaning)item.append(node('p','',s.meaning));
    box.append(item);
  }
  replaceText('provenance-time',utcDate(data.generatedAt));
  replaceText('provenance-errors',data.collectionFailures);
  replaceText('provenance-geo',data.provenance.geoMethod||'Unavailable');
  replaceText('provenance-notes',data.provenance.indicatorNote||'Snapshot-based, not real-time traffic');
  replaceText('intelligence-method',data.provenance.ranking||'Published candidate subset, not an asset risk score.');
}
function renderData(data){
  snapshot=data;
  const stamp=utcDate(data.generatedAt);
  $('source-date').textContent='Collected '+stamp+(data.stale?' · STALE':' · last reported');
  $('data-notice').classList.toggle('bad',data.stale);
  $('header-status').textContent=data.stale?'Stale snapshot':'Published snapshot';
  $('header-status').classList.toggle('stale',data.stale);
  renderMetrics(data);renderPriority(data);renderGauge(data);drawHistory(data);renderCountryList(data);renderCveTable();renderSources(data);
  drawWorld(data);
}
function failClosed(){
  snapshot=null;$('data-notice').classList.add('bad');
  $('source-date').textContent='Source snapshot unavailable. No fabricated values are displayed.';
  $('header-status').textContent='Data unavailable';$('header-status').classList.add('stale');
  for(const id of ['metric-ips','metric-kev','metric-sources','metric-age','coverage-percent','coverage-ok','coverage-unavailable','coverage-retired'])replaceText(id,'—');
  $('metric-age-detail').textContent='No validated collection time';
  $('metric-time').textContent='Unavailable';
  $('priority-list').replaceChildren(node('p','loading','CISA KEV candidates unavailable.'));
  $('country-list').replaceChildren(node('p','loading','Country allocation data unavailable.'));
  $('source-list').replaceChildren(node('p','loading','Source health data unavailable.'));
  $('gauge-segments').replaceChildren();$('world-land').replaceChildren();$('world-points').replaceChildren();
  $('trend-line').setAttribute('d','');$('trend-area').setAttribute('d','');
  $('trend-span').textContent='Unavailable';$('trend-range').textContent='No valid history';
  $('intelligence-list').replaceChildren(node('p','loading','Source-backed CVEs unavailable.'));
  renderCveTable();
}
async function fetchPublished(){
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),15000);
  try {
    const res=await fetch('./data/overview.json',{signal:controller.signal,cache:'no-store'});
    if(!res.ok)throw Error('HTTP '+res.status);
    renderData(normalizeOverview(await res.json()));
  } catch (e) {failClosed()}
  finally {clearTimeout(timer)}
}

const sampleAssets=[
  {name:'app.example.test',env:'Production / Web Application',desc:'Example internet-facing application. Fictional outdated-service observation for product demonstration only.',evidence:'Step 1 · Confirm legal scope and DNS ownership. Step 2 · Observe service version from an authorized read-only check. Step 3 · Compare source evidence to an applicable CVE. No verification has been performed here.'},
  {name:'admin.example.test',env:'Staging / Administration',desc:'Example administrative endpoint. No accessibility or authentication test was performed.',evidence:'Step 1 · Verify that the endpoint belongs to the customer. Step 2 · Document intended access controls and permitted test scope. Step 3 · Validate accessibility and impact with authorization.'},
  {name:'mail.example.test',env:'Production / Mail Gateway',desc:'Example mail infrastructure. No vulnerability or misconfiguration is asserted.',evidence:'Step 1 · Verify tenant asset ownership. Step 2 · Collect permitted configuration evidence. Step 3 · Record and review any finding before issuing recommendations.'}
];
const samplePhases=[
  ['Scope & verify','Before assessing any asset, obtain authorization, verify domain ownership and document the permitted scope.'],
  ['Observe evidence','Record a real observation with tool/source provenance, timestamp, confidence and exact affected asset.'],
  ['Assign remediation','Only verified issues move into a customer remediation queue, with an owner and target date.'],
  ['Confirm resolution','Re-check under authorization. A status button cannot substitute for evidence that the issue has been fixed.']
];
function renderSample(){
  const box=$('sample-assets');box.replaceChildren();
  for(const [index,item] of sampleAssets.entries()){
    const btn=node('button','sample-asset');btn.type='button';
    btn.setAttribute('aria-pressed',String(index===selectedAsset));
    btn.append(node('strong','',item.name),node('span','',item.env));
    btn.addEventListener('click',()=>{selectedAsset=index;workflowPhase=0;renderSample()});box.append(btn);
  }
  const asset=sampleAssets[selectedAsset];
  replaceText('asset-detail-title',asset.name);
  replaceText('asset-detail-description',asset.desc);
  replaceText('asset-evidence',samplePhases[workflowPhase][0]+' — '+samplePhases[workflowPhase][1]+' '+(workflowPhase===0?asset.evidence:''));
  replaceText('sample-next',workflowPhase===samplePhases.length-1?'Return to scope stage →':'Next simulated stage →');
}
$('sample-next').addEventListener('click',()=>{workflowPhase=(workflowPhase+1)%samplePhases.length;renderSample()});
for(const b of filters)b.addEventListener('click',()=>{
  filterMode=b.dataset.filter;
  for(const x of filters){const on=x===b;x.classList.toggle('active',on);x.setAttribute('aria-pressed',String(on))}
  renderCveTable();
});
$('search').addEventListener('input',()=>{renderCveTable();if(!['overview','intelligence'].includes(currentView))showView('intelligence')});
document.addEventListener('keydown',e=>{
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){
    e.preventDefault();$('search').focus();
  }
});
$('print-overview').addEventListener('click',()=>window.print());
renderSample();fetchPublished();
