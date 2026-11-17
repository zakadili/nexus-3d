import {normalizeOverview, formatCount, formatEpss, filterKev} from './enterprise-v2-intelligence.mjs';

const $ = id => document.getElementById(id);
const nav = [...document.querySelectorAll('nav button[data-view]')];
const filters = [...document.querySelectorAll('button[data-filter]')];
const modules = {
  dashboard: {label: 'Overview'},
  cve: {label: 'CVE Intelligence'},
  threats: {label: 'Source Coverage'},
  assets: {label: 'Assets', description: 'No customer-owned assets have been verified or securely onboarded. Domain, IP and service inventory requires ownership checks.'},
  exposure: {label: 'Exposure', description: 'An exposure score is not available. Public IP indicators and catalog CVEs cannot establish an organization\'s exposure.'},
  findings: {label: 'Findings', description: 'No customer-specific findings have been verified. Confirmed observations and remediation evidence are required.'},
  reports: {label: 'Reports', description: 'Verified findings, scope, methods, dates and evidence must exist before NEXUS can generate a customer assessment.'}
};
let snapshot = null;
let selectedFilter = 'all';
const candidates = () => filterKev(snapshot?.kev || [], $('cve-search').value, selectedFilter);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function showView(viewId) {
  if (!modules[viewId]) return;
  for (const item of nav) {
    if (item.dataset.view === viewId) item.setAttribute('aria-current','page');
    else item.removeAttribute('aria-current');
  }
  for (const view of document.querySelectorAll('main > .view')) view.classList.remove('active');
  const target = ['dashboard','cve','threats'].includes(viewId) ? viewId : 'placeholder';
  $(target).classList.add('active');
  $('page-title').textContent = modules[viewId].label;
  if (target === 'placeholder') {
    $('placeholder-title').textContent = modules[viewId].label;
    $('module-description').textContent = modules[viewId].description;
  }
}

function utc(value) {
  if (!value || !Number.isFinite(Date.parse(value))) return 'Not available';
  return new Intl.DateTimeFormat('en-US',{
    year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',
    timeZone:'UTC',timeZoneName:'short'
  }).format(new Date(value));
}

function sourceState(source) {
  if(source.status === 'retired') return ['RETIRED / HISTORIC','retired'];
  if(source.status === 'ok') return ['REPORTED OK','ok'];
  if(source.status === 'unavailable') return ['UNAVAILABLE','unknown'];
  return [source.status.toUpperCase() || 'UNKNOWN','unknown'];
}

function sourceNode(source) {
  const row = el('div','source-row');
  const title = el('div','source-row-title');
  title.append(el('strong','',source.name));
  const [label,cls] = sourceState(source);
  title.append(el('span','status-tag '+cls,label));
  row.append(title);
  const meta = source.status === 'retired'
    ? (source.count === null ? 'Archived source; no count' : formatCount(source.count)+' archived indicators')
    : (source.count === null ? 'No count reported' : formatCount(source.count)+' source records at collection');
  row.append(el('div','source-meta',meta));
  if (source.reason) row.append(el('p','source-detail',source.reason));
  return row;
}

function kevNode(kev) {
  const row = el('div','kev-item');
  const heading = el('div','kev-head');
  const anchor = el('a','cve-id',kev.id);
  anchor.href = 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(kev.id);
  anchor.target = '_blank';
  anchor.rel = 'noopener noreferrer';
  heading.append(anchor);
  if (kev.ransomwareObserved) heading.append(el('span','status-tag warning','RANSOMWARE REPORTED'));
  row.append(heading);
  row.append(el('div','kev-product',(kev.vendor || 'Unknown vendor')+' / '+(kev.product || 'Unknown product')));
  row.append(el('div','source-meta','EPSS '+formatEpss(kev.epss)+' · Added '+(kev.dateAdded || 'date unavailable')));
  return row;
}

function renderHistory(history) {
  const line = $('history-line');
  line.setAttribute('points','');
  if (history.length < 2) {
    $('history-explanation').textContent='Not enough historical snapshots to draw a trend.';
    $('history-chart').setAttribute('aria-label','Indicator trend unavailable: insufficient history');
    return;
  }
  const rows = history.slice(-24);
  const counts = rows.map(h=>h.count);
  const min = Math.min(...counts), max=Math.max(...counts);
  const span = Math.max(max-min,1);
  const points = rows.map((h,i)=>{
    const x=24+i*551/Math.max(rows.length-1,1);
    const y=175-150*(h.count-min)/span;
    return x.toFixed(1)+','+y.toFixed(1);
  }).join(' ');
  line.setAttribute('points',points);
  $('history-explanation').textContent=rows.length+' recorded snapshots · '+utc(rows[0].time)+' through '+utc(rows[rows.length-1].time)+' · range '+formatCount(min)+'–'+formatCount(max)+' listed IPs';
  $('history-chart').setAttribute('aria-label','Published IP-indicator counts across '+rows.length+' snapshots; minimum '+formatCount(min)+', maximum '+formatCount(max));
}

function renderCountries(countries) {
  const box=$('country-bars');box.replaceChildren();
  if (!countries.length) {
    box.append(el('p','empty-message','Country allocation data unavailable.'));
    return;
  }
  const largest=countries[0].count || 1;
  for (const country of countries.slice(0,7)) {
    const row=el('div','country-row');
    const label=el('div','country-label');
    label.append(el('strong','',country.code),el('span','',formatCount(country.count)+' listed IPs'));
    const progress=el('progress','country-progress');
    progress.value=country.count;progress.max=largest;
    progress.setAttribute('aria-label',country.code+' listed IP indicators');
    row.append(label,progress);box.append(row);
  }
}

function renderCandidates() {
  const body=$('kev-rows');body.replaceChildren();
  const shown=candidates();
  $('result-count').textContent=shown.length+' of '+(snapshot?.kev.length || 0)+' available candidates';
  for (const item of shown) {
    const tr=el('tr');
    const tdCve=el('td');
    const link=el('a','',item.id);
    link.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(item.id);
    link.rel='noopener noreferrer';link.target='_blank';
    tdCve.append(link);tr.append(tdCve);
    tr.append(el('td','',(item.vendor||'Unknown vendor')+' / '+(item.product||'Unknown product')));
    tr.append(el('td','',item.dateAdded||'Not available'));
    tr.append(el('td','',formatEpss(item.epss)));
    tr.append(el('td','',item.ransomwareObserved?'Reported':'Not reported in feed'));
    body.append(tr);
  }
  const empty=$('kev-empty');
  empty.hidden=shown.length>0;
  if (!shown.length) empty.textContent=snapshot && snapshot.kev.length ? 'No published candidates match these filters.' : 'No published KEV candidate rows available.';
}

function renderSnapshot(data) {
  snapshot=data;
  $('metric-ips').textContent=formatCount(data.listedIps);
  $('metric-kev').textContent=formatCount(data.kevCount);
  $('metric-countries').textContent=formatCount(data.countries.length);
  $('metric-age').textContent=data.ageHours<1?'Under 1h':Math.floor(data.ageHours)+'h';
  $('age-subtitle').textContent=utc(data.generatedAt)+(data.stale?' · STALE SNAPSHOT':' · published snapshot');
  $('source-state').textContent=data.stale?'STALE SNAPSHOT':'PUBLISHED SNAPSHOT';
  $('source-state').classList.toggle('stale',data.stale);
  $('overview-kev').replaceChildren();
  if(!data.kev.length) $('overview-kev').append(el('p','empty-message','No verified published KEV candidates in this snapshot.'));
  for(const row of data.kev.slice(0,4)) $('overview-kev').append(kevNode(row));
  $('kev-source').textContent='CISA KEV · '+formatCount(data.kevCount)+' catalog entries · '+(data.kevRelease?'Released '+utc(data.kevRelease):'Release date unavailable')+' · not customer exposure';
  $('overview-sources').replaceChildren();
  if(!data.sourceRows.length) $('overview-sources').append(el('p','empty-message','Feed-health data unavailable.'));
  for(const s of data.sourceRows.slice(0,5)) $('overview-sources').append(sourceNode(s));
  $('source-summary').textContent=data.sourceSummary+' of '+data.sourceRows.length+' sources reported OK at snapshot time; others may be retired or unavailable.';
  renderHistory(data.history);
  renderCountries(data.countries);
  $('geo-source').textContent=data.provenance.geoMethod || 'IP-based country assignment; not attacker geolocation';
  $('kev-release').textContent=data.kevCount===null?'KEV source unavailable':formatCount(data.kevCount)+' catalog records · '+data.kev.length+' research candidates published in this view';
  $('ranking-note').textContent=data.provenance.ranking || 'Research ordering is not an asset-specific risk score.';
  renderCandidates();
  $('source-rows').replaceChildren();
  if(!data.sourceRows.length) $('source-rows').append(el('p','empty-message','Source status data unavailable.'));
  for(const s of data.sourceRows) $('source-rows').append(sourceNode(s));
  $('timestamp-detail').textContent=utc(data.generatedAt);
  $('lag-detail').textContent=data.provenance.indicatorNote || 'Snapshot based; not live telemetry';
  $('failures-detail').textContent=String(data.collectionFailures)+' reported collector failures';
  $('geo-detail').textContent=data.provenance.geoMethod || 'Not available';
}

function failClosed(message) {
  $('source-state').textContent='DATA UNAVAILABLE';
  $('source-state').classList.add('stale');
  $('integrity-note').textContent='Published intelligence could not be loaded or verified: '+message+'. No numbers are shown without evidence.';
  for(const id of ['metric-ips','metric-kev','metric-countries','metric-age']) $(id).textContent='—';
  for(const id of ['overview-kev','overview-sources','country-bars','source-rows']) {
    $(id).replaceChildren(el('p','empty-message','Published source data is unavailable.'));
  }
  $('history-line').setAttribute('points','');
  $('history-explanation').textContent='No verified snapshot history available.';
  $('kev-rows').replaceChildren();
  $('kev-empty').hidden=false;
  $('kev-empty').textContent='Published CVE data unavailable.';
  $('result-count').textContent='Unavailable';
}

async function loadPublishedOverview() {
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),15000);
  try {
    const response=await fetch('./data/overview.json',{signal:controller.signal,cache:'no-store'});
    if(!response.ok) throw new Error('HTTP '+response.status);
    renderSnapshot(normalizeOverview(await response.json()));
  } catch(e) {
    failClosed(e.name==='AbortError'?'Source request timed out':'Source retrieval or schema validation failed');
  } finally {
    clearTimeout(timeout);
  }
}
for(const b of nav)b.addEventListener('click',()=>showView(b.dataset.view));
for(const b of document.querySelectorAll('[data-go]'))b.addEventListener('click',()=>showView(b.dataset.go));
for(const b of filters)b.addEventListener('click',()=>{
  selectedFilter=b.dataset.filter;
  for(const c of filters)c.setAttribute('aria-pressed',String(c===b));
  renderCandidates();
});
$('cve-search').addEventListener('input',renderCandidates);
loadPublishedOverview();
