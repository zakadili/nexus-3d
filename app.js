import {probability,rankCatalog} from './evidence-utils.mjs?v=c23f84ed905a';
const $=s=>document.querySelector(s);
const KEV_URLS=['https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json','https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'];
let catalog=[],filtered=[],page=0,selected='',assets=[];const perPage=18;
const safeText=v=>String(v??'');
function text(el,value){el.textContent=safeText(value);}
function node(tag,cls,content){const e=document.createElement(tag);if(cls)e.className=cls;if(content!==undefined)e.textContent=safeText(content);return e;}
function fmtDate(s){return s||'Not specified';}
function csvCell(v){return '"'+safeText(v).replaceAll('"','""')+'"';}
function download(name,content,type){const url=URL.createObjectURL(new Blob([content],{type}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1500);}
async function fetchJson(url,timeout=18000){const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeout);try{const response=await fetch(url,{signal:controller.signal,cache:'no-store'});if(!response.ok)throw Error('HTTP '+response.status);return await response.json();}finally{clearTimeout(timer);}}
async function load(){text($('#feed-status'),'CONNECTING TO CISA');text($('#feed-error'),'');let last;for(const url of KEV_URLS){try{const data=await fetchJson(url);if(!Array.isArray(data.vulnerabilities))throw Error('Unexpected feed format');catalog=data.vulnerabilities.sort((a,b)=>safeText(b.dateAdded).localeCompare(safeText(a.dateAdded)));text($('#total'),catalog.length.toLocaleString());text($('#release'),data.dateReleased?.slice(0,10)||'—');const threshold=new Date(Date.now()-30*86400000).toISOString().slice(0,10);text($('#recent'),catalog.filter(v=>v.dateAdded>=threshold).length);text($('#feed-status'),'CISA FEED CONNECTED');apply();return;}catch(e){last=e;}}text($('#feed-status'),'FEED UNAVAILABLE');text($('#feed-error'),'Live feed could not be loaded: '+last.message+'. Try Refresh. Your browser/network may block the feed.');text($('#records'),'No live records available.');}
function apply(){const q=$('#search').value.trim().toLowerCase(),since=$('#since').value,ransom=$('#ransomware').value;filtered=rankCatalog(catalog,q).filter(v=>(!since||v.dateAdded>=since)&&(ransom==='all'||v.knownRansomwareCampaignUse==='Known'));page=0;render();}
function render(){text($('#visible'),filtered.length.toLocaleString());const max=Math.max(1,Math.ceil(filtered.length/perPage));page=Math.min(page,max-1);text($('#page-label'),(page+1)+' / '+max);$('#prev').disabled=page===0;$('#next').disabled=page>=max-1;const list=$('#records');list.replaceChildren();text($('#shown-count'),filtered.length+' MATCHES');if(!filtered.length){list.append(node('div','placeholder',catalog.length?'No matching CVEs.':'No feed loaded.'));return;}for(const v of filtered.slice(page*perPage,(page+1)*perPage)){const b=node('button','record'+(v.cveID===selected?' selected':''));const head=node('div','record-head');head.append(node('strong','',v.cveID),node('span','tag',v.dateAdded));b.append(head,node('p','',v.vendorProject+' / '+v.product+' — '+v.vulnerabilityName));b.addEventListener('click',()=>inspect(v));list.append(b);}}
function detailRow(dl,label,value){dl.append(node('dt','',label),node('dd','',value));}
function externalLink(parent,label,url){const a=node('a','',label);a.href=url;a.target='_blank';a.rel='noopener noreferrer';parent.append(a);}
async function inspect(v){selected=v.cveID;render();const box=$('#detail');box.replaceChildren();box.append(node('h2','',v.cveID),node('p','',v.vulnerabilityName));const dl=node('dl');detailRow(dl,'VENDOR / PRODUCT',v.vendorProject+' / '+v.product);detailRow(dl,'DATE ADDED',v.dateAdded);detailRow(dl,'RANSOMWARE USE',v.knownRansomwareCampaignUse);detailRow(dl,'CISA REQUIRED ACTION',v.requiredAction);detailRow(dl,'DESCRIPTION',v.shortDescription);detailRow(dl,'CISA FEDERAL REMEDIATION DUE DATE',v.dueDate);box.append(dl);if(matchMedia('(max-width: 1000px)').matches){box.closest('.panel').scrollIntoView({block:'start'});box.setAttribute('tabindex','-1');box.focus({preventScroll:true})}const links=node('p');externalLink(links,'NVD record ↗','https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(v.cveID));links.append(' · ');externalLink(links,'CISA catalog ↗','https://www.cisa.gov/known-exploited-vulnerabilities-catalog');externalLink(links,'Open full CVE workbench ↗','./workbench.html#xray/'+encodeURIComponent(v.cveID));box.append(links);const epss=node('p','small','Loading FIRST EPSS probability…');box.append(epss);try{const data=await fetchJson('https://api.first.org/data/v1/epss?cve='+encodeURIComponent(v.cveID),12000);if(selected!==v.cveID)return;const record=data.data?.[0];text(epss,record?'FIRST EPSS: '+probability(record.epss,2)+' estimated probability of exploitation in the next 30 days; percentile '+(Number(record.percentile)*100).toFixed(1)+'%. Score date: '+(record.date||'Unavailable')+'.':'FIRST EPSS: No score available for this CVE.');}catch(e){if(selected===v.cveID)text(epss,'FIRST EPSS currently unavailable ('+e.message+').');}}
function activateView(id,update=true){
 const view=['intel','assessment','about'].includes(id)?id:'intel';
 document.querySelectorAll('[data-view]').forEach(b=>{const active=b.dataset.view===view;b.classList.toggle('active',active);b.setAttribute('aria-pressed',String(active))});
 document.querySelectorAll('.view').forEach(x=>{x.classList.toggle('active',x.id===view);x.hidden=x.id!==view});
 if(update)history.pushState(null,'','#'+view);
}
document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>activateView(b.dataset.view)));
window.addEventListener('hashchange',()=>activateView(location.hash.slice(1),false));
window.addEventListener('popstate',()=>activateView(location.hash.slice(1),false));
activateView(location.hash.slice(1),false);
$('#refresh').addEventListener('click',load);$('#apply').addEventListener('click',apply);$('#search').addEventListener('keydown',e=>{if(e.key==='Enter')apply()});$('#prev').addEventListener('click',()=>{page--;render()});$('#next').addEventListener('click',()=>{page++;render()});
$('#export-intel').addEventListener('click',()=>{if(!filtered.length)return;const fields=['cveID','vendorProject','product','vulnerabilityName','dateAdded','dueDate','knownRansomwareCampaignUse','shortDescription','requiredAction'];download('nexus-kev-filtered.csv',[fields.join(','),...filtered.map(v=>fields.map(f=>csvCell(v[f])).join(','))].join('\n'),'text/csv');});
function xmlElements(parent,tag){return [...parent.getElementsByTagName(tag)];}
function parseNmap(source){if(source.length>12_000_000)throw Error('XML file exceeds 12 MB limit');if(/<!DOCTYPE|<!ENTITY/i.test(source))throw Error('DTD and entity declarations are not supported');const xml=new DOMParser().parseFromString(source,'application/xml');if(xml.querySelector('parsererror'))throw Error('Invalid XML');if(xml.documentElement.tagName!=='nmaprun')throw Error('Expected Nmap XML root <nmaprun>');return [...xml.documentElement.children].filter(e=>e.tagName==='host').slice(0,2000).map(host=>{const addr=[...host.children].find(e=>e.tagName==='address'&&e.getAttribute('addrtype')==='ipv4')||host.querySelector('address');const ports=[...host.getElementsByTagName('port')].filter(p=>p.querySelector('state')?.getAttribute('state')==='open').slice(0,1000).map(p=>{const svc=p.querySelector('service');return {port:p.getAttribute('portid'),protocol:p.getAttribute('protocol'),name:svc?.getAttribute('name')||'unknown',product:svc?.getAttribute('product')||'',version:svc?.getAttribute('version')||''};});return {address:addr?.getAttribute('addr')||'unknown',ports};});}
$('#nmap-file').addEventListener('change',async e=>{const file=e.target.files?.[0];if(!file)return;try{assets=parseNmap(await file.text());text($('#import-status'),'Imported '+assets.length+' hosts locally. No data uploaded.');renderAssets();}catch(err){assets=[];renderAssets();text($('#import-status'),'Import error: '+err.message);}});
function renderAssets(){text($('#asset-hosts'),assets.length);text($('#asset-ports'),assets.reduce((n,h)=>n+h.ports.length,0));const box=$('#assets');box.replaceChildren();if(!assets.length){box.append(node('div','placeholder','No scan imported.'));return;}for(const host of assets){const wrap=node('div','asset');wrap.append(node('strong','',host.address),node('p','',host.ports.length+' open ports'));for(const service of host.ports){const b=node('button','service',service.port+'/'+service.protocol+' — '+service.name+' '+service.product+' '+service.version);b.addEventListener('click',()=>{const research=$('#research');research.replaceChildren();research.append(node('h3','',host.address+' / '+service.port+'/'+service.protocol),node('p','small','Observed service: '+service.name+' '+service.product+' '+service.version));const p=node('p','small','This is service fingerprint evidence, not vulnerability verification. Research vendor advisories and affected version ranges before drawing conclusions.');research.append(p);const search='https://nvd.nist.gov/vuln/search/results?query='+encodeURIComponent([service.product,service.version].filter(Boolean).join(' ')||service.name)+'&search_type=all';externalLink(research,'Research matching NVD advisories ↗',search);});wrap.append(b);}box.append(wrap);}}
$('#export-assets').addEventListener('click',()=>{if(assets.length)download('nexus-assets.json',JSON.stringify({source:'local Nmap XML import',exportedAt:new Date().toISOString(),assets},null,2),'application/json');});
load();

let activeReport=null;
function normalizeActiveReport(raw){
 if(!raw||raw.tool!=='NEXUS scoped active audit'||!Array.isArray(raw.targets)||raw.targets.length>32)throw Error('Not a supported NEXUS scan report');
 for(const t of raw.targets){if(typeof t.ip!=='string'||!Array.isArray(t.ports)||!Array.isArray(t.checks))throw Error('Malformed scan record');}
 return raw;
}
function renderActiveReport(report){
 const box=$('#scan-findings');box.replaceChildren();
 for(const target of report.targets){
  const section=node('div','asset');section.append(node('strong','',target.ip));
  for(const p of target.ports.filter(x=>x.state==='open'))section.append(node('p','small','OPEN TCP '+p.port));
  for(const check of target.checks){
   if(check.check==='http_headers'){
    section.append(node('p','small','HTTP '+check.port+': '+(check.status_code||check.error||'unknown')));
    for(const finding of check.findings||[])section.append(node('p','small',finding.check+': '+finding.status+' (observed configuration, not verified CVE)'));
   }else if(check.check==='tls_negotiation'){
    section.append(node('p','small','TLS '+check.port+': '+check.status+' '+(check.evidence?.version||'')));
   }else if(check.check==='cve_probe'){
    section.append(node('p','small',check.cve+': '+check.status+' — '+(check.reason||'')));
   }
  }
  box.append(section);
 }
}
$('#scan-file').addEventListener('change',async event=>{
 const file=event.target.files?.[0];if(!file)return;
 try{
  if(file.size>3_000_000)throw Error('Report exceeds 3 MB');
  const report=normalizeActiveReport(JSON.parse(await file.text()));
  activeReport=report;renderActiveReport(report);
  text($('#scan-status'),'Loaded '+report.targets.length+' targets from active scan report. Evidence is displayed locally; no upload.');
 }catch(error){activeReport=null;$('#scan-findings').replaceChildren();text($('#scan-status'),'Report import error: '+error.message);}
});
