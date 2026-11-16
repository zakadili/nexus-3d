import {enrichCve} from './cve-intelligence.mjs';
import {MAX_LINES,processBatch,rowsCsv,downloadableIps,makeStix} from './lookup-core.mjs?v=8cbaa2a8cc4c';
const $=s=>document.querySelector(s),state={ips:[],kev:null,extra:null,results:[],ready:false,sort:'value',desc:false};
function el(tag,cls,text){const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=String(text);return node;}
function message(text){$('#load-note').textContent=String(text);}
function download(filename,contents,type){
 const blob=new Blob([contents],{type}),url=URL.createObjectURL(blob),a=el('a');a.href=url;a.download=filename;a.click();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function getJSON(path){
 const response=await fetch(path,{cache:'no-store'});
 if(!response.ok)throw Error(path+' HTTP '+response.status);
 const raw=await response.text();
 if(raw.length>4_000_000)throw Error('Source exceeds 4 MB limit');
 return JSON.parse(raw);
}
async function load(){
 const coverage=$('#coverage');coverage.replaceChildren();
 const status=$('#status');
 // Always load the same fixed public files before accepting input, independent
 // of user text. There is no input-derived URL, request parameter or telemetry.
 const [manifest,kev,extra]=await Promise.allSettled([
   getJSON('./data/index/manifest.json'),getJSON('./data/kev.json'),getJSON('./data/extra.json')]);
 if(manifest.status==='fulfilled'){
  const data=manifest.value;
  if(data.schema===1&&Array.isArray(data.shard_keys)&&data.shard_keys.length<=256&&data.shard_keys.every(k=>/^(?:0|[1-9][0-9]{0,2})$/.test(k)&&+k<=255)){
   const keys=data.shard_keys;
   const settled=await Promise.allSettled(keys.map(k=>getJSON('./data/index/'+k+'.json')));
   state.ips=settled.filter(x=>x.status==='fulfilled'&&x.value.schema===1&&Array.isArray(x.value.records))
     .flatMap(x=>x.value.records.slice(0,100000)).filter(x=>x.type==='ipv4'&&typeof x.value==='string');
   const failed=settled.filter(x=>x.status==='rejected').length;
   coverage.append(el('p','', 'Feodo CC0 IPv4 index: '+state.ips.length+' published entries'+(failed?' · '+failed+' shard failures':'')));
  }else coverage.append(el('p','error','Feodo index manifest invalid.'));
 }else coverage.append(el('p','error','Feodo index unavailable: '+manifest.reason.message));
 if(kev.status==='fulfilled'&&kev.value.schema===1&&Array.isArray(kev.value.records)){
  state.kev=kev.value;
  coverage.append(el('p','', 'CISA KEV CC0: '+state.kev.records.length+' entries'));
 }else coverage.append(el('p','error','CISA KEV catalog unavailable.'));
 if(extra.status==='fulfilled'&&extra.value.schema===1){
  state.extra=extra.value;
  coverage.append(el('p','', 'ASN network statistics: '+(extra.value.feeds?.iptoasn?'Available':'Unavailable')));
 }else coverage.append(el('p','error','ASN summary unavailable.'));
 if(!state.kev&&!state.ips.length){status.textContent='NO INDEX AVAILABLE';message('No usable redistributable index available. No results fabricated.');return;}
 state.ready=true;status.textContent='LOCAL ENGINE READY';$('#analyze').disabled=false;
 message('Data is ready. Search stays in your browser; public files were fetched independently of input.');
}
function run(){
 if(!state.ready)return;
 const raw=[$('#single').value,...$('#bulk').value.split(/\r?\n/)].map(s=>s.trim()).filter(Boolean);
 if(raw.length>MAX_LINES){message('Maximum 1,000 lines. Nothing was processed.');return;}
 if(raw.some(x=>x.length>2048)){message('One IOC exceeds the 2,048-character limit.');return;}
 try{state.results=processBatch(raw,state);render();message('Local index checked. Open a CVE result and choose Verify with CVE Program to request its official record; only that CVE ID is sent.');}
 catch(e){message('Lookup error: '+e.message);}
}
function filtered(){
 const choice=$('#filter').value;
 let rows=state.results.filter(r=>choice==='all'||r.status===choice||(choice==='notfound'&&r.status==='notfound'));
 return rows.sort((a,b)=>{
  const left=String(a[state.sort]||''),right=String(b[state.sort]||'');
  return left.localeCompare(right)*(state.desc?-1:1);
 });
}
function render(){
 const list=$('#results');list.replaceChildren();const rows=filtered();$('#count').textContent=rows.length+' / '+state.results.length;
 if(!rows.length){const row=el('tr');const cell=el('td','','No matching results. Not listed means not found in the feeds we collect, not that it is safe.');cell.colSpan=5;row.append(cell);list.append(row);return;}
 for(const record of rows){
  const row=el('tr');const btn=el('button','record-link',record.query);
  btn.addEventListener('click',()=>showDetail(record));
  row.append(el('td'));row.lastChild.append(btn);
  for(const value of [record.type,record.type==='cve'&&record.status==='notfound'?'KEV not listed · verify CVE':record.status,record.source])row.append(el('td','',value));
  const detail=el('td');const expand=el('button','small-button','WHY?');expand.addEventListener('click',()=>showDetail(record));detail.append(expand);row.append(detail);list.append(row);
 }
}
function showDetail(row){
 const box=$('#detail');box.replaceChildren();box.append(el('h3','',row.query),el('p','',row.source));
 if(row.type==='cve'){
  const note=el('p','', 'CISA KEV is a known-exploitation subset, not the full CVE catalog. Enrich this CVE with official sources.');
  const verify=el('button','small-button','ENRICH: CVE + NVD + EPSS + KEV');
  const output=el('div','');
  verify.addEventListener('click',async()=>{
    verify.disabled=true;output.textContent='Checking CVE Program, NVD, FIRST EPSS and local CISA KEV…';
    try{
      const intel=await enrichCve(row.query,{kev:row.status==='cve'?row.details:false});
      output.replaceChildren(el('p','','CVE Program state: '+intel.state+' · '+(intel.verified?'published':'not verified as published')));
      for(const [name,source] of Object.entries(intel.sources)){
        const section=el('section','');
        section.append(el('h4','',name.toUpperCase()+' · '+source.status));
        if(source.error)section.append(el('p','','Unavailable: '+source.error));
        if(source.value!==null&&source.value!==false&&source.value!==undefined){
          const v=source.value;
          if(name==='cve'){if(v.description)section.append(el('p','',v.description));if(v.published)section.append(el('p','','Published: '+v.published));for(const a of v.affected||[])section.append(el('p','','Affected: '+(a.vendor||'Unknown')+' / '+(a.product||'Unknown')+' · '+(a.versions||[]).map(x=>x.version+' ('+x.status+')').join(', ')));}
          if(name==='nvd'){section.append(el('p','','NVD status: '+(v.status||'Unknown')));if(v.weaknesses?.length)section.append(el('p','','CWEs: '+v.weaknesses.join(', ')));}
          if(name==='epss')section.append(el('p','','30-day exploitation probability: '+(v.probability*100).toFixed(3)+'% · percentile '+(v.percentile*100).toFixed(1)+'% · '+(v.date||'date unavailable')));
          if(name==='kev')section.append(el('p','','Listed in local CISA KEV snapshot'));
          for(const m of v.metrics||[])section.append(el('p','','CVSS '+m.version+': '+(m.score??'unknown')+' '+(m.severity||'')+' · '+m.source));
          if(name==='cve'||name==='nvd')for(const url of (v.references||[]).slice(0,8)){const a=el('a','',url);a.href=url;a.target='_blank';a.rel='noopener noreferrer';section.append(a,el('span','',' '));}
        }else if(name==='kev'&&source.status==='available')section.append(el('p','','Not listed in the loaded CISA KEV snapshot; not proof of safety.'));
        output.append(section);
      }
      output.append(el('p','warning','Missing source records and failed requests are not safety verdicts. EPSS is a forecast, not confirmed exploitation.'));
    }catch(e){output.textContent='Enrichment unavailable: '+e.message;}
    finally{verify.disabled=false;}
  });
  box.append(note,verify,el('p','','Privacy: clicking Enrich sends this CVE ID to CVE Program, NVD and FIRST; no other IOC inputs are transmitted.'),output);
 }
 if(row.details){
  if(row.type==='cve'){
   const v=row.details;for(const [label,value] of [
    ['Vendor / Product',(v.vendorProject||'—')+' / '+(v.product||'—')],
    ['Added to KEV',v.dateAdded||'Unknown'],['CISA due date',v.dueDate||'Unknown'],
    ['Ransomware campaign use',v.knownRansomwareCampaignUse||'Not specified'],
    ['Required action',v.requiredAction||'Not specified'],['Description',v.shortDescription||'Not specified']
   ]){const p=el('p');p.append(el('strong','',label+': '),document.createTextNode(value));box.append(p);}
   const a=el('a','','NVD record ↗');a.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(row.query);a.target='_blank';a.rel='noopener noreferrer';box.append(a);
  }else if(row.type==='cidr'){box.append(el('p','',row.details.matches.length+' listed Feodo IPs matched in this CIDR (capped at 1,000).'));}
  else if(row.type==='ipv4'){
   box.append(el('p','','Geolocated source country: '+(row.details.country||'Unavailable')));
   box.append(el('p','','First/last seen: not available from indexed feed. Confidence: single-feed listing, not independently verified.'));
   const a=el('a','','Feodo Tracker source ↗');a.href='https://feodotracker.abuse.ch/';a.target='_blank';a.rel='noopener noreferrer';box.append(a);
  }else if(row.type==='asn')box.append(el('p','',row.details.org+' · '+row.details.listed_ips+' addresses in the aggregate sample (not an exact ASN directory).'));
 }
 box.append(el('p','warning','A negative lookup is not proof of safety. No IOC was transmitted by this page.'));
}
function exportRows(ext){
 const rows=filtered();
 if(!rows.length)return;
 const date=new Date().toISOString();
 if(ext==='csv'){download('nexus-lookup.csv',rowsCsv(rows.map(r=>({value:r.query,type:r.type,status:r.status,source:r.source,exported_at:date})),
  ['value','type','status','source','exported_at']),'text/csv');return;}
 if(ext==='json'){download('nexus-lookup.json',JSON.stringify({source:'NEXUS license-limited browser index',exported_at:date,notes:'Not listed does not mean safe',results:rows},null,2),'application/json');return;}
 if(ext==='stix'){const bundle=makeStix(rows);if(bundle.objects.length===1){message('No licensed STIX objects in this selection.');return;}download('nexus-stix-2.1.json',JSON.stringify(bundle,null,2),'application/json');return;}
 const ips=downloadableIps(rows);
 if(!ips.length){message('No redistributable listed IPv4 addresses in this selection.');return;}
 download(ext==='cidr'?'nexus-ip-cidr.txt':'nexus-ip-list.txt',
 '# Review before blocking: listed does not prove malicious ownership or safety.\n'+ips.map(ip=>ext==='cidr'?ip+'/32':ip).join('\n')+'\n','text/plain');
}
$('#analyze').addEventListener('click',run);
$('#single').addEventListener('keydown',e=>{if(e.key==='Enter')run();});
$('#filter').addEventListener('change',render);
document.querySelectorAll('[data-sort]').forEach(b=>b.addEventListener('click',()=>{
 const key=b.dataset.sort;state.desc=state.sort===key?!state.desc:false;state.sort=key;render();
}));
for(const [id,type] of [['#csv','csv'],['#json','json'],['#stix','stix'],['#ip-list','ip'],['#cidr-list','cidr']]){
 $(id).addEventListener('click',()=>exportRows(type));
}
load();
