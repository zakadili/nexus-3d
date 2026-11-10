// Pure, network-free lookup helpers. No user value is sent to a remote service.
export const MAX_LINES=1000;
const CVE=/^CVE-[0-9]{4}-[0-9]{4,}$/i;
const HEX=/^[0-9a-f]+$/i;
const DOMAIN=/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export function ipv4(input){
 const parts=String(input).split('.');
 if(parts.length!==4||parts.some(x=>!/^(?:0|[1-9][0-9]{0,2})$/.test(x)||Number(x)>255))return null;
 return parts.join('.');
}
export function classify(input){
 const text=String(input||'').trim();
 if(!text||text.length>2048)return {type:'invalid',value:text};
 const ip=ipv4(text);if(ip)return {type:'ipv4',value:ip};
 const cidr=/^(.+)\/([0-9]{1,2})$/.exec(text);
 if(cidr&&ipv4(cidr[1])&&+cidr[2]<=32)return {type:'cidr',value:text,ip:cidr[1],prefix:+cidr[2]};
 if(CVE.test(text))return {type:'cve',value:text.toUpperCase()};
 if(/^AS(?:N)?([0-9]{1,10})$/i.test(text)){
  const asn=Number(text.replace(/^ASN?/i,''));return asn>0&&asn<=4294967295?{type:'asn',value:'AS'+asn,asn}:{type:'invalid',value:text};
 }
 if([32,40,64].includes(text.length)&&HEX.test(text))return {type:'hash',value:text.toLowerCase()};
 if(/^[a-f0-9:]+$/i.test(text)&&text.includes(':')&&text.length<=45)return {type:'ipv6',value:text.toLowerCase()};
 try{const parsed=new URL(text);if(['http:','https:'].includes(parsed.protocol)&&parsed.hostname)return {type:'url',value:text};}catch(e){}
 if(DOMAIN.test(text))return {type:'domain',value:text.toLowerCase()};
 return {type:'invalid',value:text};
}
function ipv4Int(ip){return ipv4(ip).split('.').reduce((v,x)=>(v*256)+Number(x),0)>>>0;}
export function inCidr(ip,network,prefix){
 if(!ipv4(ip)||!ipv4(network)||!Number.isInteger(prefix)||prefix<0||prefix>32)return false;
 const factor=2**(32-prefix);
 return Math.floor(ipv4Int(ip)/factor)===Math.floor(ipv4Int(network)/factor);
}
export function processBatch(inputs,ctx){
 if(!Array.isArray(inputs)||inputs.length>MAX_LINES)throw Error('Maximum 1000 lines per lookup');
 const kev=new Map((ctx.kev?.records||[]).map(r=>[r.id,r]));
 const listed=new Map((ctx.ips||[]).map(r=>[r.value,r]));
 const result=[];
 for(const raw of inputs){
  const q=classify(raw),base={query:q.value,type:q.type,status:'notfound',source:'Not listed in indexed feeds',details:null};
  if(q.type==='invalid'){result.push({...base,status:'unsupported',source:'Invalid or unsupported IOC format'});continue;}
  if(q.type==='cve'){
   const record=kev.get(q.value);
   result.push(record?{...base,status:'cve',source:'CISA KEV (CC0)',details:record}:{...base,source:'Not listed in CISA KEV; not proof of safety'});
  }else if(q.type==='ipv4'){
   const item=listed.get(q.value);
   result.push(item?{...base,status:'listed',source:item.sources?.join(', ')||'Feodo',details:item}:{...base,source:'Not listed in the indexed CC0 IP feeds; not proof of safety'});
  }else if(q.type==='cidr'){
   const matches=[...listed.values()].filter(r=>inCidr(r.value,q.ip,q.prefix));
   result.push(matches.length?{...base,status:'listed',source:'Feodo (CC0) · '+matches.length+' matching listed IPs',details:{matches:matches.slice(0,1000)}}:{...base,source:'No listed IP in indexed feeds matched this CIDR'});
  }else if(q.type==='asn'){
   const candidates=[...(ctx.extra?.feeds?.iptoasn?.top_global||[])];
   const match=candidates.find(r=>r.asn===q.asn);
   result.push(match?{...base,status:'listed',source:'IPtoASN network summary (PDDL)',details:match}:{...base,source:'Not present in the collected top-ASN summaries; not exhaustive'});
  }else{
   result.push({...base,status:'notfound',source:'No redistributable index for this IOC type; not listed means not found in feeds we collect'});
  }
 }
 return result;
}
export function safeCsvCell(value){
 let s=String(value??'').replace(/[\r\n]+/g,' ').trim();
 if(/^[=+\-@]/.test(s))s="'"+s;
 return '"'+s.replaceAll('"','""')+'"';
}
export function rowsCsv(rows,columns){
 return [columns.join(','),...rows.map(row=>columns.map(c=>safeCsvCell(row[c])).join(','))].join('\r\n');
}
export function downloadableIps(rows){
 const ips=new Set();
 for(const r of rows){
  if(r.status!=='listed')continue;
  if(r.type==='ipv4'&&ipv4(r.query))ips.add(r.query);
  if(r.type==='cidr')for(const m of (r.details?.matches||[]))if(ipv4(m.value))ips.add(m.value);
 }
 return [...ips].sort((a,b)=>ipv4Int(a)-ipv4Int(b));
}
export function makeStix(rows,created=new Date().toISOString()){
 const identityId='identity--'+crypto.randomUUID();
 const objects=[{type:'identity',spec_version:'2.1',id:identityId,created,modified:created,name:'NEXUS SENTINEL',identity_class:'organization',description:'Evidence-labeled export; no numeric confidence is invented'}];
 for(const item of rows){
  if(item.type==='ipv4'&&item.status==='listed'&&ipv4(item.query)){
   objects.push({
    type:'indicator',spec_version:'2.1',id:'indicator--'+crypto.randomUUID(),created,modified:created,
    created_by_ref:identityId,name:'Publicly listed IPv4 indicator: '+item.query,
    description:'Feodo CC0 source listing. Numeric confidence not independently assessed.',
    indicator_types:['malicious-activity'],pattern:"[ipv4-addr:value = '"+item.query+"']",pattern_type:'stix',pattern_version:'2.1',valid_from:created,
    labels:['single-feed','unverified-attribution'],
    external_references:[{source_name:'abuse-ch-feodo',url:'https://feodotracker.abuse.ch/'}]
   });
  }else if(item.type==='cve'&&item.status==='cve'&&CVE.test(item.query)){
   objects.push({
    type:'vulnerability',spec_version:'2.1',id:'vulnerability--'+crypto.randomUUID(),
    created,modified:created,created_by_ref:identityId,
    name:item.query,description:'Listed in CISA Known Exploited Vulnerabilities; presence does not prove a particular system is affected.',
    external_references:[{source_name:'cve',external_id:item.query},
      {source_name:'cisa-kev',url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'}]
   });
  }
 }
 return {type:'bundle',id:'bundle--'+crypto.randomUUID(),objects};
}
