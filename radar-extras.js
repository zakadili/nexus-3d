// Supplemental, read-only global intelligence views. All strings use textContent.
export function buildExtrasUI(state, helpers) {
 const {create, note, fmt, name, link} = helpers;
 const extra = state.extra;
 const feeds = extra?.feeds || {};
 const statuses = extra?.source_health || [];
 const statusById = Object.fromEntries(statuses.map(s => [s.id,s]));

 function healthNote(id) {
   const status=statusById[id];
   if(!status||status.status!=='ok')
     return note('UNAVAILABLE — '+(status?.reason || state.extraError || 'no valid collected data')+'. No zero values inferred.');
   return null;
 }
 function simpleRow(label,value,cls='extra-row') {
   const row=create('div',cls);
   row.append(create('span','',label),create('strong','',value));
   return row;
 }
 function fill(id,source,callback) {
   const node=document.querySelector(id);if(!node)return;
   node.replaceChildren();
   const fallback=healthNote(source);
   if(fallback){node.append(fallback);return;}
   callback(node,feeds[source]);
 }
 function renderGlobal() {
   fill('#asn-global','iptoasn',(node,data)=>{
     const rows=Array.isArray(data?.top_global)?data.top_global:[];
     if(!rows.length){node.append(note('No ASN allocations matched the listed IP sample.'));return;}
     node.append(note('Source: IPtoASN PDDL 1.0. Networks hosting listed IPs are not necessarily malicious.'));
     for(const [i,r] of rows.slice(0,10).entries())
       node.append(simpleRow((i+1)+'. AS'+r.asn+' / '+r.org,fmt(r.listed_ips)+' listed IPs'));
   });
   fill('#outages-global','ioda',(node,data)=>{
     const events=Array.isArray(data?.events)?data.events:[];
     if(!events.length){node.append(note('IODA reported no recent country events in the fetched window. This is not proof of uninterrupted connectivity.'));return;}
     node.append(note('Georgia Tech / IODA. Outages have many causes and are not necessarily related to cyber activity.'));
     for(const e of events.slice(0,12)){
       const when=new Date(e.start*1000).toISOString().replace('T',' ').slice(0,16)+' UTC';
       const button=create('button','extra-row clickable-row');
       button.append(create('span','',name(e.code)+' · '+e.source),create('strong','',when));
       button.addEventListener('click',()=>helpers.select(e.code));
       node.append(button);
     }
   });
   const node=document.querySelector('#malware-global');if(!node)return;node.replaceChildren();
   for(const [key,label] of [['urlhaus','URLHAUS · MALWARE URLS'],['threatfox','THREATFOX · IOCs']]){
     node.append(create('h3','extra-subtitle',label));
     const fallback=healthNote(key);
     if(fallback){node.append(fallback);continue;}
     const data=feeds[key];
     node.append(simpleRow(key==='urlhaus'?'Listed URLs':'Recent IOCs',
       fmt(key==='urlhaus'?data?.total_urls:data?.total_iocs)));
     node.append(simpleRow('Country-mappable IP-hosted entries',
       fmt(key==='urlhaus'?data?.geolocated_url_count:data?.geolocated_ioc_count)));
     const entries=key==='urlhaus'?data?.top_tags:data?.top_malware;
     const title=key==='urlhaus'?'TOP URL TAGS':'TOP MALWARE FAMILIES';
     node.append(create('h4','',title));
     for(const e of (Array.isArray(entries)?entries:[]).slice(0,8))
       node.append(simpleRow(e.name,fmt(e.count)));
     if(key==='threatfox'){
       node.append(create('h4','','TOP IOC TAGS'));
       for(const e of (Array.isArray(data?.top_tags)?data.top_tags:[]).slice(0,6))
         node.append(simpleRow(e.name,fmt(e.count)));
     }
   }
   node.append(note('These feeds are independent. Listed URLs/IOCs hosted in a country do not reveal attacker location.'));
 }
 function countrySection(code) {
   const section=create('div','country-extra');
   section.append(create('h3','','COUNTRY NETWORKS · TOP ASNs'));
   const asn=healthNote('iptoasn');
   if(asn)section.append(asn);
   else{
     const rows=feeds.iptoasn?.countries?.[code]||[];
     if(!rows.length)section.append(note('No matched hosting ASN in this country’s listed-IP sample.'));
     for(const r of rows.slice(0,5))
       section.append(simpleRow('AS'+r.asn+' · '+r.org,fmt(r.listed_ips)+' listed IPs'));
   }
   section.append(note('Concentration within a hosting network does not imply the provider is malicious.'));
   section.append(create('h3','','MALWARE URL / IOC HOSTING SIGNALS'));
   for(const [id,label] of [['urlhaus','URLhaus IPv4-hosted URLs'],['threatfox','ThreatFox IPv4 IoCs']]){
     const fallback=healthNote(id);
     if(fallback){section.append(simpleRow(label,'UNAVAILABLE'));section.append(fallback);}
     else section.append(simpleRow(label,fmt(feeds[id]?.countries?.[code]||0)+' listed entries'));
   }
   section.append(note('Listed URLs/IOCs hosted in this country, not attacker location. Counts are not added to existing IP indicator totals.'));
   section.append(create('h3','','RECENT CONNECTIVITY DISRUPTIONS / IODA'));
   const outage=healthNote('ioda');
   if(outage)section.append(outage);
   else{
     const events=(feeds.ioda?.events||[]).filter(e=>e.code===code).slice(0,5);
     if(!events.length)section.append(note('No event for this country in the returned IODA list; results may be limited by the response cap.'));
     for(const event of events){
       const when=new Date(event.start*1000).toISOString();
       section.append(simpleRow(event.source,when.replace('T',' ').slice(0,16)+' UTC'));
     }
     section.append(note('Outages have many causes and are not necessarily related to cyber activity.'));
   }
   return section;
 }
 function renderHealthTimeline(history,baseStatuses) {
   const node=document.querySelector('#feed-timeline');if(!node)return;node.replaceChildren();
   const entries=(Array.isArray(history)?history:[]).slice(-28);
   const sources=[...new Set([...baseStatuses.map(r=>r.id),...statuses.map(r=>r.id)])];
   if(!entries.length){node.append(note('No recorded collection-run history yet.'));return;}
   for(const key of sources){
     const row=create('div','health-timeline-row');
     row.append(create('small','',key));
     const strip=create('div','health-dots');
     for(const entry of entries){
       const status=entry.feed_status?.[key];
       const dot=create('span','health-dot '+(status==='ok'?'ok':status==='unavailable'?'failed':'missing'));
       dot.title=(entry.generated_at||'unknown run')+' / '+(status||'no status recorded');
       strip.append(dot);
     }
     row.append(strip);node.append(row);
   }
   node.append(note('Green: success · red: unavailable · gray: not recorded. Timeline reflects the retained collection runs.'));
 }
 return {renderGlobal,countrySection,renderHealthTimeline};
}
