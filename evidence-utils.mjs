export function probability(value, digits=1) {
 if(value==null || value==='' || !Number.isFinite(Number(value)) || Number(value)<0 || Number(value)>1) return 'Unavailable';
 const pct=Number(value)*100, step=10**-digits;
 if(pct>0 && pct<step) return '<'+step.toFixed(digits)+'%';
 if(pct>=100-step/2) return '>'+ (100-step).toFixed(digits)+'%';
 return pct.toFixed(digits)+'%';
}
export function rankCatalog(rows,query) {
 const q=query.trim().toLowerCase();
 return rows.filter(v=>!q||[v.cveID,v.vendorProject,v.product,v.vulnerabilityName,v.shortDescription].some(x=>String(x||'').toLowerCase().includes(q)))
 .sort((a,b)=>Number(String(b.cveID).toLowerCase()===q)-Number(String(a.cveID).toLowerCase()===q));
}
export function snapshotStatus(stamp,health,now=Date.now(),failed=false) {
 const age=now-Date.parse(stamp), total=health.length, healthy=health.filter(x=>x.status==='ok').length;
 const stale=!Number.isFinite(age)||age>7*60*60*1000;
 return {healthy,total,stale,label:failed?'Cached snapshot':stale?'Snapshot delayed':healthy<total?'Partial coverage':'Snapshot available'};
}
