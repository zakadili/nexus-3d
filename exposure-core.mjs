// Passive domain exposure evidence model. No network requests or active probing.
// Only exact hostnames and subdomains are matched; suffix lookalikes are excluded.
const DOMAIN=/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
export function normalizeDomain(input){
  if(typeof input!=='string')return null;
  const value=input.trim().toLowerCase().replace(/\.$/,'');
  if(!DOMAIN.test(value))return null;
  return value;
}
export function hostInScope(host,domain){
  const h=normalizeDomain(host),d=normalizeDomain(domain);
  return Boolean(h&&d&&(h===d||h.endsWith('.'+d)));
}
export function buildDomainReport(input,observations=[],sources=[]){
  const domain=normalizeDomain(input);
  if(!domain)throw new TypeError('Enter a valid public DNS domain, not a URL or IP address');
  if(!Array.isArray(observations)||!Array.isArray(sources))throw new TypeError('Expected evidence arrays');
  const coverage=sources.map(s=>({
    name:String(s.name||'Unknown source'),
    status:['ok','stale','unavailable'].includes(s.status)?s.status:'unavailable',
    retrieved_at:s.retrieved_at||null
  }));
  const findings=observations.filter(o=>o&&hostInScope(o.hostname,domain)&&
    typeof o.source==='string'&&typeof o.evidence_url==='string'&&
    /^https:\/\//.test(o.evidence_url)&&typeof o.observed_at==='string')
    .map(o=>({
      hostname:normalizeDomain(o.hostname),
      kind:String(o.kind||'reported-indicator'),
      source:o.source,
      observed_at:o.observed_at,
      evidence_url:o.evidence_url,
      interpretation:'Source observation only; not proof of compromise or vulnerability'
    }));
  return {
    schema:1,domain,mode:'passive',findings,coverage,
    status:coverage.length===0||coverage.every(s=>s.status!=='ok')?'coverage-unavailable':
      findings.length?'evidence-found':'no-matching-evidence',
    disclaimer:'No matching evidence does not mean secure. No active scan was performed.'
  };
}
