// Evidence-only snapshot adapter for NEXUS Enterprise UI.
// Derived solely from the published same-origin overview.json (not customer exposure).
const asCount = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
const validDate = value => typeof value === 'string' && Number.isFinite(Date.parse(value));
const cleanText = value => typeof value === 'string' ? value.trim() : '';

export function normalizeOverview(raw, now = Date.now()) {
  if (!raw || raw.schema !== 2 || !validDate(raw.generated_at)) {
    throw new Error('Unsupported or invalid published snapshot');
  }
  const indicators = raw.indicators || {};
  const listedIps = asCount(indicators.unique_indicators);
  if (listedIps === null) throw new Error('Snapshot has no valid indicator count');
  const sourceRows = [...(Array.isArray(indicators.source_health) ? indicators.source_health : []),
    ...(Array.isArray(raw.extra_health) ? raw.extra_health : [])].map(s => ({
      id: cleanText(s.id),
      name: cleanText(s.name) || cleanText(s.id) || 'Unnamed source',
      // Historical Feodo data must never imply an operational live feed.
      status: s.id === 'feodo' ? 'retired' : (cleanText(s.status) || 'unknown'),
      originalStatus: cleanText(s.status) || 'unknown',
      count: asCount(s.records),
      reason: s.id === 'feodo' ? 'Archived snapshot; Feodo Tracker was retired following Operation Endgame' : cleanText(s.reason),
      meaning: cleanText(s.meaning)
    })).filter(s => s.id);
  const countries = (Array.isArray(indicators.countries) ? indicators.countries : [])
    .filter(c => /^[A-Z]{2}$/.test(c?.code || '') && asCount(c.indicators) !== null)
    .map(c => ({code:c.code, count:c.indicators}))
    .sort((a,b) => b.count - a.count);
  const kevObj = raw.cves?.status === 'ok' ? raw.cves : null;
  const kevCount = kevObj ? asCount(kevObj.total_kev) : null;
  const kev = (Array.isArray(kevObj?.top) ? kevObj.top : [])
    .filter(x => /^CVE-\d{4}-\d{4,}$/.test(x?.id || ''))
    .map(x => ({
      id:x.id, vendor:cleanText(x.vendor), product:cleanText(x.product),
      name:cleanText(x.name), dateAdded:cleanText(x.date_added),
      epss:Number.isFinite(x.epss) && x.epss >= 0 && x.epss <= 1 ? x.epss : null,
      ransomwareObserved:x.ransomware_observed === true
    }));
  const history = (Array.isArray(raw.history) ? raw.history : [])
    .filter(h => validDate(h?.generated_at) && asCount(h?.unique_indicators) !== null)
    .map(h => ({time:h.generated_at,count:h.unique_indicators}))
    .sort((a,b)=>Date.parse(a.time)-Date.parse(b.time))
    .filter((h,i,all) => i===0 || h.time !== all[i-1].time);
  const snapshotTime = Date.parse(raw.generated_at);
  const ageHours = Math.max(0, (now - snapshotTime) / 3_600_000);
  return {
    generatedAt:raw.generated_at,
    stale:ageHours > 18,
    ageHours,
    listedIps,
    countries,
    kevCount,
    kevRelease:cleanText(kevObj?.date_released || kevObj?.catalog_version),
    kev,
    sourceRows,
    history,
    sourceSummary: sourceRows.filter(x => x.status === 'ok').length,
    collectionFailures: Array.isArray(raw.failures) ? raw.failures.length : 0,
    provenance:{
      indicatorNote:cleanText(raw.data_lag),
      cveSource:cleanText(kevObj?.source),
      ranking:cleanText(kevObj?.ranking_method),
      geoMethod:cleanText(indicators.geo_method)
    }
  };
}

export function formatCount(value) {
  return value === null || value === undefined ? 'Unavailable' : value.toLocaleString('en-US');
}

export function formatEpss(value) {
  return value === null ? 'Not available' : (value * 100).toFixed(1) + '%';
}

export function filterKev(rows, query, filter='all') {
  const q = String(query ?? '').trim().toLocaleLowerCase();
  return rows.filter(row => {
    const search = [row.id, row.vendor, row.product, row.name].join(' ').toLocaleLowerCase();
    return (!q || search.includes(q)) &&
      (filter === 'all' || (filter === 'ransomware' && row.ransomwareObserved) ||
        (filter === 'epss' && row.epss !== null));
  });
}

export function exportKevCsv(rows, snapshotTime) {
  const columns = [
    'CVE', 'Vendor', 'Product', 'Vulnerability', 'Added to CISA KEV',
    'EPSS probability (0–1)', 'CISA reports ransomware use', 'KEV source',
    'CVE record', 'Snapshot collected at'
  ];
  const records = rows.map(row => [
    row.id, row.vendor, row.product, row.name, row.dateAdded,
    row.epss, row.ransomwareObserved ? 'Reported' : 'Not reported',
    'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    'https://www.cve.org/CVERecord?id=' + encodeURIComponent(row.id), snapshotTime
  ]);
  return [columns, ...records].map(record => record.map(value => {
    const text = String(value ?? '');
    // Keep spreadsheet applications from interpreting source text as a formula.
    const safe = /^[\s\uFEFF]*[=+@-]|^[\t\r\n]/u.test(text) ? "'" + text : text;
    return '"' + safe.replaceAll('"', '""') + '"';
  }).join(',')).join('\r\n') + '\r\n';
}
