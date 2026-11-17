import {matchesDemoRecord} from './enterprise-v2-filter.mjs';

const navButtons = [...document.querySelectorAll('nav button[data-view]')];
const dashboard = document.getElementById('dashboard');
const placeholder = document.getElementById('placeholder');
const pageTitle = document.getElementById('page-title');
const moduleTitle = document.getElementById('placeholder-title');
const moduleDescription = document.getElementById('module-description');
const search = document.getElementById('search');
const rows = [...document.querySelectorAll('#asset-rows tr')];
const noResults = document.getElementById('no-results');
const resultCount = document.getElementById('result-count');
const severityButtons = [...document.querySelectorAll('button[data-severity]')];

const modules = {
  dashboard: {label: 'Dashboard', description: ''},
  assets: {label: 'Assets', description: 'Verified domains, IPs and services will appear here after ownership validation and secure inventory integration.'},
  exposure: {label: 'Exposure', description: 'Exposure findings require source evidence, known scope, observation time and verification status.'},
  findings: {label: 'Findings', description: 'Findings and remediation verification are not yet connected to a customer workspace.'},
  cve: {label: 'CVE Intelligence', description: 'CISA KEV and source-attributed CVE enrichment will be connected in the next milestone.'},
  threats: {label: 'Threats', description: 'Permitted intelligence feeds, coverage gaps and observation freshness will appear here after integration.'},
  reports: {label: 'Reports', description: 'Source-backed and exportable assessment reports will be built after the evidence and scoring models.'}
};

function showView(viewId) {
  const view = modules[viewId];
  if (!view) return;
  const isDashboard = viewId === 'dashboard';
  for (const button of navButtons) {
    if (button.dataset.view === viewId) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  }
  dashboard.classList.toggle('active', isDashboard);
  placeholder.classList.toggle('active', !isDashboard);
  pageTitle.textContent = view.label;
  if (!isDashboard) {
    moduleTitle.textContent = view.label;
    moduleDescription.textContent = view.description;
  }
  search.hidden = !isDashboard;
}

let selectedSeverity = 'all';
function updateDemoResults() {
  let matches = 0;
  for (const row of rows) {
    const record = {
      text: row.textContent,
      severity: row.querySelector('.pill')?.textContent ?? ''
    };
    const visible = matchesDemoRecord(record, search.value, selectedSeverity);
    row.hidden = !visible;
    if (visible) matches += 1;
  }
  resultCount.textContent = matches + ' demo record' + (matches === 1 ? '' : 's');
  noResults.classList.toggle('show', matches === 0);
}

for (const button of navButtons) {
  button.addEventListener('click', () => showView(button.dataset.view));
}
for (const button of severityButtons) {
  button.addEventListener('click', () => {
    selectedSeverity = button.dataset.severity;
    for (const option of severityButtons) {
      option.setAttribute('aria-pressed', String(option === button));
    }
    updateDemoResults();
  });
}
search.addEventListener('input', updateDemoResults);
updateDemoResults();
