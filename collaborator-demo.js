import {normalizeOverview, formatCount} from './enterprise-v2-intelligence.mjs';

const steps = [...document.querySelectorAll('[data-step]')];
const panels = [...document.querySelectorAll('[data-panel]')];
const $ = id => document.getElementById(id);
let current = 0;

function selectStep(index) {
  if (!Number.isInteger(index) || index < 0 || index >= panels.length) return;
  current = index;
  for (const button of steps) {
    const selected = Number(button.dataset.step) === current;
    button.classList.toggle('active', selected);
    if (selected) button.setAttribute('aria-current', 'step');
    else button.removeAttribute('aria-current');
  }
  for (const panel of panels) {
    const selected = Number(panel.dataset.panel) === current;
    panel.hidden = !selected;
    panel.classList.toggle('active', selected);
  }
  $('step-counter').textContent = String(current + 1).padStart(2, '0') + ' / 05';
  $('previous').disabled = current === 0;
  $('next').disabled = current === panels.length - 1;
  $('next').textContent = current === panels.length - 1 ? 'End of walkthrough' : 'Next step →';
  $('progress-fill').style.width = ((current + 1) / panels.length * 100) + '%';
}
for (const button of steps) button.addEventListener('click', () => selectStep(Number(button.dataset.step)));
$('previous').addEventListener('click', () => selectStep(current - 1));
$('next').addEventListener('click', () => selectStep(current + 1));

const phases = [
  ['Triage the observation', 'Confirm the service version, affected asset, observation source, and customer scope before opening a real finding.'],
  ['Assign a responsible owner', 'Record accountable team, agreed remediation deadline, and review status. In this fictional demo no real ticket is created.'],
  ['Implement a remediation', 'An authorized engineer updates or isolates the affected service and attaches a change record. This illustration makes no real system changes.'],
  ['Verify with fresh evidence', 'Recheck the authorized asset, compare the result to the original evidence, and close only when the exposure is independently resolved.']
];
for (const button of document.querySelectorAll('[data-phase]')) {
  button.addEventListener('click', () => {
    const index = Number(button.dataset.phase);
    if (!Number.isInteger(index) || !phases[index]) return;
    for (const other of document.querySelectorAll('[data-phase]')) {
      other.setAttribute('aria-pressed', String(other === button));
    }
    const detail = $('phase-detail');
    detail.replaceChildren();
    const title = document.createElement('strong');
    title.textContent = phases[index][0];
    const text = document.createElement('p');
    text.textContent = phases[index][1];
    detail.append(title, text);
  });
}

function unavailable() {
  $('indicator-count').textContent = '—';
  $('kev-count').textContent = '—';
  $('snapshot-age').textContent = '—';
  $('snapshot-time').textContent = 'No source timestamp available';
  $('feed-state').textContent = 'Published snapshot unavailable';
  $('feed-detail').textContent = 'The data could not be retrieved or validated. No replacement values are generated. Open the intelligence dashboard for source details.';
}

async function loadSnapshot() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch('./data/overview.json', {signal:controller.signal,cache:'no-store'});
    if (!response.ok) throw new Error('Published overview not available');
    const data = normalizeOverview(await response.json());
    $('indicator-count').textContent = formatCount(data.listedIps);
    $('kev-count').textContent = formatCount(data.kevCount);
    $('snapshot-age').textContent = data.ageHours < 1 ? 'Under 1h' : Math.floor(data.ageHours) + 'h';
    $('snapshot-time').textContent = 'Collected: ' + new Date(data.generatedAt).toISOString().replace('T',' ').slice(0,16) + ' UTC';
    $('feed-state').textContent = data.stale ? 'Published snapshot · stale' : 'Published snapshot · available';
    $('feed-detail').textContent = data.stale
      ? 'This is historical public-intelligence data, not a current live feed. Check source freshness before decisions.'
      : 'Public indicators and KEV catalog records; not verified exposures on a customer network.';
  } catch {
    unavailable();
  } finally {
    clearTimeout(timeout);
  }
}
selectStep(0);
loadSnapshot();
