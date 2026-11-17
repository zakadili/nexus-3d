import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const load = name => readFile(new URL('../'+name,import.meta.url),'utf8');

test('NEXUS homepage has evidence-first real-data panels and no synthetic KPIs',async()=>{
  const html=await load('index.html');
  for(const id of ['metric-ips','metric-kev','metric-sources','metric-age','priority-list','source-gauge',
                    'history-chart','world-map','cve-table','source-list','provenance-time'])
    assert.ok(html.includes('id="'+id+'"'),id+' must be visible');
  for(const invented of ['12,846','37 critical','78% security','14 assets impacted','27 request attempts'])
    assert.ok(!html.includes(invented),invented+' must not appear as a finding or observation');
  assert.match(html,/PUBLIC INTELLIGENCE/);
  assert.match(html,/FICTIONAL TENANT/);
  assert.match(html,/SAMPLE CUSTOMER WORKSPACE/);
  assert.match(html,/aria-label="Primary navigation"/);
});

test('homepage is same-origin, script-external and does not connect to the demo VPS',async()=>{
  const html=await load('index.html');
  const js=await load('collaborator-demo.js');
  assert.match(html,/connect-src 'self'/);
  assert.match(html,/src="\.\/collaborator-demo.js"/);
  assert.doesNotMatch(html,/<script(?![^>]*src=)[^>]*>\s*\S/);
  assert.match(js,/fetch\('\.\/data\/overview\.json'/);
  assert.match(js,/normalizeOverview\(await res\.json\(\)\)/);
  assert.match(js,/fetch\('\.\/assets\/countries-110m\.json'/);
  assert.doesNotMatch(js,/193\.26\.115\.37|sslip\.io|127\.0\.0\.1:8000/);
});

test('fictional workspace uses reserved example.test names and workflow is non-destructive',async()=>{
  const js=await load('collaborator-demo.js');
  for(const host of ['app.example.test','admin.example.test','mail.example.test'])
    assert.ok(js.includes(host));
  assert.match(js,/No verification has been performed here/);
  assert.match(js,/A status button cannot substitute for evidence/);
  assert.doesNotMatch(js,/fetch\([^\n]*sampleAssets|POST.*\/scan/);
});

test('the executive dashboard is the canonical main page and legacy demo redirects',async()=>{
  const index=await load('index.html');
  const oldDemo=await load('collaborator-demo.html');
  assert.match(index,/rel="canonical" href="https:\/\/zakadili.github.io\/nexus-3d\/"/);
  assert.match(index,/<title>NEXUS SENTINEL — Executive Cyber Intelligence<\/title>/);
  assert.match(index,/href="\.\/index.html" aria-label="NEXUS home"/);
  assert.match(index,/href="\.\/intel.html" class="outline-btn"/);
  assert.doesNotMatch(index,/enterprise-v2-preview\.html|Original research site|href="\.\/collaborator-demo\.html"/);
  assert.match(oldDemo,/http-equiv="refresh" content="0; url=\.\/index.html"/);
  assert.match(oldDemo,/name="robots" content="noindex,follow"/);
});
