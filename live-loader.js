// The live service is contacted only after the visitor opens this section.
const details=document.getElementById('live-intelligence');let started=false;
function start(){if(!details.open||started)return;started=true;import('./stream-adapter.js?v=1b3a71dae560').catch(()=>{document.getElementById('live-content').textContent='Live updates could not load. Reload this page to try again. The country map remains a separate published snapshot.'})}
details.addEventListener('toggle',start);
function followHash(){if(location.hash==='#live-intelligence'){details.open=true;start()}}
window.addEventListener('hashchange',followHash);followHash();
