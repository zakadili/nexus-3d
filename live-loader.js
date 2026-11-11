// Load each transport only when its own disclosure is opened.
const details=document.getElementById('live-intelligence'),legacy=document.getElementById('legacy-live-updates');
let signalsStarted=false,legacyStarted=false;
function start(){
 if(!details.open)return;
 if(!signalsStarted){signalsStarted=true;import('./live-signals.js').catch(()=>{signalsStarted=false;document.getElementById('live-signals-content').textContent='Live signals could not load. Reopen this panel to retry. Snapshot data remains separate.'})}
 if(legacy.open&&!legacyStarted){legacyStarted=true;import('./stream-adapter.js').catch(()=>{legacyStarted=false;document.getElementById('live-content').textContent='List changes could not load. Reopen this panel to retry.'})}
}
details.addEventListener('toggle',start);legacy.addEventListener('toggle',start);
function followHash(){if(location.hash==='#live-intelligence'){details.open=true;start()}}
window.addEventListener('hashchange',followHash);followHash();

const mapLive=document.getElementById('open-live-signals');
mapLive.addEventListener('click',()=>{details.open=!details.open;start()});
details.addEventListener('toggle',()=>{mapLive.setAttribute('aria-expanded',String(details.open));mapLive.textContent=details.open?'LIVE PANEL OPEN':'LIVE SIGNALS'});

