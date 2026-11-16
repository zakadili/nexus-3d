// A deliberate but bounded boot animation. Never hold the overlay indefinitely.
const overlay=document.getElementById('nexus-boot');
if(overlay){
 const bar=overlay.querySelector('.boot-fill'),counter=overlay.querySelector('.boot-percent');
 const minimumDuration=2400,stepMs=45,timeoutMs=7000;
 const start=performance.now();
 let progress=0,ready=document.readyState==='complete',finished=false;
 const finish=()=>{
  if(finished)return;
  finished=true;
  overlay.classList.add('boot-done');
  setTimeout(()=>overlay.remove(),700);
 };
 window.addEventListener('load',()=>{ready=true},{once:true});
 const tick=()=>{
  const elapsed=performance.now()-start;
  const minimumProgress=Math.min(94,Math.floor(elapsed/minimumDuration*94));
  const target=ready&&elapsed>=minimumDuration?100:minimumProgress;
  progress=Math.min(target,progress+(target===100?5:2));
  bar.style.width=progress+'%';
  counter.textContent=String(progress).padStart(2,'0')+'%';
  if(progress===100){setTimeout(finish,220);return;}
  setTimeout(tick,stepMs);
 };
 tick();
 // Existing fail-open behavior: don't strand visitors behind a broken load.
 setTimeout(()=>{ready=true},timeoutMs);
}
