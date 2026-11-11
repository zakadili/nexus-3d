document.querySelectorAll('[data-menu]').forEach(button=>button.addEventListener('click',()=>{
 const nav=document.getElementById(button.getAttribute('aria-controls'));const open=button.getAttribute('aria-expanded')!=='true';
 button.setAttribute('aria-expanded',String(open));nav.classList.toggle('is-open',open);
}));
document.getElementById('clear-local-data')?.addEventListener('click',()=>{
 try{for(const store of [localStorage,sessionStorage])for(const key of Object.keys(store))if(key.startsWith('nexus'))store.removeItem(key);
 document.dispatchEvent(new CustomEvent('nexus:storage-cleared'));window.dispatchEvent(new CustomEvent('nexus:storage-cleared'));
 document.getElementById('storage-result').textContent='Saved NEXUS watchlists, catalog snapshots and cached observations have been cleared on this device.';
 }catch{document.getElementById('storage-result').textContent='Browser storage is unavailable.'}
});
