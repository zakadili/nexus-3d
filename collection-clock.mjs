// GitHub Actions schedule: cron "17 */6 * * *" (UTC).
// This is a countdown to the next *scheduled collection*, NOT guaranteed
// publication. Actions may be delayed, fail, or have no new source data.
export function nextScheduledCollection(nowMs=Date.now()){
 if(!Number.isFinite(nowMs))throw new TypeError('Invalid current timestamp');
 const now=new Date(nowMs);
 const hour=now.getUTCHours(),block=Math.floor(hour/6)*6;
 const slot=Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate(),block,17,0,0);
 return slot>nowMs?slot:slot+6*60*60*1000;
}
export function remainingToCollection(nowMs=Date.now()){
 const remainingMs=Math.max(0,nextScheduledCollection(nowMs)-nowMs);
 const seconds=Math.ceil(remainingMs/1000);
 const hours=Math.floor(seconds/3600);
 const minutes=Math.floor(seconds%3600/60);
 const secs=seconds%60;
 return {nextUTC:new Date(nextScheduledCollection(nowMs)).toISOString(),
         label:[hours,minutes,secs].map(n=>String(n).padStart(2,'0')).join(':')};
}
